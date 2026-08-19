//------------------------- FOR HARDWARE WATCHPOINTS ----------------------------------
//https://frida.re/news/2024/09/06/frida-16-5-0-released/
var setting_of_watchpoints_is_enabled=false; // UPDATED FROM DRAGONHOOK PLUGIN
var threads_and_watchpoint_ids={};
var watchpoint_ids_and_how_many_times_each_is_visited={};
var exception_handler_has_been_installed=false;
var array_of_objects_for_which_to_install_watchpoints=[{"address_offset_as_num":0xffffffffffff,"size":4,"operation":"r"}]; // UPDATED FROM DRAGONHOOK PLUGIN
var max_times_each_watchpoint_is_logged=4; // UPDATED FROM DRAGONHOOK PLUGIN

//Whether rpc.exports.dispose() should disarm the watchpoints when the agent is unloaded. ON, because
//leaving debug registers armed in a process we are walking away from is not something to do casually - but
//it is the one step of the teardown that can block (unsetHardwareWatchpoint is a cross thread ptrace
//operation, and a blocking call inside frida's C extension freezes the whole python interpreter). It runs
//LAST in dispose() for exactly that reason, after the Stalker teardown that keeps the target alive.
//Set it to false if a particular target reliably freezes on shutdown: the watchpoints then stay armed until
//the process exits, which is a far better outcome than skipping the unload altogether and crashing it.
var remove_watchpoints_on_dispose=true;

//Same reasoning as the stalker restriction in module 05: at module scope so that the thread observer can
//re-evaluate it when a thread is finally named.
var str_to_be_included_in_thread_name_for_watchpoints=""; //UPDATED FROM DRAGONHOOK PLUGIN
var there_is_a_restriction_for_the_thread_name_for_watchpoints=false;  //UPDATED FROM DRAGONHOOK PLUGIN


//Whether a thread satisfies the user's watchpoint thread NAME restriction. A thread with no name yet does
//not qualify, and onRenamed asks again once it has one.
//Called from the thread observer, in both onAdded and onRenamed.
function does_thread_pass_the_watchpoint_name_restriction(thread)
{
    if (!there_is_a_restriction_for_the_thread_name_for_watchpoints)
    {
        return true;
    }
    if (!thread || !thread.name)
    {
        return false;
    }
    return thread.name.toLowerCase().includes(str_to_be_included_in_thread_name_for_watchpoints);
}
//A SET of thread ids, keyed by the id, rather than an array of Thread objects. Two reasons:
//  * frida hands every observer callback its own Thread object for the same thread, so removing an entry
//    by object identity never matched and dead threads were left in the queue;
//  * with an array, removal is a linear scan of the whole queue on every thread exit. Keyed by id,
//    inserting and removing are both a single property operation and no search happens at all. The queue
//    is only ever walked once, when it is drained.
//The Thread object is looked up in dict_from_threadids_to_threads at drain time instead of being stored,
//which also means a thread that has since exited is detected for free, by being absent from it.
var threadids_queued_for_watchpoint_installation={};

//The watchpoint id is a hardware debug register slot FOR ONE THREAD, not a process wide counter.
//x86-64 has 4 debug registers and arm64 normally exposes 4 as well, so slots run 0..3 per thread.
var max_hardware_watchpoint_slots_per_thread=4;

//Writing the debug registers of a thread other than the current one needs the OS to let us reach
//into that thread. On linux and android that is a ptrace attach, which yama, SELinux or an already
//attached tracer can refuse ("unable to attach to thread"). On windows it is SuspendThread plus
//SetThreadContext, which normally succeeds for our own process. Either way, if it keeps failing
//there is no point retrying it for every thread and every watchpoint.
var cross_thread_watchpoint_installs_are_disabled=false;
var number_of_consecutive_cross_thread_install_failures=0;
var max_consecutive_cross_thread_install_failures_before_giving_up=3;

//marks errors we raised ourselves (bad parameters, no free slot) so that they are not mistaken for
//an OS level refusal to touch another thread
var dragonhook_error_prefix="DragonHook: ";


//the visit counter has to be keyed by thread AND slot, because slot numbers repeat across threads
//Called wherever the hit counter for a watchpoint is read or written.
function return_watchpoint_visit_key(thread_id_to_str,watchpoint_id)
{
    return thread_id_to_str+":"+watchpoint_id;
}


//The lowest hardware slot on this thread that none of our ARMED watchpoints is using. Derived from the
//bookkeeping rather than from a counter: a counter only ever went up, so a slot stayed spent after its
//watchpoint had been disarmed and a thread that had cycled through four watchpoints could never get
//another one even though every debug register was free again.
//Called from install_watchpoint_for_a_thread(). Returns -1 when all slots really are in use.
function return_first_free_hardware_watchpoint_slot_for_thread(thread_id_to_str)
{
    var slots_that_are_in_use={};
    var bookkeeping_for_thread=threads_and_watchpoint_ids[thread_id_to_str];
    if (bookkeeping_for_thread)
    {
        for (var addr_str in bookkeeping_for_thread)
        {
            if (bookkeeping_for_thread[addr_str][3]==="installed")
            {
                slots_that_are_in_use[bookkeeping_for_thread[addr_str][0]]=true;
            }
        }
    }
    for (var candidate_slot=0;candidate_slot<max_hardware_watchpoint_slots_per_thread;candidate_slot++)
    {
        if (!(candidate_slot in slots_that_are_in_use))
        {
            return candidate_slot;
        }
    }
    return -1;
}


//True when at least one watchpoint of ours was ever successfully armed on this thread and not yet
//forgotten. Used by the exception handler to tell a trap of ours from somebody else's.
function do_we_have_any_watchpoint_bookkeeping_for_thread(thread_id_to_str)
{
    var bookkeeping_for_thread=threads_and_watchpoint_ids[thread_id_to_str];
    if (!bookkeeping_for_thread)
    {
        return false;   //we never armed anything on it
    }
    for (var addr_str in bookkeeping_for_thread)
    {
        return true;    //an entry exists only once setHardwareWatchpoint() had succeeded for it
    }
    return false;       //the dict was created but every install for this thread failed
}


//thread names are frequently null at creation time and set a moment later, so both helpers cope
//with a missing name rather than printing "undefined"
//Called by the install and uninstall log lines, which take a thread object.
function describe_thread(thread_object)
{
    try
    {
        var name_of_thread=(thread_object && thread_object.name) ? thread_object.name : "unnamed";
        return "thread "+thread_object.id+" ("+name_of_thread+")";
    }
    catch (err)
    {
        return "thread <unknown>";
    }
}

//Same as describe_thread() but starting from a thread id, looking the object up as it goes.
//Called from the exception handler and the unset paths, which only have an id.
function describe_thread_by_id(thread_id_to_str)
{
    var thread_object=dict_from_threadids_to_threads[thread_id_to_str];
    if (thread_object)
    {
        return describe_thread(thread_object);
    }
    return "thread "+thread_id_to_str+" (name unknown)";
}

//Maps an r/w/rw watchpoint condition to the ghidra RefType to record.
//Called from update_ghidradb_with_comment_and_xref_for_watchpoint().
function get_valid_flowtype_for_operation(operation)
{
    if (operation=="r")
    {
        return "READ"
    }
    if (operation=="w")
    {
        return "WRITE"
    }
    return "READ_WRITE"
}

//A data watchpoint on x86 is a TRAP, not a fault: the #DB is raised after the access has completed, so
//the pc the handler is handed is the instruction AFTER the one that did the access. Stepping one byte
//back lands inside the accessing instruction, and both ghidra side updaters resolve what they are given
//with getCodeUnitContaining(), so any byte of that instruction names it correctly.
//On other architectures the pc is not adjusted: aarch64 watchpoint exceptions are allowed to be
//imprecise, so a fixed offset there would be a guess rather than a correction.
//Called from update_ghidradb_with_comment_and_xref_for_watchpoint().
function return_address_to_attribute_the_access_to(pc_from_the_exception)
{
    if (Process.arch==="x64" || Process.arch==="ia32")
    {
        return pc_from_the_exception.sub(1);
    }
    return pc_from_the_exception;
}


// we should verify  that toaddr falls into our module before calling. The fromaddr may be elsewhere
//Called from the exception handler once a hit has been attributed to one of our watchpoints.
function update_ghidradb_with_comment_and_xref_for_watchpoint(fromaddr,toaddr,operation)
{
    //everything written into the ghidra db is attributed to the instruction that really did the access
    var address_of_the_accessing_instruction=return_address_to_attribute_the_access_to(fromaddr);
    var toaddr_offset = toaddr.sub(module_to_hook_baseaddr);
    var fromaddr_offset = address_of_the_accessing_instruction.sub(module_to_hook_baseaddr);
    var module_containing_from_address=modulemap_for_all_modules.find(address_of_the_accessing_instruction);
    if (module_containing_from_address==null)
    {
        //JIT compiled code, an anonymous mapping, or a module that has since been unloaded. There is no
        //ghidra address for it and therefore no xref to record, but the WATCHED address still deserves
        //to say that something touched it: writing nothing at all made these accesses look as if they
        //had never happened. Process.findRangeByAddress() still reports base, size and protection for a
        //mapping that belongs to no module, which is what makes a JIT hit identifiable afterwards.
        var description_of_the_mapping="";
        try
        {
            var range_containing_from_address=Process.findRangeByAddress(address_of_the_accessing_instruction);
            if (range_containing_from_address!=null)
            {
                description_of_the_mapping=" , inside a mapping at "+range_containing_from_address.base
                    +" of size "+range_containing_from_address.size
                    +" and protection "+range_containing_from_address.protection;
                if (range_containing_from_address.file!=null && range_containing_from_address.file.path!=null)
                {
                    description_of_the_mapping+=" backed by "+range_containing_from_address.file.path;
                }
            }
        }
        catch (err) { }
        update_ghidradb_with_comment_at_addr(toaddr_offset,
            "Altered through a "+operation+" from code that belongs to no loaded module (JIT or anonymous mapping): "
            +describe_address_with_module_info(address_of_the_accessing_instruction)+description_of_the_mapping);
        return;
    }
    var fromaddr_offset_from_module_start=address_of_the_accessing_instruction.sub(module_containing_from_address.base);

    //update ghidradb
    var commentstr_to_add_to_ghidradb="";
    if (module_containing_from_address.base.equals(module_to_hook_baseaddr)) //our module
    {
        //update toaddr
        var function_data_for_function_that_performs_the_operation=extract_function_info_from_address_for_our_module(address_of_the_accessing_instruction)
        if (function_data_for_function_that_performs_the_operation!=null)
        {
            var function_name=function_data_for_function_that_performs_the_operation.fun_name
            commentstr_to_add_to_ghidradb="Altered through a "+operation +" from "+function_name+" at ghidra address "+ghidra_base_addr.add(fromaddr_offset)+" and offset "+fromaddr_offset+ " of curent module";
        }
        else
        {
            commentstr_to_add_to_ghidradb="Altered through a "+operation +" from ghidra address "+ghidra_base_addr.add(fromaddr_offset)+" and offset "+fromaddr_offset+ " of curent module";
        }
        update_ghidradb_with_comment_at_addr(toaddr_offset,commentstr_to_add_to_ghidradb);
        update_ghidradb_with_xref(fromaddr_offset,toaddr_offset,get_valid_flowtype_for_operation(operation))

            
        //update fromaddr (comment only, xref takes care of both)
        //neutral wording: this comment now sits on the accessing instruction itself, not on the one after it
        commentstr_to_add_to_ghidradb="Altering with a "+operation+" the ghidra address "+ghidra_base_addr.add(toaddr_offset);
        update_ghidradb_with_comment_at_addr(fromaddr_offset_from_module_start,commentstr_to_add_to_ghidradb);
    }
    else
    {
        //only update memory that is touched (toaddr)
        commentstr_to_add_to_ghidradb="Altered through a "+operation +" from offset "+fromaddr_offset_from_module_start+" relative to the module "+ module_containing_from_address.name +" , debuginfo: "+extract_DebugSymbol_fromAddress_data(address_of_the_accessing_instruction);
        update_ghidradb_with_comment_at_addr(toaddr_offset,commentstr_to_add_to_ghidradb);
    }
}


//Unsetting must never throw out of here: this runs from a native exception handler, and an
//exception escaping into that context takes the target process down.
//Called from every disarm path, including from inside the exception handler.
function safely_unset_hardware_watchpoint(thread_id_to_str,watchpoint_id,address_as_str)
{
    var bookkeeping_for_thread=threads_and_watchpoint_ids[thread_id_to_str];
    if (!bookkeeping_for_thread || !(address_as_str in bookkeeping_for_thread))
    {
        return false;
    }
    if (bookkeeping_for_thread[address_as_str][3]!=="installed")
    {
        return false;   //already uninstalled, unsetting a second time would throw
    }
    var thread_object=dict_from_threadids_to_threads[thread_id_to_str];
    if (!thread_object)
    {
        console.log("Cannot unset hardware watchpoint "+watchpoint_id+", "+describe_thread_by_id(thread_id_to_str)+" is no longer known");
        bookkeeping_for_thread[address_as_str][3]="uninstalled";
        return false;
    }
    try
    {
        thread_object.unsetHardwareWatchpoint(watchpoint_id);
        bookkeeping_for_thread[address_as_str][3]="uninstalled";
        return true;
    }
    catch (err)
    {
        //mark it uninstalled anyway, otherwise every later hit retries and throws again
        bookkeeping_for_thread[address_as_str][3]="uninstalled";
        console.log("Could not unset hardware watchpoint "+watchpoint_id+" for "+describe_thread_by_id(thread_id_to_str)+": "+err);
        return false;
    }
}


//The hardware reports the address that was ACCESSED, which is not necessarily the base of the
//watched region: a 4 byte watchpoint at 0x1000 hit by a read of 0x1002 reports 0x1002. Matching on
//the base address alone therefore misses, and a miss that leaves the watchpoint armed makes the
//faulting instruction re-execute and trigger again, forever.
//Called from the exception handler when frida did report the accessed address.
function find_watchpoint_entry_containing(thread_id_to_str,accessed_address)
{
    var bookkeeping_for_thread=threads_and_watchpoint_ids[thread_id_to_str];
    if (!bookkeeping_for_thread)
    {
        return null;
    }
    for (var addr_str in bookkeeping_for_thread)
    {
        var entry_for_this_address=bookkeeping_for_thread[addr_str];
        if (entry_for_this_address[3]!=="installed")
        {
            continue;
        }
        var watched_base=ptr(addr_str);
        var watched_size=entry_for_this_address[1];
        if (accessed_address.compare(watched_base)>=0 &&
            accessed_address.compare(watched_base.add(watched_size))<0)
        {
            return {address_as_str:addr_str, watchpoint_id:entry_for_this_address[0], size:watched_size};
        }
    }
    return null;
}


//last resort when we cannot tell which of our watchpoints fired. Leaving any of them armed while
//returning from the handler means the same access re-triggers immediately and the process spins.
//Called from the exception handler on any path where the specific watchpoint cannot be identified.
function disarm_all_watchpoints_for_thread(thread_id_to_str)
{
    var bookkeeping_for_thread=threads_and_watchpoint_ids[thread_id_to_str];
    if (!bookkeeping_for_thread)
    {
        return 0;
    }
    var number_disarmed=0;
    for (var addr_str in bookkeeping_for_thread)
    {
        if (bookkeeping_for_thread[addr_str][3]!=="installed")
        {
            continue;
        }
        if (safely_unset_hardware_watchpoint(thread_id_to_str,bookkeeping_for_thread[addr_str][0],addr_str))
        {
            number_disarmed+=1;
        }
    }
    return number_disarmed;
}


//A readable description of any address: the module that contains it and the offset inside that
//module, plus the ghidra address and covering function when it falls inside the analysed module.
//Deliberately never asks ghidra for code unit data, and only consults the function range table when
//it is already resident: this runs inside an exception handler on a target thread, where a
//send()+recv().wait() round trip would freeze that thread.
//Called from the exception handler for every address it prints.
function describe_address_with_module_info(in_addr)
{
    if (in_addr===null || in_addr===undefined)
    {
        return "<no address>";
    }
    var description=""+in_addr;
    var belonging_module=modulemap_for_all_modules.find(in_addr);
    if (belonging_module)
    {
        description+=" in module "+belonging_module.name+" at offset "+in_addr.sub(belonging_module.base);
    }
    else
    {
        description+=" (no loaded module contains this address)";
    }

    if (is_module_to_hook_loaded &&
        in_addr.compare(module_to_hook_baseaddr)>=0 &&
        in_addr.compare(module_to_hook_endaddr)<0)
    {
        var offset_in_our_module=in_addr.sub(module_to_hook_baseaddr);
        description+=" , ghidra address "+offset_in_our_module.add(ghidra_base_of_module_to_hook);
        if (function_ranges_are_loaded)   //in memory lookup only, never a blocking fetch
        {
            var fun_data=extract_function_info_from_address_for_our_module(in_addr);
            if (fun_data)
            {
                description+=" , inside function "+fun_data.fun_name
                    +"+"+offset_in_our_module.sub(ptr(fun_data.entrypoint_offset));
            }
            else
            {
                description+=" , no function defined there in ghidra";
            }
        }
    }

    try
    {
        description+=" , debuginfo: "+extract_DebugSymbol_fromAddress_data(in_addr);
    }
    catch (err) { }
    return description;
}


//The watchpoints currently armed on one thread. Called from the exception handler on x86, where the
//cpu does not report which address was accessed and the list is all we have to attribute the hit.
function return_installed_watchpoints_for_thread(thread_id_to_str)
{
    var retval=[];
    var bookkeeping_for_thread=threads_and_watchpoint_ids[thread_id_to_str];
    if (!bookkeeping_for_thread)
    {
        return retval;
    }
    for (var addr_str in bookkeeping_for_thread)
    {
        if (bookkeeping_for_thread[addr_str][3]==="installed")
        {
            retval.push({address_as_str:addr_str,
                         watchpoint_id:bookkeeping_for_thread[addr_str][0],
                         size:bookkeeping_for_thread[addr_str][1],
                         conditions:bookkeeping_for_thread[addr_str][2]});
        }
    }
    return retval;
}


//outer guard, so that nothing at all can propagate back into the native exception path
//Installed once, on the first successful watchpoint install. Frida calls it for EVERY exception in
//the process, on whichever thread raised it.
function process_wide_exception_handler_for_watchpoints(details)
{
    try
    {
        return handle_watchpoint_exception(details);
    }
    catch (err)
    {
        console.log("Exception raised inside the watchpoint exception handler, passing to the application: "+err);
        return false;
    }
}


//The real handler body: identifies which of our watchpoints fired, records it, and disarms when the
//budget is spent. Called only from the guarded wrapper above, on the faulting thread.
function handle_watchpoint_exception(details)
{
    var is_hardware_watchpoint_hit=['breakpoint', 'single-step'].includes(details.type);
    if (!is_hardware_watchpoint_hit)
    {
        //not ours. Do NOT log here: this handler sees every exception in the process and console.log
        //is a send(), so logging unconditionally floods the channel on an exception heavy target.
        return false;
    }

    var thread_id_to_str=Process.getCurrentThreadId().toString();

    //A hardware watchpoint lives in the debug registers of ONE thread and can only ever fire on that
    //thread, so a breakpoint or single-step trap on a thread where we armed nothing cannot be ours: it
    //belongs to the application (an int3 anti debug check, a deliberate single-step loop) or to another
    //tool sharing the process. Returning true would claim it as handled and swallow it.
    //The test is "was anything of ours EVER armed on this thread", not "is anything still armed":
    //safely_unset_hardware_watchpoint() marks an entry uninstalled even when the unset threw, so an
    //entry reading uninstalled may still be live in hardware, and handing that trap away would let it
    //re-trigger forever. A thread with no entry at all is the only case we can be certain about.
    if (!do_we_have_any_watchpoint_bookkeeping_for_thread(thread_id_to_str))
    {
        return false;
    }

    var address_which_triggered_the_exception=details.context.pc;
    console.log("=== Handler got "+details.type+" exception on "+describe_thread_by_id(thread_id_to_str));
    console.log("    pc: "+describe_address_with_module_info(address_which_triggered_the_exception));

    if (!details.memory)
    {
        //This is the NORMAL shape of a hardware watchpoint hit on x86. The CPU raises #DB, delivered
        //as SIGTRAP with si_code TRAP_HWBKPT, and that signal carries no faulting data address the
        //way a SIGSEGV carries si_addr. Only DR6 says which debug register fired, and frida does not
        //surface it, so details.memory cannot be filled in. The pc is all we get.
        console.log("    no details.memory: expected for a hardware watchpoint on x86, the cpu does not report which data address was accessed");
        if (details.address!==undefined && !details.address.equals(address_which_triggered_the_exception))
        {
            console.log("    exception address: "+describe_address_with_module_info(details.address));
        }

        var installed_watchpoints=return_installed_watchpoints_for_thread(thread_id_to_str);
        console.log("    watchpoints currently armed on this thread: "+installed_watchpoints.length);
        for (var ind_wp=0;ind_wp<installed_watchpoints.length;ind_wp++)
        {
            console.log("      slot "+installed_watchpoints[ind_wp].watchpoint_id
                +" , size "+installed_watchpoints[ind_wp].size
                +" , conditions "+installed_watchpoints[ind_wp].conditions
                +" , watching "+describe_address_with_module_info(ptr(installed_watchpoints[ind_wp].address_as_str)));
        }

        if (installed_watchpoints.length===1)
        {
            //Only one candidate on this thread, so the attribution is unambiguous even without
            //details.memory. Because we know WHICH watchpoint fired, the per watchpoint log budget can
            //be honoured here exactly as it is on the details.memory path below. Without this the x86
            //path never counted a visit and always disarmed after the very first hit, which made the
            //"maximum times to log" option a no op on the platform where !details.memory is the norm.
            var watchpoint_visit_key_for_the_only_one=return_watchpoint_visit_key(thread_id_to_str,installed_watchpoints[0].watchpoint_id);
            if (watchpoint_visit_key_for_the_only_one in watchpoint_ids_and_how_many_times_each_is_visited)
            {
                watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_visit_key_for_the_only_one]+=1;
            }
            else
            {
                watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_visit_key_for_the_only_one]=1;
            }
            var number_of_hits_so_far=watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_visit_key_for_the_only_one];
            console.log("    attributing the hit to the only watchpoint armed on this thread (hit "
                +number_of_hits_so_far+" of "+max_times_each_watchpoint_is_logged+")");
            update_ghidradb_with_comment_and_xref_for_watchpoint(address_which_triggered_the_exception,
                ptr(installed_watchpoints[0].address_as_str), installed_watchpoints[0].conditions);

            if (number_of_hits_so_far<max_times_each_watchpoint_is_logged)
            {
                //Budget left, so leave it armed and let the next access be recorded too. Safe because
                //#DB for a data watchpoint is a trap taken AFTER the access: resuming continues past
                //the accessing instruction and cannot re-trigger on the same one.
                return true;
            }
            console.log("    the log budget for this watchpoint is spent, disarming it");
        } 
        else if (installed_watchpoints.length>1)
        {
            console.log("    more than one watchpoint is armed on this thread and the cpu does not say which fired, so no comment is written."
                +" Arm one watchpoint at a time to get attribution on x86.");
        }

        //we cannot narrow it down further, so disarm all of ours for this thread. Returning while any
        //of them is still armed would re-trigger the same access forever.
        disarm_all_watchpoints_for_thread(thread_id_to_str);
        return true;
    }

    var address_for_which_the_exception_was_triggered=details.memory.address
    var matched_watchpoint=find_watchpoint_entry_containing(thread_id_to_str,address_for_which_the_exception_was_triggered);
    if (matched_watchpoint===null)
    {
        console.log('Could not identify which watchpoint covers the access at '+address_for_which_the_exception_was_triggered
            +' on '+describe_thread_by_id(thread_id_to_str)+'. Disarming our watchpoints for this thread so that the access cannot re-trigger forever.');
        disarm_all_watchpoints_for_thread(thread_id_to_str);
        return true;
    }

    var watchpoint_id_to_uninstall=matched_watchpoint.watchpoint_id;
    var address_of_watchpoint_as_str=matched_watchpoint.address_as_str;
    var watchpoint_visit_key=return_watchpoint_visit_key(thread_id_to_str,watchpoint_id_to_uninstall);

    if (watchpoint_visit_key in watchpoint_ids_and_how_many_times_each_is_visited)
    {
        watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_visit_key]+=1;
    }
    else
    {
        watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_visit_key]=1;
    }
    if ( watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_visit_key]>max_times_each_watchpoint_is_logged)
    {
        console.log("Strange, hit this watchpoint too many times, disabling it.")
        if (!safely_unset_hardware_watchpoint(thread_id_to_str,watchpoint_id_to_uninstall,address_of_watchpoint_as_str))
        {
            disarm_all_watchpoints_for_thread(thread_id_to_str); //could not disable just that one
        }
        return true;   //always resume once we know it was ours, never hand a still armed trap back
    }

    console.log("HARDWARE WATCHPOINT TRIGGERED: For address "+address_for_which_the_exception_was_triggered+" , we had a "+details.memory.operation+" to it, from address "+address_which_triggered_the_exception+ " from "+describe_address_with_module_info(address_which_triggered_the_exception));
    
    if (is_address_inside_module(module_to_hook_baseaddr,module_to_hook_size,address_which_triggered_the_exception))
    {
        //inside_our_module
        var offset_from_base_of_hooked_module_as_num=address_which_triggered_the_exception.sub(module_to_hook_baseaddr).toInt32()
        var ghidra_addr_for_addr_that_triggers_watchpoint=(ghidra_base_of_module_to_hook+offset_from_base_of_hooked_module_as_num).toString(16)
        console.log("HARDWARE WATCHPOINT TRIGGERED: This address corresponds to ghidra address "+ghidra_addr_for_addr_that_triggers_watchpoint)
    }
    update_ghidradb_with_comment_and_xref_for_watchpoint(address_which_triggered_the_exception,address_for_which_the_exception_was_triggered,details.memory.operation)
    if ( watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_visit_key]>=max_times_each_watchpoint_is_logged)
    {
        if (safely_unset_hardware_watchpoint(thread_id_to_str,watchpoint_id_to_uninstall,address_of_watchpoint_as_str))
        {
            console.log('Disabled hardware watchpoint ' + watchpoint_id_to_uninstall+ ' for '+describe_thread_by_id(thread_id_to_str)+' and address for which the exception was triggered '+address_for_which_the_exception_was_triggered);
        } 
    }
    return true;
}
 

//hardware watchpoints accept 1, 2, 4 or 8 bytes only, and the address must be aligned to the size.
//Checking here gives a message that names the problem instead of a bare frida exception.
//Called from install_watchpoint_for_a_thread() before frida is asked for anything.
function check_watchpoint_parameters(address,size,conditions)
{
    if (size!==1 && size!==2 && size!==4 && size!==8)
    {
        return "size "+size+" is not a valid hardware watchpoint size, it must be 1, 2, 4 or 8";
    }
    if (!address.and(ptr(size-1)).isNull())
    {
        return "address "+address+" is not aligned to the watchpoint size "+size;
    }
    if (conditions!=="r" && conditions!=="w" && conditions!=="rw")
    {
        return "conditions '"+conditions+"' is not one of r, w, rw";
    }
    return "ok";
}


//Validates, allocates a hardware slot for that thread, installs the exception handler once and arms
//the watchpoint. Throws on any problem. Called only from safe_add_watchpoint_for_a_thread().
function install_watchpoint_for_a_thread(address, size, conditions, thread) {

    var thread_id_to_str=thread.id.toString();

    var parameter_check=check_watchpoint_parameters(address,size,conditions);
    if (parameter_check!=="ok")
    {
        throw new Error(dragonhook_error_prefix+parameter_check);
    }

    //slot index for THIS thread. A process wide counter meant the second thread asked for slot 2,3,
    //4... which does not exist, so setHardwareWatchpoint() threw and the watchpoint silently never
    //existed.
    //Arming the same address twice on the same thread would overwrite the bookkeeping entry, whose key
    //is the address, and leave the slot recorded in the old entry armed with nobody left to unset it.
    var bookkeeping_that_already_exists=threads_and_watchpoint_ids[thread_id_to_str];
    if (bookkeeping_that_already_exists && bookkeeping_that_already_exists[address.toString()]
        && bookkeeping_that_already_exists[address.toString()][3]==="installed")
    {
        console.log("Hardware watchpoint for "+address+" is already armed on "+describe_thread(thread)+", not arming it again");
        return;
    }

    var watchpoint_id_to_install=return_first_free_hardware_watchpoint_slot_for_thread(thread_id_to_str);
    if (watchpoint_id_to_install<0)
    {
        throw new Error(dragonhook_error_prefix+"thread "+thread_id_to_str+" has no free hardware watchpoint slot left, all "
            +max_hardware_watchpoint_slots_per_thread+" of them are in use");
    }

    if (exception_handler_has_been_installed==false)
    {
        try
        {
            Process.setExceptionHandler(process_wide_exception_handler_for_watchpoints);
            exception_handler_has_been_installed=true;
        }
        catch (err)
        {
            throw new Error(dragonhook_error_prefix+"could not install the process wide exception handler: "+err);
        }
    }

    if ( ! (thread_id_to_str in threads_and_watchpoint_ids))
    {
        threads_and_watchpoint_ids[thread_id_to_str]={};
    }

    //Writing another thread's debug registers requires the OS to let us reach into it, which is what
    //fails with "unable to attach to thread". Installing on the CURRENT thread needs no such access.
    //In practice this is always false today: every install path goes through
    //schedule_watchpoint_installation_for_a_thread(), so the caller is always frida's own JS thread and
    //never one of the target's. The branches that test it are kept because they are what is correct if
    //an install is ever issued from the target thread again, and because "CROSS THREAD" in the log is
    //the accurate description of what is being attempted right now.
    var installing_on_the_current_thread=(thread.id===Process.getCurrentThreadId());
    console.log("Trying to set hardware watchpoint "+watchpoint_id_to_install+" for "+address+" , size "+size
        +" , conditions "+conditions+" , for "+describe_thread(thread)
        +(installing_on_the_current_thread ? " (current thread, no attach needed)" : " (CROSS THREAD, the OS has to grant access to it)"));

    //The verdict is printed from a finally, so it appears even when setHardwareWatchpoint() throws
    //and the exception is on its way up. A "Trying to set..." with no verdict after it therefore
    //means the call neither returned nor threw, i.e. it blocked.
    var the_watchpoint_was_installed=false;
    try
    {
        //record it as installed only AFTER the call succeeded, otherwise a failed install leaves an
        //entry claiming a slot that was never set and every later uninstall attempt throws
        thread.setHardwareWatchpoint(watchpoint_id_to_install, address, size, conditions);
        the_watchpoint_was_installed=true;
        threads_and_watchpoint_ids[thread_id_to_str][address.toString()]=[watchpoint_id_to_install,size,conditions,"installed"];
    }
    finally
    {
        console.log("RESULT: hardware watchpoint "+watchpoint_id_to_install+" for address "+address+" on "
            +describe_thread(thread)+" was "
            +(the_watchpoint_was_installed ? "INSTALLED (the call succeeded)" : "NOT INSTALLED"));
    }
}


//returns true only if the watchpoint really is armed
//Called once per configured watchpoint from add_all_configured_watchpoints_for_a_thread().
function safe_add_watchpoint_for_a_thread(address,size,operation,incoming_thread)
{
    var thread_description="thread <unknown>";
    var installing_on_the_current_thread=false;
    try
    {
        thread_description=describe_thread(incoming_thread);
        installing_on_the_current_thread=(incoming_thread.id===Process.getCurrentThreadId());
    }
    catch (err) { thread_description="thread <unknown>"; }

    try
    {
        install_watchpoint_for_a_thread(address,size,operation,incoming_thread);
        number_of_consecutive_cross_thread_install_failures=0;
        return true;
    }
    catch (error)
    {
        //deliberately no DebugSymbol.fromAddress() here: the address may be bogus and that call can
        //throw from inside this catch block
        var error_as_str=""+error;
        console.log("Could not install watchpoint for "+thread_description+" at address "+address
            +" , size "+size+" , conditions "+operation+" , error: "+error_as_str);

        var this_is_our_own_validation_error=(error_as_str.indexOf(dragonhook_error_prefix)>=0);
        if (this_is_our_own_validation_error || installing_on_the_current_thread)
        {
            return false;   //nothing to do with reaching into another thread, do not count it
        }

        number_of_consecutive_cross_thread_install_failures+=1;
        console.log("This was a CROSS THREAD install. The OS has to let us write "+thread_description
            +"'s debug registers (a ptrace attach on linux and android, SuspendThread plus SetThreadContext"
            +" on windows) and it refused.");
        report_linux_ptrace_scope_once();
        if (number_of_consecutive_cross_thread_install_failures>=max_consecutive_cross_thread_install_failures_before_giving_up)
        {
            cross_thread_watchpoint_installs_are_disabled=true;
            console.log("Giving up on cross thread watchpoint installs after "
                +number_of_consecutive_cross_thread_install_failures+" consecutive failures.");
        }
        return false;
    }
}


//Arms every configured watchpoint on one thread and reports how many are really armed.
//Called only from the deferred paths, never directly from an observer callback.
function add_all_configured_watchpoints_for_a_thread(incoming_thread)
{
    if (module_to_hook_baseaddr==null)
    {
        console.log("Cannot install watchpoints yet, the module is not loaded");
        return;
    }
    var thread_id_to_str=incoming_thread.id.toString();
    var thread_description=describe_thread(incoming_thread);
    var installing_on_the_current_thread=(incoming_thread.id===Process.getCurrentThreadId());
    if (!installing_on_the_current_thread && cross_thread_watchpoint_installs_are_disabled)
    {
        console.log("Skipping watchpoints for "+thread_description+", cross thread installs are disabled after repeated failures");
        return;
    }
    if (!installing_on_the_current_thread && !(thread_id_to_str in dict_from_threadids_to_threads))
    {
        console.log("Skipping watchpoints for "+thread_description+", it is no longer alive");
        return;
    }

    var number_actually_installed=0;
    var number_attempted=0;
    for (var ind2=0;ind2<array_of_objects_for_which_to_install_watchpoints.length;ind2++)
    {
        if (!installing_on_the_current_thread && cross_thread_watchpoint_installs_are_disabled)
        {
            console.log("Stopping watchpoint installation for "+thread_description+", cross thread installs were just disabled");
            break;   //the latch may have tripped on the previous iteration
        }
        var obj_describing_watchpoint=array_of_objects_for_which_to_install_watchpoints[ind2];
        var addr=module_to_hook_baseaddr.add(obj_describing_watchpoint["address_offset_as_num"]);
        var sz=obj_describing_watchpoint["size"];
        var op=obj_describing_watchpoint["operation"];
        number_attempted+=1;
        if (safe_add_watchpoint_for_a_thread(addr,sz,op,incoming_thread))
        {
            number_actually_installed+=1;
        }
    }
    console.log("SUMMARY for "+thread_description+": "+number_actually_installed+" of "+number_attempted
        +" watchpoints are actually armed"
        +(installing_on_the_current_thread ? " (installed on itself)" : " (installed cross thread)"));
}

//Never install from inside a thread observer or module observer callback. Those run on a target
//thread (a brand new one in the thread observer's case, possibly still inside pthread startup, and
//in the module observer's case possibly holding the loader lock). setHardwareWatchpoint() has to
//stop and resume a thread to write its debug registers even when that thread is the caller, and in
//those contexts it has been observed to block and never return. frida's own JS thread holds no
//target lock and is a safe place to do it from.
//Called from the thread observer, which must not do the install itself.
function schedule_watchpoint_installation_for_a_thread(incoming_thread)
{
    setTimeout(function () { add_all_configured_watchpoints_for_a_thread(incoming_thread); }, 0);
}


var linux_ptrace_scope_has_been_reported=false;
//Prints the yama ptrace_scope value and how to relax it, at most once per session.
//Called from safe_add_watchpoint_for_a_thread() the first time a cross thread install is refused.
function report_linux_ptrace_scope_once()
{
    if (linux_ptrace_scope_has_been_reported) { return; }
    linux_ptrace_scope_has_been_reported=true;
    if (Process.platform!=="linux") { return; }
    try
    {
        var ptrace_scope_value=File.readAllText("/proc/sys/kernel/yama/ptrace_scope").trim();
        if (ptrace_scope_value==="0")
        {
            console.log("kernel.yama.ptrace_scope is 0, so yama is not what is blocking the attach.");
        }
        else
        {
            console.log("kernel.yama.ptrace_scope is "+ptrace_scope_value+" . Anything other than 0 stops frida"
                +" from attaching to a thread in order to write its debug registers. On a desktop linux, run:"
                +"   sudo sysctl kernel.yama.ptrace_scope=0");
        }
    }
    catch (err)
    {
        console.log("Could not read /proc/sys/kernel/yama/ptrace_scope: "+err);
    }
}


//Installs watchpoints on the threads that appeared before the module was loaded, then empties the
//queue. Called (deferred) from the module observer once our module is found.
function add_watchpoints_for_all_queued_threads()
{
    var queued_thread_ids=threadids_queued_for_watchpoint_installation;
    threadids_queued_for_watchpoint_installation={}; //drain it first, so a second call cannot install everything twice
    for (var thread_id_str in queued_thread_ids)
    {
        //resolved now rather than stored earlier: the object is fresh, and a thread that has exited is
        //recognised simply by no longer being in this dictionary
        var thread_object_for_queued_id=dict_from_threadids_to_threads[thread_id_str];
        if (!thread_object_for_queued_id)
        {
            console.log("Not installing watchpoints on thread "+thread_id_str+", it has exited since being queued");
            continue;
        }
        add_all_configured_watchpoints_for_a_thread(thread_object_for_queued_id);
    }
}

//Disarms every watchpoint we armed on one thread. Called (deferred) from the thread observer when a
//thread is renamed into the blacklist, and from the all threads variant below.
function remove_all_installed_watchpoints_for_a_thread(incoming_thread)
{
    var thread_id_to_str=incoming_thread.id.toString();
    if (thread_id_to_str in threads_and_watchpoint_ids)
    {
        for (var addr_str in threads_and_watchpoint_ids[thread_id_to_str])
        {
            var watchpoint_id_to_uninstall=threads_and_watchpoint_ids[thread_id_to_str][addr_str][0]
            if (safely_unset_hardware_watchpoint(thread_id_to_str,watchpoint_id_to_uninstall,addr_str))
            {
                console.log('Disabled hardware watchpoint ' + watchpoint_id_to_uninstall+ ' for '+describe_thread_by_id(thread_id_to_str)+' and watched address '+addr_str);
            }
        }
    }
}


//Called from rpc.exports.dispose(), so that no watchpoint survives the agent being unloaded.
function remove_all_installed_watchpoints_for_all_threads()
{
    for (var thread_id_to_str in dict_from_threadids_to_threads)
    {
        var thread_object=dict_from_threadids_to_threads[thread_id_to_str];
        if (thread_object)
        {
            remove_all_installed_watchpoints_for_a_thread(thread_object);
        }
    }
}


//Removes every watchpoint of ours whose WATCHED address falls inside the given absolute range, and forgets
//only those. The addresses in threads_and_watchpoint_ids are absolute - setHardwareWatchpoint() keys them by
//address.toString() - which is the only reason one mapping's watchpoints can be told from another's at all.
//
//Called by the module unload teardown in place of the wholesale remover above, because that teardown is
//deferred and by the time it runs the module may have been mapped again SOMEWHERE ELSE. The new mapping's
//watchpoints are live and have to survive; only the ones watching the dead range are stale. It also means a
//watchpoint armed by hand outside our module, from the DRAGONHOOK CODE marker, is no longer collateral damage
//when our module goes away.
//
//Entries are DELETED rather than merely unset. safely_unset_hardware_watchpoint() only marks them
//"uninstalled", and do_we_have_any_watchpoint_bookkeeping_for_thread() answers true for ANY entry regardless
//of that flag - so leaving them behind would keep the exception handler claiming traps on a thread that no
//longer has a single watchpoint of ours, and would keep the slot allocator treating their debug registers as
//occupied.
function remove_installed_watchpoints_watching_addresses_in_range(start_of_range,end_of_range)
{
    var number_of_watchpoints_removed=0;
    for (var thread_id_to_str in threads_and_watchpoint_ids)
    {
        var bookkeeping_for_thread=threads_and_watchpoint_ids[thread_id_to_str];
        if (!bookkeeping_for_thread)
        {
            continue;
        }
        for (var addr_str in bookkeeping_for_thread)
        {
            var watched_address;
            try { watched_address=ptr(addr_str); }
            catch (err) { continue; }   //not an address we can reason about, so leave it alone
            if (watched_address.compare(start_of_range)<0 || watched_address.compare(end_of_range)>=0)
            {
                continue;   //belongs to another mapping, or was armed by hand outside our module
            }
            var watchpoint_id_to_uninstall=bookkeeping_for_thread[addr_str][0];
            //Guarded per ENTRY. The whole purpose of this sweep is that nothing is left armed, so one thread
            //that throws must not abandon the others - and the caller's try/catch sits outside the loop, so
            //without this a single failure ended the sweep wherever it happened to be.
            //The call also has to run while the entry is still present: safely_unset_hardware_watchpoint()
            //looks itself up in threads_and_watchpoint_ids rather than taking the entry as an argument.
            var it_was_unset=false;
            try
            {
                it_was_unset=safely_unset_hardware_watchpoint(thread_id_to_str,watchpoint_id_to_uninstall,addr_str);
            }
            catch (err)
            {
                console.log('Could not unset hardware watchpoint '+watchpoint_id_to_uninstall+' for thread '
                    +thread_id_to_str+' watching '+addr_str+': '+err);
            }
            if (it_was_unset)
            {
                //describe_thread_by_id() reaches into the thread object, so it gets its own guard rather than
                //being able to take the sweep down over a log line
                try
                {
                    console.log('Disabled hardware watchpoint '+watchpoint_id_to_uninstall+' for '
                        +describe_thread_by_id(thread_id_to_str)+' and watched address '+addr_str);
                }
                catch (err)
                {
                    console.log('Disabled hardware watchpoint '+watchpoint_id_to_uninstall+' for thread '
                        +thread_id_to_str+' and watched address '+addr_str);
                }
            }
            //dropped either way. The module is gone, so there is nothing to retry, and keeping the entry would
            //leave do_we_have_any_watchpoint_bookkeeping_for_thread() claiming traps for it forever.
            delete watchpoint_ids_and_how_many_times_each_is_visited[
                return_watchpoint_visit_key(thread_id_to_str,watchpoint_id_to_uninstall)];
            delete bookkeeping_for_thread[addr_str];   //deleting the key being visited is safe in a for..in
            number_of_watchpoints_removed+=1;
        }
        //do_we_have_any_watchpoint_bookkeeping_for_thread() already answers false for an emptied table, so
        //this is only housekeeping - it stops empty per thread tables accumulating for the life of the process
        if (Object.keys(bookkeeping_for_thread).length===0)
        {
            delete threads_and_watchpoint_ids[thread_id_to_str];
        }
    }
    return number_of_watchpoints_removed;
}


//the debug registers die with the thread, so there is nothing to unset, only bookkeeping to drop
//Called from the thread observer when a thread exits.
function forget_watchpoint_bookkeeping_for_thread(thread_id_to_str)
{
    var bookkeeping_for_thread=threads_and_watchpoint_ids[thread_id_to_str];
    if (bookkeeping_for_thread)
    {
        for (var addr_str in bookkeeping_for_thread)
        {
            delete watchpoint_ids_and_how_many_times_each_is_visited[
                return_watchpoint_visit_key(thread_id_to_str,bookkeeping_for_thread[addr_str][0])];
        }
    }
    delete threads_and_watchpoint_ids[thread_id_to_str];
}


//---------------------- END: FOR HARDWARE WATCHPOINTS --------------------------------



