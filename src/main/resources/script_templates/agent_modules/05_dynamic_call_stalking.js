//---------------------- FOR DYNAMIC CALL STALKING -------------------------------
var dynamic_call_stalking_is_enabled=false; // UPDATED FROM DRAGONHOOK PLUGIN
var modulename_to_stalk_has_been_loaded=false;
var modulename_to_stalk=module_name_to_hook
var ghidra_base_addr=ptr(ghidra_base_of_module_to_hook) 
var baseaddr_of_modulename_to_stalk=ptr(0)
var endaddr_of_modulename_to_stalk=ptr(0)
var maximum_times_to_log_call_target=1; // UPDATED FROM DRAGONHOOK PLUGIN
var dynamic_call_stalking_to_use_builtin_method=true; // UPDATED FROM DRAGONHOOK PLUGIN
var is_generally_stalking_enabled=false; //will be updated during runtime

var offsets_of_dynamic_calls={"DRAGONHOOK_OFFSETS_OF_DYNAMIC_CALLS":true}; //populated through ghidra
var dict_with_threadIds_and_whether_to_stalk_non_calls={};
var dict_with_threadIds_that_are_being_stalked={};

var call_tracing_through_stalker_is_enabled=false; // UPDATED FROM DRAGONHOOK PLUGIN
var call_tracing_ignore_callrets_outside_our_module=true; // UPDATED FROM DRAGONHOOK PLUGIN
var dict_with_threadIds_call_traces={};

var stalker_cleanup_delay_ms=5000;          //how long to wait before reclaiming
var stalker_cleanup_timer=null;
var thread_ids_pending_stalker_cleanup=[];

// we should verify  that fromaddr falls into our module before calling. The toaddr may be elsewhere
//Writes the resolved call edge (comments on both ends plus a COMPUTED_CALL xref).
//Called from whichever dynamic call stalking method resolved the target.
function update_ghidradb_with_comment_and_xref_for_dynamic_call(fromaddr,toaddr)
{
    var toaddr_offset = toaddr.sub(baseaddr_of_modulename_to_stalk);
    var fromaddr_offset = fromaddr.sub(baseaddr_of_modulename_to_stalk);
    //var instStr = Instruction.parse(toaddr).toString();
    var ghidra_addr_of_dynamic_caller=fromaddr.sub(baseaddr_of_modulename_to_stalk).add(ghidra_base_addr);
    var module_containing_target_address=modulemap_for_all_modules.find(toaddr);
    if (module_containing_target_address!=null)
    {
        var toaddr_offset_from_module_start=toaddr.sub(module_containing_target_address.base);

        //update ghidradb
        var commentstr_to_add_to_ghidradb="";
        if (module_containing_target_address.base.equals(baseaddr_of_modulename_to_stalk)) //our module
        {
            //update caller
            var probably_erroneous_stalker_flow=false; //in case of calls to external modules, Stalker sometimes believes that the next code block is the returning address of our module
            var function_data_for_function_that_is_called=extract_function_info_from_address_for_our_module(toaddr)
            if (function_data_for_function_that_is_called!=null)
            {
                var function_name=function_data_for_function_that_is_called.fun_name
                if (function_data_for_function_that_is_called.entrypoint_offset.toLowerCase()===toaddr_offset.toString().toLowerCase())
                {
                    commentstr_to_add_to_ghidradb="Calls "+function_name+" at ghidra address "+ghidra_base_addr.add(toaddr_offset)+" and offset "+toaddr_offset+ " of curent module";
                }
                else
                {
                    //call inside function
                    probably_erroneous_stalker_flow=true;
                    commentstr_to_add_to_ghidradb="Code flow continues at "+ghidra_base_addr.add(toaddr_offset)+", possibly Stalker issue";
                }
            }
            else
            {
                //ghidra has no function covering this address. Say so explicitly, otherwise the
                //comment is a bare address and looks identical to a successful lookup that lost its
                //function name.
                commentstr_to_add_to_ghidradb="Calls "+ghidra_base_addr.add(toaddr_offset)+" and offset "+toaddr_offset+" inside the current module, no function is defined there in ghidra";
            }
            update_ghidradb_with_comment_at_addr(fromaddr_offset,commentstr_to_add_to_ghidradb);
            if (probably_erroneous_stalker_flow==false)
            {
                update_ghidradb_with_xref(fromaddr_offset,toaddr_offset,"COMPUTED_CALL")
            }
                
            //update callee (comment only, xref takes care of both)
            var function_data_for_function_that_calls=extract_function_info_from_address_for_our_module(ghidra_addr_of_dynamic_caller.sub(ghidra_base_addr).add(baseaddr_of_modulename_to_stalk))
            if (function_data_for_function_that_calls!=null)
            {
                var function_name=function_data_for_function_that_calls.fun_name
                commentstr_to_add_to_ghidradb="Called from ghidra address "+ghidra_addr_of_dynamic_caller+" inside function " +function_name+ " of curent module";
            }
            else
            {
                commentstr_to_add_to_ghidradb="Called from ghidra address "+ghidra_addr_of_dynamic_caller;
            }
            if (probably_erroneous_stalker_flow)
            {
                commentstr_to_add_to_ghidradb="Code flow coming from ghidra address "+ghidra_addr_of_dynamic_caller+" , possibly Stalker issue";
            }
            update_ghidradb_with_comment_at_addr(toaddr_offset_from_module_start,commentstr_to_add_to_ghidradb);
        }
        else
        {
            //only update caller
            commentstr_to_add_to_ghidradb="Calls function at offset "+toaddr_offset_from_module_start+" relative to the module "+ module_containing_target_address.name +" , debuginfo: "+extract_DebugSymbol_fromAddress_data(toaddr);
            update_ghidradb_with_comment_at_addr(fromaddr_offset,commentstr_to_add_to_ghidradb);
        }
    }
}


//Follows one thread and resolves dynamic call targets from Stalker's own 'call' event stream.
//Called from startStalker() when the builtin method is selected in the dialog.
function stalker_follow_dynamic_calls_builtin_method(threadId)
{
    Stalker.follow(threadId, {
        events:
        {
            call:true
        },
        onReceive:function(events)
        {
            if (modulename_to_stalk_has_been_loaded==false)
            {
                return;
            }
            var calls=Stalker.parse(events,{annotate:true})
            for (var i=0; i<calls.length;i++)
            {
                var this_call=calls[i];
                //console.log(this_call)
                var fromaddr=this_call[1]
                var toaddr=this_call[2]
                
                if (fromaddr.compare(baseaddr_of_modulename_to_stalk)>=0 &&
                    fromaddr.compare(endaddr_of_modulename_to_stalk)<0 &&
                    (fromaddr.sub(baseaddr_of_modulename_to_stalk).toString() in offsets_of_dynamic_calls) &&
                    (offsets_of_dynamic_calls[fromaddr.sub(baseaddr_of_modulename_to_stalk).toString()]<maximum_times_to_log_call_target) ) 
                {
                    
                    offsets_of_dynamic_calls[fromaddr.sub(baseaddr_of_modulename_to_stalk).toString()]+=1
                    update_ghidradb_with_comment_and_xref_for_dynamic_call(fromaddr,toaddr)
                }
            }
        }
    });
}

var arm_entry_callouts_only_inside_our_module=false;   // main performance lever, see below

//Follows one thread and resolves dynamic call targets by marking the call site in a callout and
//reading the mark at the next block entry. Called from startStalker() for the marking method.
function stalker_follow_dynamic_calls_marking_threads_method(threadId)
{
    //captured by both callouts below. "var" is deliberate: it holds the same value for the whole
    //follow, so sharing one binding across every callout is exactly what we want.
    var thread_id_str=threadId.toString();
    dict_with_threadIds_and_whether_to_stalk_non_calls[thread_id_str]=-1;

    Stalker.follow(threadId, {
        transform: function (iterator) {
            var instruction=iterator.next();
            if (instruction===null) { return; }

            //--- BLOCK ENTRY: fires on every execution, reads the marker left by a dynamic call
            //"var" is safe here even though the callout below closes over block_start: that callout is
            //created ONCE per transform(), before the loop, so there is only ever one binding for it.
            var block_start=instruction.address;
            var block_is_inside_our_module=(modulename_to_stalk_has_been_loaded &&
                block_start.compare(baseaddr_of_modulename_to_stalk)>=0 &&
                block_start.compare(endaddr_of_modulename_to_stalk)<0);

            if (modulename_to_stalk_has_been_loaded &&
                (block_is_inside_our_module || !arm_entry_callouts_only_inside_our_module))
            {
                iterator.putCallout(function (context) {
                    var marker=dict_with_threadIds_and_whether_to_stalk_non_calls[thread_id_str];
                    if (marker===undefined || marker===-1) { return; }   //fast path, no dynamic call pending
                    dict_with_threadIds_and_whether_to_stalk_non_calls[thread_id_str]=-1;
                    var fromaddr=marker.sub(ghidra_base_addr).add(baseaddr_of_modulename_to_stalk);
                    update_ghidradb_with_comment_and_xref_for_dynamic_call(fromaddr,block_start);
                });
            }

            //--- THE DYNAMIC CALL: fires on every execution, sets the marker
            var dynamic_call_has_been_encountered_in_this_code_block=false;
            do
            {
                if (modulename_to_stalk_has_been_loaded &&
                    !dynamic_call_has_been_encountered_in_this_code_block &&
                    instruction.address.compare(baseaddr_of_modulename_to_stalk)>=0 &&
                    instruction.address.compare(endaddr_of_modulename_to_stalk)<0)
                {
                    //"let", not "var": offset_str and marker_value are captured by the callout below,
                    //which runs at execution time, long after this loop has finished compiling the block.
                    //One function scoped "var" would leave every callout reading the LAST instruction's
                    //values, so a call site would be recorded against the wrong address.
                    let offset_str=instruction.address.sub(baseaddr_of_modulename_to_stalk).toString();
                    if ((offset_str in offsets_of_dynamic_calls) &&
                        (offsets_of_dynamic_calls[offset_str]<maximum_times_to_log_call_target))
                    {
                        //let, for the same reason as offset_str above
                        let marker_value=ghidra_base_addr.add(instruction.address.sub(baseaddr_of_modulename_to_stalk));
                        iterator.putCallout(function (context) {
                            if (offsets_of_dynamic_calls[offset_str]>=maximum_times_to_log_call_target) { return; }
                            offsets_of_dynamic_calls[offset_str]+=1;
                            dict_with_threadIds_and_whether_to_stalk_non_calls[thread_id_str]=marker_value;
                        });
                        dynamic_call_has_been_encountered_in_this_code_block=true;
                    }
                }
                iterator.keep();
            }
            while ((instruction = iterator.next()) !== null);
        }
    });
}


//STALKER CALL TRACING
var call_tracing_log_full_stack_on_each_call=true;  //true = original behaviour (whole stack per event)
var call_tracing_depth_adjustment=0;                 //see note on the depth convention below


//Called from the call tracing filter, to decide whether an event concerns the examined module.
function is_address_inside_stalked_module(in_addr)
{
    return in_addr.compare(baseaddr_of_modulename_to_stalk)>=0 &&
           in_addr.compare(endaddr_of_modulename_to_stalk)<0;
}


//Maintains the per thread call stack and prints one trace line per call.
//Called from the call tracing onReceive(), which may run on a stalked thread.
function process_call_ret_stalk_event(threadId,is_call,fromaddr,toaddr,depth_of_event)
{
    var thread_id_to_str=threadId.toString();

    //lazy init: the entry may never have been created, or may already have been
    //reclaimed by the cleanup timer while events were still draining
    var call_trace=dict_with_threadIds_call_traces[thread_id_to_str];
    if (call_trace===undefined)
    {
        call_trace=[];
        dict_with_threadIds_call_traces[thread_id_to_str]=call_trace;
    }

    if (is_call===false)
    {
        if (call_trace.length>0) { call_trace.pop(); }   //guarded: rets can arrive with no matching push
        return;
    }

    //Stalker's own depth counter is authoritative. Resynchronising the stack to it on every
    //call means dropped or unbalanced events cannot accumulate drift.
    var target_depth=call_trace.length;
    if (typeof depth_of_event==="number")
    {
        target_depth=depth_of_event+call_tracing_depth_adjustment;
        if (target_depth<0) { target_depth=0; }
    }

    if (call_trace.length>target_depth)
    {
        call_trace.length=target_depth;                 //rets we never saw
    }
    while (call_trace.length<target_depth)
    {
        call_trace.push("(...)");                       //calls we filtered out or never saw
    }

    var succinct_info_for_fromaddr=extract_succinct_str_for_address(fromaddr).replaceAll(",","_");
    var succinct_info_for_toaddr=extract_succinct_str_for_address(toaddr).replaceAll(",","_");
    var new_frame=succinct_info_for_fromaddr+" -> "+succinct_info_for_toaddr;
    call_trace.push(new_frame);

    if (call_tracing_log_full_stack_on_each_call)
    {
        console.log("TID "+thread_id_to_str+":"+call_trace);
    }
    else
    {
        var indent="  ".repeat(Math.min(call_trace.length,40));
        console.log("TID "+thread_id_to_str+" ["+call_trace.length+"] "+indent+new_frame);
    }
}


//Follows one thread with call and ret events enabled to produce a call trace.
//Called from startStalker() when call tracing is the selected feature.
function stalker_follow_and_log_all_calls_builtin_method(threadId)
{
    Stalker.follow(threadId, {
        events:
        {
            call:true,
            ret:true
        },
        onReceive:function(events)
        {
            if (modulename_to_stalk_has_been_loaded==false)
            {
                return;
            }

            var event=Stalker.parse(events,{annotate:true});
            for (var i=0; i<event.length;i++)
            {
                var this_event=event[i];
                var event_type=this_event[0];
                if (event_type!=="call" && event_type!=="ret")
                {
                    continue;   //other event kinds if they are ever enabled
                }

                var is_call=(event_type==="call");
                var fromaddr=this_event[1];
                var toaddr=this_event[2];
                var depth_of_event=this_event[3];

                //ignore only when BOTH ends are outside our module
                if (call_tracing_ignore_callrets_outside_our_module &&
                    !is_address_inside_stalked_module(fromaddr) &&
                    !is_address_inside_stalked_module(toaddr))
                {
                    continue;
                }

                process_call_ret_stalk_event(threadId,is_call,fromaddr,toaddr,depth_of_event);
            }
        }
    });
}



// STALKER EXCLUSIONS 

//matched case-insensitively as substrings, against module name AND path
var blacklisted_module_name_substrings=["frida","gadget","gum"];

//matched case-insensitively as substrings, against the thread name.
//"gmain" and "gdbus" are deliberately NOT here: those are GLib thread names, used by any GLib based
//application (gimp, most of GNOME) for its own main loop and dbus worker, not just by frida. Having
//them in this list makes us drop instrumentation from the application's own main thread the moment
//GLib renames it, which is usually the one thread you care about most. Add them back only if you
//are sure the target is not GLib based:
//   var blacklisted_thread_name_substrings=["frida","gum-js-loop","gmain","gdbus","pool-frida"];
var blacklisted_thread_name_substrings=["frida","gum-js-loop","pool-frida"];

//When true, EVERY module except the one being analysed is excluded from Stalker.
//Big speedup, but dynamic calls into other modules can no longer be resolved.
var stalker_exclude_everything_except_our_module=false;   // guard
var stalker_already_excluded_modules={};   //shared by both mechanisms, prevents double-exclusion

//Case insensitive substring match against a list. Called by the module and thread blacklist checks.
function is_name_blacklisted(name_to_check,array_of_substrings)
{
    if (!name_to_check) { return false; }
    var lowered=name_to_check.toLowerCase();
    for (var i=0;i<array_of_substrings.length;i++)
    {
        if (lowered.indexOf(array_of_substrings[i])>=0) { return true; }
    }
    return false;
}

//Excludes one module's address range from Stalker, once. Called by the two exclude_* helpers below.
function exclude_module_range_from_stalker(mod,reason_str)
{
    var key=(mod.path || mod.name)+"@"+mod.base;
    if (key in stalker_already_excluded_modules) { return false; }
    Stalker.exclude({base:mod.base, size:mod.size});
    stalker_already_excluded_modules[key]=true;
    console.log("Stalker: excluded "+mod.name+" at "+mod.base+" size "+mod.size+" ("+reason_str+")");
    return true;
}


//--- frida's own code ---

//Excludes a module when its name or path looks like frida's own code.
//Called during the sweep at script load and again from the module observer for late arrivals.
function exclude_module_from_stalker_if_blacklisted(mod)
{
    if (!is_name_blacklisted(mod.name,blacklisted_module_name_substrings) &&
        !is_name_blacklisted(mod.path,blacklisted_module_name_substrings))
    {
        return false;
    }
    return exclude_module_range_from_stalker(mod,"blacklisted");
}

//Sweeps every loaded module and excludes frida's own. Called ONCE at script load, before any
//Stalker.follow(), because exclusions do not apply to already compiled blocks.
function exclude_all_blacklisted_modules_from_stalker()
{
    var mods=Process.enumerateModules();
    for (var i=0;i<mods.length;i++)
    {
        exclude_module_from_stalker_if_blacklisted(mods[i]);
    }
}

//Name only test, kept as the fallback used by should_this_thread_be_stalked() when frida does not
//report a thread entrypoint.
function should_this_thread_be_stalked_based_on_name(thread)
{
    return !is_name_blacklisted(thread.name,blacklisted_thread_name_substrings);
}


//True when an address belongs to a module we treat as frida's own.
//Called from should_this_thread_be_stalked() with a thread's entrypoint.
function is_address_inside_a_blacklisted_module(in_addr)
{
    try
    {
        var module_containing_the_address=Process.findModuleByAddress(in_addr);
        if (!module_containing_the_address)
        {
            return false;
        }
        return is_name_blacklisted(module_containing_the_address.name,blacklisted_module_name_substrings)
            || is_name_blacklisted(module_containing_the_address.path,blacklisted_module_name_substrings);
    }
    catch (err)
    {
        return false;
    }
}


//Where a thread starts, coping with both frida shapes for it, or null when unavailable.
//Called from should_this_thread_be_stalked().
function return_thread_entrypoint_address(thread)
{
    try
    {
        var entrypoint_of_thread=thread.entrypoint;
        if (!entrypoint_of_thread)
        {
            return null;
        }
        //frida reports either a ThreadEntrypoint object or a bare pointer, depending on the version
        return entrypoint_of_thread.routine ? entrypoint_of_thread.routine : entrypoint_of_thread;
    }
    catch (err)
    {
        return null;
    }
}


//Identify frida's own threads by WHERE THEY START, not by what they are called. "gmain" and "gdbus"
//are GLib names used by frida AND by any GLib based application (gimp, most of GNOME), so a name
//blacklist throws away the application's own main loop, which is usually the thread you care about
//most. The thread name list stays as a fallback for platforms or frida versions that do not report
//an entrypoint.
//Called from the thread observer, for onAdded and again on onRenamed.
function should_this_thread_be_stalked(thread)
{
    var entrypoint_of_thread=return_thread_entrypoint_address(thread);
    if (entrypoint_of_thread!==null)
    {
        if (is_address_inside_a_blacklisted_module(entrypoint_of_thread))
        {
            return false;
        }
        return true;
    }
    return should_this_thread_be_stalked_based_on_name(thread);   //no entrypoint reported, fall back
}


//Bulk sweep. Needs our module's base, so it can only run once the module is loaded.
//Called from begin_stalking_as_soon_as_module_is_found(), the first moment our module base is known.
function exclude_all_modules_except_our_module_from_stalker()
{
    if (!stalker_exclude_everything_except_our_module) { return 0; }
    if (!modulename_to_stalk_has_been_loaded)
    {
        console.log("Stalker: cannot exclude other modules yet, "+modulename_to_stalk+" is not loaded");
        return 0;
    }
    var mods=Process.enumerateModules();
    var excluded_count=0;
    for (var i=0;i<mods.length;i++)
    {
        var mod=mods[i];
        if (mod.base.equals(baseaddr_of_modulename_to_stalk)) { continue; }   //keep ours instrumented
        if (exclude_module_range_from_stalker(mod,"not our module")) { excluded_count+=1; }
    }
    console.log("Stalker: only "+modulename_to_stalk+" stays instrumented, excluded "+excluded_count+" more modules");
    return excluded_count;
}

//Incremental version, for modules that appear after the bulk sweep
//Called from the module observer for every module that appears after the bulk sweep.
function exclude_module_from_stalker_if_it_is_not_ours(mod)
{
    if (!stalker_exclude_everything_except_our_module) { return false; }
    if (!modulename_to_stalk_has_been_loaded) { return false; }   //bulk sweep will catch it later
    if (mod.base.equals(baseaddr_of_modulename_to_stalk)) { return false; }
    return exclude_module_range_from_stalker(mod,"not our module");
}


//STALKER CLEANUP
//Deferred and batched: garbageCollect() must not run while the thread may still be
//executing instrumented code, and this runs on frida's JS thread, not a stalked one.
//Called from stopStalker() after each unfollow.
function schedule_stalker_cleanup(thread_id_str)
{
    thread_ids_pending_stalker_cleanup.push(thread_id_str);
    if (stalker_cleanup_timer!==null) { return; }

    stalker_cleanup_timer=setTimeout(function () {
        stalker_cleanup_timer=null;
        var ids=thread_ids_pending_stalker_cleanup;
        thread_ids_pending_stalker_cleanup=[];

        Stalker.garbageCollect();

        for (var i=0;i<ids.length;i++)
        {
            delete dict_with_threadIds_that_are_being_stalked[ids[i]];
            delete dict_with_threadIds_call_traces[ids[i]];
            delete dict_with_threadIds_and_whether_to_stalk_non_calls[ids[i]];
        }
        console.log("Stalker: garbage collected, released bookkeeping for "+ids.length+" thread(s)");
    }, stalker_cleanup_delay_ms);
}


//call with stopStalker(this.threadId)
//Called from the thread observer when a thread exits or is renamed into the blacklist.
function stopStalker(threadId)
{
    var thread_id_str=threadId.toString();
    if (dict_with_threadIds_that_are_being_stalked[thread_id_str]!==true)
    {
        return;   //never followed, or already stopped - unfollowing twice is pointless
    }
    dict_with_threadIds_that_are_being_stalked[thread_id_str]=false;

    Stalker.unfollow(threadId);
    Stalker.flush();                            //deliver whatever is still buffered
    schedule_stalker_cleanup(thread_id_str);    //garbageCollect + dictionary cleanup, deferred
}


//Unfollows every thread we are still following. Called from rpc.exports.dispose(), that is when the
//script is being unloaded.
function stop_stalking_all_threads()
{
    for (var thread_id_str in dict_with_threadIds_that_are_being_stalked)
    {
        if (dict_with_threadIds_that_are_being_stalked[thread_id_str]===true)
        {
            stopStalker(parseInt(thread_id_str,10));
        }
    }
}



//call with startStalker(this.threadId,modulename_to_stalk)
//Called from the thread observer for each thread that passes the filters, and again after the string
//reference time box refollows a thread. Owns the 'already following' flag.
function startStalker(threadId, targetModule){
    var thread_id_to_str=threadId.toString();
    //Stalker.follow() on a thread that is already followed does NOT merge the two configurations, so
    //one of them is silently lost. The observer can also see the same thread twice (onAdded plus an
    //enumeration at startup).
    if (dict_with_threadIds_that_are_being_stalked[thread_id_to_str]===true)
    {
        return;
    }
    dict_with_threadIds_that_are_being_stalked[thread_id_to_str]=true;

    if (dynamic_call_stalking_is_enabled)
    {
        if (dynamic_call_stalking_to_use_builtin_method)
        {
            stalker_follow_dynamic_calls_builtin_method(threadId);
        }
        else
        {
            stalker_follow_dynamic_calls_marking_threads_method(threadId);
        }      
    }
    if (call_tracing_through_stalker_is_enabled)
    {
        stalker_follow_and_log_all_calls_builtin_method(threadId);
    }
    if (string_reference_resolution_is_enabled)
    {
        stalker_follow_and_resolve_string_references(threadId);
    }

}



//One time setup once the examined module exists: record its bounds, load the feature tables and
//apply the module exclusions. The plugin injects the call to this into
//intercept_identified_module_DragonHook(), so it runs from the module observer.
function begin_stalking_as_soon_as_module_is_found()
{
    //initialize our variables as soon as we are certain that our module has been loaded
    baseaddr_of_modulename_to_stalk=Process.getModuleByName(modulename_to_stalk).base
    endaddr_of_modulename_to_stalk=baseaddr_of_modulename_to_stalk.add(Process.getModuleByName(modulename_to_stalk).size)
    
    //Process.getModuleByName(modulename_to_stalk).ensureInitialized(); //can cause crashes on Android, particularly on process spawn
    modulename_to_stalk_has_been_loaded=true;
    if (string_reference_resolution_is_enabled)
    {
        load_strings_to_resolve();
        //the window is measured from here, the moment the examined module is actually present, rather
        //than from script load when the target may not have gone anywhere near it yet
        arm_the_timer_for_dropping_register_based_instrumentation();
    }
    if (stalker_exclude_everything_except_our_module)
    {
        exclude_all_modules_except_our_module_from_stalker(); // no-op unless the relevant guard flag is on
    }
}


//---------------------- END: FOR DYNAMIC CALL STALKING -------------------------------


