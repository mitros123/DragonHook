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

//The user's "only stalk threads whose name contains X" restriction. Declared HERE, at module scope, and
//not inside the thread observer's onAdded where they used to live, because onRenamed has to consult them
//too - see does_thread_pass_the_stalker_name_restriction().
var str_to_be_included_in_thread_name_for_stalker=""; //UPDATED FROM DRAGONHOOK PLUGIN
var there_is_a_restriction_for_the_thread_name_for_stalker=false;  //UPDATED FROM DRAGONHOOK PLUGIN


//Whether a thread satisfies the user's thread NAME restriction, as opposed to should_this_thread_be_stalked()
//which decides whether it is one of frida's own.
//Returns false for a thread with no name yet: we genuinely cannot tell, and the thread observer's
//onRenamed re-asks the moment a name appears.
//Called from the thread observer, in both onAdded and onRenamed.
function does_thread_pass_the_stalker_name_restriction(thread)
{
    if (!there_is_a_restriction_for_the_thread_name_for_stalker)
    {
        return true;   //no restriction, every thread qualifies
    }
    if (!thread || !thread.name)
    {
        return false;
    }
    return thread.name.toLowerCase().includes(str_to_be_included_in_thread_name_for_stalker);
}

var offsets_of_dynamic_calls={"DRAGONHOOK_OFFSETS_OF_DYNAMIC_CALLS":true}; //populated through ghidra
var dict_with_threadIds_and_whether_to_stalk_non_calls={};
var dict_with_threadIds_that_are_being_stalked={};

var call_tracing_through_stalker_is_enabled=false; // UPDATED FROM DRAGONHOOK PLUGIN
var call_tracing_ignore_callrets_outside_our_module=true; // UPDATED FROM DRAGONHOOK PLUGIN
//Trace calls from the moment the agent loads, rather than waiting for the examined module to appear.
//Only meaningful while call_tracing_ignore_callrets_outside_our_module is false, because the filter it
//controls is the only thing in the receiver that needs our module's bounds.
var call_tracing_before_our_module_is_loaded=false; // UPDATED FROM DRAGONHOOK PLUGIN
var the_early_call_tracing_notice_has_been_printed=false;
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
                        //captured for the Stalker.invalidate() below, for the same closure reason again
                        let address_of_this_dynamic_call=instruction.address;
                        iterator.putCallout(function (context) {
                            if (offsets_of_dynamic_calls[offset_str]>=maximum_times_to_log_call_target)
                            {
                                //Budget spent. Returning early stopped the WORK but left the callout
                                //compiled into the code cache, being executed on every pass through this
                                //call site for the rest of the session. Throwing the block away removes it,
                                //and the gate in the transform above already refuses to emit a new callout
                                //once the count has reached the limit, which is what makes the invalidate
                                //stick instead of being undone by the recompile.
                                safe_stalker_invalidate(threadId,address_of_this_dynamic_call);
                                return;
                            }
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
    //Until the module is found both bounds are ptr(0), and every address would compare as "outside".
    //That answer happens to be harmless for the filter, but it is a coincidence rather than a decision, so
    //say it explicitly: with no module there is no "inside" to be in.
    if (!modulename_to_stalk_has_been_loaded)
    {
        return false;
    }
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

    //The COMMA replacement is not cosmetic and must stay: the trace is printed as
    //console.log("TID "+tid+":"+call_trace), and string concatenating an array calls Array.toString(),
    //which joins with commas. A comma inside one frame would therefore read as a frame boundary.
    //Whitespace is collapsed to "_" as well, so that each endpoint is a single unbroken token and the
    //only spaces in a line are the " -> " between the two ends. That makes a trace line splittable and
    //greppable; it is a readability choice rather than a correctness one.
    var succinct_info_for_fromaddr=extract_succinct_str_for_address(fromaddr).replaceAll(",","_").replace(/\s+/g,"_");
    var succinct_info_for_toaddr=extract_succinct_str_for_address(toaddr).replaceAll(",","_").replace(/\s+/g,"_");
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
                //Without the module we cannot apply the "ignore call/rets outside our module" filter,
                //because we do not know where our module is, so an unfiltered run would be the only
                //honest option - and that is exactly the shape is_early_call_tracing_active() describes.
                //In every other shape there is nothing sensible to do with the event yet.
                if (!is_early_call_tracing_active())
                {
                    return;
                }
                //Said once, so that a trace full of bare module!offset lines is not mistaken for a bug.
                if (!the_early_call_tracing_notice_has_been_printed)
                {
                    the_early_call_tracing_notice_has_been_printed=true;
                    console.log("Call tracing has started BEFORE "+modulename_to_stalk+" was found. Until it"
                        +" appears there is no ghidra address to report, so trace entries are described by"
                        +" module and debug symbol only. Entries switch to ghidra addresses automatically"
                        +" once the module is loaded.");
                }
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
    //An unnamed thread tells us nothing, and this is the FALLBACK path: the entrypoint test has already
    //declined to answer. Stalking it is the right default, because a thread's name is usually set a
    //moment AFTER it is created, so refusing here would drop the application's own threads simply for
    //having been observed early. is_name_blacklisted() already returns false for a missing name, so this
    //is the same answer made explicit rather than a change of behaviour.
    if (!thread || !thread.name)
    {
        return true;
    }
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
    //Each thread is unfollowed inside its own try, because this runs on the two paths where failing halfway
    //is most expensive: the agent being unloaded, and the examined module being unloaded. Getting every
    //thread OFF Stalker's code cache is what stops the target from segfaulting when the cache is freed, so
    //one thread that cannot be unfollowed must not cost us the rest of them.
    var number_of_threads_unfollowed=0;
    for (var thread_id_str in dict_with_threadIds_that_are_being_stalked)
    {
        if (dict_with_threadIds_that_are_being_stalked[thread_id_str]!==true)
        {
            continue;
        }
        try
        {
            stopStalker(parseInt(thread_id_str,10));
            number_of_threads_unfollowed+=1;
        }
        catch (err)
        {
            console.log("Could not unfollow thread "+thread_id_str+": "+err
                +" . That thread may still be executing out of Stalker's code cache.");
        }
    }
    return number_of_threads_unfollowed;
}



//Thread ids waiting to be followed once our module has been found. An id keyed set, not an array of
//Thread objects, for the same two reasons as the watchpoint queue: removing by object identity never
//matches, because frida hands each observer callback its own object, and an id keyed set needs no linear
//scan to insert or remove. The Thread object is resolved at drain time.
var threadids_queued_for_stalking={};
var timer_for_warning_that_our_module_was_never_found=null;
var seconds_before_warning_that_our_module_was_never_found=30;


//Whether a thread should be QUEUED instead of followed right now.
//
//The problem being avoided: Stalker compiles a basic block once and reuses the instrumented copy for
//ever, and both transforms in this agent refuse to instrument anything while
//modulename_to_stalk_has_been_loaded is still false. Following a thread before our module has been found
//therefore fills its code cache with permanently empty copies. Deferring the follow means the very first
//block a thread compiles already sees the loaded flags, the string table, and the module exclusions.
//
//Scoped to the "only stalk our module" case on purpose, because that is the configuration where following
//early is most wasteful: the exclusions cannot be installed until our module's bounds are known, so an
//early follow instruments foreign modules that we were about to exclude anyway. Widening this to every
//configuration is a one line change, but it alters behaviour for runs that work today, so it is left as a
//deliberate decision rather than a side effect. The refollow logic still covers the cases this does not.
//Called from the thread observer.
function should_following_this_thread_wait_for_our_module()
{
    if (modulename_to_stalk_has_been_loaded)
    {
        return false;   //the module is known, so following now is correct
    }

    //The one configuration where following early actually GAINS something. Call tracing is event based:
    //Stalker emits call/ret from its engine rather than from instrumentation we place, so nothing is
    //compiled wrong and the events are real. The only reason they used to be thrown away is that the
    //receiver needs our module's bounds to apply the "ignore call/rets outside our module" filter - and
    //when that filter is off, it does not need them at all. So with the filter off and the user having
    //asked for it, follow immediately and trace the loader, the constructors and the rest of startup.
    if (is_early_call_tracing_active())
    {
        return false;
    }

    //Everything else waits. Each of the remaining cases either produces wrong or missing data when
    //followed early, or produces nothing at all:
    //  * the marking method and string reference resolution are TRANSFORM based, and both transforms
    //    refuse to instrument while modulename_to_stalk_has_been_loaded is false. Stalker caches those
    //    empty copies for ever, which loses our module's own .init_array constructors and, for the
    //    marking method, mis-attributes a dynamic call marker to whatever block runs next;
    //  * the builtin dynamic call method and ordinary call tracing are event based and therefore not
    //    compiled wrong, but their onReceive discards everything until the module is known, so following
    //    early pays for Stalker to copy and instrument every block of every module during startup and
    //    throws away the entire result.
    return is_generally_stalking_enabled;
}


//True when call tracing has been asked to run before our module exists, and is in the only shape where
//that is meaningful. Called from the follow decision and from the call tracing receiver, so that the two
//can never disagree about whether an early event should be processed.
function is_early_call_tracing_active()
{
    return (call_tracing_through_stalker_is_enabled
            && call_tracing_before_our_module_is_loaded
            && !call_tracing_ignore_callrets_outside_our_module);
}


//Our module has been unloaded from the process. Everything derived from it is now meaningless: the base
//and end addresses point at memory that is no longer mapped, so every "is this address inside our module"
//test would misclassify whatever gets mapped there next, ghidra offsets computed from that base would be
//nonsense, and any hardware watchpoint is watching an address that no longer exists.
//
//This used to be ignored entirely - the module observer's onRemoved only refreshed the module map - so the
//agent carried on confidently producing wrong output. Report it loudly and tear the state down.
//Called from the module observer's onRemoved when the unloaded module is ours.
function handle_our_module_being_unloaded()
{
    console.log("==================================================================================");
    console.log("DragonHook: the examined module "+modulename_to_stalk+" has been UNLOADED from the process.");
    console.log("  Everything derived from it is now invalid, so instrumentation is being torn down:");
    console.log("  stalking stops on every thread, and every hardware watchpoint we installed is removed.");
    console.log("  Results already written to the ghidra database are unaffected.");
    console.log("==================================================================================");

    //stop stalking first, while the bounds are still correct, so the transforms and receivers are not
    //running against zeroed addresses while we take them away
    try
    {
        stop_stalking_all_threads();
    }
    catch (err)
    {
        console.log("  could not stop stalking cleanly: "+err);
    }
    //nothing queued should be started against a module that is gone
    threadids_queued_for_stalking={};

    if (setting_of_watchpoints_is_enabled)
    {
        //Where the mapping that just went away actually lived. Captured HERE, while the bounds are still the
        //dead mapping's - they are zeroed at the end of this function - because the teardown below is deferred
        //and by the time it runs those globals may describe a completely different mapping.
        var base_of_the_mapping_that_went_away=baseaddr_of_modulename_to_stalk;
        var end_of_the_mapping_that_went_away=endaddr_of_modulename_to_stalk;
        var the_old_range_is_usable=false;
        try
        {
            the_old_range_is_usable=(!base_of_the_mapping_that_went_away.isNull()
                && base_of_the_mapping_that_went_away.compare(end_of_the_mapping_that_went_away)<0);
        }
        catch (err) { the_old_range_is_usable=false; }

        //deferred: this callback runs on whichever thread called dlclose, which may hold the loader lock,
        //and unsetting a watchpoint has to stop and resume the owning thread
        setTimeout(function () {
            //The bookkeeping is NOT cleared before this point, and that is deliberate on two counts. The
            //removal is driven entirely by threads_and_watchpoint_ids - it gates on the thread id being a key
            //and reads the watchpoint id out of the entry - so emptying the map first turned the removal into a
            //silent no-op that left every debug register armed on addresses the module no longer occupied. And
            //until the removal actually runs those watchpoints are still LIVE, while
            //do_we_have_any_watchpoint_bookkeeping_for_thread() is what the exception handler uses to recognise
            //their traps as ours - so emptying it early made the handler hand our own traps to the application,
            //a SIGTRAP the target never armed on memory the loader may since have reused. A crash, not a leak.
            //
            //The module can also be mapped AGAIN before this callback runs: module observer notifications fire
            //on the thread doing the dlclose/dlopen, while this timer waits for the JS event loop, so both
            //observers can get there first. A plugin host reopening a library it just closed is the normal way
            //that happens. Three cases:
            //
            // - mapped again at the SAME base: the watchpoints still armed are watching valid addresses once
            //   more, and their addresses are identical to the ones a reload would install, so there is nothing
            //   to tell apart and nothing worth doing. Leave them.
            // - mapped again ELSEWHERE: only the entries watching the OLD range are stale, and the new
            //   mapping's are live, so this must not be the wholesale remover. Left unfiltered it would either
            //   disarm the new mapping, or - if we simply skipped - leak the old debug registers forever, which
            //   the slot allocator counts as occupied and which would starve the new mapping of slots.
            // - still gone: every entry of ours lies in the old range, so the filter removes all of them,
            //   exactly as the wholesale remover would have.
            if (modulename_to_stalk_has_been_loaded && the_old_range_is_usable
                && baseaddr_of_modulename_to_stalk.equals(base_of_the_mapping_that_went_away))
            {
                console.log("DragonHook: " + modulename_to_stalk + " was mapped again at the same base before"
                    + " the watchpoint teardown ran, so its watchpoints are being left in place.");
                return;
            }
            try
            {
                if (the_old_range_is_usable)
                {
                    var number_of_watchpoints_removed=remove_installed_watchpoints_watching_addresses_in_range(
                        base_of_the_mapping_that_went_away, end_of_the_mapping_that_went_away);
                    console.log("  removed " + number_of_watchpoints_removed + " hardware watchpoint(s) that"
                        + " belonged to the unloaded mapping");
                }
                else
                {
                    //no usable bounds to filter by, so fall back to the wholesale teardown: without a range
                    //there is nothing this could be confusing with a live mapping anyway
                    remove_all_installed_watchpoints_for_all_threads();
                    threads_and_watchpoint_ids={};
                    watchpoint_ids_and_how_many_times_each_is_visited={};
                }
            }
            catch (err)
            {
                console.log("  could not remove all watchpoints: "+err);
            }
        }, 0);
        threadids_queued_for_watchpoint_installation={};
    }

    //Now forget where the module was. Done AFTER the teardown above for the reason given there.
    modulename_to_stalk_has_been_loaded=false;
    is_module_to_hook_loaded=false;
    baseaddr_of_modulename_to_stalk=ptr(0);
    endaddr_of_modulename_to_stalk=ptr(0);
    module_to_hook_baseaddr=ptr(0);
    module_to_hook_endaddr=ptr(0);
    module_to_hook_size=0;

    //The feature tables are offsets RELATIVE to the module, so they stay valid if it is mapped again at a
    //different address, and are deliberately not cleared.
    our_module_has_been_unloaded_at_least_once=true;
}

var our_module_has_been_unloaded_at_least_once=false;


//Remembers a thread to follow later, and arms a one shot warning. Called from the thread observer.
function queue_thread_for_stalking_when_our_module_is_found(threadId)
{
    threadids_queued_for_stalking[threadId.toString()]=true;

    //Without this, a wrong module name in the config produces total silence: nothing is ever followed,
    //nothing is ever reported, and there is no hint that the agent is simply waiting for a module that
    //will never appear. That is the single easiest mistake to make, so say so loudly.
    if (timer_for_warning_that_our_module_was_never_found===null)
    {
        timer_for_warning_that_our_module_was_never_found=setTimeout(function () {
            timer_for_warning_that_our_module_was_never_found=null;
            var number_still_waiting=0;
            for (var thread_id_str in threadids_queued_for_stalking) { number_still_waiting+=1; }
            if (number_still_waiting===0) { return; }   //the module turned up, nothing to warn about
            console.log("DragonHook: still waiting for the module \""+modulename_to_stalk+"\" after "
                +seconds_before_warning_that_our_module_was_never_found+" seconds, so "+number_still_waiting
                +" thread(s) are queued and NOTHING is being stalked yet. If that module name is wrong,"
                +" nothing will ever be reported. The modules currently loaded are:");
            try
            {
                var mods=Process.enumerateModules();
                for (var i=0;i<mods.length;i++)
                {
                    console.log("    "+mods[i].name+"  at "+mods[i].base+"  ("+mods[i].path+")");
                }
            }
            catch (err)
            {
                console.log("    could not enumerate modules: "+err);
            }
        }, seconds_before_warning_that_our_module_was_never_found*1000);
    }
}


//Follows every thread that was queued while our module was still unknown.
//Called deferred from begin_stalking_as_soon_as_module_is_found(), AFTER the flags, the feature tables and
//the module exclusions are all in place, which is the whole point of having waited.
function start_stalking_all_queued_threads()
{
    var queued_thread_ids=threadids_queued_for_stalking;
    threadids_queued_for_stalking={};   //drain first, so a second call cannot follow everything twice

    var number_of_threads_followed=0;
    for (var thread_id_str in queued_thread_ids)
    {
        //resolved now rather than stored earlier, so the object is fresh and an exited thread is simply
        //absent from the dictionary
        var thread_object=dict_from_threadids_to_threads[thread_id_str];
        if (!thread_object)
        {
            console.log("Not stalking thread "+thread_id_str+", it exited while queued");
            continue;
        }
        //it may also have been renamed into the blacklist since it was queued
        if (!should_this_thread_be_stalked(thread_object))
        {
            console.log("Not stalking "+describe_thread_by_id(thread_id_str)+", it no longer passes the thread filter");
            continue;
        }
        dict_with_threadIds_call_traces[thread_id_str]=[];
        startStalker(parseInt(thread_id_str,10), modulename_to_stalk);
        number_of_threads_followed+=1;
    }
    if (number_of_threads_followed>0)
    {
        console.log("Stalker: began stalking "+number_of_threads_followed+" thread(s) that were waiting for "
            +modulename_to_stalk+" to be found, so their very first compiled block is already instrumented");
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

    //The flag is set only AFTER a follow has really happened. Setting it up front meant that when every
    //enabled feature declined to follow - which stalker_follow_and_resolve_string_references() now does
    //once all the selected strings have been resolved - the thread was recorded as followed while Stalker
    //knew nothing about it. A later unfollow then threw, and the refollow logic trusted the same lie.
    var a_follow_actually_happened=false;

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
        a_follow_actually_happened=true;
    }
    if (call_tracing_through_stalker_is_enabled)
    {
        stalker_follow_and_log_all_calls_builtin_method(threadId);
        a_follow_actually_happened=true;
    }
    if (string_reference_resolution_is_enabled
        && !string_reference_resolution_has_been_stopped_because_it_is_complete)
    {
        stalker_follow_and_resolve_string_references(threadId);
        a_follow_actually_happened=true;
    }

    if (a_follow_actually_happened)
    {
        dict_with_threadIds_that_are_being_stalked[thread_id_to_str]=true;
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

    //Now that the flags, the feature tables and the module exclusions are all in place, follow the threads
    //that were deliberately made to wait for exactly this moment. Deferred to frida's own JS thread,
    //because Stalker.follow() on another thread has to interrupt and rewrite that thread's context, and
    //this function runs on whichever thread loaded the module - possibly holding the loader lock.
    setTimeout(start_stalking_all_queued_threads,0);

}


//---------------------- END: FOR DYNAMIC CALL STALKING -------------------------------


