// DRAGONHOOK PREPARATION STEPS BEFORE REGISTERING OBSERVERS GO HERE


if (dynamic_call_stalking_is_enabled || call_tracing_through_stalker_is_enabled || string_reference_resolution_is_enabled)
{
    is_generally_stalking_enabled=true;
    exclude_all_blacklisted_modules_from_stalker();
}

//---------------------- FOR ATTACHING TO MODULE -------------------------------

//The most reliable method to hook a module is through the attachModuleObserver()
var observer_KYjQgb = Process.attachModuleObserver({
    onAdded(module) {
        if (is_generally_stalking_enabled)
        {
            exclude_module_from_stalker_if_blacklisted(module);
            exclude_module_from_stalker_if_it_is_not_ours(module); //no-op if related flag is not enabled
        }
        modulemap_for_all_modules.update();
        var current_module_name=module.name
        var we_just_found_our_module=false;
        if (Process.platform.includes("windows"))
        {
            we_just_found_our_module=(module.name.toLowerCase()==module_name_to_hook.toLowerCase());
        }
        else
        {
            we_just_found_our_module=(module.name==module_name_to_hook);
        }
        if (we_just_found_our_module)
        {
            console.log('Found our module, at '+module.path);
            console.log(JSON.stringify(module));
            module_name_to_hook=module.name; modulename_to_stalk=module.name; //Update the variables to the proper case if needed , UPDATED FROM DRAGONHOOK PLUGIN
            if (is_module_to_hook_loaded==false)
            {
                module_to_hook_baseaddr=Process.getModuleByName(module_name_to_hook).base;
                module_to_hook_size=Process.getModuleByName(module_name_to_hook).size;
                module_to_hook_endaddr=module_to_hook_baseaddr.add(module_to_hook_size);
                module_to_hook_obj=module;
                is_module_to_hook_loaded=true;
                if (our_module_has_been_unloaded_at_least_once)
                {
                    //A RELOAD, after handle_our_module_being_unloaded() tore everything down. The bounds
                    //recorded just above are the NEW ones, so stalking can restart correctly - the feature
                    //tables hold offsets relative to the module and are therefore still valid at a
                    //different base.
                    //The Interceptor hooks are deliberately NOT re-installed: attaching to the same
                    //function twice gives two hooks and therefore duplicated output, and the hooks from
                    //the previous load were left dangling when the module was unmapped. If hooks matter
                    //for what you are doing, re-run the agent rather than trusting this session.
                    console.log("DragonHook: "+module_name_to_hook+" has been loaded AGAIN, at "
                        +module_to_hook_baseaddr+". Stalking restarts against the new base. Interceptor"
                        +" hooks are NOT re-installed - re-run the agent if you need them.");
                    begin_stalking_as_soon_as_module_is_found();
                }
                else
                {
                    intercept_identified_module_DragonHook();
                }
            }
            else
            {
                console.log("Another module with the same name spotted, not bothering to hook the second one.")
            }
            
            if (setting_of_watchpoints_is_enabled)
            {
                //process the queued threads, but NOT from here. This callback runs on whichever
                //thread loaded the module, potentially holding the loader lock, and installing a
                //watchpoint on another thread makes frida ptrace attach to it. If that thread is
                //waiting on the loader lock we hold, the attach never completes and we deadlock.
                //Defer to frida's own JS thread, which holds no target lock.
                setTimeout(add_watchpoints_for_all_queued_threads,0);
            }
        }
    },
    onRemoved(module) {
        //console.log('Module '+module.path+' was  unloaded');
        //Compare by BASE ADDRESS, not by name. Two modules can share a name, and by the time this fires
        //the name is the only thing left to go on for anything else - but the base is what identifies the
        //mapping we recorded.
        var this_is_our_module=(is_module_to_hook_loaded
            && module_to_hook_baseaddr!=null
            && !module_to_hook_baseaddr.isNull()
            && module.base.equals(module_to_hook_baseaddr));
        modulemap_for_all_modules.update();
        if (this_is_our_module)
        {
            handle_our_module_being_unloaded();
        }
    }
});


var threadobserver_KYjQgb = Process.attachThreadObserver({
        onAdded(thread) 
        {
            dict_from_threadids_to_threads[thread.id.toString()]=thread;
            
            //No "thread.name &&" guard any more. should_this_thread_be_stalked() decides primarily from
            //the thread's ENTRYPOINT, which is exactly what works when the name is still null - and a
            //thread's name is usually set a moment AFTER creation, so the old guard skipped the
            //entrypoint test for precisely the threads it existed to catch, letting frida's own unnamed
            //threads be stalked. The name test remains inside as the fallback, and it treats a missing
            //name as "stalk it".
            if (!should_this_thread_be_stalked(thread))
            {
                return; //frida's own thread, or one excluded by the thread name blacklist
            }
            
            //STALKER
            //be careful when stalking everything, depending on the application the thread list may need to be restricted. For example,in Android Unity applications, UnityMain is the name of the thread that must be stalked .
            //The restriction itself now lives at module scope, so that onRenamed can re-evaluate it: a
            //thread is usually named a moment AFTER it is created, so testing the name here alone
            //rejected precisely the threads the option exists to select.
            if (is_generally_stalking_enabled && does_thread_pass_the_stalker_name_restriction(thread))
            {
                if (should_following_this_thread_wait_for_our_module())
                {
                    //Our module is not loaded yet, so following now would compile blocks that both
                    //transforms refuse to instrument, and Stalker would cache those empty copies for ever.
                    //Wait instead: the follow happens from begin_stalking_as_soon_as_module_is_found(),
                    //once the flags, the feature tables and the module exclusions are all in place.
                    console.log("Queueing thread "+thread.id+" ("+thread.name+") for stalking, "
                        +modulename_to_stalk+" has not been found yet");
                    queue_thread_for_stalking_when_our_module_is_found(thread.id);
                }
                else
                {
                    console.log("Tryng to start stalking thread "+thread.id+" with name "+thread.name)
                    dict_with_threadIds_call_traces[thread.id.toString()]=[];
                    startStalker(thread.id, modulename_to_stalk)   //owns the followed-flag itself now
                    console.log("Began stalking thread "+thread.id+" with name "+thread.name)
                }
            }
            
            
            
            // WATCHPOINTS
            if (setting_of_watchpoints_is_enabled && does_thread_pass_the_watchpoint_name_restriction(thread))
            {
                if (is_module_to_hook_loaded)
                {
                    //deferred on purpose, see schedule_watchpoint_installation_for_a_thread(). Doing
                    //it inline here runs setHardwareWatchpoint() on a thread that is still starting
                    //up, which blocks and never returns.
                    schedule_watchpoint_installation_for_a_thread(thread);
                }
                else
                {
                    //enqueue the thread so that the watchpoint will be installed as soon as the module is loaded
                    threadids_queued_for_watchpoint_installation[thread.id.toString()]=true;
                }
                
            }
            
        },
        onRemoved(thread) 
        {
            delete dict_from_threadids_to_threads[thread.id.toString()];
            
            if (is_generally_stalking_enabled)
            {
                //one property delete, no scan of the queue
                delete threadids_queued_for_stalking[thread.id.toString()];
                stopStalker(thread.id)
            }
            
            if (setting_of_watchpoints_is_enabled)
            {
                //one property delete, no scan of the queue
                delete threadids_queued_for_watchpoint_installation[thread.id.toString()];
                forget_watchpoint_bookkeeping_for_thread(thread.id.toString());
            }
        },
        onRenamed(thread,previousName) {
            if (is_generally_stalking_enabled
                || setting_of_watchpoints_is_enabled)
            {
                console.log("Thread with name "+previousName+" was renamed to "+thread.name);
            }

            if (!should_this_thread_be_stalked(thread) && thread.id.toString() in dict_with_threadIds_that_are_being_stalked &&
                dict_with_threadIds_that_are_being_stalked[thread.id.toString()]===true)
            {
                console.log("Stopping stalking thread "+thread.id+" ("+thread.name+") due to rename");
                stopStalker(thread.id);
                dict_with_threadIds_that_are_being_stalked[thread.id.toString()]=false;
            }

            //A thread's name almost always arrives AFTER it was created, so a name restriction evaluated
            //in onAdded saw null and rejected the very threads it exists to select - "only stalk threads
            //called UnityMain" matched nothing at all on a target that names its threads late, which is
            //most of them. onRenamed could previously only ever STOP stalking, never start it, so there
            //was no second chance. Re-evaluate here and start the thread if it now qualifies.
            if (is_generally_stalking_enabled
                && should_this_thread_be_stalked(thread)
                && does_thread_pass_the_stalker_name_restriction(thread)
                && dict_with_threadIds_that_are_being_stalked[thread.id.toString()]!==true
                && !(thread.id.toString() in threadids_queued_for_stalking))
            {
                console.log("Thread "+thread.id+" now matches the thread name restriction after being renamed to \""
                    +thread.name+"\", starting it");
                if (should_following_this_thread_wait_for_our_module())
                {
                    queue_thread_for_stalking_when_our_module_is_found(thread.id);
                }
                else
                {
                    dict_with_threadIds_call_traces[thread.id.toString()]=[];
                    startStalker(thread.id, modulename_to_stalk);
                }
            }

            //the same second chance for watchpoints, which had the identical structure and the identical gap
            if (setting_of_watchpoints_is_enabled
                && should_this_thread_be_stalked(thread)
                && does_thread_pass_the_watchpoint_name_restriction(thread)
                && !do_we_have_any_watchpoint_bookkeeping_for_thread(thread.id.toString())
                && !(thread.id.toString() in threadids_queued_for_watchpoint_installation))
            {
                console.log("Thread "+thread.id+" now matches the watchpoint thread name restriction after being"
                    +" renamed to \""+thread.name+"\", installing watchpoints on it");
                if (is_module_to_hook_loaded)
                {
                    schedule_watchpoint_installation_for_a_thread(thread);
                }
                else
                {
                    threadids_queued_for_watchpoint_installation[thread.id.toString()]=true;
                }
            }

            if (setting_of_watchpoints_is_enabled && !should_this_thread_be_stalked(thread))
            {
                delete threadids_queued_for_watchpoint_installation[thread.id.toString()];
                //deferred for exactly the same reason as installation: unsetHardwareWatchpoint() also
                //has to stop and resume the thread to reach its debug registers, and this callback
                //runs on a target thread. Calling it inline blocks.
                setTimeout(function () { remove_all_installed_watchpoints_for_a_thread(thread); }, 0);
            }
        }
    });
    
//---------------------- END: FOR ATTACHING TO MODULE ---------------------------


