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
                intercept_identified_module_DragonHook();
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
        modulemap_for_all_modules.update();
    }
});


var threadobserver_KYjQgb = Process.attachThreadObserver({
        onAdded(thread) 
        {
            dict_from_threadids_to_threads[thread.id.toString()]=thread;
            
            if (thread.name && !should_this_thread_be_stalked(thread) ) 
            {
                return; //do nothing in this case
            }
            
            //STALKER 
            var str_to_be_included_in_thread_name_for_stalker=""; //UPDATED FROM DRAGONHOOK PLUGIN
            var there_is_a_restriction_for_the_thread_name_for_stalker=false;  //UPDATED FROM DRAGONHOOK PLUGIN
            
            //be careful when stalking everything, depending on the application the thread list may need to be restricted. For example,in Android Unity applications, UnityMain is the name of the thread that must be stalked .
            if ((is_generally_stalking_enabled) && 
                ((!there_is_a_restriction_for_the_thread_name_for_stalker) ||
                (there_is_a_restriction_for_the_thread_name_for_stalker && thread.name &&  thread.name.toLowerCase().includes(str_to_be_included_in_thread_name_for_stalker) ) )
               )   
            {
                console.log("Tryng to start stalking thread "+thread.id+" with name "+thread.name)
                //note: maybe the module to be stalked has not even been loaded yet
                dict_with_threadIds_call_traces[thread.id.toString()]=[];
                startStalker(thread.id, modulename_to_stalk)   //owns the followed-flag itself now
                console.log("Began stalking thread "+thread.id+" with name "+thread.name)
            }
            
            
            
            // WATCHPOINTS
            var str_to_be_included_in_thread_name_for_watchpoints=""; //UPDATED FROM DRAGONHOOK PLUGIN
            var there_is_a_restriction_for_the_thread_name_for_watchpoints=false;  //UPDATED FROM DRAGONHOOK PLUGIN
            
            if (setting_of_watchpoints_is_enabled && 
                ((!there_is_a_restriction_for_the_thread_name_for_watchpoints) ||
               (there_is_a_restriction_for_the_thread_name_for_watchpoints && thread.name &&  thread.name.toLowerCase().includes(str_to_be_included_in_thread_name_for_watchpoints) ) )
               ) 
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
                    queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded.push(thread);
                }
                
            }
            
        },
        onRemoved(thread) 
        {
            delete dict_from_threadids_to_threads[thread.id.toString()];
            
            if (is_generally_stalking_enabled)
            {
                stopStalker(thread.id)
            }
            
            if (setting_of_watchpoints_is_enabled)
            {
                //remove thread from queue
                queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded= queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded.filter(item => item !== thread)
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

            if (setting_of_watchpoints_is_enabled && !should_this_thread_be_stalked(thread))
            {
                queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded=
                    queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded.filter(item => item !== thread);
                //deferred for exactly the same reason as installation: unsetHardwareWatchpoint() also
                //has to stop and resume the thread to reach its debug registers, and this callback
                //runs on a target thread. Calling it inline blocks.
                setTimeout(function () { remove_all_installed_watchpoints_for_a_thread(thread); }, 0);
            }
        }
    });
    
//---------------------- END: FOR ATTACHING TO MODULE ---------------------------


