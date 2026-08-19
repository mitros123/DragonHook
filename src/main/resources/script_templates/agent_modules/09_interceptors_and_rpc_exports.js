//This is the function that should be edited, if manual alterations are needed
//Called from the module observer the moment the examined module is found. The plugin injects the
//generated hooks, and begin_stalking_as_soon_as_module_is_found(), at the marker inside it.
function intercept_identified_module_DragonHook()
{
    console.log("Registering interceptors...");
    

    //DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE

        
    Interceptor.flush();
    console.log("Registered interceptors.");
}


rpc.exports = {
    return_total_script_output_api_call: return_total_script_output,
    //Called by frida when script.unload() is invoked from the python side, and python WAITS for it.
    //
    //Every step is logged and individually guarded, because two of them perform CROSS THREAD operations
    //that go through gum_process_modify_thread() - ptrace on linux and android: Stalker.unfollow() for each
    //followed thread, and unsetHardwareWatchpoint() for each armed watchpoint. Those are the same calls that
    //are deferred everywhere else in this agent precisely because they can block, and here they cannot be
    //deferred: a setTimeout would never run, the script is going away.
    //When one of them blocked, script.unload() never returned and the whole shutdown stalled until Ghidra
    //terminated the python process. The python side now bounds each step with its own timeout, so a hang
    //here no longer prevents shutdown - and these log lines are what identify WHICH step hung.
    dispose: function () {
        try
        {
            //--- STEP 1, AND IT MUST COME FIRST. This is the step that keeps the target alive.
            //While Stalker follows a thread, that thread executes out of Stalker's CODE CACHE rather than
            //out of the original code. Stalker.unfollow() is what puts it back on its own instructions.
            //Skip this and the session detach frees the code cache while a thread's program counter is
            //still inside it - the target segfaults immediately. That was observed, it is not theoretical.
            //stop_stalking_all_threads() guards each thread individually, so one that cannot be unfollowed
            //does not cost us the rest.
            console.log("dispose: unfollowing stalked threads (this is what prevents a crash on detach)...");
            try { console.log("dispose: unfollowed "+stop_stalking_all_threads()+" thread(s)"); }
            catch (err) { console.log("dispose: unfollowing threads failed: "+err); }

            //--- STEP 2: only now is it safe to hand the cache memory back.
            console.log("dispose: reclaiming stalker code caches...");
            try { Stalker.garbageCollect(); }   //immediate here, the script is going away anyway
            catch (err) { console.log("dispose: garbageCollect failed: "+err); }

            //--- STEP 3, DELIBERATELY LAST, because it is the step that can block.
            //unsetHardwareWatchpoint() is a cross thread operation and goes through ptrace, and a blocking
            //call in frida's C extension can hold the python GIL - freezing the whole python interpreter so
            //that not even its own timeouts can fire. Ghidra then has to terminate the process from outside.
            //Having it last means that when that happens, steps 1 and 2 have already completed and the
            //target is safe; only the watchpoint disarm is lost. Set remove_watchpoints_on_dispose to false
            //to skip it entirely if a target reliably freezes here.
            if (setting_of_watchpoints_is_enabled && remove_watchpoints_on_dispose)
            {
                console.log("dispose: removing hardware watchpoints (cross thread, MAY BLOCK - the target is"
                    +" already safe at this point)...");
                try { remove_all_installed_watchpoints_for_all_threads(); }
                catch (err) { console.log("dispose: watchpoint removal failed: "+err); }
            }
            console.log("dispose: finished");
        }
        catch (err)
        {
            //console.log() is a send(), and sends can be refused while the script is being unloaded, so
            //even the logging above needs an outer guard. Nothing useful can be reported at this point.
        }
    }
};
