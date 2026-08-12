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
    dispose: function () {
        stop_stalking_all_threads();
        Stalker.garbageCollect();      //immediate here, the script is going away anyway
        if (setting_of_watchpoints_is_enabled)
        {
            remove_all_installed_watchpoints_for_all_threads();
        }
    }
};
