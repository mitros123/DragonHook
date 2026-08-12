var module_name_to_hook='DRAGONHOOK_MODULENAME';  var ghidra_base_of_module_to_hook=0x0; // UPDATED FROM DRAGONHOOK PLUGIN

var module_to_hook_obj=null;
var module_to_hook_baseaddr=null;
var module_to_hook_endaddr=null;
var module_to_hook_size=null;
var is_module_to_hook_loaded=false;
var modulemap_for_all_modules=new ModuleMap(); //holds the loaded modules, and is optimized for searching an address, where it falls in.
var dict_from_threadids_to_threads={};

//---------------------- FOR INTERACTION WITH PYTHON -------------------------------
//override console.log() to send every line back to python
var original_console_log=console.log;
var keep_entire_console_log_history_in_js_memory=false
var total_script_output_arr=[];
console.log = function(str) {
    if (keep_entire_console_log_history_in_js_memory)
    {
        total_script_output_arr.push(str);
    }
    send(str); //send the data back to python
    return original_console_log(str);
}

//Returns every line console.log() has produced, when history keeping is on.
//Called by python over RPC, not from inside the agent.
function return_total_script_output()
{
    return total_script_output_arr;
}

//---------------------- END: FOR INTERACTION WITH PYTHON -------------------------

