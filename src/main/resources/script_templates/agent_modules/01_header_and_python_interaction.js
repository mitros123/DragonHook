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

//Latched once a send() has failed. The channel to python does not come back, and without this every later
//log line would pay for raising and catching an exception - during a teardown that is a great many lines.
var the_channel_to_python_is_gone=false;

//Renders one console.log argument as text. Frida's own console.log prints objects structurally, and plain
//String() on an object gives the useless "[object Object]", so fall back to JSON for those.
//Called only from the console.log override below.
function return_log_argument_as_string(argument_to_log)
{
    if (argument_to_log===null) { return "null"; }
    if (argument_to_log===undefined) { return "undefined"; }
    if (typeof argument_to_log==="string") { return argument_to_log; }
    var argument_as_text;
    try { argument_as_text=String(argument_to_log); }
    catch (err) { return "[unprintable argument]"; }
    if (argument_as_text==="[object Object]")
    {
        //JSON.stringify throws on a circular structure, and it returns the VALUE undefined - not a string -
        //for anything it considers unrepresentable, such as an object whose toJSON() returns undefined.
        //Keep the plain "[object Object]" form in both of those cases, rather than letting undefined be
        //concatenated into the line and printed as the word "undefined".
        try
        {
            var argument_as_json=JSON.stringify(argument_to_log);
            if (typeof argument_as_json==="string") { argument_as_text=argument_as_json; }
        }
        catch (err) { }
    }
    return argument_as_text;
}

//Every line the agent logs is also sent to python, which is how it reaches the ghidra console and
//agent_stdout.txt.
//
//Takes MULTIPLE arguments now, like the real console.log. It used to declare a single parameter, so
//console.log(a,b) silently dropped b. A single string argument produces byte-identical output to before,
//which is what every existing call site passes.
//
//It CANNOT affect how python parses an API call: the |||DH_GHIDRA_API_CALL||| lines are written with send()
//directly, in module 02, and never pass through here.
//
//And it can no longer throw. send() is refused while a script is being unloaded, and it used to be called
//unguarded and BEFORE the local log - so a refused send threw into whatever was logging and lost the line
//entirely. That is what made the dispose() diagnostic able to take the teardown down with it instead of
//merely going missing. Note the consequence that remains: during an unload a line may simply not arrive, so
//the absence of a dispose() message is not proof that the step did not run.
console.log = function() {
    var joined_text="";
    for (var index_of_argument=0;index_of_argument<arguments.length;index_of_argument++)
    {
        if (index_of_argument>0) { joined_text+=" "; }
        joined_text+=return_log_argument_as_string(arguments[index_of_argument]);
    }

    if (keep_entire_console_log_history_in_js_memory)
    {
        total_script_output_arr.push(joined_text);
    }

    if (!the_channel_to_python_is_gone)
    {
        try { send(joined_text); } //send the data back to python
        catch (err) { the_channel_to_python_is_gone=true; }
    }
    //guarded for the same reason: frida's own console.log also travels over the message channel
    try { return original_console_log(joined_text); }
    catch (err) { return undefined; }
}

//Sends one |||DH_GHIDRA_API_CALL||| protocol line to python and reports whether it actually went out.
//
//The api functions in module 02 used to call send() bare. Once the channel is gone that throws, and it
//throws INSIDE whatever asked for the update - an Interceptor callback, a Stalker receiver, a watchpoint
//exception handler - abandoning that callback halfway through its work. The console.log override latches the
//very same condition, so without this the LOGGING went quiet during a teardown while the calls that actually
//carry results kept raising.
//
//A false return also tells the caller not to wait for a reply. recv() has no timeout, so waiting on an
//answer that can never arrive parks the calling thread permanently, which is one of the ways the agent
//refused to shut down.
//
//Note what this cannot do: send() only throws once frida has torn the script down. If python has died but
//the script is still alive the send succeeds, the message goes nowhere, and a following recv().wait() still
//blocks forever - that case has to be resolved from the python side.
function send_protocol_line_to_python(line_to_send)
{
    if (the_channel_to_python_is_gone)
    {
        return false;
    }
    try
    {
        send(line_to_send);
        return true;
    }
    catch (err)
    {
        the_channel_to_python_is_gone=true;
        return false;
    }
}

//Returns every line console.log() has produced, when history keeping is on.
//Called by python over RPC, not from inside the agent.
function return_total_script_output()
{
    return total_script_output_arr;
}

//---------------------- END: FOR INTERACTION WITH PYTHON -------------------------

