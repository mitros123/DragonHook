//------------------ FOR FUNCTION/ADDRESS INFORMATION EXTRACTION ----------------

var fetch_function_data_in_bulk_at_first=true; // UPDATED FROM DRAGONHOOK PLUGIN
var debuginfo_for_various_addresses={};
var consider_debuginfo_unchanged=true;



//returns the {fun_name, entrypoint_offset} object owning this module offset, or null
//Called from the bulk lookup path, once get_full_function_data_by_ranges() has loaded the table.
function binarySearchFunRange(offset_as_number) {
    var starts = ghidra_api_storage["FUN_RANGE_STARTS"];
    var ends = ghidra_api_storage["FUN_RANGE_ENDS"];
    var low = 0;
    var high = starts.length - 1;
    while (low <= high)
    {
        var mid = (low + high) >> 1;
        if (offset_as_number < starts[mid]) {
            high = mid - 1;
        } else if (offset_as_number > ends[mid]) {
            low = mid + 1;
        } else {
            // Found the value in the range
            return ghidra_api_storage["FUN_OBJECTS"][ghidra_api_storage["FUN_RANGE_FUNIDX"][mid]];
        }
    }
    // Not found
    return null;
}

//Capstone and frida do not agree on every register name. Capstone reports the arm64 frame pointer
//and link register as x29 and x30, while frida's Arm64CpuContext exposes them as fp and lr, and a
//32 bit view such as w2 has no entry at all. Reading context[name] directly therefore returned
//undefined for the frame pointer, which is one of the most common bases for a memory access.
var register_name_aliases_for_cpu_context={"x29":"fp","x30":"lr","w29":"fp","w30":"lr"};

//Reads a register out of a live CpuContext by capstone's name for it, coping with the naming
//mismatches. Called from the runtime address resolver in module 06, inside a Stalker callout.
function return_register_value_from_context(context,register_name)
{
    if (!context || !register_name)
    {
        return undefined;
    }
    var value_of_register=context[register_name];
    if (value_of_register!==undefined)
    {
        return value_of_register;
    }
    if (register_name in register_name_aliases_for_cpu_context)
    {
        return context[register_name_aliases_for_cpu_context[register_name]];
    }
    //arm64 32 bit views: w5 holds the low half of x5, and for an address computation the x view is
    //what we want
    if (register_name.length>1 && (register_name.charAt(0)==="w" || register_name.charAt(0)==="W"))
    {
        return context["x"+register_name.substring(1)];
    }
    return undefined;
}


//Offset of a runtime address inside a named module. Not used by the template itself, it is a
//convenience for hand written hooks.
function get_offset_from_base_of_module(modulename,in_addr)
{
    var base_of_module=Process.getModuleByName(modulename).base
    return in_addr.sub(base_of_module);
}


//Bulk path: resolves a runtime address to its ghidra function through the in memory range table.
//Called from extract_function_info_from_address_for_our_module() when bulk mode is on.
function extract_function_info_from_address_for_our_module_when_loading_all_fun_data_in_mem(in_addr) 
{
    var base_of_module=module_to_hook_baseaddr
    var offset_of_addr_str=""+in_addr.sub(base_of_module)
    var offset_of_addr_as_number=parseInt(offset_of_addr_str, 16)
    var extract_all_fun_info=get_full_function_data_by_ranges()
    if (extract_all_fun_info!="ok")
    {
        console.log("problem with get_full_function_data_by_ranges(), "+extract_all_fun_info)
        return null
    }
    var object_from_binsearch=binarySearchFunRange(offset_of_addr_as_number);
    if (object_from_binsearch===null)
    {
        //prints the offset that was searched AND the table size, which separates "the table never
        //loaded" from "the table is fine but this offset is not covered by any ghidra function"
        console.log("BULK LOOKUP MISS: no ghidra function covers module offset "+offset_of_addr_str
            +" (searched as "+offset_of_addr_as_number+", table holds "
            +ghidra_api_storage["FUN_RANGE_STARTS"].length+" ranges over "
            +ghidra_api_storage["FUN_OBJECTS"].length+" functions)");
    }
    return object_from_binsearch;
}


//Live path: asks ghidra per address instead of using the table. BLOCKS on every miss.
//Called from extract_function_info_from_address_for_our_module() when bulk mode is off.
function extract_function_info_from_address_for_our_module_with_live_api_calls(in_addr) 
{
    var base_of_module=module_to_hook_baseaddr
    var offset_of_addr_str=""+in_addr.sub(base_of_module)
    var offset_of_addr_as_number=parseInt(offset_of_addr_str, 16)
    var found=false
    var name_of_current_function=""
    var start_addroffset_of_function=""
    var returned_str_from_ghidra_api=get_function_data_from_ghidra_given_address_offset(offset_of_addr_as_number)
    if (do_we_have_proper_function_data_given_address_offset(offset_of_addr_as_number))
    {
        found=true
        var json_obj_returned=JSON.parse(returned_str_from_ghidra_api)
        name_of_current_function=json_obj_returned.fun_name
        start_addroffset_of_function=json_obj_returned.entrypoint_offset
        return json_obj_returned
    }
    //this path used to fail completely silently, so a DOS limit or an invalid offset looked
    //identical to "ghidra has no function there"
    console.log("LIVE LOOKUP MISS for module offset "+offset_of_addr_str+" , ghidra replied: "+returned_str_from_ghidra_api);
    return null;
}

//Front door for 'which ghidra function owns this runtime address', dispatching to the bulk or the
//live path. Called by the backtracer and by all three feature update functions.
function extract_function_info_from_address_for_our_module(in_addr)
{
    if (!function_data_retrieval_mode_has_been_logged)
    {
        function_data_retrieval_mode_has_been_logged=true;
        console.log("function data retrieval mode: "+(fetch_function_data_in_bulk_at_first ? "BULK" : "LIVE api call per address"));
    }
    var function_data;
    if (fetch_function_data_in_bulk_at_first)
    {
        function_data=extract_function_info_from_address_for_our_module_when_loading_all_fun_data_in_mem(in_addr)
    }
    else
    {
        function_data=extract_function_info_from_address_for_our_module_with_live_api_calls(in_addr)
    }
    return function_data;
}


//Frida's own symbol text for an address, plus module!offset. Called from the caching wrapper below.
function extract_DebugSymbol_fromAddress_data_with_offset_calculation(in_addr)
{
    var actual_debugsymbol_fromAddress_data=DebugSymbol.fromAddress(in_addr);
    var belonging_module=modulemap_for_all_modules.find(in_addr)
    if (belonging_module)
    {
        var offset_from_start_of_module=in_addr.sub(belonging_module.base)
        var name_of_module=belonging_module.name
        return actual_debugsymbol_fromAddress_data+" ("+name_of_module+"!"+offset_from_start_of_module+")"
    }
    else
    {
        return actual_debugsymbol_fromAddress_data;
    }
}


//Cached wrapper over the above, since debug info does not change while the process runs.
//Called wherever an address outside our module has to be described.
function extract_DebugSymbol_fromAddress_data(in_addr)
{
    if (consider_debuginfo_unchanged)
    {
        var in_addr_str=in_addr.toString()
        if (in_addr_str in debuginfo_for_various_addresses)
        {
            return debuginfo_for_various_addresses[in_addr_str];
        }
        else
        {
            var retval=extract_DebugSymbol_fromAddress_data_with_offset_calculation(in_addr);
            debuginfo_for_various_addresses[in_addr_str]=retval;
            return retval;
        }
    }
    else
    {
        return extract_DebugSymbol_fromAddress_data_with_offset_calculation(in_addr)
    }
}

//Short one line description of an address, ghidra style inside our module and DebugSymbol outside.
//Called from process_call_ret_stalk_event() while building a call trace line.
function extract_succinct_str_for_address(in_addr)
{

    if (is_module_to_hook_loaded &&
        in_addr.compare(module_to_hook_baseaddr)>=0 &&
        in_addr.compare(module_to_hook_endaddr)<0
        ) //it falls inside our module
    {
        var offset_of_in_addr=in_addr.sub(module_to_hook_baseaddr)
        var ghidra_addr_of_in_addr=offset_of_in_addr.add(ghidra_base_of_module_to_hook)
        var fun_data=extract_function_info_from_address_for_our_module(in_addr)
        if (fun_data)
        {
            return ghidra_addr_of_in_addr+" ("+fun_data.fun_name+"!"+offset_of_in_addr.sub(ptr(fun_data.entrypoint_offset))+")";
        }
        else
        {
            //""+ is not cosmetic: every other branch returns a string, and callers do string things
            //to the result (process_call_ret_stalk_event() calls .replaceAll on it). Returning the
            //NativePointer itself threw a TypeError inside the stalker callback.
            return ""+ghidra_addr_of_in_addr;
        }
    }
    else
    {
        var debugsymbol_data=extract_DebugSymbol_fromAddress_data(in_addr)
        return debugsymbol_data.toString().split(" ").slice(1).toString()
    }
}

//Verbose description of an address, optionally including the ghidra primary symbol (which BLOCKS).
//Called from custom_backtracer() and from the watchpoint exception handler.
function extract_extended_str_for_address(in_addr,should_include_ghidra_symbol_name)
{

    if (is_module_to_hook_loaded &&
        in_addr.compare(module_to_hook_baseaddr)>=0 &&
        in_addr.compare(module_to_hook_endaddr)<0
        ) //it falls inside our module
    {
        var offset_of_in_addr=in_addr.sub(module_to_hook_baseaddr)
        var ghidra_addr_of_in_addr=offset_of_in_addr.add(ghidra_base_of_module_to_hook)
        var symbol_str=""
        if (should_include_ghidra_symbol_name)
        {
            var returned_symbol_str=return_codeunit_symbol_str(offset_of_in_addr)
            if (returned_symbol_str)
            {
                symbol_str=", with Primary Symbol "+returned_symbol_str
            }
        }
        var fun_data=extract_function_info_from_address_for_our_module(in_addr)
        if (fun_data)
        {
            return ghidra_addr_of_in_addr+" ("+fun_data.fun_name+"!"+offset_of_in_addr.sub(ptr(fun_data.entrypoint_offset))+") with offset from start of current module: "+offset_of_in_addr+symbol_str;
        }
        else
        {
            return ghidra_addr_of_in_addr +" with offset from start of current module: "+offset_of_in_addr+symbol_str;
        }
    }
    else
    {
        var debugsymbol_data=extract_DebugSymbol_fromAddress_data(in_addr)
        return debugsymbol_data.toString()
    }
}

//--------------- END: FOR FUNCTION/ADDRESS INFORMATION EXTRACTION --------------



