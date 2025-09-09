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

function return_total_script_output()
{
    return total_script_output_arr;
}

//---------------------- END: FOR INTERACTION WITH PYTHON -------------------------

//---------------------- FOR INTERACTION WITH THE GHIDRA API ----------------------

var ghidra_api_storage={
    "FUN_DATA_BY_ADDR":{},
    "FUN_DATA_BY_RANGES":[],
    "REACHED_UPDATE_LIMIT_FOR_ADDR":{},
    "CODEUNIT_DATA_BY_ADDR":{}
}

var comment_updates_to_ghidradb_are_asynchronous=true; //enable to make the updates faster, it gives a significant performance boost. However it seems that it makes the process more prone to crashing
var xref_updates_to_ghidradb_are_asynchronous=true; //enable to make the updates faster, it gives a significant performance boost. However it seems that it makes the process more prone to crashing
var memory_updates_to_ghidradb_are_asynchronous=true; //enable to make the updates faster

function get_function_data_from_ghidra_given_address_offset(address_offset)
{
    var address_offset_as_str="0x"+address_offset.toString(16);
    if (address_offset_as_str in ghidra_api_storage["FUN_DATA_BY_ADDR"])
    {
        return (ghidra_api_storage["FUN_DATA_BY_ADDR"][address_offset_as_str])
    }
    //else
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"FUN_DATA_GIVEN_ADDR_OFFSET","PARAMS":["'+address_offset_as_str+'"]}|||\n'
    send(line_to_send)
    var str_to_ret;
    var response=recv('api-response-FUN_DATA_GIVEN_ADDR_OFFSET-[\''+address_offset_as_str+'\']', //python puts single quotes in this case for some reason...
        function onrecv(fun_data)
        {
            var str_that_is_returned=fun_data.payload //may be an error string, we need to check for that
            str_to_ret=str_that_is_returned;
        }
    );
    response.wait()
    ghidra_api_storage["FUN_DATA_BY_ADDR"][address_offset_as_str]=str_to_ret;
    return str_to_ret;
}

//only call when certain that a value is inside the dictionary
function do_we_have_proper_function_data_given_address_offset(address_offset)
{
    var address_offset_as_str="0x"+address_offset.toString(16);
    var known_data=ghidra_api_storage["FUN_DATA_BY_ADDR"][address_offset_as_str]
    try{
        var resulting_json=JSON.parse(known_data);
        return true;
    }
    catch (err)
    {
        return false;
    }
}



function get_codeunit_data_from_ghidra_given_address_offset(address_offset)
{
    var address_offset_as_str="0x"+address_offset.toString(16);
    if (address_offset_as_str in ghidra_api_storage["CODEUNIT_DATA_BY_ADDR"])
    {
        return (ghidra_api_storage["CODEUNIT_DATA_BY_ADDR"][address_offset_as_str])
    }
    //else
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"CODEUNIT_DATA_GIVEN_ADDR_OFFSET","PARAMS":["'+address_offset_as_str+'"]}|||\n'
    send(line_to_send)
    var str_to_ret;
    var response=recv('api-response-CODEUNIT_DATA_GIVEN_ADDR_OFFSET-[\''+address_offset_as_str+'\']', //python puts single quotes in this case for some reason...
        function onrecv(fun_data)
        {
            var str_that_is_returned=fun_data.payload //may be an error string, we need to check for that
            str_to_ret=str_that_is_returned;
        }
    );
    response.wait()
    ghidra_api_storage["CODEUNIT_DATA_BY_ADDR"][address_offset_as_str]=str_to_ret;
    return str_to_ret;
}

//only call when certain that a value is inside the dictionary
function do_we_have_proper_codeunit_data_given_address_offset(address_offset)
{
    var address_offset_as_str="0x"+address_offset.toString(16);
    var known_data=ghidra_api_storage["CODEUNIT_DATA_BY_ADDR"][address_offset_as_str]
    try{
        var resulting_json=JSON.parse(known_data);
        return true;
    }
    catch (err)
    {
        return false;
    }
}


function get_codeunit_information_as_dict(address_offset)
{
    var address_offset_as_str="0x"+address_offset.toString(16);
    if ( ! (address_offset_as_str in ghidra_api_storage["CODEUNIT_DATA_BY_ADDR"]))
    {
        get_codeunit_data_from_ghidra_given_address_offset(address_offset);
    }
    if (do_we_have_proper_codeunit_data_given_address_offset(address_offset))
    {
        var codeunit_data=ghidra_api_storage["CODEUNIT_DATA_BY_ADDR"][address_offset_as_str];
        var codeunit_data_as_json=JSON.parse(codeunit_data);
        return codeunit_data_as_json;
    }
    return null;
}

function is_codeunit_a_dynamic_call(address_offset)
{
    var codeunit_data_as_json=get_codeunit_information_as_dict(address_offset)
    if (codeunit_data_as_json)
    {
        if (codeunit_data_as_json["type_of_codeunit"]!="Instruction")
        {
            return false;
        }
        var instruction_data=codeunit_data_as_json["instruction_data"]
        if (instruction_data.is_call && instruction_data.is_computed_jmpORcall)
        {
            return true;
        }
    }
    return false;
}

function return_codeunit_symbol_str(address_offset)
{
    var codeunit_data_as_json=get_codeunit_information_as_dict(address_offset);
    if (codeunit_data_as_json && ("primary_symbol" in codeunit_data_as_json))
    {
        return codeunit_data_as_json["primary_symbol"];
    }
    return null;
}


function get_full_function_data_by_ranges()
{
    if (ghidra_api_storage["FUN_DATA_BY_RANGES"].length>0)
    {
        return "ok";
    }
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"ALL_FUN_DATA_SORTED_BY_RANGESTART","PARAMS":[]}|||\n'
    send(line_to_send)
    var str_that_is_returned;
    var response=recv('api-response-ALL_FUN_DATA_SORTED_BY_RANGESTART-[]', 
        function onrecv(fun_data)
        {
            str_that_is_returned=fun_data.payload //may be an error string, we need to check for that
        }
    );
    response.wait()
    try
    {
        var returned_dict=JSON.parse(str_that_is_returned)
        ghidra_api_storage["FUN_DATA_BY_RANGES"]=returned_dict["big_array_with_function_ranges"];
        console.log("length of array of ranges with function data:"+ghidra_api_storage["FUN_DATA_BY_RANGES"].length)
        return "ok";
    }
    catch (err)
    {
        return str_that_is_returned.substring(0,2000)+"...." //reduce size
    }
}



function have_we_hit_limit_on_ghidradb_updates_for_addr(in_addr_offset)
{
    if (in_addr_offset in ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"])
    {
        return ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][in_addr_offset];
    }
    else
    {
        ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][in_addr_offset]=false;
        return false;
    }
}


function update_ghidradb_with_comment_at_addr(offset_of_address_to_update,comment_to_update_with)
{
    if (have_we_hit_limit_on_ghidradb_updates_for_addr(offset_of_address_to_update))
    {
        return "It was previously detected that the update limit for this address has been reached";
    }
    var address_offset_as_str="0x"+offset_of_address_to_update.toString(16);
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR","PARAMS":[\"'+address_offset_as_str+'\",'+JSON.stringify(comment_to_update_with)+']}|||\n'
    send(line_to_send)
    var str_that_is_returned;
    var response=recv('api-response-UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR-[\''+address_offset_as_str+'\']', //no need to include the comment in this type . Also, again, single quotes 
        function onrecv(resp)
        {
            str_that_is_returned=resp.payload; //may be an error string, we need to check for that
        }
    );
    if (comment_updates_to_ghidradb_are_asynchronous)
    {
        //ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_to_update]=false;
        return "We don't care for the reply"
    }
    else
    {
        response.wait() 
        if (str_that_is_returned.includes("Error, reached maximum"))
        {
            ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_to_update]=true;
        }
        return str_that_is_returned
    }
}


function update_ghidradb_with_xref(offset_of_address_from,offset_of_address_to,type_of_xref)
{
    if (have_we_hit_limit_on_ghidradb_updates_for_addr(offset_of_address_from))
    {
        return "It was previously detected that the update limit for address_from has been reached";
    }
    if (have_we_hit_limit_on_ghidradb_updates_for_addr(offset_of_address_to))
    {
        return "It was previously detected that the update limit for address_to has been reached";
    }
    var address_offset_from_as_str="0x"+offset_of_address_from.toString(16);
    var address_offset_to_as_str="0x"+offset_of_address_to.toString(16);
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"UPDATE_GHIDRADB_WITH_XREF","PARAMS":[\"'+address_offset_from_as_str+'\",\"'+address_offset_to_as_str+'\",\"'+type_of_xref+'\"]}|||\n'
    send(line_to_send)
    var str_that_is_returned;
    var response=recv('api-response-UPDATE_GHIDRADB_WITH_XREF-[\''+address_offset_from_as_str+'\', \''+address_offset_to_as_str+'\', \''+type_of_xref+'\']', //that's how python will return the reply
        function onrecv(resp)
        {
            str_that_is_returned=resp.payload; //may be an error string, we need to check for that
        }
    );
    if (xref_updates_to_ghidradb_are_asynchronous)
    {
        //ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_from]=false;
        //ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_to]=false;
        return "We don't care for the reply"
    }
    else
    {
        response.wait() 
        if (str_that_is_returned.includes("Error, reached maximum"))
        {
            if (str_that_is_returned.includes("target_codeunit_to"))
            {
                ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_to]=true;
            }
            if (str_that_is_returned.includes("target_codeunit_from"))
            {
                ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_from]=true;
            }
        }
        return str_that_is_returned
    }
}



function update_ghidradb_with_memory_contents(offset_of_starting_address_to_update,memory_addr_to_start_reading,length_of_bytes_to_read)
{
    var address_offset_as_str="0x"+offset_of_starting_address_to_update.toString(16);
    //TODO: convert to base64 in a succint fashion. Now we are sending an array of decimals
    var bytes_from_mem=memory_addr_to_start_reading.readByteArray(length_of_bytes_to_read);
    var u8=new Uint8Array(bytes_from_mem);
    var decimalarray=Array.from(u8)
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"CHANGE_BYTES_INSIDE_GHIDRADB","PARAMS":[\"'+address_offset_as_str+'\",\"'+JSON.stringify(decimalarray)+'\"]}|||\n'
    send(line_to_send)
    var str_that_is_returned;
    var response=recv('api-response-CHANGE_BYTES_INSIDE_GHIDRADB-[\''+address_offset_as_str+'\']', //no need to include the comment in this type . Also, again, single quotes 
        function onrecv(resp)
        {
            str_that_is_returned=resp.payload; //may be an error string, we need to check for that
        }
    );
    if (memory_updates_to_ghidradb_are_asynchronous)
    {
        return "We don't care for the reply"
    }
    else
    {
        response.wait() 
        return str_that_is_returned
    }
}

//---------------------- END: FOR INTERACTION WITH THE GHIDRA API -----------------



//------------------ FOR FUNCTION/ADDRESS INFORMATION EXTRACTION ----------------

var fetch_function_data_in_bulk_at_first=true; // UPDATED FROM DRAGONHOOK PLUGIN
var debuginfo_for_various_addresses={};
var consider_debuginfo_unchanged=true;



function binarySearchFunRange(ranges, value) {
    let low = 0;
    let high = ranges.length - 1;
    while (low <= high) 
    {
        var mid = Math.floor((low + high) / 2);
        var range = ranges[mid];
        if (value < parseInt(range.start,16)) {
            high = mid - 1;
        } else if (value > parseInt(range.end,16)) {
            low = mid + 1;
        } else {
            // Found the value in the range
            return range;
        }
    }
    // Not found
    return null;
}

function get_offset_from_base_of_module(modulename,in_addr)
{
    var base_of_module=Process.getModuleByName(modulename).base
    return in_addr.sub(base_of_module);
}


function extract_function_info_from_address_for_our_module_when_loading_all_fun_data_in_mem(in_addr) 
{
    var base_of_module=module_to_hook_baseaddr
    var offset_of_addr_str=""+in_addr.sub(base_of_module)
    var offset_of_addr_as_number=parseInt(offset_of_addr_str, 16)
    var found=false
    var name_of_current_function=""
    var start_addr_of_function=""
    var extract_all_fun_info=get_full_function_data_by_ranges()
    if (extract_all_fun_info!="ok")
    {
        console.log("problem with get_full_function_data_by_ranges(), "+extract_all_fun_info)
        return null
    }
    var object_from_binsearch=binarySearchFunRange(ghidra_api_storage["FUN_DATA_BY_RANGES"], offset_of_addr_as_number) 
    if (object_from_binsearch)
    {
        found=true
        return object_from_binsearch.data
    }
    return null;
}


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
    return null;
}

function extract_function_info_from_address_for_our_module(in_addr)
{
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

function extract_succinct_str_for_address(in_addr)
{

    if (is_module_to_hook_loaded &&
        in_addr.compare(module_to_hook_baseaddr)>=1 && 
        in_addr.compare(module_to_hook_endaddr)<=0
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
            return ghidra_addr_of_in_addr;
        }
    }
    else
    {
        var debugsymbol_data=extract_DebugSymbol_fromAddress_data(in_addr)
        return debugsymbol_data.toString().split(" ").slice(1).toString()
    }
}

function extract_extended_str_for_address(in_addr,should_include_ghidra_symbol_name)
{

    if (is_module_to_hook_loaded &&
        in_addr.compare(module_to_hook_baseaddr)>=1 && 
        in_addr.compare(module_to_hook_endaddr)<=0
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



//---------------------- FOR CUSTOM BACKTRACER -------------------------------


var number_of_backtrace_lines_that_can_be_trusted=1; // From experience, only the first entry is to be trusted
var update_ghidradb_with_backtrace_callers=true;
var number_of_backtrace_lines_to_collect=6; //frida supports up to 16. Also, increasing the number is computationally expensive
var only_update_ghidradb_when_dynamic_call_is_spotted_in_bt=true; 




function is_address_inside_module(base_of_module,size_of_module,in_addr)
{
    if (in_addr.sub(base_of_module).compare(ptr(0))>=0 && in_addr.sub(base_of_module).compare(ptr(size_of_module))<=0)
    {
        return true;
    }
    return false;
}




function custom_backtracer(context,backtracer_type)
{
    var examined_module_from_ghidra=module_to_hook_obj
    var base_of_module=examined_module_from_ghidra.base
    var size_of_module=examined_module_from_ghidra.size
    var addresses_of_backtrace=Thread.backtrace(context, backtracer_type)
    //var classic_backtrace_str=addresses_of_backtrace.map(DebugSymbol.fromAddress);
    var entrypoint_of_current_function_which_is_being_hooked=context.pc
    var offset_of_entrypoint_of_current_function_which_is_being_hooked=entrypoint_of_current_function_which_is_being_hooked.sub(base_of_module)
    var offset_of_entrypoint_of_current_function_which_is_being_hooked_as_hex_str="0x"+offset_of_entrypoint_of_current_function_which_is_being_hooked.toString(16);
    var caller_has_been_identified_in_our_module=false;
    var backtrace_str_for_this_iteration=""
    var retval_describing_backtrace=""
    for (var i=0;i<Math.min(addresses_of_backtrace.length,number_of_backtrace_lines_to_collect);i++)
    {
        var current_bt_addr=ptr(addresses_of_backtrace[i])
        caller_has_been_identified_in_our_module=false
        if (is_address_inside_module(base_of_module,size_of_module,current_bt_addr)==false)
        {
            backtrace_str_for_this_iteration=extract_extended_str_for_address(current_bt_addr,false);
            caller_has_been_identified_in_our_module=false;
        }
        else //caller is inside our module
        {
            caller_has_been_identified_in_our_module=true
            var offset_of_bt_relative_to_module_base=current_bt_addr.sub(base_of_module)
            var offset_of_bt_relative_to_module_base_as_hex_str="0x"+offset_of_bt_relative_to_module_base.toString(16)
            var offset_of_bt_relative_to_module_base_as_num=offset_of_bt_relative_to_module_base.toInt32() // we know that it is a small number
            var ghidra_addr_for_bt=(ghidra_base_of_module_to_hook+offset_of_bt_relative_to_module_base_as_num).toString(16)
            var function_data=extract_function_info_from_address_for_our_module(current_bt_addr)
            if (function_data!=null)
            {
                var offset_of_bt_fun_entrypoint_as_num=parseInt(function_data.entrypoint_offset,16)
                var current_bt_function_start_addr=ptr(base_of_module.add(offset_of_bt_fun_entrypoint_as_num))
                var current_bt_function_name=function_data.fun_name
                var offset_from_start_of_current_bt_function=current_bt_addr.sub(current_bt_function_start_addr)
                var new_backtrace_str=module_name_to_hook+"!"+offset_of_bt_relative_to_module_base_as_hex_str+"  ,ghidra address: "+ghidra_addr_for_bt+" , function name: "+current_bt_function_name+", offset from start of function: "+offset_from_start_of_current_bt_function
                backtrace_str_for_this_iteration=new_backtrace_str;
                
            }
            else
            {
                backtrace_str_for_this_iteration=extract_extended_str_for_address(current_bt_addr,false);
            }
        }
        
        
        //create the backtrace string
        //console.log(backtrace_str_for_this_iteration);
        retval_describing_backtrace+=backtrace_str_for_this_iteration+"\n"
        
        
        
        //update with comments+xrefs
        if (i<number_of_backtrace_lines_that_can_be_trusted && update_ghidradb_with_backtrace_callers
            && ((only_update_ghidradb_when_dynamic_call_is_spotted_in_bt==false) || //either we update ghidra db in all cases
                (only_update_ghidradb_when_dynamic_call_is_spotted_in_bt && caller_has_been_identified_in_our_module && is_codeunit_a_dynamic_call(offset_of_bt_relative_to_module_base.sub(1)))) //or we update only when we have a dynamic call beginning from inside the examined module. Important: we subtract 1 byte to fall into the PREVIOUS codeunit because the backtrace will point us to the next one
        )
        {
            //update hooked function to indicate where it is called from
            var commentstr_to_add_to_ghidradb="Called from:" + backtrace_str_for_this_iteration+"\n"
            update_ghidradb_with_comment_at_addr(offset_of_entrypoint_of_current_function_which_is_being_hooked,commentstr_to_add_to_ghidradb)
        
            if (caller_has_been_identified_in_our_module)
            {
                //update backtrace address to indicate where it calls
                var offset_of_entrypoint_of_current_function_which_is_being_hooked_as_num=offset_of_entrypoint_of_current_function_which_is_being_hooked.toInt32() // we know that it is a small number
                var ghidra_addr_str_for_current_function_which_is_being_hooked=(ghidra_base_of_module_to_hook+offset_of_entrypoint_of_current_function_which_is_being_hooked_as_num).toString(16)
                var function_data_for_function_that_is_hooked=extract_function_info_from_address_for_our_module(entrypoint_of_current_function_which_is_being_hooked)
                if (function_data_for_function_that_is_hooked!=null)
                {
                    var current_hooked_function_name=function_data_for_function_that_is_hooked.fun_name
                    commentstr_to_add_to_ghidradb="Calls "+current_hooked_function_name+" at ghidra address "+ghidra_addr_str_for_current_function_which_is_being_hooked+" and offset "+offset_of_entrypoint_of_current_function_which_is_being_hooked_as_hex_str+ "of curent module\n";
                }
                else
                {
                    commentstr_to_add_to_ghidradb="Calls code at ghidra address "+ghidra_addr_str_for_current_function_which_is_being_hooked+" and offset "+offset_of_entrypoint_of_current_function_which_is_being_hooked_as_hex_str+ " of curent module\n";
                }
                update_ghidradb_with_comment_at_addr(current_bt_addr.sub(base_of_module),commentstr_to_add_to_ghidradb)
                update_ghidradb_with_xref(current_bt_addr.sub(base_of_module),offset_of_entrypoint_of_current_function_which_is_being_hooked,"COMPUTED_CALL")
            }
        }
        
    }
    
    return retval_describing_backtrace;
}

//---------------------- END: FOR CUSTOM BACKTRACER -------------------------------


//---------------------- FOR DYNAMIC CALL STALKING -------------------------------
var dynamic_call_stalking_is_enabled=false; // UPDATED FROM DRAGONHOOK PLUGIN
var modulename_to_stalk_has_been_loaded=false;
var modulename_to_stalk=module_name_to_hook
var ghidra_base_addr=ptr(ghidra_base_of_module_to_hook) 
var baseaddr_of_modulename_to_stalk=ptr(0)
var endaddr_of_modulename_to_stalk=ptr(0)
var maximum_times_to_log_call_target=1; // UPDATED FROM DRAGONHOOK PLUGIN
var dynamic_call_stalking_to_use_builtin_method=true; // UPDATED FROM DRAGONHOOK PLUGIN

var offsets_of_dynamic_calls={"DRAGONHOOK_OFFSETS_OF_DYNAMIC_CALLS":true}; //populated through ghidra
var dict_with_threadIds_and_whether_to_stalk_non_calls={};
var dict_with_threadIds_that_are_being_stalked={};

var call_tracing_through_stalker_is_enabled=false; // UPDATED FROM DRAGONHOOK PLUGIN
var call_tracing_ignore_callrets_outside_our_module=true; // UPDATED FROM DRAGONHOOK PLUGIN
var dict_with_threadIds_call_traces={};


// we should verify  that fromaddr falls into our module before calling. The toaddr may be elsewhere
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
                commentstr_to_add_to_ghidradb="Calls " + ghidra_base_addr.add(toaddr_offset)
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
                
                if (fromaddr.compare(baseaddr_of_modulename_to_stalk)>=1 && 
                    fromaddr.compare(endaddr_of_modulename_to_stalk)<=0 &&
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


function stalker_follow_dynamic_calls_marking_threads_method(threadId)
{
    Stalker.follow(threadId, {
        transform: function (iterator) {
            var instruction;         
            var dynamic_call_has_been_encountered_in_this_code_block=false;
            while ((instruction = iterator.next()) !== null) 
            {

                if (modulename_to_stalk_has_been_loaded==false)
                {
                    iterator.keep();
                    continue;
                }
                
                if (dynamic_call_has_been_encountered_in_this_code_block) //effectively ignore all other instructions. Valid dynamic call targets should appear in the next call of transform
                {
                    iterator.keep();
                    continue;
                }

                //This handles the NEXT address of the dynamic call, where the code jumps to
                if (threadId.toString() in dict_with_threadIds_and_whether_to_stalk_non_calls &&
                 dict_with_threadIds_and_whether_to_stalk_non_calls[threadId.toString()]!==-1 )
                {
                    var offset = instruction.address.sub(baseaddr_of_modulename_to_stalk);
                    //var instStr = Instruction.parse(instruction.address).toString();
                    var ghidra_addr_of_dynamic_caller=dict_with_threadIds_and_whether_to_stalk_non_calls[threadId.toString()];
                    var fromaddr=ghidra_addr_of_dynamic_caller.sub(ghidra_base_addr).add(baseaddr_of_modulename_to_stalk)
                    var toaddr=instruction.address;
                    update_ghidradb_with_comment_and_xref_for_dynamic_call(fromaddr,toaddr)
                    dict_with_threadIds_and_whether_to_stalk_non_calls[threadId.toString()]=-1
   
                }


                //This handles the dynamic call
                if (instruction.address.compare(baseaddr_of_modulename_to_stalk)>=1 && 
                    instruction.address.compare(endaddr_of_modulename_to_stalk)<=0 &&
                    (instruction.address.sub(baseaddr_of_modulename_to_stalk).toString() in offsets_of_dynamic_calls) &&
                    (offsets_of_dynamic_calls[instruction.address.sub(baseaddr_of_modulename_to_stalk).toString()]<maximum_times_to_log_call_target) ) 
                {
                    var offset = instruction.address.sub(baseaddr_of_modulename_to_stalk);
                    //var instStr = Instruction.parse(instruction.address).toString();
                    //console.log("DYNCALL-> TID:"+threadId+" "+"OFFSET:"+offset+" "+"GHIDRAOFFSET:"+ghidra_base_addr.add(offset)+" "+"INSTR:"+instStr);
                    dict_with_threadIds_and_whether_to_stalk_non_calls[threadId.toString()]=ghidra_base_addr.add(offset)

                    //increase the counter for the dynamic call. If the number exceeds the threshold the call target will not be logged
                    offsets_of_dynamic_calls[offset.toString()]+=1 
                     
                    //exhaust all other processed instructions in this basic block that is being processed by the Stalker
                    dynamic_call_has_been_encountered_in_this_code_block=true;
                }


                iterator.keep();          
            }
        }
    });
}


function process_call_ret_stalk_event(threadId,is_call,fromaddr,toaddr)
{
    var thread_id_to_str=threadId.toString()
    if (is_call==false)
    {
        dict_with_threadIds_call_traces[thread_id_to_str].pop();
        return;
    }

    var succinct_info_for_fromaddr=extract_succinct_str_for_address(fromaddr).replaceAll(",","_")
    var succinct_info_for_toaddr=extract_succinct_str_for_address(toaddr).replaceAll(",","_")
    dict_with_threadIds_call_traces[thread_id_to_str].push(succinct_info_for_fromaddr+" -> "+succinct_info_for_toaddr)
    console.log("TID "+thread_id_to_str+":"+dict_with_threadIds_call_traces[thread_id_to_str])
    return;
}


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
            
            var event=Stalker.parse(events,{annotate:true})
            for (var i=0; i<event.length;i++)
            {
                var this_event=event[i];
                var is_call=false
                var is_ret=false
                if (this_event[0]=="call")
                {
                    is_call=true;
                }
                if (this_event[0]=="ret")
                {
                    is_ret=true;
                }

                var fromaddr=this_event[1]
                var toaddr=this_event[2]

                //we will include the information of an external call/ret that will end up in our module
                //in other words, BOTH addresses must fall outside the module
                if ( call_tracing_ignore_callrets_outside_our_module && 
                    ((fromaddr.compare(baseaddr_of_modulename_to_stalk)<0 || 
                    fromaddr.compare(endaddr_of_modulename_to_stalk)>=1 ) 
                    &&
                    (toaddr.compare(baseaddr_of_modulename_to_stalk)<0 || 
                    toaddr.compare(endaddr_of_modulename_to_stalk)>=1)
                    ))
                {
                   ; //ignore
                }
                else
                {
                    process_call_ret_stalk_event(threadId,is_call,fromaddr,toaddr);
                }
            }
        }
    });
}


//call with startStalker(this.threadId,modulename_to_stalk)
function startStalker(threadId, targetModule){
    var modules = Process.enumerateModules();    
    modules.forEach(mod => {
        //if ((mod.name.toLowerCase().indexOf(targetModule.toLowerCase())) < 0) {
        if ((mod.name.toLowerCase().indexOf("frida")) >= 0) {
            //console.log("Excluding "+mod.name+" from stalking...");            
            // We're not interested in stalking frida. However, for dynamic call targets that fall outside of our module, we will need to stalk everything else 
            
            Stalker.exclude({ //global exclusion
                'base': mod.base,
                'size': mod.size,
            });
                    
        }
    }); 
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

}


//call with stopStalker(this.threadId)
function stopStalker(threadId){
    Stalker.unfollow(threadId);
    Stalker.flush();
}


function begin_stalking_as_soon_as_module_is_found()
{
    //initialize our variables as soon as we are certain that our module has been loaded
    baseaddr_of_modulename_to_stalk=Process.getModuleByName(modulename_to_stalk).base
    endaddr_of_modulename_to_stalk=baseaddr_of_modulename_to_stalk.add(Process.getModuleByName(modulename_to_stalk).size)
    
    //Process.getModuleByName(modulename_to_stalk).ensureInitialized(); //can cause crashes on Android, particularly on process spawn
    modulename_to_stalk_has_been_loaded=true;

}


//---------------------- END: FOR DYNAMIC CALL STALKING -------------------------------


//------------------------- FOR HARDWARE WATCHPOINTS ----------------------------------
//https://frida.re/news/2024/09/06/frida-16-5-0-released/
var setting_of_watchpoints_is_enabled=false; // UPDATED FROM DRAGONHOOK PLUGIN
var watchpoint_global_cnt=0;
var threads_and_watchpoint_ids={};
var watchpoint_ids_and_how_many_times_each_is_visited={};
var exception_handler_has_been_installed=false;
var array_of_objects_for_which_to_install_watchpoints=[{"address_offset_as_num":0xffffffffffff,"size":4,"operation":"r"}]; // UPDATED FROM DRAGONHOOK PLUGIN
var max_times_each_watchpoint_is_logged=4; // UPDATED FROM DRAGONHOOK PLUGIN
var queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded=[];



function getRandomInt(max) {
  return Math.floor(Math.random() * max);
}

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

// we should verify  that toaddr falls into our module before calling. The fromaddr may be elsewhere
function update_ghidradb_with_comment_and_xref_for_watchpoint(fromaddr,toaddr,operation)
{
    var toaddr_offset = toaddr.sub(module_to_hook_baseaddr);
    var fromaddr_offset = fromaddr.sub(module_to_hook_baseaddr);
    var ghidra_addr_of_memory_that_is_changed=toaddr.sub(module_to_hook_baseaddr).add(ghidra_base_of_module_to_hook);
    var module_containing_from_address=modulemap_for_all_modules.find(fromaddr);
    if (module_containing_from_address!=null)
    {
        var fromaddr_offset_from_module_start=fromaddr.sub(module_containing_from_address.base);

        //update ghidradb
        var commentstr_to_add_to_ghidradb="";
        if (module_containing_from_address.base.equals(module_to_hook_baseaddr)) //our module
        {
            //update toaddr
            var function_data_for_function_that_performs_the_operation=extract_function_info_from_address_for_our_module(fromaddr)
            if (function_data_for_function_that_performs_the_operation!=null)
            {
                var function_name=function_data_for_function_that_performs_the_operation.fun_name
                commentstr_to_add_to_ghidradb="Altered through a "+operation +" from "+function_name+" at ghidra address "+ghidra_base_addr.add(fromaddr_offset)+" and offset "+toaddr_offset+ " of curent module";
            }
            else
            {
                commentstr_to_add_to_ghidradb="Altered through a "+operation +" from ghidra address "+ghidra_base_addr.add(fromaddr_offset)+" and offset "+toaddr_offset+ " of curent module";
            }
            update_ghidradb_with_comment_at_addr(toaddr_offset,commentstr_to_add_to_ghidradb);
            update_ghidradb_with_xref(fromaddr_offset,toaddr_offset,get_valid_flowtype_for_operation(operation))

                
            //update fromaddr (comment only, xref takes care of both)
            commentstr_to_add_to_ghidradb="Previous address is altering with a "+operation+" ghidra address "+ghidra_base_addr.add(toaddr_offset);
            update_ghidradb_with_comment_at_addr(fromaddr_offset_from_module_start,commentstr_to_add_to_ghidradb);
        }
        else
        {
            //only update memory that is touched (toaddr)
            commentstr_to_add_to_ghidradb="Altered through a "+operation +" from offset "+fromaddr_offset_from_module_start+" relative to the module "+ module_containing_target_address.name +" , debuginfo: "+extract_DebugSymbol_fromAddress_data(fromaddr);
            update_ghidradb_with_comment_at_addr(toaddraddr_offset,commentstr_to_add_to_ghidradb);
        }
    }
}


function process_wide_exception_handler_for_watchpoints(details)
{
    console.log("=== Handler got "+details.type+" exception at "+details.context.pc +", details: "+JSON.stringify(details));
    var is_hardware_watchpoint_hit=['breakpoint', 'single-step'].includes(details.type);
    var address_which_triggered_the_exception=details.context.pc;
    if (!is_hardware_watchpoint_hit)
    {
        console.log('Passing to application');
        return false;
    }
    if (!details.memory)
    {
        console.log('Strange, no details.memory object for exception. Handling the exception.');
        if (is_address_inside_module(module_to_hook_baseaddr,module_to_hook_size,details.address))
        {
            console.log("HARDWARE WATCHPOINT TRIGGERED, with incomplete information. Possibly the address accessing the memory is  "+extract_extended_str_for_address(details.address, true)+ ", or its previous instruction")   
        }
        return true;
    }
    var address_for_which_the_exception_was_triggered=details.memory.address
    var thread_id_to_str=Process.getCurrentThreadId().toString();
    var current_thread=dict_from_threadids_to_threads[thread_id_to_str];
    var watchpoint_id_to_uninstall;
    var size_of_memory_for_watchpoint;
    var condition_for_which_watchpoint_was_hit;
    
    if (thread_id_to_str in threads_and_watchpoint_ids && address_for_which_the_exception_was_triggered.toString() in threads_and_watchpoint_ids[thread_id_to_str])
    {
        watchpoint_id_to_uninstall=threads_and_watchpoint_ids[thread_id_to_str][address_for_which_the_exception_was_triggered.toString()][0]
        size_of_memory_for_watchpoint=threads_and_watchpoint_ids[thread_id_to_str][address_for_which_the_exception_was_triggered.toString()][1]
        condition_for_which_watchpoint_was_hit=threads_and_watchpoint_ids[thread_id_to_str][address_for_which_the_exception_was_triggered.toString()][2]
        if (watchpoint_id_to_uninstall in watchpoint_ids_and_how_many_times_each_is_visited)
        {
            watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_id_to_uninstall]+=1;
        }
        else
        {
            watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_id_to_uninstall]=1;
        }
        if ( watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_id_to_uninstall]>max_times_each_watchpoint_is_logged)
        {
            console.log("Strange, hit this watchpoint too many times. Passing to the application.")
            current_thread.unsetHardwareWatchpoint(watchpoint_id_to_uninstall);
            threads_and_watchpoint_ids[thread_id_to_str][address_for_which_the_exception_was_triggered.toString()][3]="uninstalled";
            return false;
        }
    }
    else
    {
        console.log('Strange, could not identify the correct watchpoint id for the memory access. Passing to application.');
        return false;
    }
    
    console.log("HARDWARE WATCHPOINT TRIGGERED: For address "+address_for_which_the_exception_was_triggered+" , we had a "+details.memory.operation+" to it, from address "+address_which_triggered_the_exception+ " from module "+extract_extended_str_for_address(address_which_triggered_the_exception,true));
    
    if (is_address_inside_module(module_to_hook_baseaddr,module_to_hook_size,address_which_triggered_the_exception))
    {
        //inside_our_module
        var offset_from_base_of_hooked_module_as_num=address_which_triggered_the_exception.sub(module_to_hook_baseaddr).toInt32()
        var ghidra_addr_for_addr_that_triggers_watchpoint=(ghidra_base_of_module_to_hook+offset_from_base_of_hooked_module_as_num).toString(16)
        console.log("HARDWARE WATCHPOINT TRIGGERED: This address corresponds to ghidra address "+ghidra_addr_for_addr_that_triggers_watchpoint)
    }
    update_ghidradb_with_comment_and_xref_for_watchpoint(address_which_triggered_the_exception,address_for_which_the_exception_was_triggered,details.memory.operation)
    if ( watchpoint_ids_and_how_many_times_each_is_visited[watchpoint_id_to_uninstall]>=max_times_each_watchpoint_is_logged)
    {
        current_thread.unsetHardwareWatchpoint(watchpoint_id_to_uninstall);
        threads_and_watchpoint_ids[thread_id_to_str][address_for_which_the_exception_was_triggered.toString()][3]="uninstalled";
        console.log('Disabled hardware watchpoint ' + watchpoint_id_to_uninstall+ ' for thread '+thread_id_to_str+' and address for which the exception was triggered '+address_for_which_the_exception_was_triggered);
    }
    return true;
}


function install_watchpoint_for_a_thread(address, size, conditions, thread) {
    
    var watchpoint_id_to_install=watchpoint_global_cnt;
    watchpoint_global_cnt+=1;
    var thread_id_to_str=thread.id.toString();
    
    if (exception_handler_has_been_installed==false)
    {
        Process.setExceptionHandler(process_wide_exception_handler_for_watchpoints);
        exception_handler_has_been_installed=true;
    }
    
    if (thread_id_to_str in threads_and_watchpoint_ids && Object.keys(threads_and_watchpoint_ids[thread_id_to_str]).length>0)
    {
        threads_and_watchpoint_ids[thread_id_to_str][address.toString()]=[watchpoint_id_to_install,size,conditions,"installed"];
    }
    else
    {
        threads_and_watchpoint_ids[thread_id_to_str]={};
        threads_and_watchpoint_ids[thread_id_to_str][address.toString()]=[watchpoint_id_to_install,size,conditions,"installed"];
    }
    console.log("Trying to set hardware watchpoint "+watchpoint_id_to_install+" for "+address+" for thread "+JSON.stringify(thread))
    thread.setHardwareWatchpoint(watchpoint_id_to_install, address, size, conditions);
    console.log('Installed watchpoint '+watchpoint_id_to_install+' for address '+address+' for thread '+thread_id_to_str);
}


function safe_add_watchpoint_for_a_thread(address,size,operation,incoming_thread)
{
    try 
    {
        install_watchpoint_for_a_thread(address,size,operation,incoming_thread);
    }
    catch (error)
    {
        console.log("Could not install watchpoint for thread "+JSON.stringify(incoming_thread)+" at address "+extract_DebugSymbol_fromAddress_data(address)+" , error: "+ error +". Possibly hardware watchpoints are not supported.");
    }
}


function add_all_configured_watchpoints_for_a_thread(incoming_thread)
{
    for (var ind2=0;ind2<array_of_objects_for_which_to_install_watchpoints.length;ind2++)
    {
        var obj_describing_watchpoint=array_of_objects_for_which_to_install_watchpoints[ind2];
        var addr=module_to_hook_baseaddr.add(obj_describing_watchpoint["address_offset_as_num"]);
        var sz=obj_describing_watchpoint["size"];
        var op=obj_describing_watchpoint["operation"];
        safe_add_watchpoint_for_a_thread(addr,sz,op,incoming_thread);
    }
}

function add_watchpoints_for_all_queued_threads()
{
    for (var ind=0;ind<queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded.length;ind++)
    {
        var queued_thread=queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded[i];
        add_all_configured_watchpoints_for_a_thread(queued_thread);
    }
}

function remove_all_installed_watchpoints_for_a_thread(incoming_thread)
{
    var thread_id_to_str=incoming_thread.id.toString();
    if (thread_id_to_str in threads_and_watchpoint_ids)
    {
        for (var addr_str in threads_and_watchpoint_ids[thread_id_to_str])
        {
            var watchpoint_id_to_uninstall=threads_and_watchpoint_ids[thread_id_to_str][addr_str][0]
            var size_of_memory_for_watchpoint=threads_and_watchpoint_ids[thread_id_to_str][addr_str][1]
            var condition_for_which_watchpoint_was_hit=threads_and_watchpoint_ids[thread_id_to_str][addr_str][2]
            var installed_or_not=threads_and_watchpoint_ids[thread_id_to_str][addr_str][3]
            if (installed_or_not=="installed")
            {
                incoming_thread.unsetHardwareWatchpoint(watchpoint_id_to_uninstall);
                threads_and_watchpoint_ids[thread_id_to_str][addr_str][3]="uninstalled";
                console.log('Disabled hardware watchpoint ' + watchpoint_id_to_uninstall+ ' for thread '+thread_id_to_str+' and address for which the exception was triggered '+addr_str);

            }
        }
    }
}


//---------------------- END: FOR HARDWARE WATCHPOINTS --------------------------------



// DRAGONHOOK PREPARATION STEPS BEFORE REGISTERING OBSERVERS GO HERE


//---------------------- FOR ATTACHING TO MODULE -------------------------------

//The most reliable method to hook a module is through the attachModuleObserver()
var observer_KYjQgb = Process.attachModuleObserver({
    onAdded(module) {
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
                //process the queued threads
                add_watchpoints_for_all_queued_threads();
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
            
            if (thread.name && thread.name.toLowerCase().includes("frida"))
            {
                return; //do nothing in this case
            }
            
            //STALKER 
            var str_to_be_included_in_thread_name_for_stalker=""; //UPDATED FROM DRAGONHOOK PLUGIN
            var there_is_a_restriction_for_the_thread_name_for_stalker=false;  //UPDATED FROM DRAGONHOOK PLUGIN
            
            //be careful when stalking everything, depending on the application the thread list may need to be restricted. For example,in Android Unity applications, UnityMain is the name of the thread that must be stalked .
            if ((dynamic_call_stalking_is_enabled || call_tracing_through_stalker_is_enabled) && 
                ((!there_is_a_restriction_for_the_thread_name_for_stalker) ||
                (there_is_a_restriction_for_the_thread_name_for_stalker && thread.name &&  thread.name.toLowerCase().includes(str_to_be_included_in_thread_name_for_stalker) ) )
               )   
            {
                console.log("Tryng to start stalking thread "+thread.id+" with name "+thread.name)
                //note: maybe the module to be stalked has not even been loaded yet
                dict_with_threadIds_that_are_being_stalked[thread.id.toString()]=true;
                dict_with_threadIds_call_traces[thread.id.toString()]=[];
                startStalker(thread.id, modulename_to_stalk)
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
                    add_all_configured_watchpoints_for_a_thread(thread);
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
            dict_from_threadids_to_threads[thread.id.toString()]=null;
            
            if ((dynamic_call_stalking_is_enabled || call_tracing_through_stalker_is_enabled) && 
                thread.id.toString() in dict_with_threadIds_that_are_being_stalked && 
                dict_with_threadIds_that_are_being_stalked[thread.id.toString()]==true)
            {
                stopStalker(thread.id)
                dict_with_threadIds_that_are_being_stalked[thread.id.toString()]=false
            }
            
            if (setting_of_watchpoints_is_enabled)
            {
                //remove thread from queue
                queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded= queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded.filter(item => item !== thread)
            }
        },
        onRenamed(thread,previousName)
        {
            if (dynamic_call_stalking_is_enabled || call_tracing_through_stalker_is_enabled
                || setting_of_watchpoints_is_enabled )
            {
                console.log("Thread with name "+previousName+" was renamed to "+thread.name)
            }
            
            if (thread.name && thread.name.toLowerCase().includes("frida")
            &&  thread.id.toString() in dict_with_threadIds_that_are_being_stalked && 
             dict_with_threadIds_that_are_being_stalked[thread.id.toString()]==true)
            {
                console.log("Stopping stalking thread "+thread.name+" due to rename");
                stopStalker(thread.id);
                dict_with_threadIds_that_are_being_stalked[thread.id.toString()]=false;
            }
            
            if (setting_of_watchpoints_is_enabled
                && thread.name && thread.name.toLowerCase().includes("frida") )
            {
                //remove thread from queue
                queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded= queue_of_threads_for_which_watchpoint_will_be_added_when_the_module_is_loaded.filter(item => item !== thread)
                //Also remove watchpoints which may have already been established
                remove_all_installed_watchpoints_for_a_thread(thread)

            }
        }
    });
    
//---------------------- END: FOR ATTACHING TO MODULE ---------------------------


//This is the function that should be edited, if manual alterations are needed
function intercept_identified_module_DragonHook()
{
    console.log("Registering interceptors...");
    

    //DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE

        
    Interceptor.flush();
    console.log("Registered interceptors.");
}


rpc.exports = {
    return_total_script_output_api_call: return_total_script_output
};
