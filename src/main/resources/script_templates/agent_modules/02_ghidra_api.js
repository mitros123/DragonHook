//---------------------- FOR INTERACTION WITH THE GHIDRA API ----------------------

var ghidra_api_storage={
    "FUN_DATA_BY_ADDR":{},
    "REACHED_UPDATE_LIMIT_FOR_ADDR":{},
    "CODEUNIT_DATA_BY_ADDR":{},
    //compact function range table, filled in by get_full_function_data_by_ranges().
    //Three parallel arrays instead of an array of objects: one object per FUNCTION is allocated
    //(shared by all of its ranges) instead of one per RANGE, and the bounds stay as numbers so the
    //binary search never has to parseInt() a hex string.
    "FUN_RANGE_STARTS":[],   //numbers, sorted ascending
    "FUN_RANGE_ENDS":[],     //numbers, inclusive
    "FUN_RANGE_FUNIDX":[],   //index into FUN_OBJECTS
    "FUN_OBJECTS":[]         //{fun_name, entrypoint_offset}, shared by every range of that function
}
var function_ranges_are_loaded=false;
var bulk_function_data_fetch_has_failed=false;
var function_data_retrieval_mode_has_been_logged=false;

var comment_updates_to_ghidradb_are_asynchronous=true; //enable to make the updates faster, it gives a significant performance boost. However it seems that it makes the process more prone to crashing
var xref_updates_to_ghidradb_are_asynchronous=true; //enable to make the updates faster, it gives a significant performance boost. However it seems that it makes the process more prone to crashing
var memory_updates_to_ghidradb_are_asynchronous=true; //enable to make the updates faster

//Asks ghidra for the function covering one module offset, caching the reply. BLOCKS the calling
//thread on recv().wait(). Called only from the live (non bulk) lookup path in module 03.
function get_function_data_from_ghidra_given_address_offset(address_offset)
{
    var address_offset_as_str="0x"+address_offset.toString(16);
    if (address_offset_as_str in ghidra_api_storage["FUN_DATA_BY_ADDR"])
    {
        return (ghidra_api_storage["FUN_DATA_BY_ADDR"][address_offset_as_str])
    }
    //else
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"FUN_DATA_GIVEN_ADDR_OFFSET","PARAMS":["'+address_offset_as_str+'"]}|||\n'
    if (!send_protocol_line_to_python(line_to_send))
    {
        //Deliberately leaves the cache untouched: do_we_have_proper_function_data_given_address_offset()
        //reads the CACHE rather than this return value, finds no entry, and JSON.parse(undefined) throws
        //there - so it reports false, exactly as it does for a malformed reply. No caller has to change.
        return "Error, the channel to python is gone, no function data can arrive";
    }
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
//Called right after get_function_data_from_ghidra_given_address_offset(), to tell a real JSON reply
//from an error string.
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



//Asks ghidra for one code unit (instruction text, refs, symbol), caching the reply. BLOCKS on
//recv().wait(). Reached from get_codeunit_information_as_dict() only.
function get_codeunit_data_from_ghidra_given_address_offset(address_offset)
{
    var address_offset_as_str="0x"+address_offset.toString(16);
    if (address_offset_as_str in ghidra_api_storage["CODEUNIT_DATA_BY_ADDR"])
    {
        return (ghidra_api_storage["CODEUNIT_DATA_BY_ADDR"][address_offset_as_str])
    }
    //else
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"CODEUNIT_DATA_GIVEN_ADDR_OFFSET","PARAMS":["'+address_offset_as_str+'"]}|||\n'
    if (!send_protocol_line_to_python(line_to_send))
    {
        //as above: nothing cached, so do_we_have_proper_codeunit_data_given_address_offset() reports false
        //and get_codeunit_information_as_dict() returns null, which every caller already handles
        return "Error, the channel to python is gone, no codeunit data can arrive";
    }
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
//Called from get_codeunit_information_as_dict() to tell a real JSON reply from an error string.
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


//Fetches (or reuses) the code unit description for a module offset and parses it.
//Called by is_codeunit_a_dynamic_call() and return_codeunit_symbol_str(). Can block.
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

//True when the code unit at this offset is a computed call. Called only as the FALLBACK inside
//did_we_get_here_through_a_computed_call(), when the plugin did not precompute the table.
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

//Primary symbol name at a module offset, or null. Called from extract_extended_str_for_address()
//when it is asked to include ghidra symbol names. Can block, so avoid it in native callbacks.
function return_codeunit_symbol_str(address_offset)
{
    var codeunit_data_as_json=get_codeunit_information_as_dict(address_offset);
    if (codeunit_data_as_json && ("primary_symbol" in codeunit_data_as_json))
    {
        return codeunit_data_as_json["primary_symbol"];
    }
    return null;
}


//expands the compact structure produced by ALL_FUN_DATA_SORTED_BY_RANGESTART, see the java side
//Called from get_full_function_data_by_ranges() once the reply has arrived.
function load_compact_function_ranges(compact_obj)
{
    var functions_from_ghidra=compact_obj["functions"];
    var ranges_from_ghidra=compact_obj["ranges"];

    var fun_objects=new Array(functions_from_ghidra.length);
    for (var i=0;i<functions_from_ghidra.length;i++)
    {
        //same shape as what FUN_DATA_GIVEN_ADDR_OFFSET returns, so every consumer keeps working
        fun_objects[i]={fun_name:functions_from_ghidra[i][0], entrypoint_offset:functions_from_ghidra[i][1]};
    }

    var number_of_ranges=ranges_from_ghidra.length;
    var starts=new Array(number_of_ranges);
    var ends=new Array(number_of_ranges);
    var funidx=new Array(number_of_ranges);
    for (var j=0;j<number_of_ranges;j++)
    {
        starts[j]=ranges_from_ghidra[j][0];
        ends[j]=ranges_from_ghidra[j][1];
        funidx[j]=ranges_from_ghidra[j][2];
    }

    ghidra_api_storage["FUN_OBJECTS"]=fun_objects;
    ghidra_api_storage["FUN_RANGE_STARTS"]=starts;
    ghidra_api_storage["FUN_RANGE_ENDS"]=ends;
    ghidra_api_storage["FUN_RANGE_FUNIDX"]=funidx;
    function_ranges_are_loaded=true;
    return number_of_ranges;
}


//Fetches the whole function range table once and expands it for the binary search. BLOCKS.
//Called at script load (injected at the preparation marker in bulk mode) and lazily on first
//lookup. Latches on failure so a broken fetch is not retried per address.
function get_full_function_data_by_ranges()
{
    if (function_ranges_are_loaded)
    {
        return "ok";
    }
    if (bulk_function_data_fetch_has_failed)
    {
        //without this latch every single address lookup re-issues the whole ALL_FUN_DATA request
        return "the bulk function data fetch already failed once, not retrying it";
    }
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"ALL_FUN_DATA_SORTED_BY_RANGESTART","PARAMS":[]}|||\n'
    if (!send_protocol_line_to_python(line_to_send))
    {
        //the channel does not come back, so latch the failure and let every later lookup take the early exit
        //above instead of re-issuing the whole table request per address
        bulk_function_data_fetch_has_failed=true;
        return "Error, the channel to python is gone, the function range table cannot be fetched";
    }
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
        if ( ! ("function_ranges_compact" in returned_dict))
        {
            bulk_function_data_fetch_has_failed=true;
            var missing_key_msg="the reply has no function_ranges_compact key. If the DragonHook plugin was updated, reset the JS agent file so that both sides use the same format.";
            console.log("get_full_function_data_by_ranges() FAILED: "+missing_key_msg);
            return missing_key_msg;
        }
        var number_of_ranges=load_compact_function_ranges(returned_dict["function_ranges_compact"]);
        console.log("length of array of ranges with function data:"+number_of_ranges)
        return "ok";
    }
    catch (err)
    {
        //the top level caller injected by the plugin discards the return value, so log it here or
        //the failure is completely silent and every lookup afterwards just returns null
        bulk_function_data_fetch_has_failed=true;
        var error_str=(""+str_that_is_returned).substring(0,2000)+"...." //reduce size. Also survives an undefined reply
        console.log("get_full_function_data_by_ranges() FAILED, "+err+" , reply was: "+error_str);
        return error_str;
    }
}



//How many updates the AGENT will send for any one address before it stops on its own. The ghidra side
//has its own per codeunit limit, but while the update flags are asynchronous we never see its replies,
//so REACHED_UPDATE_LIMIT_FOR_ADDR below can never be populated and that limit cannot brake us. Without
//an agent side count, a hooked function on a hot path keeps sending a comment and an xref on every
//single call, for the life of the process, while ghidra silently discards everything past its own
//limit. Kept equal to the ghidra side default so that we stop sending at roughly the point ghidra
//stops accepting.
var max_ghidradb_updates_per_address_from_the_agent=15;
var number_of_ghidradb_updates_sent_for_address={};

//Counts one update actually sent for an address. Called by the comment and xref update functions after
//they have decided to send, so the count reflects traffic rather than attempts.
function count_one_ghidradb_update_for_addr(in_addr_offset)
{
    var key_for_address=""+in_addr_offset;
    var number_already_sent=number_of_ghidradb_updates_sent_for_address[key_for_address];
    if (number_already_sent===undefined) { number_already_sent=0; }
    number_of_ghidradb_updates_sent_for_address[key_for_address]=number_already_sent+1;
}

//True when we should stop updating this address: either ghidra told us its own limit was reached (only
//possible on the synchronous path) or the agent has already sent its own allowance.
//Called at the top of the comment and xref update functions.
function have_we_hit_limit_on_ghidradb_updates_for_addr(in_addr_offset)
{
    var key_for_address=""+in_addr_offset;
    var number_already_sent=number_of_ghidradb_updates_sent_for_address[key_for_address];
    if (number_already_sent!==undefined && number_already_sent>=max_ghidradb_updates_per_address_from_the_agent)
    {
        return true;
    }
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


//Appends a PRE comment at a module offset in the ghidra db. Fire and forget while the async flag is
//on, blocking otherwise. Called by every feature: backtracer, dynamic calls, watchpoints, strings.
function update_ghidradb_with_comment_at_addr(offset_of_address_to_update,comment_to_update_with)
{
    if (have_we_hit_limit_on_ghidradb_updates_for_addr(offset_of_address_to_update))
    {
        return "It was previously detected that the update limit for this address has been reached";
    }
    var address_offset_as_str="0x"+offset_of_address_to_update.toString(16);
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR","PARAMS":[\"'+address_offset_as_str+'\",'+JSON.stringify(comment_to_update_with)+']}|||\n'
    if (!send_protocol_line_to_python(line_to_send))
    {
        //returned before the count is bumped, since that count tracks traffic that really went out
        return "Error, the channel to python is gone, the comment was not sent";
    }
    count_one_ghidradb_update_for_addr(offset_of_address_to_update);

    //recv() registers a one-shot pending handler keyed by the type string. Registering one and then
    //walking away from it (which is what the async path used to do) leaves it pending until the
    //matching reply happens to arrive, so under heavy stalking the pending set grows as fast as we
    //issue updates. On the async path we never look at the reply, so do not register a handler.
    if (comment_updates_to_ghidradb_are_asynchronous)
    {
        //ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_to_update]=false;
        return "We don't care for the reply"
    }

    var str_that_is_returned;
    var response=recv('api-response-UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR-[\''+address_offset_as_str+'\']', //no need to include the comment in this type . Also, again, single quotes
        function onrecv(resp)
        {
            str_that_is_returned=resp.payload; //may be an error string, we need to check for that
        }
    );
    response.wait()
    if (str_that_is_returned.includes("Error, reached maximum"))
    {
        ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_to_update]=true;
    }
    return str_that_is_returned
}


//Adds an xref between two module offsets with the given RefType. Fire and forget while the async
//flag is on, blocking otherwise. Called by every feature that discovers a new edge.
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
    if (!send_protocol_line_to_python(line_to_send))
    {
        //again before the count, for the same reason
        return "Error, the channel to python is gone, the xref was not sent";
    }
    count_one_ghidradb_update_for_addr(offset_of_address_from);   //the referencing side is the one that floods

    //see the note in update_ghidradb_with_comment_at_addr(): no recv() handler on the async path
    if (xref_updates_to_ghidradb_are_asynchronous)
    {
        //ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_from]=false;
        //ghidra_api_storage["REACHED_UPDATE_LIMIT_FOR_ADDR"][offset_of_address_to]=false;
        return "We don't care for the reply"
    }

    var str_that_is_returned;
    var response=recv('api-response-UPDATE_GHIDRADB_WITH_XREF-[\''+address_offset_from_as_str+'\', \''+address_offset_to_as_str+'\', \''+type_of_xref+'\']', //that's how python will return the reply
        function onrecv(resp)
        {
            str_that_is_returned=resp.payload; //may be an error string, we need to check for that
        }
    );
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



//Writes live memory back into the ghidra db. Not called by the template: it exists for hand written
//hooks added at the DRAGONHOOK CODE marker.
function update_ghidradb_with_memory_contents(offset_of_starting_address_to_update,memory_addr_to_start_reading,length_of_bytes_to_read)
{
    var address_offset_as_str="0x"+offset_of_starting_address_to_update.toString(16);
    //TODO: convert to base64 in a succint fashion. Now we are sending an array of decimals
    var bytes_from_mem=memory_addr_to_start_reading.readByteArray(length_of_bytes_to_read);
    var u8=new Uint8Array(bytes_from_mem);
    var decimalarray=Array.from(u8)
    var line_to_send='|||DH_GHIDRA_API_CALL:{"FUNCTION":"CHANGE_BYTES_INSIDE_GHIDRADB","PARAMS":[\"'+address_offset_as_str+'\",\"'+JSON.stringify(decimalarray)+'\"]}|||\n'
    if (!send_protocol_line_to_python(line_to_send))
    {
        return "Error, the channel to python is gone, the memory contents were not sent";
    }

    //see the note in update_ghidradb_with_comment_at_addr(): no recv() handler on the async path
    if (memory_updates_to_ghidradb_are_asynchronous)
    {
        return "We don't care for the reply"
    }

    var str_that_is_returned;
    var response=recv('api-response-CHANGE_BYTES_INSIDE_GHIDRADB-[\''+address_offset_as_str+'\']', //no need to include the comment in this type . Also, again, single quotes
        function onrecv(resp)
        {
            str_that_is_returned=resp.payload; //may be an error string, we need to check for that
        }
    );
    response.wait()
    return str_that_is_returned
}

//---------------------- END: FOR INTERACTION WITH THE GHIDRA API -----------------



