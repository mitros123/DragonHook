//---------------------- FOR CUSTOM BACKTRACER -------------------------------


var number_of_backtrace_lines_that_can_be_trusted=1; // From experience, only the first entry is to be trusted
var update_ghidradb_with_backtrace_callers=true;
var number_of_backtrace_lines_to_collect=6; //frida supports up to 16. Also, increasing the number is computationally expensive
var only_update_ghidradb_when_dynamic_call_is_spotted_in_bt=true;

//A backtrace entry is a RETURN address: the instruction right after the call that got us here. When
//the plugin has precomputed the set of such addresses for every computed call in the module, the
//"did a computed call bring us here" question is a dictionary lookup. Without it we have to ask
//ghidra at runtime, which sends a request and blocks the hooked thread until the reply arrives.
var precomputed_offsets_after_computed_calls_are_available=false; // UPDATED FROM DRAGONHOOK PLUGIN
var offsets_right_after_a_computed_call={"DRAGONHOOK_OFFSETS_AFTER_COMPUTED_CALLS":true}; //populated through ghidra


//Called from custom_backtracer() for the first backtrace entry, to decide whether the edge is worth
//writing into the ghidra db at all.
function did_we_get_here_through_a_computed_call(offset_of_bt_relative_to_module_base)
{
    if (precomputed_offsets_after_computed_calls_are_available)
    {
        //exact match: the precomputed set holds return addresses, which is what a backtrace gives us
        return (offset_of_bt_relative_to_module_base.toString() in offsets_right_after_a_computed_call);
    }
    //fallback, blocks the hooked thread for a ghidra round trip. We subtract 1 byte to fall into the
    //PREVIOUS codeunit, because the backtrace points us at the next one.
    return is_codeunit_a_dynamic_call(offset_of_bt_relative_to_module_base.sub(1));
}




//True when a runtime address falls inside [base, base+size). Called by custom_backtracer() and by
//the watchpoint exception handler.
function is_address_inside_module(base_of_module,size_of_module,in_addr)
{
    //base+size is the first byte AFTER the module, so the upper bound is exclusive
    if (in_addr.sub(base_of_module).compare(ptr(0))>=0 && in_addr.sub(base_of_module).compare(ptr(size_of_module))<0)
    {
        return true;
    }
    return false;
}




//Builds a ghidra aware backtrace and records the caller edge in the ghidra db. Runs INSIDE an
//Interceptor callback, on the hooked thread, so everything it touches must be cheap.
//Called from the hooks the Frida Hook Generator injects at the DRAGONHOOK CODE marker.
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
        //declared for the whole iteration and reset on every one of them: var is function scoped, so
        //without the reset an entry whose caller is NOT in our module would still see the offset that
        //the PREVIOUS iteration computed. Only the branch below that identifies a caller inside our
        //module ever gives it a value, and only the guards that test for that value read it.
        var offset_of_bt_relative_to_module_base=null
        if (is_address_inside_module(base_of_module,size_of_module,current_bt_addr)==false)
        {
            backtrace_str_for_this_iteration=extract_extended_str_for_address(current_bt_addr,false);
            caller_has_been_identified_in_our_module=false;
        }
        else //caller is inside our module
        {
            caller_has_been_identified_in_our_module=true
            offset_of_bt_relative_to_module_base=current_bt_addr.sub(base_of_module)
            var offset_of_bt_relative_to_module_base_as_hex_str="0x"+offset_of_bt_relative_to_module_base.toString(16)
            var offset_of_bt_relative_to_module_base_as_num=offset_of_bt_relative_to_module_base.toInt32() // we know that it is a small number
            var ghidra_addr_for_bt="0x"+(ghidra_base_of_module_to_hook+offset_of_bt_relative_to_module_base_as_num).toString(16)
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
                (only_update_ghidradb_when_dynamic_call_is_spotted_in_bt && caller_has_been_identified_in_our_module && offset_of_bt_relative_to_module_base!=null && did_we_get_here_through_a_computed_call(offset_of_bt_relative_to_module_base))) //or we update only when we have a dynamic call beginning from inside the examined module
        )
        {
            //update hooked function to indicate where it is called from
            var commentstr_to_add_to_ghidradb="Called from:" + backtrace_str_for_this_iteration+"\n"
            update_ghidradb_with_comment_at_addr(offset_of_entrypoint_of_current_function_which_is_being_hooked,commentstr_to_add_to_ghidradb)
        
            if (caller_has_been_identified_in_our_module)
            {
                //update backtrace address to indicate where it calls
                var offset_of_entrypoint_of_current_function_which_is_being_hooked_as_num=offset_of_entrypoint_of_current_function_which_is_being_hooked.toInt32() // we know that it is a small number
                var ghidra_addr_str_for_current_function_which_is_being_hooked="0x"+(ghidra_base_of_module_to_hook+offset_of_entrypoint_of_current_function_which_is_being_hooked_as_num).toString(16)
                var function_data_for_function_that_is_hooked=extract_function_info_from_address_for_our_module(entrypoint_of_current_function_which_is_being_hooked)
                if (function_data_for_function_that_is_hooked!=null)
                {
                    var current_hooked_function_name=function_data_for_function_that_is_hooked.fun_name
                    commentstr_to_add_to_ghidradb="Calls "+current_hooked_function_name+" at ghidra address "+ghidra_addr_str_for_current_function_which_is_being_hooked+" and offset "+offset_of_entrypoint_of_current_function_which_is_being_hooked_as_hex_str+ " of curent module\n";
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


