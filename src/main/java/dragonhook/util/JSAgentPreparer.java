package dragonhook.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import ghidra.program.model.listing.Program;

public class JSAgentPreparer {
    
    public static boolean agent_has_been_updated_with_current_program=false;


    //not the most efficient when called multiple times, but it is concise 
    public static void change_specific_line_in_agent_file(String linefrom_contents, String lineto_contents, boolean completely_replace_line)
    {
        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Path path_for_agent_file = path_for_dragonhook_dir.resolve(CreatorOfNecessaryFiles.agent_file_name);
        String path_for_agent_as_str=path_for_agent_file.toString();
        File file = new File(path_for_agent_as_str);
        
        List<String> lines=null;
        try {
            lines = Files.readAllLines(Paths.get(path_for_agent_as_str));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).contains(linefrom_contents)) {
                if (completely_replace_line)
                {
                    lines.set(i,lineto_contents);
                }
                else
                {
                    lines.set(i,  lines.get(i).replace(linefrom_contents, lineto_contents));
                }
                break;
            }
        }
    
        try {
            Files.write(Paths.get(path_for_agent_as_str), lines);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    
    public static void prepare_agent_file_if_not_already_prepared(Program current_program)
    {
        if (!agent_has_been_updated_with_current_program && current_program!=null) 
        {
            prepare_agent_file(current_program);
            agent_has_been_updated_with_current_program=true;
        }
    }
    
    public static void prepare_agent_file(Program current_program)
    {
        //let's also create a variable that satisfies the module name according to the Frida Hook Generator
        String characters_allowed_in_module_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String current_program_name_sanitized=current_program.getName().replaceAll("[^"+characters_allowed_in_module_name+"]", "_");
        change_specific_line_in_agent_file("var module_name_to_hook='",
                "var module_name_to_hook='"+current_program.getName()+"'; var ghidra_base_of_module_to_hook=0x"+Long.toHexString(current_program.getImageBase().getOffset())+"; // UPDATED FROM DRAGONHOOK PLUGIN\n"
                + "var module_name_"+current_program_name_sanitized+"=module_name_to_hook;\n",
                true);
        //This anchor is the SHORT prefix of the line, and the line is replaced WHOLE, so that preparing the
        //same agent file a second time still works. It used to match the full original line and patch it
        //by substring, which meant that once the line had been patched for one program the anchor no
        //longer matched at all - the second preparation silently did nothing, leaving the previous
        //program's alias being assigned here. That only became reachable when DragonHookPlugin started
        //re-preparing the agent on a program switch; before that the agent was only ever prepared once,
        //against a freshly written file.
        //The replacement deliberately keeps this prefix intact, which is what makes the anchor survive.
        change_specific_line_in_agent_file("module_name_to_hook=module.name; modulename_to_stalk=module.name;",
                "            module_name_to_hook=module.name; modulename_to_stalk=module.name; module_name_"+current_program_name_sanitized+"=module_name_to_hook; //Update the variables to the proper case if needed , UPDATED FROM DRAGONHOOK PLUGIN",
                true);
    }
        
    
    
    public static void set_dynamic_call_offsets_in_agent(String dictionary_with_dynamic_call_offsets_as_str)
    {
        
        change_specific_line_in_agent_file("var offsets_of_dynamic_calls=",
                "var offsets_of_dynamic_calls="+dictionary_with_dynamic_call_offsets_as_str+";",
                true);

    }
    
    //lets the custom backtracer answer "did a computed call bring us here" from a baked in table,
    //instead of asking ghidra at runtime and blocking the hooked thread until the reply arrives
    public static void enable_precomputed_offsets_after_computed_calls(String dictionary_with_offsets_as_str)
    {
        change_specific_line_in_agent_file("var offsets_right_after_a_computed_call=",
                "var offsets_right_after_a_computed_call="+dictionary_with_offsets_as_str+";",
                true);
        change_specific_line_in_agent_file("var precomputed_offsets_after_computed_calls_are_available=",
                "var precomputed_offsets_after_computed_calls_are_available=true; // UPDATED FROM DRAGONHOOK PLUGIN",
                true);
    }

    //When only our own module is stalked, every other module is excluded from Stalker. That is much
    //cheaper, but code executing in another module is then run natively, so nothing it does is observed
    //and a dynamic call into it resolves to the return continuation instead of the callee.
    public static void set_whether_only_our_module_is_stalked(boolean only_our_module_is_stalked)
    {
        change_specific_line_in_agent_file("var stalker_exclude_everything_except_our_module=",
                "var stalker_exclude_everything_except_our_module="
                +(only_our_module_is_stalked ? "true" : "false")
                +"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
    }

    public static void set_name_of_threads_to_be_stalked(String str_that_must_be_included_in_thread_names)
    {
        change_specific_line_in_agent_file("var there_is_a_restriction_for_the_thread_name_for_stalker=",
                "var there_is_a_restriction_for_the_thread_name_for_stalker=true;//",false);
        change_specific_line_in_agent_file("var str_to_be_included_in_thread_name_for_stalker=",
                "var str_to_be_included_in_thread_name_for_stalker=\""+str_that_must_be_included_in_thread_names+"\";//",false);
    }
    
    
    //The agent has always carried these two variables, marked "UPDATED FROM DRAGONHOOK PLUGIN", but
    //nothing ever wrote them, so the watchpoint thread filter was permanently off. A watchpoint has to be
    //installed on EVERY thread separately, and each cross thread install needs the OS to grant access to
    //that thread, so restricting the set of threads is worth having.
    public static void set_name_of_threads_for_watchpoints(String str_that_must_be_included_in_thread_names)
    {
        change_specific_line_in_agent_file("var there_is_a_restriction_for_the_thread_name_for_watchpoints=",
                "var there_is_a_restriction_for_the_thread_name_for_watchpoints=true;//",false);
        change_specific_line_in_agent_file("var str_to_be_included_in_thread_name_for_watchpoints=",
                "var str_to_be_included_in_thread_name_for_watchpoints=\""+str_that_must_be_included_in_thread_names+"\";//",false);
    }


    public static void enable_stalking_of_dynamic_calls()
    {
        change_specific_line_in_agent_file("var dynamic_call_stalking_is_enabled=",
                "var dynamic_call_stalking_is_enabled=true; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        change_specific_line_in_agent_file("//DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE",
                "//DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE\n    begin_stalking_as_soon_as_module_is_found();", true);
    }
    
    public static void set_boolean_variable_for_dynamic_call_stalking_to_use_builtin_method(String incoming_var)
    {
        change_specific_line_in_agent_file("var dynamic_call_stalking_to_use_builtin_method=",
                "var dynamic_call_stalking_to_use_builtin_method="+incoming_var+"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
    }
    
    
    public static void config_bulk_retrieval_of_function_data(String incoming_var)
    {
        change_specific_line_in_agent_file("var fetch_function_data_in_bulk_at_first=",
                "var fetch_function_data_in_bulk_at_first="+incoming_var+"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
     
        if (incoming_var.equals("true"))
        {
            change_specific_line_in_agent_file("// DRAGONHOOK PREPARATION STEPS BEFORE REGISTERING OBSERVERS GO HERE",
                    "// DRAGONHOOK PREPARATION STEPS BEFORE REGISTERING OBSERVERS GO HERE\nget_full_function_data_by_ranges();", true);
        }
    }
    
    public static void set_number_of_logged_dynamic_calls(String incoming_var)
    {
        change_specific_line_in_agent_file("var maximum_times_to_log_call_target=",
                "var maximum_times_to_log_call_target="+incoming_var+"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
    }


    public static void enable_hardware_watchpoint_logging(String max_times_to_log_watchpoints)
    {
        change_specific_line_in_agent_file("var setting_of_watchpoints_is_enabled=",
                "var setting_of_watchpoints_is_enabled=true; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        change_specific_line_in_agent_file("var max_times_each_watchpoint_is_logged=",
                "var max_times_each_watchpoint_is_logged="+max_times_to_log_watchpoints+"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        
    }

    public static void set_array_of_watchpoints(String incoming_object_with_watchpoints)
    {
        change_specific_line_in_agent_file("var array_of_objects_for_which_to_install_watchpoints=",
                "var array_of_objects_for_which_to_install_watchpoints="+incoming_object_with_watchpoints+"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
    }


    
    public static void enable_string_reference_resolution(String js_object_with_strings_to_resolve,
                                                         String max_times_to_log_each_reference,
                                                         boolean also_instrument_register_based_memory_accesses,
                                                         boolean also_instrument_call_arguments,
                                                         boolean also_instrument_register_arithmetic,
                                                         boolean stalk_other_modules)
    {
        change_specific_line_in_agent_file("var string_reference_resolution_is_enabled=",
                "var string_reference_resolution_is_enabled=true; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        change_specific_line_in_agent_file("var strings_to_resolve_compact=",
                "var strings_to_resolve_compact="+js_object_with_strings_to_resolve+";", true);
        change_specific_line_in_agent_file("var max_times_to_log_each_string_reference=",
                "var max_times_to_log_each_string_reference="+max_times_to_log_each_reference+"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        change_specific_line_in_agent_file("var also_instrument_register_based_memory_accesses=",
                "var also_instrument_register_based_memory_accesses="
                +(also_instrument_register_based_memory_accesses ? "true" : "false")
                +"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        change_specific_line_in_agent_file("var string_refs_instrument_call_arguments=",
                "var string_refs_instrument_call_arguments="
                +(also_instrument_call_arguments ? "true" : "false")
                +"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        change_specific_line_in_agent_file("var string_refs_instrument_register_arithmetic=",
                "var string_refs_instrument_register_arithmetic="
                +(also_instrument_register_arithmetic ? "true" : "false")
                +"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        change_specific_line_in_agent_file("var string_refs_stalk_other_modules=",
                "var string_refs_stalk_other_modules="
                +(stalk_other_modules ? "true" : "false")
                +"; // UPDATED FROM DRAGONHOOK PLUGIN", true);

        //the string table only becomes usable once the module base is known
        change_specific_line_in_agent_file("//DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE",
                "//DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE\n    begin_stalking_as_soon_as_module_is_found();", true);
    }


    //"0" keeps the register based tier on for the whole session
    public static void set_seconds_before_register_based_string_instrumentation_is_dropped(String seconds)
    {
        change_specific_line_in_agent_file("var seconds_before_register_based_instrumentation_is_dropped=",
                "var seconds_before_register_based_instrumentation_is_dropped="+seconds
                +"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
    }


    public static void enable_call_tracing_through_stalker(boolean only_include_functions_in_our_own_module)
    {
        change_specific_line_in_agent_file("var call_tracing_through_stalker_is_enabled=",
                "var call_tracing_through_stalker_is_enabled=true; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        
        change_specific_line_in_agent_file("//DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE",
                "//DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE\n    begin_stalking_as_soon_as_module_is_found();", true);
        
        if (only_include_functions_in_our_own_module)
        {
            change_specific_line_in_agent_file("var call_tracing_ignore_callrets_outside_our_module=",
                    "var call_tracing_ignore_callrets_outside_our_module=true; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        }
        else
        {
            change_specific_line_in_agent_file("var call_tracing_ignore_callrets_outside_our_module=",
                    "var call_tracing_ignore_callrets_outside_our_module=false; // UPDATED FROM DRAGONHOOK PLUGIN", true);
        }
        
    }
    
    //Lets call tracing start before the examined module exists. Only meaningful together with an
    //unfiltered trace, because the "ignore call/rets outside our module" filter is the only thing in the
    //agent's receiver that needs the module's bounds. The dialog enforces that dependency, and the agent
    //checks it again in is_early_call_tracing_active().
    public static void set_call_tracing_before_our_module_is_loaded(boolean trace_before_the_module_is_loaded)
    {
        change_specific_line_in_agent_file("var call_tracing_before_our_module_is_loaded=",
                "var call_tracing_before_our_module_is_loaded="
                +(trace_before_the_module_is_loaded ? "true" : "false")
                +"; // UPDATED FROM DRAGONHOOK PLUGIN", true);
    }


    public static void add_custom_hooks(String custom_hooks_to_add)
    {
        change_specific_line_in_agent_file("//DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE",
                "//DRAGONHOOK CODE GOES HERE, DO NOT REMOVE THIS LINE\n"+custom_hooks_to_add+";", true);
    }
    



}
