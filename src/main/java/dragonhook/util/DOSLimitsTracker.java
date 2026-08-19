package dragonhook.util;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;

public class DOSLimitsTracker {

    //Keyed by Address, not by CodeUnit. Ghidra hands out DB backed CodeUnit objects from an evictable
    //cache and they do not define value based equals/hashCode, so once an entry had been evicted a second
    //lookup for the SAME address produced a key that did not match the stored one and the limit silently
    //stopped counting. Address has well defined equality, and it also stops these static maps from pinning
    //database objects in memory for the life of the tool.

    public static long allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET; //per codeunit
    public static Map<Address,Integer> map_of_codeunits_for_which_function_data_have_been_returned;
    public static long allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART; 
    public static long number_of_times_ALL_FUN_DATA_SORTED_BY_RANGESTART_has_been_called;
    public static long max_comments_per_codeunit_for_each_agent_run;
    public static Map<Address,Integer> map_of_codeunits_that_are_updated_with_comment;
    public static long max_xrefs_per_codeunit_for_each_agent_run;
    public static Map<Address,Integer> map_of_codeunits_that_are_updated_with_xref;
    public static long allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET;
    public static Map<Address,Integer> map_of_codeunits_for_which_codeunit_data_has_been_returned;
    public static long allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB; 
    public static long number_of_times_CHANGE_BYTES_INSIDE_GHIDRADB_has_been_called;
    
    
    //Defaults, used whenever the config file does not carry the setting. These mirror the shipped
    //DragonHook_plugin_config.json.
    public static final long default_allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET=15;
    public static final long default_allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART=15;
    public static final long default_max_comments_per_codeunit=15;
    public static final long default_max_xrefs_per_codeunit=15;
    public static final long default_allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET=10;
    public static final long default_allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB=0;


    //A DOS limit read straight out of the config with Long.parseLong((String) map.get(key)) throws
    //NumberFormatException the moment the key is absent, because parseLong(null) throws. That exception is
    //not caught by the agent runner, so it escaped the Task and the agent simply never started.
    //CreatorOfNecessaryFiles only writes the config file when it is MISSING, so the day a new limit is
    //added every existing user's config would break in exactly that way. Falling back to the default and
    //saying so keeps an older config working.
    private static long return_limit_from_config(Map<String, Object> json_map_with_config,
                                                 String name_of_setting, long default_value)
    {
        Object raw_value=(json_map_with_config==null) ? null : json_map_with_config.get(name_of_setting);
        if (raw_value==null)
        {
            System.out.println("DragonHook: the config setting "+name_of_setting+" is missing, using the"
                    +" default of "+default_value+". Add it to the config file, or reset the config files"
                    +" from the right click menu, to silence this.");
            return default_value;
        }
        try
        {
            //the shipped config stores these as JSON strings, but tolerate a bare number too
            if (raw_value instanceof Number)
            {
                return ((Number) raw_value).longValue();
            }
            return Long.parseLong(((String) raw_value).trim());
        }
        catch (Exception e)
        {
            System.out.println("DragonHook: the config setting "+name_of_setting+" has the unusable value \""
                    +raw_value+"\", using the default of "+default_value+" instead.");
            return default_value;
        }
    }


    public static void reset_DOS_limits()
    {
        initialize_max_limits_from_config();
        //the counters themselves, which is what makes this "reset" rather than "load"
        map_of_codeunits_for_which_function_data_have_been_returned= new HashMap<Address,Integer>();
        number_of_times_ALL_FUN_DATA_SORTED_BY_RANGESTART_has_been_called=0;
        map_of_codeunits_that_are_updated_with_comment= new HashMap<Address,Integer>();
        map_of_codeunits_that_are_updated_with_xref= new HashMap<Address,Integer>();
        map_of_codeunits_for_which_codeunit_data_has_been_returned=new HashMap<Address,Integer>();
        number_of_times_CHANGE_BYTES_INSIDE_GHIDRADB_has_been_called=0;
    }

    public static void initialize_max_limits_from_config()
    {
        Map<String, Object> json_map_with_config=ConfigFileParser.extract_config_file_as_map();
        allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET = return_limit_from_config(json_map_with_config,
                "DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_FUN_DATA_GIVEN_ADDR_OFFSET", default_allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET);
        allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART = return_limit_from_config(json_map_with_config,
                "DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_ALL_FUN_DATA_SORTED_BY_RANGESTART", default_allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART);
        max_comments_per_codeunit_for_each_agent_run= return_limit_from_config(json_map_with_config,
                "DOS_LIMIT_PER_AGENT_RUN_MAX_COMMENTS_TO_BE_SET_PER_CODEUNIT", default_max_comments_per_codeunit);
        max_xrefs_per_codeunit_for_each_agent_run= return_limit_from_config(json_map_with_config,
                "DOS_LIMIT_PER_AGENT_RUN_MAX_XREFS_TO_BE_SET_PER_CODEUNIT", default_max_xrefs_per_codeunit);
        allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET=return_limit_from_config(json_map_with_config,
                "DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_CODEUNIT_DATA_GIVEN_ADDR_OFFSET", default_allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET);
        allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB=return_limit_from_config(json_map_with_config,
                "DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_CHANGE_BYTES_INSIDE_GHIDRADB", default_allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB);
    }
}
