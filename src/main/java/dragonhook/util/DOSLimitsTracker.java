package dragonhook.util;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.CodeUnit;

public class DOSLimitsTracker {

    public static long allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET; //per codeunit
    public static Map<CodeUnit,Integer> map_of_codeunits_for_which_function_data_have_been_returned;
    public static long allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART; 
    public static long number_of_times_ALL_FUN_DATA_SORTED_BY_RANGESTART_has_been_called;
    public static long max_comments_per_codeunit_for_each_agent_run;
    public static Map<CodeUnit,Integer> map_of_codeunits_that_are_updated_with_comment;
    public static long max_xrefs_per_codeunit_for_each_agent_run;
    public static Map<CodeUnit,Integer> map_of_codeunits_that_are_updated_with_xref;
    public static long allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET;
    public static Map<CodeUnit,Integer> map_of_codeunits_for_which_codeunit_data_has_been_returned;
    public static long allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB; 
    public static long number_of_times_CHANGE_BYTES_INSIDE_GHIDRADB_has_been_called;
    
    
    public static void reset_DOS_limits()
    {
        Map<String, Object> json_map_with_config=ConfigFileParser.extract_config_file_as_map();
       
        allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET = Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_FUN_DATA_GIVEN_ADDR_OFFSET"));
        map_of_codeunits_for_which_function_data_have_been_returned= new HashMap<CodeUnit,Integer>();
        allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART = Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_ALL_FUN_DATA_SORTED_BY_RANGESTART"));
        number_of_times_ALL_FUN_DATA_SORTED_BY_RANGESTART_has_been_called=0;
        max_comments_per_codeunit_for_each_agent_run= Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_MAX_COMMENTS_TO_BE_SET_PER_CODEUNIT"));
        map_of_codeunits_that_are_updated_with_comment= new HashMap<CodeUnit,Integer>();
        max_xrefs_per_codeunit_for_each_agent_run= Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_MAX_XREFS_TO_BE_SET_PER_CODEUNIT"));
        map_of_codeunits_that_are_updated_with_xref= new HashMap<CodeUnit,Integer>();
        allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET=Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_CODEUNIT_DATA_GIVEN_ADDR_OFFSET"));
        map_of_codeunits_for_which_codeunit_data_has_been_returned=new HashMap<CodeUnit,Integer>();
        allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB=Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_CHANGE_BYTES_INSIDE_GHIDRADB"));
        number_of_times_CHANGE_BYTES_INSIDE_GHIDRADB_has_been_called=0;
    }
    
    public static void initialize_max_limits_from_config()
    {
        Map<String, Object> json_map_with_config=ConfigFileParser.extract_config_file_as_map();
        allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET = Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_FUN_DATA_GIVEN_ADDR_OFFSET"));
        allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART = Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_ALL_FUN_DATA_SORTED_BY_RANGESTART"));
        max_comments_per_codeunit_for_each_agent_run= Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_MAX_COMMENTS_TO_BE_SET_PER_CODEUNIT"));
        max_xrefs_per_codeunit_for_each_agent_run= Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_MAX_XREFS_TO_BE_SET_PER_CODEUNIT"));
        allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET=Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_CODEUNIT_DATA_GIVEN_ADDR_OFFSET"));
        allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB=Long.parseLong((String) json_map_with_config.get("DOS_LIMIT_PER_AGENT_RUN_ALLOWED_CALLS_FOR_CHANGE_BYTES_INSIDE_GHIDRADB"));
    }
}
