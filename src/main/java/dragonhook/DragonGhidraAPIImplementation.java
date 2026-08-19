package dragonhook;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dragonhook.util.DOSLimitsTracker;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.MemReferenceImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

public class DragonGhidraAPIImplementation {

    protected PluginTool tool;
    //volatile: written from the SWING thread by set_current_program() when the user switches program, read
    //by the HTTP server's dispatcher thread on every request. Without it there is no guarantee the server
    //thread ever observes the new program, which would silently defeat the whole retargeting mechanism -
    //the server would keep writing into the database of the program that was open when it started.
    protected volatile Program current_program;
    protected Plugin incoming_plugin;
    long max_displacement;
    //https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/RefType.html
    String[] valid_reftypes_as_strings= {"CALL_OVERRIDE_UNCONDITIONAL","CALL_TERMINATOR","CALLOTHER_OVERRIDE_CALL","CALLOTHER_OVERRIDE_JUMP","COMPUTED_CALL","COMPUTED_CALL_TERMINATOR","COMPUTED_JUMP","CONDITIONAL_CALL","CONDITIONAL_CALL_TERMINATOR","CONDITIONAL_COMPUTED_CALL","CONDITIONAL_COMPUTED_JUMP","CONDITIONAL_JUMP","CONDITIONAL_TERMINATOR","DATA","EXTERNAL_REF","FALL_THROUGH","FLOW","INDIRECTION","INVALID","JUMP_OVERRIDE_UNCONDITIONAL","JUMP_TERMINATOR","PARAM","READ","READ_IND","READ_WRITE","READ_WRITE_IND","TERMINATOR","THUNK","UNCONDITIONAL_CALL","UNCONDITIONAL_JUMP","WRITE","WRITE_IND"};
    RefType[] valid_reftypes= {RefType.CALL_OVERRIDE_UNCONDITIONAL,RefType.CALL_TERMINATOR,RefType.CALLOTHER_OVERRIDE_CALL,RefType.CALLOTHER_OVERRIDE_JUMP,RefType.COMPUTED_CALL,RefType.COMPUTED_CALL_TERMINATOR,RefType.COMPUTED_JUMP,RefType.CONDITIONAL_CALL,RefType.CONDITIONAL_CALL_TERMINATOR,RefType.CONDITIONAL_COMPUTED_CALL,RefType.CONDITIONAL_COMPUTED_JUMP,RefType.CONDITIONAL_JUMP,RefType.CONDITIONAL_TERMINATOR,RefType.DATA,RefType.EXTERNAL_REF,RefType.FALL_THROUGH,RefType.FLOW,RefType.INDIRECTION,RefType.INVALID,RefType.JUMP_OVERRIDE_UNCONDITIONAL,RefType.JUMP_TERMINATOR,RefType.PARAM,RefType.READ,RefType.READ_IND,RefType.READ_WRITE,RefType.READ_WRITE_IND,RefType.TERMINATOR,RefType.THUNK,RefType.UNCONDITIONAL_CALL,RefType.UNCONDITIONAL_JUMP,RefType.WRITE,RefType.WRITE_IND};

    
    //The HTTP server's handlers capture this object when the contexts are created, so when the user switches
    //program in Ghidra the running server has to be retargeted or it keeps serving the old one - writing
    //comments and xrefs into the wrong database. Called from DragonStartHTTPServerAction.
    public void set_current_program(Program incoming_program)
    {
        this.current_program=incoming_program;
    }

    public DragonGhidraAPIImplementation(Plugin plugin, Program current_program) {
        this.tool = plugin.getTool();
        this.current_program = current_program;
        this.incoming_plugin=plugin;
        this.max_displacement=2000000000;
    }
    
    //String.replaceAll() compiles its pattern on every single call. These run once per function (and
    //once per range, per comment, per instruction), so on a large program that was tens of thousands
    //of Pattern compilations of a fairly long character class. Compile them once instead.
    private static final Pattern pattern_for_variable_name=
            Pattern.compile("[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_]");
    private static final Pattern pattern_for_instruction_text=
            Pattern.compile("[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_\\ \\,\\!\\+\\-\\#\\[\\]\\:\\.\\(\\)\\~\\$]");
    //"<" and ">" are allowed so that C++ template names survive: foo<int> used to become foo_int_, which
    //does not match anything the user sees in ghidra. They are safe here because a function name only ever
    //travels inside a JSON string (parsed with JSON.parse on the agent side, so markup means nothing) and
    //into a ghidra listing comment, which is plain text and not HTML. The characters that WOULD matter are
    //the quote, the backslash and the pipe - the quote and backslash would break the JSON, and the pipe
    //would break the |||DH_GHIDRA_API_CALL||| framing - and this is a whitelist, so all three stay excluded.
    private static final Pattern pattern_for_function_name=
            Pattern.compile("[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_\\~\\:\\$\\<\\>]");

    public static String sanitize_str(String incoming_str)
    {
        if (incoming_str==null) { return ""; }
        return pattern_for_variable_name.matcher(incoming_str).replaceAll("_");
    }

    public static String sanitize_instruction_text(String incoming_str)
    {
        if (incoming_str==null) { return ""; }
        return pattern_for_instruction_text.matcher(incoming_str).replaceAll("_");
    }

    public static String sanitize_comment(String incoming_str)
    {
        return sanitize_instruction_text(incoming_str); //sanitize_instruction_text() is fine in this case
    }

    public static String sanitize_fun_name(String incoming_str)
    {
        if (incoming_str==null) { return ""; }
        return pattern_for_function_name.matcher(incoming_str).replaceAll("_");
    }
    
    public static String return_offset_for_addr(Address in_addr, Program current_program) {
        return "0x"+Long.toHexString(in_addr.getOffset() - current_program.getImageBase().getOffset());
    }
    
    public static boolean is_computed_jump_or_computed_call(Instruction instr)
    {
        FlowType flowType = instr.getFlowType();

        // Only check instructions that are CALL or JUMP
        if (flowType.isCall() || flowType.isJump()) 
        {
           if (flowType.isComputed())           
           {
               return true;
           }
        }
        return false;
    }
    
    public String make_sure_address_offset_is_valid(long address_offset)
    {
        if (address_offset<0 || address_offset>this.max_displacement)
        {
            return "Error, abnormal value for address offset: "+ address_offset;
        }
        
        Listing program_listing=this.current_program.getListing();
        Address image_base = this.current_program.getImageBase();
        Address max_addr=this.current_program.getMaxAddress();
        Address min_addr=this.current_program.getMinAddress();

        //Address.add() throws AddressOutOfBoundsException when the sum leaves the address space.
        //max_displacement allows offsets up to 2e9, so this is reachable on a program whose image
        //base sits high in a 32 bit space. Uncaught it would kill the endpoint handler, and the
        //http server closes the exchange without a reply, leaving the caller waiting.
        Address target_addr;
        try
        {
            target_addr=image_base.add(address_offset);
        }
        catch (Exception e)
        {
            return "Error, target address outside the range of valid addresses";
        }

        if (target_addr.compareTo(min_addr)<0 || target_addr.compareTo(max_addr)>0)
        {
            return "Error, target address outside the range of valid addresses";
        }

        return "ok";
    }
    
    
    public boolean is_reftype_valid(String candidate_reftype)
    {
        return Arrays.asList(this.valid_reftypes_as_strings).contains(candidate_reftype);
    }
    
    public int return_corresponding_number_for_reftype_in_list_of_valid_ones(String candidate_reftype)
    {
        return Arrays.asList(this.valid_reftypes_as_strings).indexOf(candidate_reftype);
    }
    
    public RefType return_corresponding_reftype_from_candidate_reftype_str(String candidate_reftype)
    {
        if (!is_reftype_valid(candidate_reftype))
        {
            return null;
        }
        int idx=return_corresponding_number_for_reftype_in_list_of_valid_ones(candidate_reftype);
        return this.valid_reftypes[idx];
    }
    
    
    
    
    public String FUN_DATA_GIVEN_ADDR_OFFSET(long address_offset, boolean apply_DOS_limits)
    {
        String retval="";
        if (this.current_program==null)
        {
            return "Error, current Program is null";
        }
        
        String check=make_sure_address_offset_is_valid(address_offset);
        if (!check.equals("ok"))
        {
            return check;
        }

        Listing program_listing=this.current_program.getListing();
        Address image_base = this.current_program.getImageBase();
        Address target_addr=image_base.add(address_offset);
        

        Function function_to_return=program_listing.getFunctionContaining(target_addr);
        if (function_to_return==null)
        {
            return "Error, address does not fall inside known function";
        }
        
        CodeUnit target_codeunit= program_listing.getCodeUnitContaining(target_addr);
        
        if (target_codeunit==null)
        {
            return "Error, target codeunit is null";
        }
        
        
        //check for limits
        if (apply_DOS_limits)
        {
            if (DOSLimitsTracker.allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET==0)
            {
                return "Error, maximum allowed times to call the FUN_DATA_GIVEN_ADDR_OFFSET is 0";
            }
            
            if (DOSLimitsTracker.map_of_codeunits_for_which_function_data_have_been_returned.containsKey(target_codeunit.getMinAddress()))
            {
                int times_returned=DOSLimitsTracker.map_of_codeunits_for_which_function_data_have_been_returned.get(target_codeunit.getMinAddress());
                if (times_returned<DOSLimitsTracker.allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET)
                {
                    DOSLimitsTracker.map_of_codeunits_for_which_function_data_have_been_returned.put(target_codeunit.getMinAddress(),times_returned+1);
                }
                else
                {
                    return "Error, reached  maximum allowed times to call the FUN_DATA_GIVEN_ADDR_OFFSET for this function for this agent run";
                }
            }
            else
            {
                DOSLimitsTracker.map_of_codeunits_for_which_function_data_have_been_returned.put(target_codeunit.getMinAddress(),1);
            }
        }
        
        
        
        String name_of_fun=sanitize_fun_name(function_to_return.getName(true));
        Address start_of_fun=function_to_return.getEntryPoint();
        String start_of_fun_offset=return_offset_for_addr(start_of_fun,current_program);
        int number_of_params=function_to_return.getParameterCount();
        String calling_convention=sanitize_str(function_to_return.getCallingConventionName());
        String function_signature_as_str=sanitize_str(function_to_return.getSignature().toString());
        retval+="{\"fun_name\":\""+name_of_fun+"\",\"entrypoint_offset\":\""+start_of_fun_offset+"\",";
        retval+="\"num_of_params\":"+number_of_params+",\"calling_convention\":\""+calling_convention+"\",";
        retval+="\"fun_signature\":\""+function_signature_as_str+"\",\"ranges\":[";
        
        AddressRangeIterator current_function_ranges_iter= function_to_return.getBody().getAddressRanges(true);
        while (current_function_ranges_iter!=null && current_function_ranges_iter.hasNext())
        {
            AddressRange current_function_range=current_function_ranges_iter.next();
            String start_of_range_offset=return_offset_for_addr(current_function_range.getMinAddress(),current_program);
            String end_of_range_offset=return_offset_for_addr(current_function_range.getMaxAddress(),current_program);
            String addcomma=",";
            if (current_function_ranges_iter.hasNext()==false)
            {
                addcomma="";
            }
            retval+="[\""+start_of_range_offset+"\",\""+end_of_range_offset+"\"]"+addcomma;
        }
        retval+="]}";
        
        return retval;
    }
    
    //computationally intensive, but it will be called at most once per agent execution.
    //
    //The JS agent binary-searches the "ranges" array, so it MUST be globally sorted by range start.
    //Iterating the functions by entry point does NOT give that ordering, because a function body can
    //be non-contiguous: function A at 0x1000 may own a range at 0x5000 while function B starts at
    //0x2000, so the naive emission order is 0x1000, 0x5000, 0x2000. Hence the explicit sort below.
    //
    //Only the two fields the agent actually consumes (fun_name / entrypoint_offset) are sent, and
    //they are sent ONCE per function instead of once per range. Range bounds are plain numbers so
    //that the agent does not have to parseInt() a hex string on every binary-search comparison.
    //
    //returns an object of the form:
    /*
        {"function_ranges_compact":{
            "functions":[ ["FUN_0060d8c0","0x50d8c0"], ["FUN_0060d920","0x50d920"], [...] ],
            "ranges":[ [5298880,5298898,0], [5299000,5299016,1], [5299032,5299046,1], [...] ]
        }}
        each range is [start_offset, end_offset_inclusive, index_into_functions]
     */

    public String ALL_FUN_DATA_SORTED_BY_RANGESTART()
    {
        //This check was missing while every other endpoint had it, and closing a program while an agent runs
        //made the line below throw a NullPointerException INSIDE the http handler. The handler then never
        //called provide_httpserver_reply(), the exchange was never closed, and the agent's blocking
        //recv().wait() never got a reply - hanging that target thread for the life of the process.
        if (this.current_program==null)
        {
            return "Error, current Program is null";
        }

        //The per-agent-run call limit is enforced HERE as well as in the endpoint, so that the limit cannot
        //be bypassed by any other caller of this method.
        if (DOSLimitsTracker.allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART<=0)
        {
            return "The ALL_FUN_DATA_SORTED_BY_RANGESTART endpoint is not allowed to be called.";
        }
        if (DOSLimitsTracker.number_of_times_ALL_FUN_DATA_SORTED_BY_RANGESTART_has_been_called
                >DOSLimitsTracker.allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART)
        {
            return "The ALL_FUN_DATA_SORTED_BY_RANGESTART endpoint has reached the maximum amount of times to be called per agent execution.";
        }

        long time_at_start=System.nanoTime();
        long image_base_offset=current_program.getImageBase().getOffset();
        long number_of_functions_below_the_image_base=0;
        ArrayList<String> function_entries=new ArrayList<String>();   //index -> ["name","0xentrypoint"]
        ArrayList<long[]> range_entries=new ArrayList<long[]>();      //{start, end, index into function_entries}

        FunctionIterator fun_iter = current_program.getFunctionManager().getFunctions(true);
        while (fun_iter!=null && fun_iter.hasNext())
        {
            Function current_function=fun_iter.next();
            String name_of_fun=sanitize_fun_name(current_function.getName(true));
            //A program can hold memory blocks BELOW its image base, which makes the offset negative.
            //Long.toHexString() then renders it as sixteen hex digits starting with f, the agent does
            //ptr() on that and gets an enormous value, and every "function+delta" it prints in a comment is
            //nonsense. Skip such a function rather than emit an entry that can only mislead.
            long entrypoint_offset_of_function=current_function.getEntryPoint().getOffset() - image_base_offset;
            if (entrypoint_offset_of_function<0)
            {
                number_of_functions_below_the_image_base+=1;
                continue;
            }
            //inlined instead of return_offset_for_addr(), which re-reads the image base every call
            String start_of_fun_offset="0x"+Long.toHexString(entrypoint_offset_of_function);
            int index_of_this_function=function_entries.size();
            function_entries.add("[\""+name_of_fun+"\",\""+start_of_fun_offset+"\"]");

            AddressRangeIterator current_function_ranges_iter= current_function.getBody().getAddressRanges(true);
            while (current_function_ranges_iter!=null && current_function_ranges_iter.hasNext())
            {
                AddressRange current_function_range=current_function_ranges_iter.next();
                long start_offset_of_range=current_function_range.getMinAddress().getOffset() - image_base_offset;
                long end_offset_of_range=current_function_range.getMaxAddress().getOffset() - image_base_offset;
                if (start_offset_of_range<0 || end_offset_of_range<0)
                {
                    continue;   //same reason as the entry point above
                }
                range_entries.add(new long[]{start_offset_of_range,end_offset_of_range,index_of_this_function});
            }
        }

        //required by the binary search on the agent side, see the comment above
        Collections.sort(range_entries, new Comparator<long[]>() {
            @Override
            public int compare(long[] first_range, long[] second_range) {
                return Long.compare(first_range[0], second_range[0]);
            }
        });

        long time_after_gathering=System.nanoTime();

        //preallocate, otherwise the builder doubles its backing array around twenty times and copies
        //the whole multi megabyte string each time. ~48 bytes per function entry, ~28 per range.
        StringBuilder sb=new StringBuilder(64 + function_entries.size()*48 + range_entries.size()*28);
        sb.append("{\"function_ranges_compact\":{\"functions\":[");
        for (int i=0;i<function_entries.size();i++)
        {
            if (i>0) { sb.append(","); }
            sb.append(function_entries.get(i));
        }
        sb.append("],\"ranges\":[");
        for (int i=0;i<range_entries.size();i++)
        {
            long[] current_range=range_entries.get(i);
            if (i>0) { sb.append(","); }
            sb.append('[').append(current_range[0]).append(',')
              .append(current_range[1]).append(',').append(current_range[2]).append(']');
        }
        sb.append("]}}");
        String retval=sb.toString();

        long time_at_end=System.nanoTime();
        if (number_of_functions_below_the_image_base>0)
        {
            System.out.println("ALL_FUN_DATA_SORTED_BY_RANGESTART: skipped "+number_of_functions_below_the_image_base
                    +" function(s) that live below the image base, because a negative module offset cannot be"
                    +" expressed in the table the agent looks up.");
        }
        System.out.println("ALL_FUN_DATA_SORTED_BY_RANGESTART: "+function_entries.size()+" functions, "
                +range_entries.size()+" ranges, "+retval.length()+" chars. Gathering from ghidra took "
                +((time_after_gathering-time_at_start)/1000000)+" ms, serialising took "
                +((time_at_end-time_after_gathering)/1000000)+" ms.");
        return retval;
    }
    
    
    public String UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR(long address_offset, String comment)
    {
        String retval="";
        if (this.current_program==null)
        {
            return "Error, current Program is null";
        }
        String check=make_sure_address_offset_is_valid(address_offset);
        if (!check.equals("ok"))
        {
            return check;
        }
        
        Listing program_listing=this.current_program.getListing();
        Address image_base = this.current_program.getImageBase();
        Address target_addr=image_base.add(address_offset);
         
        
        CodeUnit target_codeunit= program_listing.getCodeUnitContaining(target_addr);
        
        if (target_codeunit==null)
        {
            return "Error, target codeunit is null";
        }
 
        
        //check for limits
        
        if (DOSLimitsTracker.max_comments_per_codeunit_for_each_agent_run==0)
        {
            return "Error, maximum comment limit for codeunits is 0";
        }
        
        if (DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.containsKey(target_codeunit.getMinAddress()))
        {
            int times_updated=DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.get(target_codeunit.getMinAddress());
            if (times_updated<DOSLimitsTracker.max_comments_per_codeunit_for_each_agent_run)
            {
                DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.put(target_codeunit.getMinAddress(),times_updated+1);
            }
            else
            {
                return "Error, reached maximum comment update limit for this codeunit for this agent run";
            }
        }
        else
        {
            DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.put(target_codeunit.getMinAddress(),1);
        }
        
        //update the comment

        String oldcomment=target_codeunit.getComment(CommentType.PRE); //use CodeUnit.PRE_COMMENT in previous ghidra versions
        String newcomment=merge_comment_into_existing_comment(oldcomment,comment);

        try
        {
            int tx_id=current_program.startTransaction("Set comment");
            boolean transaction_succeeded=false;
            try
            {
                target_codeunit.setComment(CommentType.PRE,newcomment);
                transaction_succeeded=true;
            }
            finally
            {
                //without this, an exception would leave the transaction open on the Program
                current_program.endTransaction(tx_id, transaction_succeeded);
            }
        }
        catch (Exception e)
        {
            return "Problem during setComment() "+e;
        }
        
        retval="ok";
        return retval;
    }
    
    
    
    //Matches a line that already carries a repeat marker, so "Calls foo (x3)" is recognised as three
    //occurrences of "Calls foo" rather than as a different line.
    private static final Pattern pattern_for_repeat_marker_at_end_of_line=Pattern.compile("^(.*?)\\s*\\(x(\\d+)\\)$");

    //Appends a comment, collapsing an immediate repeat into a "(xN)" counter instead of writing the same
    //sentence again. Comments used to be appended unconditionally, so re-running a feature produced
    //byte-identical duplicates and a hot address ended up with fifteen copies of one line.
    //
    //Only the LAST line is considered, deliberately. Line order carries meaning here - the comments are a
    //chronological record of what the agent observed - so if the same text appears earlier but something
    //else has been written since, it is appended as a new line rather than merged backwards. That keeps
    //"A, B, A" distinguishable from "A (x2), B".
    public static String merge_comment_into_existing_comment(String existing_comment, String comment_to_add)
    {
        if (comment_to_add==null)
        {
            return (existing_comment==null) ? "" : existing_comment;
        }
        //the agent frequently terminates its comments with a newline
        String trimmed_comment_to_add=comment_to_add.replaceAll("[\\r\\n]+$","");
        if (existing_comment==null || existing_comment.isEmpty())
        {
            return trimmed_comment_to_add;
        }
        //A multi line addition has no single "previous line" to compare against, so merging it would be
        //guesswork. Append it as it is.
        if (trimmed_comment_to_add.contains("\n"))
        {
            return existing_comment+"\n"+trimmed_comment_to_add;
        }

        String[] existing_lines=existing_comment.split("\n",-1);
        int index_of_last_line=existing_lines.length-1;
        //tolerate a trailing empty line in what is already stored
        while (index_of_last_line>0 && existing_lines[index_of_last_line].isEmpty())
        {
            index_of_last_line-=1;
        }
        String last_line=existing_lines[index_of_last_line];

        String base_text_of_last_line=last_line;
        int times_the_last_line_already_occurred=1;
        Matcher matcher_for_repeat=pattern_for_repeat_marker_at_end_of_line.matcher(last_line);
        if (matcher_for_repeat.matches())
        {
            base_text_of_last_line=matcher_for_repeat.group(1);
            try
            {
                times_the_last_line_already_occurred=Integer.parseInt(matcher_for_repeat.group(2));
            }
            catch (NumberFormatException e)
            {
                //a literal "(x...)" that is not a counter, treat the whole line as the text
                base_text_of_last_line=last_line;
                times_the_last_line_already_occurred=1;
            }
        }

        if (!base_text_of_last_line.equals(trimmed_comment_to_add))
        {
            return existing_comment+"\n"+trimmed_comment_to_add;   //a different line, order is preserved
        }

        existing_lines[index_of_last_line]=base_text_of_last_line+" (x"+(times_the_last_line_already_occurred+1)+")";
        StringBuilder sb=new StringBuilder();
        for (int i=0;i<existing_lines.length;i++)
        {
            if (i>0) { sb.append("\n"); }
            sb.append(existing_lines[i]);
        }
        return sb.toString();
    }


    public String UPDATE_GHIDRADB_WITH_XREF(long address_offset_from,long address_offset_to, String type_of_xref, boolean apply_DOS_limits)
    {
        String retval="";
        if (this.current_program==null)
        {
            return "Error, current Program is null";
        }
        String check=make_sure_address_offset_is_valid(address_offset_from);
        if (!check.equals("ok"))
        {
            return check;
        }
        check=make_sure_address_offset_is_valid(address_offset_to);
        if (!check.equals("ok"))
        {
            return check;
        }
        
        if (!is_reftype_valid(type_of_xref))
        {
            return "Error, invalid reftype submitted";
        }
        RefType reftype_of_xref;
        try
        {
            reftype_of_xref=return_corresponding_reftype_from_candidate_reftype_str(type_of_xref);
            if (reftype_of_xref==null)
            {
                return "Error, invalid reftype submitted";
            }
        }
        catch (Exception e)
        {
            return "Error, unknown error in trying to parse reftype, "+e.toString();
        }
        
        
        Listing program_listing=this.current_program.getListing();
        ReferenceManager reference_manager=this.current_program.getReferenceManager();
        Address image_base = this.current_program.getImageBase();
        Address target_addr_from=image_base.add(address_offset_from);
        Address target_addr_to=image_base.add(address_offset_to);
        
        
        CodeUnit target_codeunit_from= program_listing.getCodeUnitContaining(target_addr_from);
        
        if (target_codeunit_from==null)
        {
            return "Error, target_codeunit_from is null";
        }
        
        CodeUnit target_codeunit_to= program_listing.getCodeUnitContaining(target_addr_to);
        
        if (target_codeunit_to==null)
        {
            return "Error, target_codeunit_to is null";
        }
 
        
        //check for limits.
        //These used to consult map_of_codeunits_that_are_updated_with_comment while comparing against
        //max_xrefs_per_codeunit_for_each_agent_run, so comments and xrefs shared ONE counter per address
        //and map_of_codeunits_that_are_updated_with_xref was never touched at all. Since every feature
        //writes a comment AND an xref for the same address, that counter was consumed twice as fast and
        //you got roughly half of each configured limit - and setting the two limits independently did
        //nothing, because whichever check reached the shared counter first won.
        if (apply_DOS_limits)
        {
            if (DOSLimitsTracker.max_xrefs_per_codeunit_for_each_agent_run==0)
            {
                return "Error, maximum xref limit for codeunits is 0";
            }
            
            if (DOSLimitsTracker.map_of_codeunits_that_are_updated_with_xref.containsKey(target_codeunit_from.getMinAddress()))
            {
                int times_updated=DOSLimitsTracker.map_of_codeunits_that_are_updated_with_xref.get(target_codeunit_from.getMinAddress());
                if (times_updated<DOSLimitsTracker.max_xrefs_per_codeunit_for_each_agent_run)
                {
                    DOSLimitsTracker.map_of_codeunits_that_are_updated_with_xref.put(target_codeunit_from.getMinAddress(),times_updated+1);
                }
                else
                {
                    return "Error, reached maximum xref update limit for target_codeunit_from for this agent run";
                }
            }
            else
            {
                DOSLimitsTracker.map_of_codeunits_that_are_updated_with_xref.put(target_codeunit_from.getMinAddress(),1);
            }
            
            if (DOSLimitsTracker.map_of_codeunits_that_are_updated_with_xref.containsKey(target_codeunit_to.getMinAddress()))
            {
                int times_updated=DOSLimitsTracker.map_of_codeunits_that_are_updated_with_xref.get(target_codeunit_to.getMinAddress());
                if (times_updated<DOSLimitsTracker.max_xrefs_per_codeunit_for_each_agent_run)
                {
                    DOSLimitsTracker.map_of_codeunits_that_are_updated_with_xref.put(target_codeunit_to.getMinAddress(),times_updated+1);
                }
                else
                {
                    return "Error, reached maximum xref update limit for target_codeunit_to for this agent run";
                }
            }
            else
            {
                DOSLimitsTracker.map_of_codeunits_that_are_updated_with_xref.put(target_codeunit_to.getMinAddress(),1);
            }
        }
        
        //update the xref
        try
        {
            MemReferenceImpl this_ref= new MemReferenceImpl(target_codeunit_from.getMinAddress(), target_codeunit_to.getMinAddress(),reftype_of_xref,SourceType.USER_DEFINED,0,false);
            int tx_id=current_program.startTransaction("Set xref");
            boolean transaction_succeeded=false;
            try
            {
                reference_manager.addReference(this_ref);
                transaction_succeeded=true;
            }
            finally
            {
                //without this, an exception would leave the transaction open on the Program
                current_program.endTransaction(tx_id, transaction_succeeded);
            }
        }
        catch (Exception e)
        {
            return "Problem during addReference() "+e;
        }
        
        retval="ok";
        return retval;
    }
    
    
    public String CODEUNIT_DATA_GIVEN_ADDR_OFFSET(long address_offset)
    {
        String retval="";
        if (this.current_program==null)
        {
            return "Error, current Program is null";
        }
        
        String check=make_sure_address_offset_is_valid(address_offset);
        if (!check.equals("ok"))
        {
            return check;
        }

        Listing program_listing=this.current_program.getListing();
        Address image_base = this.current_program.getImageBase();
        Address target_addr=image_base.add(address_offset);

        CodeUnit target_codeunit= program_listing.getCodeUnitContaining(target_addr);
        
        if (target_codeunit==null)
        {
            return "Error, target codeunit is null";
        }
        
        
        //check for limits
        
        if (DOSLimitsTracker.allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET==0)
        {
            return "Error, the endpoint CODEUNIT_DATA_GIVEN_ADDR_OFFSET is not allowed to be called";
        }
        
        if (DOSLimitsTracker.map_of_codeunits_for_which_codeunit_data_has_been_returned.containsKey(target_codeunit.getMinAddress()))
        {
            int times_returned=DOSLimitsTracker.map_of_codeunits_for_which_codeunit_data_has_been_returned.get(target_codeunit.getMinAddress());
            if (times_returned<DOSLimitsTracker.allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET)
            {
                DOSLimitsTracker.map_of_codeunits_for_which_codeunit_data_has_been_returned.put(target_codeunit.getMinAddress(),times_returned+1);
            }
            else
            {
                return "Error, reached maximum codeunit data extraction for this codeunit for this agent run";
            }
        }
        else
        {
            DOSLimitsTracker.map_of_codeunits_for_which_codeunit_data_has_been_returned.put(target_codeunit.getMinAddress(),1);
        }
        
                
        boolean is_instruction=false;
        if (target_codeunit instanceof Instruction)
        {
            is_instruction=true;
        }
        
        retval+="{";
        
        retval+="\"type_of_codeunit\":";
        
        if (is_instruction)
        {
            retval+="\"Instruction\",";
        }
        else
        {
            retval+="\"Data\",";
        }
        
        
        retval+="\"length\":\""+Integer.toString(target_codeunit.getLength())+"\",";
        retval+="\"min_addr\":\""+ return_offset_for_addr(target_codeunit.getMinAddress(),this.current_program)+"\",";
        
        int maxbytes_to_ret=100;
        byte[] bytes_of_codeunit;
        try {
            bytes_of_codeunit=target_codeunit.getBytes();
        } catch (MemoryAccessException e) {
            return "Error, memory exception when reading the bytes inside the code unit";
        }
                
        byte[] bytes_that_will_be_sent=Arrays.copyOfRange(bytes_of_codeunit, 0, Math.min(maxbytes_to_ret,target_codeunit.getLength()));
        byte[] encoded_bytes=Base64.getEncoder().encode(bytes_that_will_be_sent);
        String b64_string_with_bytes=new String(encoded_bytes);
        retval+="\"b64_content\":\""+b64_string_with_bytes+"\",";
       
        if (target_codeunit.getLabel()!=null)
        {
            retval+="\"label\":\""+sanitize_str(target_codeunit.getLabel())+"\",";
        }
        
        String PRE_comment=target_codeunit.getComment(CommentType.PRE); //use CodeUnit.PRE_COMMENT in previous ghidra versions
        if (PRE_comment!=null)
        {
            retval+="\"pre_comment\":\""+sanitize_comment(PRE_comment)+"\","; 
        }
        

        if (target_codeunit.getPrimarySymbol()!=null)
        {
            retval+="\"primary_symbol\":\""+sanitize_str(target_codeunit.getPrimarySymbol().getName(true))+"\",";
        }
        
        Reference[] referencesfrom=target_codeunit.getReferencesFrom();
        retval+="\"references_from\":[";
        for (int i=0;i<referencesfrom.length;i++)
        {
            try 
            {
                Address tmp_targetaddr=referencesfrom[i].getToAddress();
                String offset_of_targetaddr=return_offset_for_addr(tmp_targetaddr,this.current_program);
                retval+="\""+offset_of_targetaddr+"\"";
                if (i<referencesfrom.length-1)
                {
                    retval+=",";
                }
            }
            catch(Exception e)
            {
                return "Error in referenceFrom parsing";
            }
            
        }
        retval+="],"; 
                
        retval+="\"references_to\":[";
        ReferenceIterator ref_iter = target_codeunit.getReferenceIteratorTo();
        while (ref_iter!=null && ref_iter.hasNext())
        {
            Reference current_ref=ref_iter.next();
            try 
            {
                Address tmp_targetaddr=current_ref.getFromAddress();
                String offset_of_targetaddr=return_offset_for_addr(tmp_targetaddr,this.current_program);
                retval+="\""+offset_of_targetaddr+"\"";
                if (ref_iter.hasNext())
                {
                    retval+=",";
                }
            }
            catch(Exception e)
            {
                return "Error in referenceTo parsing";
            }
        }
        retval+="]";
        
        if (is_instruction)
        {
            Instruction current_instr=(Instruction) target_codeunit;
            retval+=",\"instruction_data\":{";
            retval+="\"instr_as_text\":\""+sanitize_instruction_text(current_instr.toString().toLowerCase().trim())+"\",";
            retval+="\"is_computed_jmpORcall\":";
            if (is_computed_jump_or_computed_call(current_instr))
            {
                retval+="true,";
            }
            else
            {
                retval+="false,";
            }
            retval+="\"is_call\":";
            if (current_instr.getFlowType().isCall())
            {
                retval+="true,";
            }
            else
            {
                retval+="false,";
            }
            retval+="\"is_jump\":";
            if (current_instr.getFlowType().isJump())
            {
                retval+="true";
            }
            else
            {
                retval+="false";
            }
            
            retval+="}";
        }
        
   
        retval+="}";
        
      
        return retval;
    }
    
    
    
    
    
    public String CHANGE_BYTES_INSIDE_GHIDRADB(long address_offset, byte[] decoded_bytes)
    {
        String retval="";
        int max_allowed_length_for_array=20000000;
        if (this.current_program==null)
        {
            return "Error, current Program is null";
        }
        String check=make_sure_address_offset_is_valid(address_offset);
        if (!check.equals("ok"))
        {
            return check;
        }
        
                
        Listing program_listing=this.current_program.getListing();
        Address image_base = this.current_program.getImageBase();
        Address target_addr=image_base.add(address_offset);
        Memory program_mem=this.current_program.getMemory();
        
        int length_of_array=decoded_bytes.length;
        
        if (length_of_array>max_allowed_length_for_array)
        {
            return "Error, too large content";
        }
        
        if (length_of_array==0)
        {
            return "Error, length_of_array==0";
        }
        
        //Bound the write by the memory BLOCK that contains the target, not by image_base+Memory.getSize().
        //getSize() is the total number of bytes across all blocks, so treating it as the distance from the
        //image base assumes one contiguous region - false for almost any real program, which has .text,
        //.data and often blocks far away from each other. It happened to fail safe, because setBytes()
        //throws on unmapped memory and the transaction rolls back, but it was accepting and rejecting on a
        //meaningless number. The containing block gives the exact answer, and also catches a write that
        //starts inside a block and runs off its end into a gap.
        MemoryBlock block_containing_target=program_mem.getBlock(target_addr);
        if (block_containing_target==null)
        {
            return "Error, the target address does not fall inside any memory block of the program";
        }
        if (!block_containing_target.isInitialized())
        {
            return "Error, the target address is inside an uninitialized memory block, its bytes cannot be set";
        }
        long bytes_available_until_the_end_of_the_block=
                block_containing_target.getEnd().getOffset() - target_addr.getOffset() + 1;
        if (bytes_available_until_the_end_of_the_block<length_of_array)
        {
            return "Error, the write of "+length_of_array+" bytes would run past the end of the memory block \""
                    +block_containing_target.getName()+"\", which has only "
                    +bytes_available_until_the_end_of_the_block+" bytes left from this address";
        }
        
        //write the memory
        try
        {
            int tx_id=this.current_program.startTransaction("Set mem");
            boolean transaction_succeeded=false;
            try
            {
                program_listing.clearCodeUnits(target_addr, target_addr.add(length_of_array-1), false);
                program_mem.setBytes(target_addr, decoded_bytes);
                transaction_succeeded=true;
            }
            finally
            {
                //without this, an exception would leave the transaction open on the Program.
                //Rolling back also undoes the clearCodeUnits() if setBytes() is the call that failed.
                this.current_program.endTransaction(tx_id, transaction_succeeded);
            }
        }
        catch (Exception e)
        {
            return "Error in setting memory, exception" +e ;
        }
        
        retval="ok";
        return retval;
    }
    
    
}
