package dragonhook;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
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
    protected Program current_program;
    protected Plugin incoming_plugin;
    long max_displacement;
    //https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/RefType.html
    String[] valid_reftypes_as_strings= {"CALL_OVERRIDE_UNCONDITIONAL","CALL_TERMINATOR","CALLOTHER_OVERRIDE_CALL","CALLOTHER_OVERRIDE_JUMP","COMPUTED_CALL","COMPUTED_CALL_TERMINATOR","COMPUTED_JUMP","CONDITIONAL_CALL","CONDITIONAL_CALL_TERMINATOR","CONDITIONAL_COMPUTED_CALL","CONDITIONAL_COMPUTED_JUMP","CONDITIONAL_JUMP","CONDITIONAL_TERMINATOR","DATA","EXTERNAL_REF","FALL_THROUGH","FLOW","INDIRECTION","INVALID","JUMP_OVERRIDE_UNCONDITIONAL","JUMP_TERMINATOR","PARAM","READ","READ_IND","READ_WRITE","READ_WRITE_IND","TERMINATOR","THUNK","UNCONDITIONAL_CALL","UNCONDITIONAL_JUMP","WRITE","WRITE_IND"};
    RefType[] valid_reftypes= {RefType.CALL_OVERRIDE_UNCONDITIONAL,RefType.CALL_TERMINATOR,RefType.CALLOTHER_OVERRIDE_CALL,RefType.CALLOTHER_OVERRIDE_JUMP,RefType.COMPUTED_CALL,RefType.COMPUTED_CALL_TERMINATOR,RefType.COMPUTED_JUMP,RefType.CONDITIONAL_CALL,RefType.CONDITIONAL_CALL_TERMINATOR,RefType.CONDITIONAL_COMPUTED_CALL,RefType.CONDITIONAL_COMPUTED_JUMP,RefType.CONDITIONAL_JUMP,RefType.CONDITIONAL_TERMINATOR,RefType.DATA,RefType.EXTERNAL_REF,RefType.FALL_THROUGH,RefType.FLOW,RefType.INDIRECTION,RefType.INVALID,RefType.JUMP_OVERRIDE_UNCONDITIONAL,RefType.JUMP_TERMINATOR,RefType.PARAM,RefType.READ,RefType.READ_IND,RefType.READ_WRITE,RefType.READ_WRITE_IND,RefType.TERMINATOR,RefType.THUNK,RefType.UNCONDITIONAL_CALL,RefType.UNCONDITIONAL_JUMP,RefType.WRITE,RefType.WRITE_IND};

    
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
    private static final Pattern pattern_for_function_name=
            Pattern.compile("[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_\\~\\:\\$]");

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
            
            if (DOSLimitsTracker.map_of_codeunits_for_which_function_data_have_been_returned.containsKey(target_codeunit))
            {
                int times_returned=DOSLimitsTracker.map_of_codeunits_for_which_function_data_have_been_returned.get(target_codeunit);
                if (times_returned<DOSLimitsTracker.allowed_times_FUN_DATA_GIVEN_ADDR_OFFSET)
                {
                    DOSLimitsTracker.map_of_codeunits_for_which_function_data_have_been_returned.put(target_codeunit,times_returned+1);
                }
                else
                {
                    return "Error, reached  maximum allowed times to call the FUN_DATA_GIVEN_ADDR_OFFSET for this function for this agent run";
                }
            }
            else
            {
                DOSLimitsTracker.map_of_codeunits_for_which_function_data_have_been_returned.put(target_codeunit,1);
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
        long time_at_start=System.nanoTime();
        long image_base_offset=current_program.getImageBase().getOffset();
        ArrayList<String> function_entries=new ArrayList<String>();   //index -> ["name","0xentrypoint"]
        ArrayList<long[]> range_entries=new ArrayList<long[]>();      //{start, end, index into function_entries}

        FunctionIterator fun_iter = current_program.getFunctionManager().getFunctions(true);
        while (fun_iter!=null && fun_iter.hasNext())
        {
            Function current_function=fun_iter.next();
            String name_of_fun=sanitize_fun_name(current_function.getName(true));
            //inlined instead of return_offset_for_addr(), which re-reads the image base every call
            String start_of_fun_offset="0x"+Long.toHexString(current_function.getEntryPoint().getOffset() - image_base_offset);
            int index_of_this_function=function_entries.size();
            function_entries.add("[\""+name_of_fun+"\",\""+start_of_fun_offset+"\"]");

            AddressRangeIterator current_function_ranges_iter= current_function.getBody().getAddressRanges(true);
            while (current_function_ranges_iter!=null && current_function_ranges_iter.hasNext())
            {
                AddressRange current_function_range=current_function_ranges_iter.next();
                range_entries.add(new long[]{
                        current_function_range.getMinAddress().getOffset() - image_base_offset,
                        current_function_range.getMaxAddress().getOffset() - image_base_offset,
                        index_of_this_function});
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
        
        if (DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.containsKey(target_codeunit))
        {
            int times_updated=DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.get(target_codeunit);
            if (times_updated<DOSLimitsTracker.max_comments_per_codeunit_for_each_agent_run)
            {
                DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.put(target_codeunit,times_updated+1);
            }
            else
            {
                return "Error, reached maximum comment update limit for this codeunit for this agent run";
            }
        }
        else
        {
            DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.put(target_codeunit,1);
        }
        
        //update the comment
        
        String oldcomment=target_codeunit.getComment(CommentType.PRE); //use CodeUnit.PRE_COMMENT in previous ghidra versions
        String newcomment="";
        if (oldcomment==null)
        {
            newcomment=comment;
        }
        else
        {
            newcomment=oldcomment+"\n"+comment;
        }

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
 
        
        //check for limits
        if (apply_DOS_limits)
        {
            if (DOSLimitsTracker.max_xrefs_per_codeunit_for_each_agent_run==0)
            {
                return "Error, maximum xref limit for codeunits is 0";
            }
            
            if (DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.containsKey(target_codeunit_from))
            {
                int times_updated=DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.get(target_codeunit_from);
                if (times_updated<DOSLimitsTracker.max_xrefs_per_codeunit_for_each_agent_run)
                {
                    DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.put(target_codeunit_from,times_updated+1);
                }
                else
                {
                    return "Error, reached maximum xref update limit for target_codeunit_from for this agent run";
                }
            }
            else
            {
                DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.put(target_codeunit_from,1);
            }
            
            if (DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.containsKey(target_codeunit_to))
            {
                int times_updated=DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.get(target_codeunit_to);
                if (times_updated<DOSLimitsTracker.max_xrefs_per_codeunit_for_each_agent_run)
                {
                    DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.put(target_codeunit_to,times_updated+1);
                }
                else
                {
                    return "Error, reached maximum xref update limit for target_codeunit_to for this agent run";
                }
            }
            else
            {
                DOSLimitsTracker.map_of_codeunits_that_are_updated_with_comment.put(target_codeunit_to,1);
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
        
        if (DOSLimitsTracker.map_of_codeunits_for_which_codeunit_data_has_been_returned.containsKey(target_codeunit))
        {
            int times_returned=DOSLimitsTracker.map_of_codeunits_for_which_codeunit_data_has_been_returned.get(target_codeunit);
            if (times_returned<DOSLimitsTracker.allowed_times_CODEUNIT_DATA_GIVEN_ADDR_OFFSET)
            {
                DOSLimitsTracker.map_of_codeunits_for_which_codeunit_data_has_been_returned.put(target_codeunit,times_returned+1);
            }
            else
            {
                return "Error, reached maximum codeunit data extraction for this codeunit for this agent run";
            }
        }
        else
        {
            DOSLimitsTracker.map_of_codeunits_for_which_codeunit_data_has_been_returned.put(target_codeunit,1);
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
        
        Address maxaddr=this.current_program.getMaxAddress(); //does not work. do not use. Its offset is all over the place.
        long memsize=program_mem.getSize();
        
        
        long difference_in_size=(image_base.getOffset()+memsize) - target_addr.getOffset();
        
        if (difference_in_size<length_of_array)
        {
            return "Error, attempting to write past the program end";
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
