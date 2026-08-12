package dragonhook.tasks.dynamic_call_tracing;

import java.util.ArrayList;
import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

public class DynamicCallTracingUtils {

    
    public static String return_offset_for_addr(Address in_addr, Program current_program) {
        return "0x"+Long.toHexString(in_addr.getOffset() - current_program.getImageBase().getOffset());
    }
    
    
    public static boolean target_of_codeunit_ref_is_a_known_symbol(Program current_program,CodeUnit incoming_codeunit)
    {
        
        Listing program_listing = current_program.getListing();
        SymbolTable symbol_table = current_program.getSymbolTable();
        ReferenceManager ref_manager= current_program.getReferenceManager();
        boolean retval=false;
        Reference[] refs_from_codeunit=ref_manager.getReferencesFrom(incoming_codeunit.getMinAddress());
        for (int i=0;i<refs_from_codeunit.length;i++)
        {
            Address toAddr = refs_from_codeunit[i].getToAddress();
            Symbol symbol_of_toAddr=symbol_table.getPrimarySymbol(toAddr);
            if (symbol_of_toAddr!=null)
            {
                return true;
            }
        }
        return retval;
    }
    
    
    public static ArrayList<CodeUnit> extract_dynamic_calls_from_selection(Program current_program,ArrayList<AddressRange> incoming_addressrange_list, TaskMonitor incoming_monitor)
    {
        ArrayList<CodeUnit> retval=new ArrayList<CodeUnit>();
        Iterator<AddressRange> list_iter=incoming_addressrange_list.iterator();
        Listing current_program_listing=current_program.getListing();
        int list_cnt=0;
        int cnt_for_gc=0;
        while (list_iter.hasNext())
        {
            AddressRange current_address_range = list_iter.next();
            list_cnt++;
            if (incoming_monitor.isCancelled())
            {
                incoming_monitor.cancel();
                retval=new ArrayList<CodeUnit>();
                System.out.println("Extraction of dynamic calls task is cancelled");
                return retval;
            }
            incoming_monitor.setMessage("Filtering dynamic calls ... "+Long.toString(list_cnt)+"/"+Long.toString(incoming_addressrange_list.size()));
            
            AddressSet addr_set = new AddressSet(current_address_range);
            Iterator<CodeUnit> codeunit_iterator= current_program_listing.getCodeUnits(addr_set,true);
            
            int cnt_for_addressrange=0;
            
            while (codeunit_iterator!=null && codeunit_iterator.hasNext())
            {
                CodeUnit codeunit_in_question=codeunit_iterator.next();
                cnt_for_addressrange+=1;
                cnt_for_gc+=1;
                if (cnt_for_addressrange % 10000 == 0)
                {
                    if (incoming_monitor.isCancelled())
                    {
                        incoming_monitor.cancel();
                        retval=new ArrayList<CodeUnit>();
                        System.out.println("Extraction of dynamic calls task is cancelled");
                        return retval;
                    }
                    incoming_monitor.setMessage("Filtering dynamic calls... "+Long.toString(list_cnt)+"/"+Long.toString(incoming_addressrange_list.size())+", "+Long.toString(cnt_for_addressrange)+"/"+Long.toString(current_address_range.getLength()));
                }
                if (cnt_for_gc % 2000000 == 0)
                {
                    System.out.println("Invoking garbage collector to reduce memory footprint...");
                    System.gc();
                }
                
                boolean is_instruction=false;
                if (codeunit_in_question instanceof Instruction)
                {
                    is_instruction=true;
                }
                if (is_instruction)
                {
                    Instruction instr=(Instruction) codeunit_in_question;
                    if (instr.getFlowType().isCall() && instr.getFlowType().isComputed()
                        && !target_of_codeunit_ref_is_a_known_symbol(current_program,codeunit_in_question))
                    {
                        retval.add(codeunit_in_question);
                    }
                }
            }
        }
        System.out.println(retval.size());
        return retval;
    }
    
    //Emits the offsets that immediately FOLLOW a computed call, that is the return addresses such a
    //call pushes. A backtrace entry is exactly one of those, so with this table the agent answers
    //"did a computed call bring us here" with a dictionary lookup instead of asking ghidra over IPC
    //at runtime, which blocks the hooked thread for a full round trip on every hit.
    //
    //Scans the WHOLE program on purpose: a backtrace can point anywhere inside the module, not only
    //at the user's selection.
    //
    //Returns null if the user cancelled.
    public static String return_all_offsets_after_computed_calls_as_js_dict(Program current_program, TaskMonitor incoming_monitor)
    {
        long image_base_offset=current_program.getImageBase().getOffset();
        Listing current_program_listing=current_program.getListing();
        long total_number_of_instructions=current_program_listing.getNumInstructions();
        long number_of_instructions_examined=0;
        long number_of_computed_calls_found=0;

        incoming_monitor.setMessage("Precomputing the return addresses of computed calls...");

        StringBuilder sb=new StringBuilder();
        sb.append("{");

        InstructionIterator instruction_iterator=current_program_listing.getInstructions(true);
        while (instruction_iterator!=null && instruction_iterator.hasNext())
        {
            Instruction current_instruction=instruction_iterator.next();
            number_of_instructions_examined+=1;

            if (number_of_instructions_examined % 10000 == 0)
            {
                if (incoming_monitor.isCancelled())
                {
                    incoming_monitor.cancel();
                    System.out.println("Precomputation of the return addresses of computed calls is cancelled");
                    return null;
                }
                incoming_monitor.setMessage("Precomputing the return addresses of computed calls ... "
                        +Long.toString(number_of_instructions_examined)+"/"+Long.toString(total_number_of_instructions)
                        +" , found "+Long.toString(number_of_computed_calls_found));
            }

            if (current_instruction.getFlowType().isCall() && current_instruction.getFlowType().isComputed())
            {
                long offset_right_after_the_call=current_instruction.getMinAddress().getOffset()
                        + current_instruction.getLength() - image_base_offset;
                sb.append("\""+"0x"+Long.toHexString(offset_right_after_the_call)+"\":true,");
                number_of_computed_calls_found+=1;
            }
        }

        sb.append("\"0xffffffffffff\":true}"); //dummy entry, so that the trailing comma above stays valid
        System.out.println("Precomputed "+Long.toString(number_of_computed_calls_found)
                +" computed call return addresses, after examining "+Long.toString(number_of_instructions_examined)+" instructions");
        return sb.toString();
    }


    public static String return_all_offsets_of_dynamic_calls_as_js_dict(ArrayList<CodeUnit> incoming_list, Program current_program)
    {
        String retval="{";
        StringBuilder sb= new StringBuilder();
        for (int i=0;i<incoming_list.size();i++)
        {
            CodeUnit codeunit_in_question=incoming_list.get(i); 
            String offset_as_str=return_offset_for_addr( codeunit_in_question.getMinAddress(),current_program);
            sb.append("\""+offset_as_str+"\":0,");
        }
        
        retval+=sb.toString();
        retval+="\"0xffffffffffff\":0"; //dummy value
        retval+="};";
        return retval;
    }
    
}
