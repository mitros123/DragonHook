package dragonhook.tasks.watchpoint_processing;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

public class WatchpointProcessingUtils {

    
    public static String return_offset_for_addr(Address in_addr, Program current_program) {
        return "0x"+Long.toHexString(in_addr.getOffset() - current_program.getImageBase().getOffset());
    }

    

    //This should finish instantly. Watchpoints should not be set for over than 2-3 addresses.
    public static ArrayList<CodeUnit> extract_selection_as_arraylist_of_codeunits(Program current_program,ArrayList<AddressRange> incoming_addressrange_list, TaskMonitor incoming_monitor)
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
            incoming_monitor.setMessage("Extracting codeunits to set watchpoints ... "+Long.toString(list_cnt)+"/"+Long.toString(incoming_addressrange_list.size()));
            
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
                        System.out.println("Extraction of codeunits to set watchpoints task is cancelled");
                        return retval;
                    }
                    incoming_monitor.setMessage("Extracting codeunits to set watchpoints ... "+Long.toString(list_cnt)+"/"+Long.toString(incoming_addressrange_list.size())+", "+Long.toString(cnt_for_addressrange)+"/"+Long.toString(current_address_range.getLength()));
                }
                if (cnt_for_gc % 2000000 == 0)
                {
                    System.out.println("Invoking garbage collector to reduce memory footprint...");
                    System.gc();
                }
                
                retval.add(codeunit_in_question); //just add the codeunit
            }
        }
        System.out.println(retval.size());
        return retval;
    }
    
    
        
    //[{"address_offset_as_num":0xffffffffffff,"size":4,"operation":"r"}]
    public static String return_all_watchpoint_info_objects_as_js_array(ArrayList<CodeUnit> incoming_list, Program current_program, String operation)
    {
        String retval="[";
        StringBuilder sb= new StringBuilder();
        for (int i=0;i<incoming_list.size();i++)
        {
            CodeUnit codeunit_in_question=incoming_list.get(i); 
            int length_of_codeunit=codeunit_in_question.getLength();
            String offset_as_str=return_offset_for_addr( codeunit_in_question.getMinAddress(),current_program);
            sb.append("{\"address_offset_as_num\":"+offset_as_str+",\"size\":"+length_of_codeunit+",\"operation\":\""+operation+"\"}");
            if (i<incoming_list.size()-1)
            {
                sb.append(",");
            }
        }
        
        retval+=sb.toString();
        retval+="];";
        return retval;
    }
    
}
