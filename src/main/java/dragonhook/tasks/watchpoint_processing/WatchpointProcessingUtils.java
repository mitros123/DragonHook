package dragonhook.tasks.watchpoint_processing;

import java.util.ArrayList;
import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
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
    
    
        
    //Hardware watchpoints only accept a size of 1, 2, 4 or 8 bytes, and the address has to be
    //aligned to that size. A code unit length is neither: an x86 instruction is 1 to 15 bytes and a
    //data item can be any length, so passing it straight through made setHardwareWatchpoint() throw
    //for most selections, which the agent then reported as "hardware watchpoints not supported".
    //Module bases are page aligned, so alignment of the offset carries over to the runtime address.
    //An 8 byte watchpoint only exists on 64 bit targets: on 32 bit x86 the DR7 LEN field has no
    //encoding for it, so max_size has to come from the program's pointer size.
    public static int return_largest_valid_watchpoint_size(long offset_from_image_base, int length_of_codeunit, int max_size)
    {
        int[] candidate_sizes={8,4,2,1};
        for (int i=0;i<candidate_sizes.length;i++)
        {
            int candidate_size=candidate_sizes[i];
            if (candidate_size<=max_size && length_of_codeunit>=candidate_size
                && Math.floorMod(offset_from_image_base,candidate_size)==0)
            {
                return candidate_size;
            }
        }
        return 1;
    }


    //[{"address_offset_as_num":0xffffffffffff,"size":4,"operation":"r"}]
    public static String return_all_watchpoint_info_objects_as_js_array(ArrayList<CodeUnit> incoming_list, Program current_program, String operation)
    {
        String retval="[";
        StringBuilder sb= new StringBuilder();
        long image_base_offset=current_program.getImageBase().getOffset();
        //8 byte watchpoints exist on 64 bit targets only
        int max_watchpoint_size=(current_program.getDefaultPointerSize()>=8) ? 8 : 4;
        for (int i=0;i<incoming_list.size();i++)
        {
            CodeUnit codeunit_in_question=incoming_list.get(i);
            int length_of_codeunit=codeunit_in_question.getLength();
            long offset_as_long=codeunit_in_question.getMinAddress().getOffset() - image_base_offset;
            String offset_as_str=return_offset_for_addr( codeunit_in_question.getMinAddress(),current_program);
            int size_for_watchpoint=return_largest_valid_watchpoint_size(offset_as_long,length_of_codeunit,max_watchpoint_size);
            sb.append("{\"address_offset_as_num\":"+offset_as_str+",\"size\":"+size_for_watchpoint+",\"operation\":\""+operation+"\"}");
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
