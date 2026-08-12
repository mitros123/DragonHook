package dragonhook;

import java.util.ArrayList;
import java.util.Iterator;

import dragonhook.util.AddressRangeMinMaxContainer;
import dragonhook.util.ConsolePrinter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DragonSelectionAddressRangeGathererTask extends Task {

    public Boolean is_cancelled;
    public ArrayList<CodeUnit> code_units_for_instructions_that_are_gathered;
    public ArrayList<AddressRange> address_ranges_that_are_gathered;
    public ArrayList<AddressRangeMinMaxContainer> min_max_addresses_in_address_ranges;
    public ArrayList<CodeUnit> incoming_selection_to_exclude;
    protected PluginTool incoming_plugintool;
    protected Program current_program;
    protected ProgramSelection incoming_program_selection;
    
    public DragonSelectionAddressRangeGathererTask(String title, Program incoming_program, PluginTool tool,ProgramSelection incoming_program_selection,ArrayList<CodeUnit> incoming_selection_to_exclude) {
        //Task(String title) means canCancel=false, so monitor.isCancelled() was permanently false
        //and the cancel handling below could never trigger. No progress bar on purpose: progress is
        //reported as counts inside monitor.setMessage().
        //Arguments are (title, canCancel, hasProgress, isModal).
        super(title, true, false, true);
        this.current_program=incoming_program;
        this.incoming_plugintool=tool;
        this.incoming_program_selection=incoming_program_selection;
        this.incoming_selection_to_exclude=incoming_selection_to_exclude;
        this.is_cancelled=false;
    }
    
    public AddressSet create_address_set_from_arraylist_of_codeunits(ArrayList<CodeUnit> to_exclude)
    {
        AddressSet retval= new AddressSet();
        for (int i=0;i<to_exclude.size();i++)
        {
            retval.add(to_exclude.get(i).getMinAddress(),to_exclude.get(i).getMaxAddress());
        }
        return retval;
    }
    

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        
        this.code_units_for_instructions_that_are_gathered=new ArrayList<CodeUnit>(); //these will be the code units in the selection. THIS WILL STAY EMPTY 
        this.address_ranges_that_are_gathered=new ArrayList<AddressRange>(); //these will be the address ranges in the selection
        this.min_max_addresses_in_address_ranges=new ArrayList<AddressRangeMinMaxContainer>(); //and the corresponding min/max values
        
        Listing current_program_listing=this.current_program.getListing();
        ConsolePrinter cp=new ConsolePrinter(this.incoming_plugintool);
        
        if (this.incoming_selection_to_exclude.size()>0)
        {
            monitor.setMessage("Removing excluded addresses from selection... ");
            AddressSet excluded_addresses= create_address_set_from_arraylist_of_codeunits(this.incoming_selection_to_exclude);
            AddressSet remaining_addresses=this.incoming_program_selection.subtract(excluded_addresses);
            this.incoming_program_selection=new ProgramSelection(remaining_addresses);
        }

        long num_of_total_addresses_selected=this.incoming_program_selection.getNumAddresses();
        int num_of_total_address_ranges_selected=this.incoming_program_selection.getNumAddressRanges();
        Iterator<Address> address_iterator= this.incoming_program_selection.getAddresses(true);
        Iterator<AddressRange> addressRangeIterator=this.incoming_program_selection.getAddressRanges(true);
        
        /* Get all the code units */
        /* This will allocate immense amounts of RAM. It is better to only return the address ranges.*/
        /*
        System.out.println("Getting all the code units for the selected addresses...");
        long cnt=0;
        long cnt_for_gc=0;
        monitor.setMessage("Gathering Code Units ... "+Long.toString(cnt)+"/"+Long.toString(num_of_total_addresses_selected));
        boolean force_check_for_cancelled=false;
        while (address_iterator!=null && address_iterator.hasNext())
        {
            Address current_address=address_iterator.next();
            cnt+=1;
            cnt_for_gc+=1;
            CodeUnit current_code_unit=current_program_listing.getCodeUnitAt(current_address); //Is the current address at the start of a code unit?
            if (current_code_unit!=null &&  current_code_unit instanceof Instruction)
            {
                code_units_for_instructions_that_are_gathered.add(current_code_unit); //If yes, add it to the list
            }
            if (cnt % 10000==0 || force_check_for_cancelled)
            {
                force_check_for_cancelled=false;
                if (monitor.isCancelled())
                {
                    this.is_cancelled=true;
                    monitor.cancel();
                    this.code_units_for_instructions_that_are_gathered=new ArrayList<CodeUnit>();
                    System.out.println("Code Unit Gathering Task is cancelled");
                    return;
                }
                monitor.setMessage("Gathering Code Units ... "+Long.toString(cnt)+"/"+Long.toString(num_of_total_addresses_selected));
                if (cnt_for_gc>3000000)
                {
                    cnt_for_gc=1;
                    code_units_for_instructions_that_are_gathered.trimToSize();
                    System.out.println("Invoking garbage collector...");
                    System.gc(); //let's free up any unneeded memory
                }
            }
            if (current_code_unit!=null)
            {
                int size_of_code_unit=current_code_unit.getLength();
                //it is safe to skip the next (size_of_code_unit-1) iterations
                for (int i=0;i<size_of_code_unit-1;i++)
                {
                    if (address_iterator.hasNext()) 
                    {
                        address_iterator.next();
                        cnt+=1;
                        cnt_for_gc+=1;
                        if (cnt % 10000==0)
                        {
                            force_check_for_cancelled=true; //on next loop
                        }
                    }
                }
            }
        }
        System.out.println("Got all the code units for the selected addresses.");
        cp.print_to_console("Got all the code units for the selected addresses.");

        if (code_units_for_instructions_that_are_gathered.size()>1000000)
        {
            code_units_for_instructions_that_are_gathered.trimToSize();
            System.gc();
        }
        System.out.println("Length of array of codeunits: "+code_units_for_instructions_that_are_gathered.size());
        */
        
        
        /* Get all the address ranges  */
        System.out.println("Getting all the address ranges for the selected addresses...");
        int cnt2=0;
        monitor.setMessage("Gathering Address Ranges ... "+Integer.toString(cnt2)+"/"+Integer.toString(num_of_total_address_ranges_selected));
        while (addressRangeIterator!=null && addressRangeIterator.hasNext())
        {
            AddressRange current_address_range=addressRangeIterator.next();
            cnt2+=1;
            this.address_ranges_that_are_gathered.add(current_address_range);
            Address minaddr=current_address_range.getMinAddress();
            Address maxaddr=current_address_range.getMaxAddress();
            CodeUnit min_code_unit=current_program_listing.getCodeUnitAt(minaddr); //Is the min address at the start of a code unit?
            CodeUnit max_code_unit=current_program_listing.getCodeUnitContaining(maxaddr); //Is the max address inside  a code unit?
            //Code Units may be null here
            AddressRangeMinMaxContainer cont=new AddressRangeMinMaxContainer(minaddr,maxaddr,min_code_unit,max_code_unit);
            this.min_max_addresses_in_address_ranges.add(cont);
                        
            if (cnt2 % 100==0)
            {
                if (monitor.isCancelled())
                {
                    this.is_cancelled=true;
                    monitor.cancel();
                    this.address_ranges_that_are_gathered=new ArrayList<AddressRange>();
                    this.min_max_addresses_in_address_ranges=new ArrayList<AddressRangeMinMaxContainer>(); 
                    System.out.println("Address Range Gathering Task is cancelled");
                    return;
                }
                monitor.setMessage("Gathering Address Ranges ... "+Integer.toString(cnt2)+"/"+Integer.toString(num_of_total_address_ranges_selected));
            }
        }
        cp.print_to_console("Got all the address ranges for the selected addresses.");
        System.out.println("Got all the address ranges for the selected addresses.");

        

    }

}
