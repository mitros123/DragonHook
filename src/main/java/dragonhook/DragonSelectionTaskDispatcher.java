package dragonhook;

import java.util.ArrayList;
import java.util.Map;
import java.util.Properties;

import dragonhook.tasks.dynamic_call_tracing.DynamicCallTracingUtils;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.JSAgentPreparer;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class DragonSelectionTaskDispatcher {
    
    private PluginTool incoming_plugintool;
    private ProgramSelection incoming_selection;
    private ArrayList<CodeUnit> incoming_selection_to_exclude;
    private DragonSelectionOptionsDialog incoming_selection_options_dialog;
    private Program current_program;
    private Boolean is_this_an_API_call;

    public DragonSelectionTaskDispatcher(PluginTool plugintool, Program incoming_program,ProgramSelection incoming_selection, ArrayList<CodeUnit> selected_code_units_to_exclude, Boolean is_this_an_API_call, DragonSelectionOptionsDialog incoming_selection_options_dialog)
    {
        this.incoming_plugintool=plugintool;
        this.current_program=incoming_program;
        this.incoming_selection=incoming_selection;
        this.incoming_selection_to_exclude=selected_code_units_to_exclude;
        if (this.incoming_selection_to_exclude==null)
        {
            this.incoming_selection_to_exclude=new ArrayList<CodeUnit>();
        }
        this.is_this_an_API_call=is_this_an_API_call;
        this.incoming_selection_options_dialog=incoming_selection_options_dialog;
    }
    
    private void clear_mem_for_codeunit_gatherer_task(DragonSelectionAddressRangeGathererTask code_unit_gatherer_task)
    {
        code_unit_gatherer_task.code_units_for_instructions_that_are_gathered=null;
        code_unit_gatherer_task.address_ranges_that_are_gathered=null;
        System.gc();
    }
    
    public void perform_selection_task()
    {
        
        //Gather code units from selection
        DragonSelectionAddressRangeGathererTask address_range_gatherer_task=new DragonSelectionAddressRangeGathererTask("Gathering Selected Code Units",this.current_program,this.incoming_plugintool,this.incoming_selection,this.incoming_selection_to_exclude);
        this.incoming_plugintool.execute(address_range_gatherer_task); //Execute the task
        if (address_range_gatherer_task.is_cancelled)
        {
            clear_mem_for_codeunit_gatherer_task(address_range_gatherer_task);
            return;
        }
        
        if (!this.is_this_an_API_call)
        {
            //spawn dialog
            DragonSelectionOptionsDialog selection_options_dialog=new DragonSelectionOptionsDialog("Selection Dialog",this.incoming_plugintool, this.current_program , incoming_selection);
            selection_options_dialog.show_window();
            if (!selection_options_dialog.isOKpressed)
            {
                clear_mem_for_codeunit_gatherer_task(address_range_gatherer_task);
                return;
            }
            this.incoming_selection_options_dialog=selection_options_dialog;
        }
        
        //now update the JS file accordingly
        DragonSelectionTask dragon_selection_task=new DragonSelectionTask("Executing the Selection Options",this.current_program,this.incoming_plugintool,this.incoming_selection_options_dialog,address_range_gatherer_task);
        this.incoming_plugintool.execute(dragon_selection_task); //Execute the task
        if (dragon_selection_task.is_cancelled)
        {
            clear_mem_for_codeunit_gatherer_task(address_range_gatherer_task);
            return;
        }
        
        clear_mem_for_codeunit_gatherer_task(address_range_gatherer_task);


    }
}
