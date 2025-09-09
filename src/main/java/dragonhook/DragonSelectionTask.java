package dragonhook;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;

import dragonhook.tasks.custom_backtracer.CustomBacktracerUtils;
import dragonhook.tasks.dynamic_call_tracing.DynamicCallTracingUtils;
import dragonhook.tasks.watchpoint_processing.WatchpointProcessingUtils;
import dragonhook.util.AddressRangeMinMaxContainer;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.JSAgentPreparer;
import dragonhook.util.PackageChecker;
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

public class DragonSelectionTask extends Task {

    public Boolean is_cancelled;
    protected PluginTool incoming_plugintool;
    protected Program current_program;
    protected DragonSelectionOptionsDialog incoming_selection_options_dialog;
    protected DragonSelectionAddressRangeGathererTask code_unit_gatherer_task;
    
    public DragonSelectionTask(String title, Program incoming_program, PluginTool tool,DragonSelectionOptionsDialog incoming_selection_options_dialog,DragonSelectionAddressRangeGathererTask code_unit_gatherer_task) {
        super(title);
        this.current_program=incoming_program;
        this.incoming_plugintool=tool;
        this.is_cancelled=false;
        this.incoming_selection_options_dialog=incoming_selection_options_dialog;
        this.code_unit_gatherer_task=code_unit_gatherer_task;
    }
    

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        
        ConsolePrinter cp=new ConsolePrinter(this.incoming_plugintool);
        monitor.setMessage("Altering JS agent according to options... ");
        if (this.incoming_selection_options_dialog.isResetAgentContentsBeforePerformingChangesCheckBoxchecked)
        {
            CreatorOfNecessaryFiles.resetAgentFile();
            CreatorOfNecessaryFiles.createAllNecessaryFiles();
            JSAgentPreparer.agent_has_been_updated_with_current_program=false;
            JSAgentPreparer.prepare_agent_file_if_not_already_prepared(this.current_program);
        }
        
        
        if (monitor.isCancelled())
        {
            this.is_cancelled=true;
            monitor.cancel();
            return;
        }
        
        
        //Function Data extraction method
        if (this.incoming_selection_options_dialog.FunctionDataRetrievalRadioButtonBulk.isSelected())
        {
            JSAgentPreparer.config_bulk_retrieval_of_function_data("true");
        }
        else
        {
            JSAgentPreparer.config_bulk_retrieval_of_function_data("false");
        }
        
        
        //Dynamic Calls
        if (this.incoming_selection_options_dialog.isStalkSelectedDynamicCallsCheckBoxchecked)
        {
            ArrayList<CodeUnit> dyncalls= DynamicCallTracingUtils.extract_dynamic_calls_from_selection(this.current_program,code_unit_gatherer_task.address_ranges_that_are_gathered,monitor );
            
            if (monitor.isCancelled())
            {
                this.is_cancelled=true;
                monitor.cancel();
                return;
            }
            
            String js_dict_with_dyncall_addresses=DynamicCallTracingUtils.return_all_offsets_of_dynamic_calls_as_js_dict(dyncalls,this.current_program);
            
            System.out.println(js_dict_with_dyncall_addresses);
            
            JSAgentPreparer.set_dynamic_call_offsets_in_agent(js_dict_with_dyncall_addresses);
            JSAgentPreparer.enable_stalking_of_dynamic_calls();
            if (this.incoming_selection_options_dialog.StalkingMethodRadioButtonBuiltin.isSelected())
            {
                JSAgentPreparer.set_boolean_variable_for_dynamic_call_stalking_to_use_builtin_method("true");
            }
            else
            {
                JSAgentPreparer.set_boolean_variable_for_dynamic_call_stalking_to_use_builtin_method("false");
            }
            
            
            if (this.incoming_selection_options_dialog.isDynCalls_OnlyStalkThreadsWithNameCheckBoxchecked)
            {
                String str_that_is_included_in_threadnames=incoming_selection_options_dialog.DynCalls_OnlyStalkThreadsWithNameTextField.getText();
                JSAgentPreparer.set_name_of_threads_to_be_stalked(str_that_is_included_in_threadnames);
            }
            
            
            
            JSAgentPreparer.set_number_of_logged_dynamic_calls((String) this.incoming_selection_options_dialog.MaxTimesToUpdateCodeUnitInGhidraDBComboBox.getSelectedItem());
            
            
        }
        
        if (monitor.isCancelled())
        {
            this.is_cancelled=true;
            monitor.cancel();
            return;
        }
        
        
        
        //Call tracing
        if (this.incoming_selection_options_dialog.isStalkForCallTracingCheckBoxchecked)
        {

            if (monitor.isCancelled())
            {
                this.is_cancelled=true;
                monitor.cancel();
                return;
            }
                        
            JSAgentPreparer.enable_call_tracing_through_stalker(!this.incoming_selection_options_dialog.isCallTraceOutsideOurModuleCheckBoxchecked);
            
            if (this.incoming_selection_options_dialog.isCallTracing_OnlyStalkThreadsWithNameCheckBoxchecked)
            {
                String str_that_is_included_in_threadnames=incoming_selection_options_dialog.CallTracing_OnlyStalkThreadsWithNameTextField.getText();
                JSAgentPreparer.set_name_of_threads_to_be_stalked(str_that_is_included_in_threadnames);
            }
            
        }
        
        
        
        if (monitor.isCancelled())
        {
            this.is_cancelled=true;
            monitor.cancel();
            return;
        }
        
        
        
        if (this.incoming_selection_options_dialog.isSetHardwareWatchPointCheckBoxchecked)
        {
            
            ArrayList<CodeUnit> codeunits_for_watchpoints= WatchpointProcessingUtils.extract_selection_as_arraylist_of_codeunits(this.current_program,code_unit_gatherer_task.address_ranges_that_are_gathered,monitor );

            
            if (monitor.isCancelled())
            {
                this.is_cancelled=true;
                monitor.cancel();
                return;
            }

            JSAgentPreparer.enable_hardware_watchpoint_logging((String) this.incoming_selection_options_dialog.MaxTimesLogWatchpointsComboBox.getSelectedItem());
            
            
            int selected_index_for_operation=this.incoming_selection_options_dialog.WatchpointTriggerOnOperationComboBox.getSelectedIndex();
            
            String operation="r";
            if (selected_index_for_operation==0)
            {
                operation="r";
            }
            if (selected_index_for_operation==1)
            {
                operation="w";
            }
            if (selected_index_for_operation==2)
            {
                operation="rw";
            }
            
            String js_array_with_watchpoint_objects=WatchpointProcessingUtils.return_all_watchpoint_info_objects_as_js_array(codeunits_for_watchpoints,this.current_program, operation);
            
            if (monitor.isCancelled())
            {
                this.is_cancelled=true;
                monitor.cancel();
                return;
            }
            
            System.out.println(js_array_with_watchpoint_objects);
            
            JSAgentPreparer.set_array_of_watchpoints(js_array_with_watchpoint_objects);

        }
        
        
        
        if (this.incoming_selection_options_dialog.isCustomBackTraceFromSelectedAddressesCheckBoxchecked
                && !PackageChecker.isClassAvailable("fridahookgenerator.FridaHookGeneratorPlugin"))
        {
            //class not available
            cp.print_to_console(CustomBacktracerUtils.error_plugin_not_loaded);
            String hook="console.log(\""+CustomBacktracerUtils.error_plugin_not_loaded+"\");";
            JSAgentPreparer.add_custom_hooks(hook);
        }
        
        if (this.incoming_selection_options_dialog.isCustomBackTraceFromSelectedAddressesCheckBoxchecked
            && PackageChecker.isClassAvailable("fridahookgenerator.FridaHookGeneratorPlugin"))
        {
            boolean we_are_using_regex=(this.incoming_selection_options_dialog.BacktraceFunctionsOrAddressesComboBox.getSelectedIndex()==2);
            
            
            String addresses_to_hook="";
            if (we_are_using_regex)
            {
                String regex_for_fun_name=this.incoming_selection_options_dialog.BacktraceFunctionsByRegexTextField.getText();
                addresses_to_hook=CustomBacktracerUtils.extract_str_with_hook_addresses_for_function_regex(this.current_program, monitor,regex_for_fun_name);

            }
            else
            {
                boolean should_hook_function_starts_only= (this.incoming_selection_options_dialog.BacktraceFunctionsOrAddressesComboBox.getSelectedIndex()==0);
                addresses_to_hook=CustomBacktracerUtils.extract_str_with_hook_addresses_from_selection(this.current_program,code_unit_gatherer_task.address_ranges_that_are_gathered,monitor ,should_hook_function_starts_only);
            }
                
            if (monitor.isCancelled())
            {
                this.is_cancelled=true;
                monitor.cancel();
                return;
            }

            String backtracer_type=(String) this.incoming_selection_options_dialog.BacktrackerTypeComboBox.getSelectedItem();
            
            String hook=CustomBacktracerUtils.invoke_FridaHookGenerator(current_program, incoming_plugintool, addresses_to_hook,backtracer_type);
            System.out.println(hook);
            if (hook.equals(CustomBacktracerUtils.error_plugin_not_loaded))
            {
                hook="console.log(\""+CustomBacktracerUtils.error_plugin_not_loaded+"\");";
            }
            JSAgentPreparer.add_custom_hooks(hook);

        }
        

        
        cp.print_to_console("Selection Options have been applied to the JS Agent.");
        
        

    }

}
