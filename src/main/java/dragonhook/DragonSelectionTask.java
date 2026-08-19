package dragonhook;

import java.util.ArrayList;

import dragonhook.tasks.custom_backtracer.CustomBacktracerUtils;
import dragonhook.tasks.dynamic_call_tracing.DynamicCallTracingUtils;
import dragonhook.tasks.string_reference_resolution.StringReferenceResolutionUtils;
import dragonhook.tasks.watchpoint_processing.WatchpointProcessingUtils;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.JSAgentPreparer;
import dragonhook.util.PackageChecker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DragonSelectionTask extends Task {

    //volatile primitive, for the reason spelled out on the same field in
    //DragonSelectionAddressRangeGathererTask: written on the task thread, read by the dispatcher on another.
    public volatile boolean is_cancelled;
    protected PluginTool incoming_plugintool;
    protected Program current_program;
    protected DragonSelectionOptionsDialog incoming_selection_options_dialog;
    protected DragonSelectionAddressRangeGathererTask code_unit_gatherer_task;
    
    public DragonSelectionTask(String title, Program incoming_program, PluginTool tool,DragonSelectionOptionsDialog incoming_selection_options_dialog,DragonSelectionAddressRangeGathererTask code_unit_gatherer_task) {
        //Task(String title) means canCancel=false, so monitor.isCancelled() was permanently false and
        //every isCancelled() check inside this task was dead, including the one in the whole program
        //scan for the backtracer's computed call table. No progress bar on purpose: progress is
        //reported as counts inside monitor.setMessage().
        //Arguments are (title, canCancel, hasProgress, isModal).
        super(title, true, false, true);
        this.current_program=incoming_program;
        this.incoming_plugintool=tool;
        this.is_cancelled=false;
        this.incoming_selection_options_dialog=incoming_selection_options_dialog;
        this.code_unit_gatherer_task=code_unit_gatherer_task;
    }
    

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        
        ConsolePrinter cp=new ConsolePrinter(this.incoming_plugintool);

        //The address range gathering runs as its OWN task, with its own monitor, and on cancel it returns an
        //empty range list - which is intended, but it means a cancelled gather is indistinguishable from
        //"nothing was selected" unless its flag is consulted. Our own monitor is not necessarily cancelled,
        //so without this check every feature below would carry on against zero addresses and report that it
        //found nothing, as though the selection had been empty.
        if (this.code_unit_gatherer_task!=null && this.code_unit_gatherer_task.is_cancelled)
        {
            cp.print_to_console("Gathering of the selected address ranges was cancelled, so nothing is applied.");
            this.is_cancelled=true;
            monitor.cancel();
            return;
        }

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

            JSAgentPreparer.set_whether_only_our_module_is_stalked(
                    !this.incoming_selection_options_dialog.isDynCalls_StalkOtherModulesCheckBoxchecked);
            
            
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

            JSAgentPreparer.set_whether_only_our_module_is_stalked(
                    !this.incoming_selection_options_dialog.isCallTracing_StalkOtherModulesCheckBoxchecked);

            JSAgentPreparer.set_call_tracing_before_our_module_is_loaded(
                    this.incoming_selection_options_dialog.isCallTracing_TraceBeforeOurModuleIsLoadedCheckBoxchecked);

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



        //Resolution of references to strings that ghidra sees as unreferenced
        if (this.incoming_selection_options_dialog.isResolveStringsWithoutReferencesCheckBoxchecked)
        {
            ArrayList<Data> strings_to_resolve=
                    StringReferenceResolutionUtils.extract_strings_from_selection(this.current_program,
                            code_unit_gatherer_task.address_ranges_that_are_gathered, monitor,
                            this.incoming_selection_options_dialog.isStringRefs_AlsoIncludeStringsWithReferencesCheckBoxchecked);

            if (strings_to_resolve==null || monitor.isCancelled())
            {
                this.is_cancelled=true;
                monitor.cancel();
                return;
            }

            if (strings_to_resolve.size()==0)
            {
                cp.print_to_console("No strings were found in the selection, string reference resolution was not enabled."
                        +" Select the strings whose references you want to resolve.");
            }
            else
            {
                String js_object_with_strings_to_resolve=
                        StringReferenceResolutionUtils.return_selected_strings_as_js_object(strings_to_resolve,this.current_program);

                JSAgentPreparer.enable_string_reference_resolution(
                        js_object_with_strings_to_resolve,
                        (String) this.incoming_selection_options_dialog.MaxTimesToLogEachStringReferenceComboBox.getSelectedItem(),
                        this.incoming_selection_options_dialog.isStringRefs_AlsoInstrumentRegisterBasedAccessesCheckBoxchecked,
                        this.incoming_selection_options_dialog.isStringRefs_AlsoInstrumentCallArgumentsCheckBoxchecked,
                        this.incoming_selection_options_dialog.isStringRefs_AlsoInstrumentRegisterArithmeticCheckBoxchecked,
                        this.incoming_selection_options_dialog.isStringRefs_StalkOtherModulesCheckBoxchecked);

                JSAgentPreparer.set_whether_only_our_module_is_stalked(
                        !this.incoming_selection_options_dialog.isStringRefs_StalkOtherModulesCheckBoxchecked);

                JSAgentPreparer.set_seconds_before_register_based_string_instrumentation_is_dropped(
                        (String) this.incoming_selection_options_dialog.StringRefs_SecondsBeforeDroppingRegisterTierComboBox.getSelectedItem());

                if (this.incoming_selection_options_dialog.isStringRefs_OnlyStalkThreadsWithNameCheckBoxchecked)
                {
                    String str_that_is_included_in_threadnames=
                            incoming_selection_options_dialog.StringRefs_OnlyStalkThreadsWithNameTextField.getText();
                    JSAgentPreparer.set_name_of_threads_to_be_stalked(str_that_is_included_in_threadnames);
                }

                cp.print_to_console("String reference resolution enabled for "+Integer.toString(strings_to_resolve.size())
                        +" selected strings.");
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

            
            //null means the extraction was cancelled, which is now distinguishable from an empty
            //selection. Without the null check the next line would dereference it.
            if (codeunits_for_watchpoints==null || monitor.isCancelled())
            {
                this.is_cancelled=true;
                monitor.cancel();
                return;
            }

            JSAgentPreparer.enable_hardware_watchpoint_logging((String) this.incoming_selection_options_dialog.MaxTimesLogWatchpointsComboBox.getSelectedItem());

            //restrict which threads get a watchpoint installed, same shape as the three stalker features
            if (this.incoming_selection_options_dialog.isWatchpoints_OnlyUseThreadsWithNameCheckBoxchecked)
            {
                String str_that_is_included_in_threadnames=
                        incoming_selection_options_dialog.Watchpoints_OnlyUseThreadsWithNameTextField.getText();
                JSAgentPreparer.set_name_of_threads_for_watchpoints(str_that_is_included_in_threadnames);
            }
            
            
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
            //Precompute the return addresses of every computed call in the program, so that the agent
            //can decide whether a backtrace came through a computed call with a dictionary lookup.
            //Without it the agent asks ghidra at runtime and blocks the hooked thread each time.
            if (this.incoming_selection_options_dialog.isPrecomputeComputedCallReturnAddressesCheckBoxchecked)
            {
                String js_dict_with_offsets_after_computed_calls=
                        DynamicCallTracingUtils.return_all_offsets_after_computed_calls_as_js_dict(this.current_program, monitor);

                if (js_dict_with_offsets_after_computed_calls==null || monitor.isCancelled())
                {
                    this.is_cancelled=true;
                    monitor.cancel();
                    return;
                }
                JSAgentPreparer.enable_precomputed_offsets_after_computed_calls(js_dict_with_offsets_after_computed_calls);
            }

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
                
            //null means the extraction was cancelled, or the regex was unusable, and is now distinct from
            //"" which means nothing matched. Without the null check the code below would NPE.
            if (addresses_to_hook==null || monitor.isCancelled())
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
