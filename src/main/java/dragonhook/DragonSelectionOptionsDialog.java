package dragonhook;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ToolTipManager;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.VerticalLayout;

/*
 * This class is responsible for creating the window of the Selection Options, but also serves as the object
 * that is passed around containing the user's selection options, from which actions are performed.
 */
public class DragonSelectionOptionsDialog extends DialogComponentProvider {

    protected PluginTool tool;
    protected Program current_program;
    protected Plugin incoming_plugin;
    public boolean isOKpressed;
    protected ProgramSelection incoming_selection;
    
    //Function Data Retrieval options
    public ButtonGroup FunctionDataRetrievalButtonGroup;
    public GRadioButton FunctionDataRetrievalRadioButtonBulk;
    public GRadioButton FunctionDataRetrievalRadioButtonOneByOne;
    
    //Dynamic call options
    public JCheckBox StalkSelectedDynamicCallsCheckBox;
    public Boolean isStalkSelectedDynamicCallsCheckBoxchecked=false;
    
    public JCheckBox DynCalls_OnlyStalkThreadsWithNameCheckBox;
    public Boolean isDynCalls_OnlyStalkThreadsWithNameCheckBoxchecked=false;
    public JTextField DynCalls_OnlyStalkThreadsWithNameTextField;
    
    public ButtonGroup StalkingMethodButtonGroup;
    public GRadioButton StalkingMethodRadioButtonBuiltin;
    public GRadioButton StalkingMethodRadioButtonMarkingThreads;
    
    public JLabel MaxTimesToUpdateCodeUnitInGhidraDBLabel;
    public JComboBox<String> MaxTimesToUpdateCodeUnitInGhidraDBComboBox;

    public JCheckBox DynCalls_StalkOtherModulesCheckBox;
    public Boolean isDynCalls_StalkOtherModulesCheckBoxchecked=false;
    
    
    //Call tracing options
    public JCheckBox StalkForCallTracingCheckBox;
    public Boolean isStalkForCallTracingCheckBoxchecked=false;
    
    public JCheckBox CallTracing_OnlyStalkThreadsWithNameCheckBox;
    public Boolean isCallTracing_OnlyStalkThreadsWithNameCheckBoxchecked=false;
    public JTextField CallTracing_OnlyStalkThreadsWithNameTextField;
    
    public JCheckBox CallTraceOutsideOurModuleCheckBox;
    public Boolean isCallTraceOutsideOurModuleCheckBoxchecked=false;

    public JCheckBox CallTracing_StalkOtherModulesCheckBox;
    public Boolean isCallTracing_StalkOtherModulesCheckBoxchecked=false;
    
    
    //String reference resolution options
    public JCheckBox ResolveStringsWithoutReferencesCheckBox;
    public Boolean isResolveStringsWithoutReferencesCheckBoxchecked=false;

    public JCheckBox StringRefs_AlsoIncludeStringsWithReferencesCheckBox;
    public Boolean isStringRefs_AlsoIncludeStringsWithReferencesCheckBoxchecked=false;

    public JCheckBox StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox;
    public Boolean isStringRefs_AlsoInstrumentRegisterBasedAccessesCheckBoxchecked=false;

    public JCheckBox StringRefs_OnlyStalkThreadsWithNameCheckBox;
    public Boolean isStringRefs_OnlyStalkThreadsWithNameCheckBoxchecked=false;
    public JTextField StringRefs_OnlyStalkThreadsWithNameTextField;

    public JCheckBox StringRefs_StalkOtherModulesCheckBox;
    public Boolean isStringRefs_StalkOtherModulesCheckBoxchecked=false;

    public JLabel MaxTimesToLogEachStringReferenceLabel;
    public JComboBox<String> MaxTimesToLogEachStringReferenceComboBox;

    public JLabel StringRefs_SecondsBeforeDroppingRegisterTierLabel;
    public JComboBox<String> StringRefs_SecondsBeforeDroppingRegisterTierComboBox;


    //Hardware Watchpoint options
    public JCheckBox SetHardwareWatchPointCheckBox;
    public Boolean isSetHardwareWatchPointCheckBoxchecked=false;
    
    public JLabel MaxTimesLogWatchpointsLabel;
    public JComboBox<String> MaxTimesLogWatchpointsComboBox;
    
    public JLabel WatchpointTriggerOnOperationLabel;
    public JComboBox<String> WatchpointTriggerOnOperationComboBox;
    
    
    //Backtrace options
    public JCheckBox CustomBackTraceFromSelectedAddressesCheckBox;
    public Boolean isCustomBackTraceFromSelectedAddressesCheckBoxchecked=false;
    
    public JLabel BacktrackerTypeLabel;
    public JComboBox<String> BacktrackerTypeComboBox;
    
    public JLabel BacktraceFunctionsOrAddressesLabel;
    public JComboBox<String> BacktraceFunctionsOrAddressesComboBox;
    
    public JLabel BacktraceFunctionsByRegexLabel;
    public JTextField BacktraceFunctionsByRegexTextField;

    public JCheckBox PrecomputeComputedCallReturnAddressesCheckBox;
    public Boolean isPrecomputeComputedCallReturnAddressesCheckBoxchecked=false;
      
    
    //General options
    public JCheckBox ResetAgentContentsBeforePerformingChangesCheckBox;
    public Boolean isResetAgentContentsBeforePerformingChangesCheckBoxchecked=false;
    
    public DragonSelectionOptionsDialog(String title, PluginTool tool, Program current_program , ProgramSelection incoming_selection) {
        super(title, true, true, true, false);
        this.tool = tool;
        this.current_program=current_program;
        this.isOKpressed=false;
        this.incoming_selection=incoming_selection;
        
        
        addWorkPanel(create());
        //setFocusComponent(ReferencestoAddressCheckBox);
        addOKButton();
        addCancelButton();
        setDefaultButton(okButton);
    }
    
    

    public void show_window() 
    {
        show_window(tool.getActiveWindow());
    }
    
    
    //Several of the options below carry a long explanation in their tooltip, and swing hides a tooltip
    //after 4 seconds by default, which is not enough time to read them. The change is scoped to while
    //this dialog is open: ToolTipManager is a process wide singleton, so the previous values are put
    //back afterwards rather than left altered for the rest of ghidra. tool.showDialog() blocks here
    //because this dialog is modal, so the finally really does run when the dialog closes.
    public static int milliseconds_before_a_tooltip_is_hidden=120000;   //two minutes
    public static int milliseconds_before_a_tooltip_appears=350;

    public void show_window(Component centeredOverComponent) 
    {
        initDialogForSelectionOptions();

        ToolTipManager tooltip_manager=ToolTipManager.sharedInstance();
        int previous_dismiss_delay=tooltip_manager.getDismissDelay();
        int previous_initial_delay=tooltip_manager.getInitialDelay();
        int previous_reshow_delay=tooltip_manager.getReshowDelay();
        try
        {
            tooltip_manager.setDismissDelay(milliseconds_before_a_tooltip_is_hidden);
            tooltip_manager.setInitialDelay(milliseconds_before_a_tooltip_appears);
            tooltip_manager.setReshowDelay(0);
            tool.showDialog(this, centeredOverComponent);
        }
        finally
        {
            tooltip_manager.setDismissDelay(previous_dismiss_delay);
            tooltip_manager.setInitialDelay(previous_initial_delay);
            tooltip_manager.setReshowDelay(previous_reshow_delay);
        }
    }
    
    
    
    protected void initDialogForSelectionOptions() 
    {

        setTitle("DragonHook Selection Options");
        ResetAgentContentsBeforePerformingChangesCheckBox.setSelected(true);
        DynCalls_OnlyStalkThreadsWithNameCheckBox.setEnabled(false);
        DynCalls_OnlyStalkThreadsWithNameTextField.setEnabled(false);
        StalkingMethodRadioButtonBuiltin.setEnabled(false);
        StalkingMethodRadioButtonMarkingThreads.setEnabled(false);
        MaxTimesToUpdateCodeUnitInGhidraDBLabel.setEnabled(false);
        MaxTimesToUpdateCodeUnitInGhidraDBComboBox.setEnabled(false);
        
        CallTracing_OnlyStalkThreadsWithNameCheckBox.setEnabled(false);
        CallTracing_OnlyStalkThreadsWithNameTextField.setEnabled(false);
        CallTraceOutsideOurModuleCheckBox.setEnabled(false);
        
        DynCalls_StalkOtherModulesCheckBox.setEnabled(false);
        CallTracing_StalkOtherModulesCheckBox.setEnabled(false);
        StringRefs_StalkOtherModulesCheckBox.setEnabled(false);
        StringRefs_AlsoIncludeStringsWithReferencesCheckBox.setEnabled(false);
        StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.setEnabled(false);
        StringRefs_OnlyStalkThreadsWithNameCheckBox.setEnabled(false);
        StringRefs_OnlyStalkThreadsWithNameTextField.setEnabled(false);
        MaxTimesToLogEachStringReferenceLabel.setEnabled(false);
        MaxTimesToLogEachStringReferenceComboBox.setEnabled(false);
        StringRefs_SecondsBeforeDroppingRegisterTierLabel.setEnabled(false);
        StringRefs_SecondsBeforeDroppingRegisterTierComboBox.setEnabled(false);

        MaxTimesLogWatchpointsLabel.setEnabled(false);
        MaxTimesLogWatchpointsComboBox.setEnabled(false);
        WatchpointTriggerOnOperationLabel.setEnabled(false);
        WatchpointTriggerOnOperationComboBox.setEnabled(false);
        
        BacktrackerTypeLabel.setEnabled(false);
        BacktrackerTypeComboBox.setEnabled(false);
        BacktraceFunctionsOrAddressesLabel.setEnabled(false);
        BacktraceFunctionsOrAddressesComboBox.setEnabled(false);
        BacktraceFunctionsByRegexLabel.setEnabled(false);
        BacktraceFunctionsByRegexTextField.setEnabled(false);
        PrecomputeComputedCallReturnAddressesCheckBox.setEnabled(false);
                
        clearStatusText();

    }
    
    

    /**
     * Define the Main panel for the dialog.
     */
    private JPanel create() {

        StalkSelectedDynamicCallsCheckBox = new GCheckBox("Stalk and resolve the targets of the selected dynamic calls");
        StalkSelectedDynamicCallsCheckBox.setToolTipText(
            "Take the selected addresses, extract the ones containing dynamic calls and generate Frida code which stalks them, resolving their target during runtime and updating the GhidraDB.");
        
        

        FunctionDataRetrievalButtonGroup= new ButtonGroup();
        FunctionDataRetrievalRadioButtonBulk = new GRadioButton("Retrieve function data from GhidraDB at first, all at once (recommended)");
        FunctionDataRetrievalRadioButtonOneByOne = new GRadioButton("Retrieve function data from GhidraDB live, when they are needed");
        FunctionDataRetrievalButtonGroup.add(FunctionDataRetrievalRadioButtonBulk);
        FunctionDataRetrievalButtonGroup.add(FunctionDataRetrievalRadioButtonOneByOne);
        FunctionDataRetrievalRadioButtonBulk.setSelected(true);
        
        
        StalkingMethodButtonGroup= new ButtonGroup();
        StalkingMethodRadioButtonBuiltin = new GRadioButton("Stalk through builtin method (slower, more prone to crashing, more reliable Stalker output)");
        StalkingMethodRadioButtonMarkingThreads = new GRadioButton("Stalk through Marking Threads method, which marks the thread to log the next instruction of a dynamic call");
        StalkingMethodButtonGroup.add(StalkingMethodRadioButtonBuiltin);
        StalkingMethodButtonGroup.add(StalkingMethodRadioButtonMarkingThreads);
        StalkingMethodRadioButtonBuiltin.setSelected(true);
        
        DynCalls_OnlyStalkThreadsWithNameCheckBox= new GCheckBox("Only Stalk threads whose lowercase name contains: ");
        DynCalls_OnlyStalkThreadsWithNameCheckBox.setToolTipText(
                "<html>In certain environments such as Android, stalking all threads is unstable and leads to crashes.<br>However, usually only what we need is to stalk a specific thread (check stdout for thread names). For example, only the thread \"UnityMain\" may need to be stalked.<html>");
        DynCalls_OnlyStalkThreadsWithNameTextField = new JTextField(10);


        MaxTimesToUpdateCodeUnitInGhidraDBLabel= new JLabel("Maximum times to update each dynamic call location and target of call, in GhidraDB: ");
        MaxTimesToUpdateCodeUnitInGhidraDBLabel.setToolTipText("<html>Dynamic calls can call different targets each time. This field controls how many times (for each dynamic call), the result will be logged.<br>This limit is set for the Frida side. There is also the hard DOS limit from the Ghidra side, as configured from the config file.<html>");
        String[] maximum_updates_to_a_certain_codeunit= {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15"};
        MaxTimesToUpdateCodeUnitInGhidraDBComboBox=new JComboBox<>(maximum_updates_to_a_certain_codeunit);
        MaxTimesToUpdateCodeUnitInGhidraDBComboBox.setSelectedIndex(0);

        DynCalls_StalkOtherModulesCheckBox = new GCheckBox("Instrument other modules too (needed to resolve a call whose target is in another module)");
        DynCalls_StalkOtherModulesCheckBox.setSelected(true);
        DynCalls_StalkOtherModulesCheckBox.setToolTipText(
            "<html>On by default, and needed here: a dynamic call whose target is in another module can only be resolved if that module is stalked too.<br>"
            + "If you uncheck this, every other module is EXCLUDED from Stalker. That is much faster, but a call into an excluded module runs natively,<br>"
            + "so the next block Stalker sees is the return continuation and the target is recorded as a possible Stalker issue instead of the real callee.<html>");
        
        
        
        
        
        
        StalkForCallTracingCheckBox = new GCheckBox("Stalk all calls, creating a call trace");
        StalkForCallTracingCheckBox.setToolTipText(
            "<html>Use the Stalker builtin method to trace all calls and rets, so that a call trace is displayed in the standard output file.<br>This option is not related to the current selection, all the called functions inside the current module will be logged.<html>");
        
        CallTracing_OnlyStalkThreadsWithNameCheckBox= new GCheckBox("Only Stalk threads whose lowercase name contains: ");
        CallTracing_OnlyStalkThreadsWithNameCheckBox.setToolTipText(
                "<html>In certain environments such as Android, stalking all threads is unstable and leads to crashes.<br>However, usually only what we need is to stalk a specific thread (check stdout for thread names). For example, only the thread \"UnityMain\" may need to be stalked.<html>");
        CallTracing_OnlyStalkThreadsWithNameTextField = new JTextField(10);
        
        CallTraceOutsideOurModuleCheckBox = new GCheckBox("Include calls whose BOTH ends are outside the examined module in the trace");
        CallTraceOutsideOurModuleCheckBox.setToolTipText(
            "<html>This is a <b>filter on the trace</b>, not an instrumentation switch. Stalker has already produced the event and already paid for it;<br>"
            + "this only decides whether it is printed.<br>"
            + "<br>"
            + "Unselected: an event is dropped when <i>both</i> of its endpoints are outside the examined module. Calls that cross the boundary in either<br>"
            + "direction are still traced, so you see the module talking to the outside world without the noise of the outside world talking to itself.<br>"
            + "Selected: nothing is filtered.<br>"
            + "<br>"
            + "It depends on the option above: a module that is not instrumented emits no events at all, so with \"Instrument other modules too\"<br>"
            + "switched off there is nothing for this filter to let through. That is why it is disabled in that case.<html>");

        CallTracing_StalkOtherModulesCheckBox = new GCheckBox("Instrument other modules too (needed to see anything happening inside them)");
        CallTracing_StalkOtherModulesCheckBox.setSelected(true);
        CallTracing_StalkOtherModulesCheckBox.setToolTipText(
            "<html>On by default. If you uncheck this, every other module is EXCLUDED from Stalker, which is much faster but means no call or ret inside another module<br>"
            + "produces an event at all. The option above (trace calls outside our module) then has nothing to report, so leave this on if you want an external trace.<html>");


        ResolveStringsWithoutReferencesCheckBox = new GCheckBox("Stalk and resolve the references of the SELECTED STRINGS  (x64, x86 and ARM64)");
        ResolveStringsWithoutReferencesCheckBox.setToolTipText(
            "<html>Select the <b>strings</b> whose references you want to find, not code. A cancellable task collects them when you press OK.<br>"
            + "By default only the selected strings that ghidra has no references for are kept, since those are the ones static analysis missed.<br>"
            + "The whole examined module is then stalked, and each instruction is examined to work out which address it forms or touches.<br>"
            + "When that address falls inside one of those strings, an xref and comments are written into the GhidraDB.<br>"
            + "<br>"
            + "<b>Supported architectures:</b> operand decoding is implemented for <b>x64</b>, <b>x86 (32 bit)</b> and <b>ARM64</b>.<br>"
            + "&nbsp;&nbsp;x64: rip relative forms (lea [rip+x], mov [rip+x]) are resolved while the code is instrumented, at no runtime cost.<br>"
            + "&nbsp;&nbsp;ARM64: adrp+add and adrp+ldr pairs are resolved the same way, also for free.<br>"
            + "&nbsp;&nbsp;x86 32 bit: there is no PC relative addressing, so position independent code builds string addresses from a GOT base<br>"
            + "&nbsp;&nbsp;register. Those need the register based option below; only non PIC absolute immediates resolve without it.<br>"
            + "On any other architecture only absolute immediates will be found.<html>");

        StringRefs_StalkOtherModulesCheckBox = new GCheckBox("Instrument other modules too (only useful if the code forming the address lives elsewhere)");
        StringRefs_StalkOtherModulesCheckBox.setToolTipText(
            "<html>OFF by default, unlike the other Stalker features: only instructions inside the examined module are ever examined for string references,<br>"
            + "so stalking the rest of the process is pure cost. Turn it on only if the code that forms the address lives in another module (a helper in a shared library, for instance).<html>");

        StringRefs_AlsoIncludeStringsWithReferencesCheckBox = new GCheckBox("Also include selected strings that already have static references");
        StringRefs_AlsoIncludeStringsWithReferencesCheckBox.setToolTipText(
            "<html>Off by default: a string ghidra already has references for is usually understood, and including it only adds noise.<br>"
            + "Turn it on to confirm at runtime which of the known references are actually taken, or to find additional callers of a string that is already referenced from somewhere else.<html>");

        StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox = new GCheckBox("Also resolve addresses built from registers (slower, needed for table driven string access)");
        StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.setSelected(true);
        StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.setToolTipText(
            "<html>PC relative references are resolved for free while the block is compiled.<br>"
            + "An address held in a register can only be computed while the instruction runs, which needs a callout on every such instruction in the module.<br>"
            + "<br>"
            + "<b>Cost:</b> that callout stays attached for the life of the process and fires on EVERY execution of the instruction. It is only removed once<br>"
            + "the instruction reaches its log limit, which happens only if it actually referenced one of the strings, so instructions that never touch one<br>"
            + "keep paying. Expect a large, permanent slowdown on hot code.<br>"
            + "<br>"
            + "<b>Required on x86 32 bit</b>, where position independent code forms string addresses from a GOT base register rather than PC relative.<br>"
            + "On x64 and ARM64 you can leave it off and still catch the usual rip relative / adrp+add forms.<html>");

        StringRefs_OnlyStalkThreadsWithNameCheckBox= new GCheckBox("Only Stalk threads whose lowercase name contains: ");
        StringRefs_OnlyStalkThreadsWithNameCheckBox.setToolTipText(
                "<html>In certain environments such as Android, stalking all threads is unstable and leads to crashes.<br>However, usually only what we need is to stalk a specific thread (check stdout for thread names). For example, only the thread \"UnityMain\" may need to be stalked.<html>");
        StringRefs_OnlyStalkThreadsWithNameTextField = new JTextField(10);

        MaxTimesToLogEachStringReferenceLabel= new JLabel("Maximum times to log each instruction that references such a string, in GhidraDB: ");
        MaxTimesToLogEachStringReferenceLabel.setToolTipText("<html>An instruction can be executed a great many times. This field controls how many times each one will be logged.<br>This limit is set for the Frida side. There is also the hard DOS limit from the Ghidra side, as configured from the config file.<html>");
        String[] maximum_times_to_log_a_string_reference= {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15"};
        MaxTimesToLogEachStringReferenceComboBox=new JComboBox<>(maximum_times_to_log_a_string_reference);
        MaxTimesToLogEachStringReferenceComboBox.setSelectedIndex(0);

        StringRefs_SecondsBeforeDroppingRegisterTierLabel= new JLabel("Stop resolving register based addresses after this many seconds (0 = never stop): ");
        StringRefs_SecondsBeforeDroppingRegisterTierLabel.setToolTipText(
            "<html>Puts a time limit on the expensive half of this feature, and only on that half.<br>"
            + "<br>"
            + "<b>What it does.</b> Resolving an address held in a register needs a Frida callout on every such instruction in the module, and that callout<br>"
            + "keeps firing on every execution for as long as the process lives. When this timer expires the agent switches that off: it clears the flag and<br>"
            + "then unfollows and re-follows each stalked thread, which throws away the instrumented code cache so the callouts are really gone rather than<br>"
            + "just disabled. Frida has no \"invalidate everything\" call, which is why the threads have to be re-followed.<br>"
            + "<br>"
            + "<b>What keeps working afterwards.</b> Everything that is resolved while the code is being instrumented, at no runtime cost: rip relative forms<br>"
            + "on x64, adrp+add and adrp+ldr on ARM64, and absolute immediates on all of them. Those carry on for the whole session, so you keep finding<br>"
            + "references after the timer fires, just not the ones that need live register values.<br>"
            + "<br>"
            + "<b>When to use it.</b> The register tier earns its cost early: initialisation, config and argument parsing, first use paths. Its cost, on the<br>"
            + "other hand, grows with how long you leave it on. A window of 30 to 60 seconds after the module loads usually captures the interesting work and<br>"
            + "then hands the process back its normal speed.<br>"
            + "<br>"
            + "The countdown starts when the examined module is found, not when the agent loads, so time spent before the target reaches your module does not<br>"
            + "eat into the window. Pick 0 to keep the register tier on for the whole session.<html>");
        String[] seconds_before_dropping_the_register_tier= {"0","10","20","30","45","60","90","120","300","600"};
        StringRefs_SecondsBeforeDroppingRegisterTierComboBox=new JComboBox<>(seconds_before_dropping_the_register_tier);
        StringRefs_SecondsBeforeDroppingRegisterTierComboBox.setSelectedIndex(0);
        StringRefs_SecondsBeforeDroppingRegisterTierComboBox.setToolTipText(
            StringRefs_SecondsBeforeDroppingRegisterTierLabel.getToolTipText());
        
        
        
        
        //add action listeners
        StalkSelectedDynamicCallsCheckBox.addActionListener( e -> {
            boolean is_stalking_dyncalls_selected=StalkSelectedDynamicCallsCheckBox.isSelected();
            DynCalls_OnlyStalkThreadsWithNameCheckBox.setEnabled(is_stalking_dyncalls_selected);
            DynCalls_OnlyStalkThreadsWithNameTextField.setEnabled(is_stalking_dyncalls_selected);
            StalkingMethodRadioButtonBuiltin.setEnabled(is_stalking_dyncalls_selected);
            StalkingMethodRadioButtonMarkingThreads.setEnabled(is_stalking_dyncalls_selected);
            MaxTimesToUpdateCodeUnitInGhidraDBLabel.setEnabled(is_stalking_dyncalls_selected);
            MaxTimesToUpdateCodeUnitInGhidraDBComboBox.setEnabled(is_stalking_dyncalls_selected);
            DynCalls_StalkOtherModulesCheckBox.setEnabled(is_stalking_dyncalls_selected);
            
            StalkForCallTracingCheckBox.setEnabled(!is_stalking_dyncalls_selected);  //disable the other Stalker options if selected
            ResolveStringsWithoutReferencesCheckBox.setEnabled(!is_stalking_dyncalls_selected);
         });
        
        StalkForCallTracingCheckBox.addActionListener( e -> {
            boolean is_stalking_for_call_traces_selected=StalkForCallTracingCheckBox.isSelected();
            CallTracing_OnlyStalkThreadsWithNameCheckBox.setEnabled(is_stalking_for_call_traces_selected);
            CallTracing_OnlyStalkThreadsWithNameTextField.setEnabled(is_stalking_for_call_traces_selected);
            CallTracing_StalkOtherModulesCheckBox.setEnabled(is_stalking_for_call_traces_selected);
            //the trace filter can only let something through if the other modules are instrumented at all
            CallTraceOutsideOurModuleCheckBox.setEnabled(is_stalking_for_call_traces_selected
                    && CallTracing_StalkOtherModulesCheckBox.isSelected());
            
            StalkSelectedDynamicCallsCheckBox.setEnabled(!is_stalking_for_call_traces_selected); //disable the other Stalker options
            ResolveStringsWithoutReferencesCheckBox.setEnabled(!is_stalking_for_call_traces_selected);
         });

        //Excluding the other modules from Stalker means they emit no call or ret events at all, so the
        //"include purely external calls" filter would have nothing to pass. Rather than let the two
        //options contradict each other, clear and disable the filter when the instrumentation is off.
        CallTracing_StalkOtherModulesCheckBox.addActionListener( e -> {
            boolean other_modules_are_instrumented=(CallTracing_StalkOtherModulesCheckBox.isEnabled()
                    && CallTracing_StalkOtherModulesCheckBox.isSelected());
            if (!other_modules_are_instrumented)
            {
                CallTraceOutsideOurModuleCheckBox.setSelected(false);
            }
            CallTraceOutsideOurModuleCheckBox.setEnabled(other_modules_are_instrumented);
         });

        ResolveStringsWithoutReferencesCheckBox.addActionListener( e -> {
            boolean is_resolving_string_refs_selected=ResolveStringsWithoutReferencesCheckBox.isSelected();
            StringRefs_StalkOtherModulesCheckBox.setEnabled(is_resolving_string_refs_selected);
            StringRefs_AlsoIncludeStringsWithReferencesCheckBox.setEnabled(is_resolving_string_refs_selected);
            StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.setEnabled(is_resolving_string_refs_selected);
            StringRefs_OnlyStalkThreadsWithNameCheckBox.setEnabled(is_resolving_string_refs_selected);
            StringRefs_OnlyStalkThreadsWithNameTextField.setEnabled(is_resolving_string_refs_selected);
            MaxTimesToLogEachStringReferenceLabel.setEnabled(is_resolving_string_refs_selected);
            MaxTimesToLogEachStringReferenceComboBox.setEnabled(is_resolving_string_refs_selected);
            boolean the_register_tier_is_on=(is_resolving_string_refs_selected
                    && StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.isSelected());
            StringRefs_SecondsBeforeDroppingRegisterTierLabel.setEnabled(the_register_tier_is_on);
            StringRefs_SecondsBeforeDroppingRegisterTierComboBox.setEnabled(the_register_tier_is_on);

            StalkSelectedDynamicCallsCheckBox.setEnabled(!is_resolving_string_refs_selected); //disable the other Stalker options
            StalkForCallTracingCheckBox.setEnabled(!is_resolving_string_refs_selected);
         });

        //the time limit only means anything while the register based tier is actually on
        StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.addActionListener( e -> {
            boolean the_register_tier_is_on=(StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.isEnabled()
                    && StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.isSelected());
            StringRefs_SecondsBeforeDroppingRegisterTierLabel.setEnabled(the_register_tier_is_on);
            StringRefs_SecondsBeforeDroppingRegisterTierComboBox.setEnabled(the_register_tier_is_on);
         });
        
        
        
        
        
        SetHardwareWatchPointCheckBox = new GCheckBox("Set Hardware Watchpoints to monitor accesses to selected addresses if supported (Highly Experimental)");
        SetHardwareWatchPointCheckBox.setToolTipText(
                "<html>Frida supports hardware watchpoints, if the hardware itself provides access to them.<br>This allows for monitoring specific memory addresses, when they are read or written, and noting which code part accessed them."
               +"<br>This option is highly experimental, first ensure that the environment you are in provides access to hardware watchpoints,<br> and then select one or two codeunits in Ghidra and enable the option for them."
               +"<br>Look at the standard output file to see information on the hardware watchpoints. Expect bugs.<html>");
            
            
        MaxTimesLogWatchpointsLabel= new JLabel("Maximum times to trigger watchpoint for a certain codeunit: ");
        MaxTimesLogWatchpointsLabel.setToolTipText("<html>For a certain codeunit, this option specifies the maximum times the corresponding watchpoint is triggered.<br>Then, the watchpoint is removed.<html>");
        String[] maximum_times_to_log_watchpoint= {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","15"};
        MaxTimesLogWatchpointsComboBox=new JComboBox<>(maximum_times_to_log_watchpoint);
        MaxTimesLogWatchpointsComboBox.setSelectedIndex(0);

        WatchpointTriggerOnOperationLabel= new JLabel("Operation on which the watchpoint is triggered: ");
        WatchpointTriggerOnOperationLabel.setToolTipText("<html>Operation on which the watchpoint is triggered.<html>");
        String[] watchpoint_operation= {"read","write","read/write (unreliable, not recommended)"};
        WatchpointTriggerOnOperationComboBox=new JComboBox<>(watchpoint_operation);
        WatchpointTriggerOnOperationComboBox.setSelectedIndex(0);
        
        //add the action listener too
        SetHardwareWatchPointCheckBox.addActionListener( e -> {
            boolean is_setting_watchpoints_selected=SetHardwareWatchPointCheckBox.isSelected();
            MaxTimesLogWatchpointsLabel.setEnabled(is_setting_watchpoints_selected);
            MaxTimesLogWatchpointsComboBox.setEnabled(is_setting_watchpoints_selected);
            WatchpointTriggerOnOperationLabel.setEnabled(is_setting_watchpoints_selected);
            WatchpointTriggerOnOperationComboBox.setEnabled(is_setting_watchpoints_selected);
         });
        
        
        CustomBackTraceFromSelectedAddressesCheckBox=new GCheckBox("Use Custom Backtracer (requires Frida Hook Generator plugin for Ghidra)");
        CustomBackTraceFromSelectedAddressesCheckBox.setToolTipText(
                "<html>Having access to the Ghidra DB allows us to add information to the old backtracer, specifically which function each address belongs to (if it falls within our module).<br>The Frida Hook Generator plugin (https://github.com/CENSUS/ghidra-frida-hook-gen) is required to be installed.<html>");

        
        BacktrackerTypeLabel= new JLabel("Which Frida Backtracer backend to use: ");
        BacktrackerTypeLabel.setToolTipText("<html>Which Frida Backtracer backend to use.<html>");
        String[] backtracer_options= {"Backtracer.FUZZY","Backtracer.ACCURATE"};
        BacktrackerTypeComboBox=new JComboBox<>(backtracer_options);
        BacktrackerTypeComboBox.setSelectedIndex(0);
        
        
        BacktraceFunctionsOrAddressesLabel= new JLabel("Hook the following and use Custom Backtracer : ");
        BacktraceFunctionsOrAddressesLabel.setToolTipText("<html>Which Frida Backtracer backend to use.<html>");
        String[] backtracer_hooks_generation_based_on= {"Functions holding selected addresses","Selected addresses", "Ignore selection and use regex for Function Names"};
        BacktraceFunctionsOrAddressesComboBox=new JComboBox<>(backtracer_hooks_generation_based_on);
        BacktraceFunctionsOrAddressesComboBox.setSelectedIndex(0);
        

        BacktraceFunctionsByRegexLabel= new JLabel("Case Insensitive regex to match function names for which Custom Backtracer will be used: ");
        BacktraceFunctionsByRegexTextField = new JTextField(10);


        PrecomputeComputedCallReturnAddressesCheckBox=new GCheckBox("Precompute the return addresses of all computed calls (launches a scan of the whole program)");
        PrecomputeComputedCallReturnAddressesCheckBox.setSelected(true);
        PrecomputeComputedCallReturnAddressesCheckBox.setToolTipText(
                "<html>The backtracer only writes to the Ghidra DB when the call that reached the hooked function was one that Ghidra could not resolve statically.<br>"
                + "Answering that at runtime costs one request to Ghidra per hooked call, and it <b>blocks the hooked thread</b> until the reply arrives, which can freeze the target.<br>"
                + "With this enabled, a cancellable scan of every instruction in the program runs now and the answer is baked into the agent as a lookup table.<br>"
                + "Leave it unchecked to keep the previous behaviour of querying Ghidra at runtime.<html>");
        
        
        
        //add the action listener too
        CustomBackTraceFromSelectedAddressesCheckBox.addActionListener( e -> {
            boolean is_using_custom_backtracer_selected=CustomBackTraceFromSelectedAddressesCheckBox.isSelected();
            BacktrackerTypeLabel.setEnabled(is_using_custom_backtracer_selected);
            BacktrackerTypeComboBox.setEnabled(is_using_custom_backtracer_selected);
            BacktraceFunctionsOrAddressesLabel.setEnabled(is_using_custom_backtracer_selected);
            BacktraceFunctionsOrAddressesComboBox.setEnabled(is_using_custom_backtracer_selected);
            
            if (!is_using_custom_backtracer_selected)
            {
                BacktraceFunctionsByRegexLabel.setEnabled(false);
                BacktraceFunctionsByRegexTextField.setEnabled(false);
            }
            
            boolean are_we_using_regex=
                    (BacktraceFunctionsOrAddressesComboBox.isEnabled() && BacktraceFunctionsOrAddressesComboBox.getSelectedIndex()==2);
            
            BacktraceFunctionsByRegexLabel.setEnabled(are_we_using_regex);
            BacktraceFunctionsByRegexTextField.setEnabled(are_we_using_regex);

            PrecomputeComputedCallReturnAddressesCheckBox.setEnabled(is_using_custom_backtracer_selected);
         });
        
        
        //enable if regex is selected
        BacktraceFunctionsOrAddressesComboBox.addActionListener( e -> {
            boolean are_we_using_regex=
                    (BacktraceFunctionsOrAddressesComboBox.isEnabled() && BacktraceFunctionsOrAddressesComboBox.getSelectedIndex()==2);
            
            BacktraceFunctionsByRegexLabel.setEnabled(are_we_using_regex);
            BacktraceFunctionsByRegexTextField.setEnabled(are_we_using_regex);
         });
        
        
        
        
        ResetAgentContentsBeforePerformingChangesCheckBox = new GCheckBox("Reset JS Agent script to default before applying the Selection Options to it");
        ResetAgentContentsBeforePerformingChangesCheckBox.setToolTipText(
            "The JS Agent is recommended to be reset between runs. This options resets it to default before applying any other selected option.");
        
        
        
        JPanel mainPanel = new JPanel(new VerticalLayout(30));
        JPanel funDataRetrievalOptionsPanel= new JPanel(new VerticalLayout(4));
        JPanel dynamicCallOptionsPanel = new JPanel(new VerticalLayout(4));
        JPanel dynamicCallOptionssubPanel1 = new JPanel(new VerticalLayout(4));
        JPanel dynamicCallOptionssubPanel2 = new JPanel(new HorizontalLayout(4));
        JPanel dynamicCallOptionssubPanel4 = new JPanel(new HorizontalLayout(4));
        JPanel dynamicCallOptionssubPanel5 = new JPanel(new HorizontalLayout(4));
        JPanel callTracingOptionsPanel = new JPanel(new VerticalLayout(4));
        JPanel callTracingOptionssubPanel1 = new JPanel(new HorizontalLayout(4));
        JPanel callTracingOptionssubPanel2 = new JPanel(new HorizontalLayout(4));
        JPanel callTracingOptionssubPanel3 = new JPanel(new HorizontalLayout(4));

        JPanel stringRefsOptionsPanel = new JPanel(new VerticalLayout(4));
        JPanel stringRefsOptionssubPanel1 = new JPanel(new HorizontalLayout(4));
        JPanel stringRefsOptionssubPanel2 = new JPanel(new HorizontalLayout(4));
        JPanel stringRefsOptionssubPanel3 = new JPanel(new HorizontalLayout(4));
        JPanel stringRefsOptionssubPanel4 = new JPanel(new HorizontalLayout(4));
        JPanel stringRefsOptionssubPanel5 = new JPanel(new HorizontalLayout(4));
        JPanel stringRefsOptionssubPanel6 = new JPanel(new HorizontalLayout(4));
        JPanel hardwareWatchpointPanel = new JPanel(new VerticalLayout(4));
        JPanel hardwareWatchpointsubPanel1 = new JPanel(new HorizontalLayout(4));
        JPanel hardwareWatchpointsubPanel2 = new JPanel(new HorizontalLayout(4));
        JPanel customBacktracerPanel = new JPanel(new VerticalLayout(4));
        JPanel customBacktracersubPanel1 = new JPanel(new HorizontalLayout(4));
        JPanel customBacktracersubPanel2 = new JPanel(new HorizontalLayout(4));
        JPanel customBacktracersubPanel3 = new JPanel(new HorizontalLayout(4));
        JPanel customBacktracersubPanel4 = new JPanel(new HorizontalLayout(4));
        JPanel generalOptionsPanel = new JPanel(new VerticalLayout(4));
        
        
        TitledBorder funDataRetrievalBorder =
                BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Function data retrieval options:");
        funDataRetrievalOptionsPanel.setBorder(funDataRetrievalBorder);
            
        TitledBorder dynamicCallBorder =
            BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Dynamic Call options:");
        dynamicCallOptionsPanel.setBorder(dynamicCallBorder);
        
        //indent to the right
        dynamicCallOptionssubPanel1.setBorder(new EmptyBorder(0,20,0,0));
        dynamicCallOptionssubPanel2.setBorder(new EmptyBorder(0,20,0,0));
        dynamicCallOptionssubPanel4.setBorder(new EmptyBorder(0,20,0,0));
        
        
        TitledBorder CallTracingBorder =
                BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Call Tracing options:");
        callTracingOptionsPanel.setBorder(CallTracingBorder);

        TitledBorder StringRefsBorder =
                BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "String reference resolution options:");
        stringRefsOptionsPanel.setBorder(StringRefsBorder);

        stringRefsOptionssubPanel1.setBorder(new EmptyBorder(0,20,0,0));
        stringRefsOptionssubPanel2.setBorder(new EmptyBorder(0,20,0,0));
        stringRefsOptionssubPanel3.setBorder(new EmptyBorder(0,20,0,0));
        stringRefsOptionssubPanel4.setBorder(new EmptyBorder(0,20,0,0));
        stringRefsOptionssubPanel5.setBorder(new EmptyBorder(0,20,0,0));
        stringRefsOptionssubPanel6.setBorder(new EmptyBorder(0,20,0,0));
        
        callTracingOptionssubPanel1.setBorder(new EmptyBorder(0,20,0,0));
        callTracingOptionssubPanel2.setBorder(new EmptyBorder(0,20,0,0));
        callTracingOptionssubPanel3.setBorder(new EmptyBorder(0,20,0,0));
        
        
        TitledBorder HardwareWatchpointBorder =
                BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Hardware Watchpoint options:");
        hardwareWatchpointPanel.setBorder(HardwareWatchpointBorder);
        
        hardwareWatchpointsubPanel1.setBorder(new EmptyBorder(0,20,0,0));
        hardwareWatchpointsubPanel2.setBorder(new EmptyBorder(0,20,0,0));
        
        
        TitledBorder CustomBackTracerBorder =
                BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Custom Backtracer options:");
        customBacktracerPanel.setBorder(CustomBackTracerBorder);
        
        
        customBacktracersubPanel1.setBorder(new EmptyBorder(0,20,0,0));
        customBacktracersubPanel2.setBorder(new EmptyBorder(0,20,0,0));
        customBacktracersubPanel3.setBorder(new EmptyBorder(0,20,0,0));
        customBacktracersubPanel4.setBorder(new EmptyBorder(0,20,0,0));
        
        
        TitledBorder generalOptionsBorder =
                BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "General options:");
        generalOptionsPanel.setBorder(generalOptionsBorder);
        
        
        funDataRetrievalOptionsPanel.add(FunctionDataRetrievalRadioButtonBulk,BorderLayout.NORTH);
        funDataRetrievalOptionsPanel.add(FunctionDataRetrievalRadioButtonOneByOne,BorderLayout.NORTH);

        dynamicCallOptionsPanel.add(StalkSelectedDynamicCallsCheckBox,BorderLayout.NORTH);
        dynamicCallOptionssubPanel1.add(StalkingMethodRadioButtonBuiltin,BorderLayout.NORTH);
        dynamicCallOptionssubPanel1.add(StalkingMethodRadioButtonMarkingThreads,BorderLayout.NORTH);
        dynamicCallOptionssubPanel2.add(DynCalls_OnlyStalkThreadsWithNameCheckBox,BorderLayout.NORTH);
        dynamicCallOptionssubPanel2.add(DynCalls_OnlyStalkThreadsWithNameTextField,BorderLayout.NORTH);
        dynamicCallOptionssubPanel4.add(MaxTimesToUpdateCodeUnitInGhidraDBLabel,BorderLayout.NORTH);
        dynamicCallOptionssubPanel4.add(MaxTimesToUpdateCodeUnitInGhidraDBComboBox,BorderLayout.NORTH);
        dynamicCallOptionsPanel.add(dynamicCallOptionssubPanel1,BorderLayout.NORTH); 
        dynamicCallOptionsPanel.add(dynamicCallOptionssubPanel2,BorderLayout.NORTH);
        dynamicCallOptionssubPanel5.add(DynCalls_StalkOtherModulesCheckBox,BorderLayout.NORTH);
        dynamicCallOptionsPanel.add(dynamicCallOptionssubPanel4,BorderLayout.NORTH);
        dynamicCallOptionsPanel.add(dynamicCallOptionssubPanel5,BorderLayout.NORTH);

        
        callTracingOptionsPanel.add(StalkForCallTracingCheckBox,BorderLayout.NORTH);
        callTracingOptionssubPanel1.add(CallTracing_StalkOtherModulesCheckBox,BorderLayout.NORTH);
        callTracingOptionssubPanel3.add(CallTraceOutsideOurModuleCheckBox,BorderLayout.NORTH);
        callTracingOptionssubPanel2.add(CallTracing_OnlyStalkThreadsWithNameCheckBox,BorderLayout.NORTH);
        callTracingOptionssubPanel2.add(CallTracing_OnlyStalkThreadsWithNameTextField,BorderLayout.NORTH);

        callTracingOptionsPanel.add(callTracingOptionssubPanel1,BorderLayout.NORTH); 
        callTracingOptionsPanel.add(callTracingOptionssubPanel3,BorderLayout.NORTH);
        callTracingOptionsPanel.add(callTracingOptionssubPanel2,BorderLayout.NORTH);


        stringRefsOptionsPanel.add(ResolveStringsWithoutReferencesCheckBox,BorderLayout.NORTH);
        stringRefsOptionssubPanel5.add(StringRefs_StalkOtherModulesCheckBox,BorderLayout.NORTH);
        stringRefsOptionssubPanel1.add(StringRefs_AlsoIncludeStringsWithReferencesCheckBox,BorderLayout.NORTH);
        stringRefsOptionssubPanel6.add(StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox,BorderLayout.NORTH);
        stringRefsOptionssubPanel2.add(StringRefs_OnlyStalkThreadsWithNameCheckBox,BorderLayout.NORTH);
        stringRefsOptionssubPanel2.add(StringRefs_OnlyStalkThreadsWithNameTextField,BorderLayout.NORTH);
        stringRefsOptionssubPanel3.add(MaxTimesToLogEachStringReferenceLabel,BorderLayout.NORTH);
        stringRefsOptionssubPanel3.add(MaxTimesToLogEachStringReferenceComboBox,BorderLayout.NORTH);
        stringRefsOptionssubPanel4.add(StringRefs_SecondsBeforeDroppingRegisterTierLabel,BorderLayout.NORTH);
        stringRefsOptionssubPanel4.add(StringRefs_SecondsBeforeDroppingRegisterTierComboBox,BorderLayout.NORTH);

        stringRefsOptionsPanel.add(stringRefsOptionssubPanel5,BorderLayout.NORTH);
        stringRefsOptionsPanel.add(stringRefsOptionssubPanel1,BorderLayout.NORTH);
        stringRefsOptionsPanel.add(stringRefsOptionssubPanel6,BorderLayout.NORTH);
        stringRefsOptionsPanel.add(stringRefsOptionssubPanel2,BorderLayout.NORTH);
        stringRefsOptionsPanel.add(stringRefsOptionssubPanel3,BorderLayout.NORTH);
        stringRefsOptionsPanel.add(stringRefsOptionssubPanel4,BorderLayout.NORTH);

        
        hardwareWatchpointPanel.add(SetHardwareWatchPointCheckBox,BorderLayout.NORTH);
        hardwareWatchpointsubPanel1.add(MaxTimesLogWatchpointsLabel,BorderLayout.NORTH);
        hardwareWatchpointsubPanel1.add(MaxTimesLogWatchpointsComboBox,BorderLayout.NORTH);
        hardwareWatchpointsubPanel2.add(WatchpointTriggerOnOperationLabel,BorderLayout.NORTH);
        hardwareWatchpointsubPanel2.add(WatchpointTriggerOnOperationComboBox,BorderLayout.NORTH);
        
        hardwareWatchpointPanel.add(hardwareWatchpointsubPanel1,BorderLayout.NORTH); 
        hardwareWatchpointPanel.add(hardwareWatchpointsubPanel2,BorderLayout.NORTH);

        
        customBacktracerPanel.add(CustomBackTraceFromSelectedAddressesCheckBox,BorderLayout.NORTH);
        customBacktracersubPanel1.add(BacktrackerTypeLabel,BorderLayout.NORTH);
        customBacktracersubPanel1.add(BacktrackerTypeComboBox,BorderLayout.NORTH);
        customBacktracersubPanel2.add(BacktraceFunctionsOrAddressesLabel,BorderLayout.NORTH);
        customBacktracersubPanel2.add(BacktraceFunctionsOrAddressesComboBox,BorderLayout.NORTH);
        customBacktracersubPanel3.add(BacktraceFunctionsByRegexLabel,BorderLayout.NORTH);
        customBacktracersubPanel3.add(BacktraceFunctionsByRegexTextField,BorderLayout.NORTH);
        customBacktracersubPanel4.add(PrecomputeComputedCallReturnAddressesCheckBox,BorderLayout.NORTH);
        
        customBacktracerPanel.add(customBacktracersubPanel1,BorderLayout.NORTH);
        customBacktracerPanel.add(customBacktracersubPanel2,BorderLayout.NORTH);
        customBacktracerPanel.add(customBacktracersubPanel3,BorderLayout.NORTH);
        customBacktracerPanel.add(customBacktracersubPanel4,BorderLayout.NORTH);
        
        generalOptionsPanel.add(ResetAgentContentsBeforePerformingChangesCheckBox,BorderLayout.NORTH);

        mainPanel.add(funDataRetrievalOptionsPanel);
        mainPanel.add(dynamicCallOptionsPanel);
        mainPanel.add(callTracingOptionsPanel);
        mainPanel.add(stringRefsOptionsPanel);
        mainPanel.add(hardwareWatchpointPanel);
        
        
        //now get the preferred size before the window grows too large vertically
        Dimension preferred_sz=mainPanel.getPreferredSize();
        
        //add the rest
        mainPanel.add(customBacktracerPanel);
        mainPanel.add(generalOptionsPanel);
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));


        
        JScrollPane scroller = new JScrollPane(mainPanel,JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scroller.getVerticalScrollBar().setUnitIncrement(10); //speed up scrolling a little bit
        JPanel PaneltoReturn = new JPanel();
        PaneltoReturn.setLayout(new BorderLayout());
        PaneltoReturn.add(scroller,BorderLayout.CENTER);
        PaneltoReturn.setPreferredSize(preferred_sz);
        
        return PaneltoReturn;
    }
    

    protected void okCallback() {
        this.isOKpressed=true;
        
        
        if (StalkSelectedDynamicCallsCheckBox.isEnabled() && StalkSelectedDynamicCallsCheckBox.isSelected()) {
            this.isStalkSelectedDynamicCallsCheckBoxchecked=true;
        }
        
        if (DynCalls_OnlyStalkThreadsWithNameCheckBox.isEnabled() && DynCalls_OnlyStalkThreadsWithNameCheckBox.isSelected()) {
            this.isDynCalls_OnlyStalkThreadsWithNameCheckBoxchecked=true;
        }
        
        if (StalkForCallTracingCheckBox.isEnabled() && StalkForCallTracingCheckBox.isSelected()) {
            this.isStalkForCallTracingCheckBoxchecked=true;
        }
        
        if (CallTraceOutsideOurModuleCheckBox.isEnabled() && CallTraceOutsideOurModuleCheckBox.isSelected()) {
            this.isCallTraceOutsideOurModuleCheckBoxchecked=true;
        }
        
        if (CallTracing_OnlyStalkThreadsWithNameCheckBox.isEnabled() && CallTracing_OnlyStalkThreadsWithNameCheckBox.isSelected()) {
            this.isCallTracing_OnlyStalkThreadsWithNameCheckBoxchecked=true;
        }
        
        if (DynCalls_StalkOtherModulesCheckBox.isEnabled() && DynCalls_StalkOtherModulesCheckBox.isSelected()) {
            this.isDynCalls_StalkOtherModulesCheckBoxchecked=true;
        }

        if (CallTracing_StalkOtherModulesCheckBox.isEnabled() && CallTracing_StalkOtherModulesCheckBox.isSelected()) {
            this.isCallTracing_StalkOtherModulesCheckBoxchecked=true;
        }

        if (StringRefs_StalkOtherModulesCheckBox.isEnabled() && StringRefs_StalkOtherModulesCheckBox.isSelected()) {
            this.isStringRefs_StalkOtherModulesCheckBoxchecked=true;
        }

        if (ResolveStringsWithoutReferencesCheckBox.isEnabled() && ResolveStringsWithoutReferencesCheckBox.isSelected()) {
            this.isResolveStringsWithoutReferencesCheckBoxchecked=true;
        }

        if (StringRefs_AlsoIncludeStringsWithReferencesCheckBox.isEnabled() && StringRefs_AlsoIncludeStringsWithReferencesCheckBox.isSelected()) {
            this.isStringRefs_AlsoIncludeStringsWithReferencesCheckBoxchecked=true;
        }

        if (StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.isEnabled() && StringRefs_AlsoInstrumentRegisterBasedAccessesCheckBox.isSelected()) {
            this.isStringRefs_AlsoInstrumentRegisterBasedAccessesCheckBoxchecked=true;
        }

        if (StringRefs_OnlyStalkThreadsWithNameCheckBox.isEnabled() && StringRefs_OnlyStalkThreadsWithNameCheckBox.isSelected()) {
            this.isStringRefs_OnlyStalkThreadsWithNameCheckBoxchecked=true;
        }

        if (SetHardwareWatchPointCheckBox.isEnabled() && SetHardwareWatchPointCheckBox.isSelected()) {
            this.isSetHardwareWatchPointCheckBoxchecked=true;
        }
        
        if (CustomBackTraceFromSelectedAddressesCheckBox.isEnabled() && CustomBackTraceFromSelectedAddressesCheckBox.isSelected()) {
            this.isCustomBackTraceFromSelectedAddressesCheckBoxchecked=true;
        }

        if (PrecomputeComputedCallReturnAddressesCheckBox.isEnabled() && PrecomputeComputedCallReturnAddressesCheckBox.isSelected()) {
            this.isPrecomputeComputedCallReturnAddressesCheckBoxchecked=true;
        }
 
        if (ResetAgentContentsBeforePerformingChangesCheckBox.isEnabled() && ResetAgentContentsBeforePerformingChangesCheckBox.isSelected()) {
            this.isResetAgentContentsBeforePerformingChangesCheckBoxchecked=true;
        }
        
        

        
        close();
    }
        
    
}
