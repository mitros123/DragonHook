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
    
    
    //Call tracing options
    public JCheckBox StalkForCallTracingCheckBox;
    public Boolean isStalkForCallTracingCheckBoxchecked=false;
    
    public JCheckBox CallTracing_OnlyStalkThreadsWithNameCheckBox;
    public Boolean isCallTracing_OnlyStalkThreadsWithNameCheckBoxchecked=false;
    public JTextField CallTracing_OnlyStalkThreadsWithNameTextField;
    
    public JCheckBox CallTraceOutsideOurModuleCheckBox;
    public Boolean isCallTraceOutsideOurModuleCheckBoxchecked=false;
    
    
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
    
    
    public void show_window(Component centeredOverComponent) 
    {
        initDialogForSelectionOptions();
        tool.showDialog(this, centeredOverComponent);
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
        
        
        
        
        
        
        StalkForCallTracingCheckBox = new GCheckBox("Stalk all calls, creating a call trace");
        StalkForCallTracingCheckBox.setToolTipText(
            "<html>Use the Stalker builtin method to trace all calls and rets, so that a call trace is displayed in the standard output file.<br>This option is not related to the current selection, all the called functions inside the current module will be logged.<html>");
        
        CallTracing_OnlyStalkThreadsWithNameCheckBox= new GCheckBox("Only Stalk threads whose lowercase name contains: ");
        CallTracing_OnlyStalkThreadsWithNameCheckBox.setToolTipText(
                "<html>In certain environments such as Android, stalking all threads is unstable and leads to crashes.<br>However, usually only what we need is to stalk a specific thread (check stdout for thread names). For example, only the thread \"UnityMain\" may need to be stalked.<html>");
        CallTracing_OnlyStalkThreadsWithNameTextField = new JTextField(10);
        
        CallTraceOutsideOurModuleCheckBox = new GCheckBox("Trace and log all calls, even outside our module");
        CallTraceOutsideOurModuleCheckBox.setToolTipText("<html>If selected, the trace will include calls that are outside the examined module.<br> If unselected, only the functions inside the module will be included, and their direct interactions outside of it<html>");
        
        
        
        
        //add action listeners
        StalkSelectedDynamicCallsCheckBox.addActionListener( e -> {
            boolean is_stalking_dyncalls_selected=StalkSelectedDynamicCallsCheckBox.isSelected();
            DynCalls_OnlyStalkThreadsWithNameCheckBox.setEnabled(is_stalking_dyncalls_selected);
            DynCalls_OnlyStalkThreadsWithNameTextField.setEnabled(is_stalking_dyncalls_selected);
            StalkingMethodRadioButtonBuiltin.setEnabled(is_stalking_dyncalls_selected);
            StalkingMethodRadioButtonMarkingThreads.setEnabled(is_stalking_dyncalls_selected);
            MaxTimesToUpdateCodeUnitInGhidraDBLabel.setEnabled(is_stalking_dyncalls_selected);
            MaxTimesToUpdateCodeUnitInGhidraDBComboBox.setEnabled(is_stalking_dyncalls_selected);
            
            StalkForCallTracingCheckBox.setEnabled(!is_stalking_dyncalls_selected);  //disable the other Stalker option if selected
         });
        
        StalkForCallTracingCheckBox.addActionListener( e -> {
            boolean is_stalking_for_call_traces_selected=StalkForCallTracingCheckBox.isSelected();
            CallTracing_OnlyStalkThreadsWithNameCheckBox.setEnabled(is_stalking_for_call_traces_selected);
            CallTracing_OnlyStalkThreadsWithNameTextField.setEnabled(is_stalking_for_call_traces_selected);
            CallTraceOutsideOurModuleCheckBox.setEnabled(is_stalking_for_call_traces_selected);
            
            StalkSelectedDynamicCallsCheckBox.setEnabled(!is_stalking_for_call_traces_selected); //disable the other Stalker option
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
        JPanel callTracingOptionsPanel = new JPanel(new VerticalLayout(4));
        JPanel callTracingOptionssubPanel1 = new JPanel(new HorizontalLayout(4));
        JPanel callTracingOptionssubPanel2 = new JPanel(new HorizontalLayout(4));
        JPanel hardwareWatchpointPanel = new JPanel(new VerticalLayout(4));
        JPanel hardwareWatchpointsubPanel1 = new JPanel(new HorizontalLayout(4));
        JPanel hardwareWatchpointsubPanel2 = new JPanel(new HorizontalLayout(4));
        JPanel customBacktracerPanel = new JPanel(new VerticalLayout(4));
        JPanel customBacktracersubPanel1 = new JPanel(new HorizontalLayout(4));
        JPanel customBacktracersubPanel2 = new JPanel(new HorizontalLayout(4));
        JPanel customBacktracersubPanel3 = new JPanel(new HorizontalLayout(4));
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
        
        callTracingOptionssubPanel1.setBorder(new EmptyBorder(0,20,0,0));
        callTracingOptionssubPanel2.setBorder(new EmptyBorder(0,20,0,0));
        
        
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
        dynamicCallOptionsPanel.add(dynamicCallOptionssubPanel4,BorderLayout.NORTH);

        
        callTracingOptionsPanel.add(StalkForCallTracingCheckBox,BorderLayout.NORTH);
        callTracingOptionssubPanel1.add(CallTraceOutsideOurModuleCheckBox,BorderLayout.NORTH);
        callTracingOptionssubPanel2.add(CallTracing_OnlyStalkThreadsWithNameCheckBox,BorderLayout.NORTH);
        callTracingOptionssubPanel2.add(CallTracing_OnlyStalkThreadsWithNameTextField,BorderLayout.NORTH);

        callTracingOptionsPanel.add(callTracingOptionssubPanel1,BorderLayout.NORTH); 
        callTracingOptionsPanel.add(callTracingOptionssubPanel2,BorderLayout.NORTH);

        
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
        
        customBacktracerPanel.add(customBacktracersubPanel1,BorderLayout.NORTH);
        customBacktracerPanel.add(customBacktracersubPanel2,BorderLayout.NORTH);
        customBacktracerPanel.add(customBacktracersubPanel3,BorderLayout.NORTH);
        
        generalOptionsPanel.add(ResetAgentContentsBeforePerformingChangesCheckBox,BorderLayout.NORTH);

        mainPanel.add(funDataRetrievalOptionsPanel);
        mainPanel.add(dynamicCallOptionsPanel);
        mainPanel.add(callTracingOptionsPanel);
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
        
        if (SetHardwareWatchPointCheckBox.isEnabled() && SetHardwareWatchPointCheckBox.isSelected()) {
            this.isSetHardwareWatchPointCheckBoxchecked=true;
        }
        
        if (CustomBackTraceFromSelectedAddressesCheckBox.isEnabled() && CustomBackTraceFromSelectedAddressesCheckBox.isSelected()) {
            this.isCustomBackTraceFromSelectedAddressesCheckBoxchecked=true;
        }
 
        if (ResetAgentContentsBeforePerformingChangesCheckBox.isEnabled() && ResetAgentContentsBeforePerformingChangesCheckBox.isSelected()) {
            this.isResetAgentContentsBeforePerformingChangesCheckBoxchecked=true;
        }
        
        

        
        close();
    }
        
    
}
