package dragonhook;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.JSAgentPreparer;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class DragonSelectionAction extends DockingAction {

    protected PluginTool tool;
    protected Program current_program;

    //Called by DragonHookPlugin.programActivated/programDeactivated. Without this the program captured
    //when the action was constructed was used forever, so after switching program in Ghidra every offset
    //and every comment went to the WRONG program's database.
    public void set_current_program(Program incoming_program) {
        this.current_program=incoming_program;
    }
    protected ProgramSelection incoming_selection;
    protected Plugin incoming_plugin;
    protected DragonSelectionTaskDispatcher selection_task_dispatcher;
    
    public DragonSelectionAction(DragonHookPlugin plugin, ProgramSelection current_selection) {
        super("DragonHookPlugin", plugin.getName());
        this.tool = plugin.getTool();
        this.current_program = plugin.currentprogram; //may be null initially
        this.incoming_selection=current_selection; //will be null initially
        this.incoming_plugin=plugin;
        init();
    }
    
    private void init() {
        setPopupMenuData(
            new MenuData(new String[] { "DragonHook selection..." }, null,"Dragon-Hook"));
        setDescription("Generate Frida Hooks that will return information from the selected addresses");
    }
    
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    //A pure predicate. Ghidra calls this constantly - on every context change and every menu build - and
    //it used to ASSIGN this.incoming_selection as a side effect, so action state was being mutated from an
    //enablement check.
    @Override
    public boolean isEnabledForContext(ActionContext context) {
        ProgramSelection selection_right_now=((ProgramPlugin)incoming_plugin).getProgramSelection();
        return (selection_right_now!=null && selection_right_now.getNumAddresses()>0);
    }

    @Override
    public void actionPerformed(ActionContext context) {

        //Read the selection HERE rather than trusting whatever the last enablement check happened to
        //store. That is also more correct: the selection can change between the menu being built and the
        //menu item being clicked.
        this.incoming_selection=((ProgramPlugin)incoming_plugin).getProgramSelection();
        CreatorOfNecessaryFiles.createAllNecessaryFiles();
        this.current_program = (this.current_program==null) ? getCurrentProgram() : this.current_program;
        JSAgentPreparer.prepare_agent_file_if_not_already_prepared(this.current_program);

        this.selection_task_dispatcher=new DragonSelectionTaskDispatcher(this.incoming_plugin.getTool(),this.current_program,this.incoming_selection,null,false,null);
        this.selection_task_dispatcher.perform_selection_task();

        
    }
     
}
