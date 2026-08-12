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

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        this.incoming_selection=((ProgramPlugin)incoming_plugin).getProgramSelection();  
        return (this.incoming_selection!=null && incoming_selection.getNumAddresses()>0);
    }

    @Override
    public void actionPerformed(ActionContext context) {
        
        CreatorOfNecessaryFiles.createAllNecessaryFiles();
        this.current_program = (this.current_program==null) ? getCurrentProgram() : this.current_program;
        JSAgentPreparer.prepare_agent_file_if_not_already_prepared(this.current_program);

        this.selection_task_dispatcher=new DragonSelectionTaskDispatcher(this.incoming_plugin.getTool(),this.current_program,this.incoming_selection,null,false,null);
        this.selection_task_dispatcher.perform_selection_task();

        
    }
     
}
