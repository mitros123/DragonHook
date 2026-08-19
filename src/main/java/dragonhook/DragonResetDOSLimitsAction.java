package dragonhook;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.DOSLimitsTracker;
import dragonhook.util.JSAgentPreparer;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class DragonResetDOSLimitsAction extends DockingAction {

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

    
    public DragonResetDOSLimitsAction(DragonHookPlugin plugin) {
        super("DragonHookPlugin", plugin.getName());
        this.tool = plugin.getTool();
        this.current_program = plugin.currentprogram; //may be null initially
        this.incoming_plugin=plugin;
        init();
    }
    
    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return true;
    }
    
    private void init() {
        setPopupMenuData(
            new MenuData(new String[] { "DragonHook Config...", "Reset DOS limit counters" }, null,"Dragon-Hook"));
        setDescription("Reset the DOS limit counters set for the HTTP API.");
    }
    
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    @Override
    public void actionPerformed(ActionContext context) {
        CreatorOfNecessaryFiles.createAllNecessaryFiles();
        this.current_program = (this.current_program==null) ? getCurrentProgram() : this.current_program;
        JSAgentPreparer.prepare_agent_file_if_not_already_prepared(this.current_program);
        
        DOSLimitsTracker.reset_DOS_limits();
        ConsolePrinter cp=new ConsolePrinter(this.tool);
        cp.print_to_console("DOS limit counters have been reset.");
        
    }

}
