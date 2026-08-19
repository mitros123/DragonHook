package dragonhook;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.JSAgentPreparer;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class DragonHookRunAgentAction extends DockingAction {

    protected PluginTool tool;
    protected Program current_program;

    //Called by DragonHookPlugin.programActivated/programDeactivated. Without this the program captured
    //when the action was constructed was used forever, so after switching program in Ghidra every offset
    //and every comment went to the WRONG program's database.
    public void set_current_program(Program incoming_program) {
        this.current_program=incoming_program;
    }
    protected Plugin incoming_plugin;
    protected DragonAgentRunnerTaskDispatcher agentrunner_taskdispatcher;

    
    public DragonHookRunAgentAction(DragonHookPlugin plugin) {
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
            new MenuData(new String[] { "DragonHook Run Agent!" }, null,"Dragon-Hook"));
        setDescription("Run the Javascript Agent of the DragonHook plugin (<DefaultUserSettingsDir>/DragonHookPlugin_files/<version>/DragonHook_plugin_agent.js) using the configured parameters.");
    }
    
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    @Override
    public void actionPerformed(ActionContext context) {
        //One agent at a time. There is a single static handle to the running python process, so a second run
        //would overwrite it and the first run's cleanup would then clear it while the second was still going.
        if (DragonAgentRunnerTask.refuse_to_start_because_an_agent_is_already_running(this.tool))
        {
            return;
        }
        DragonAgentRunnerTask.the_agent_was_force_stopped=false;   //fresh run, fresh state
        CreatorOfNecessaryFiles.createAllNecessaryFiles();
        String path_for_agent_as_str = CreatorOfNecessaryFiles.createAgentFile();
        this.current_program = (this.current_program==null) ? getCurrentProgram() : this.current_program;
        JSAgentPreparer.prepare_agent_file_if_not_already_prepared(this.current_program);
        
        ConsolePrinter cp=new ConsolePrinter(this.tool);
        cp.print_to_console("Running DragonHook Agent.");
        
        //run agent through task dispatcher     
        this.agentrunner_taskdispatcher=new DragonAgentRunnerTaskDispatcher(this.incoming_plugin.getTool(),this.current_program,false);
        this.agentrunner_taskdispatcher.perform_runagent_task();
    }

}
