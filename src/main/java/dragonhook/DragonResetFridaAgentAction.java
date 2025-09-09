package dragonhook;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.FileAndDirOpener;
import dragonhook.util.JSAgentPreparer;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class DragonResetFridaAgentAction extends DockingAction {

	protected PluginTool tool;
	protected Program current_program;
	protected ProgramSelection incoming_selection;
	protected Plugin incoming_plugin;

	
	public DragonResetFridaAgentAction(DragonHookPlugin plugin) {
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
			new MenuData(new String[] { "DragonHook Config...", "Reset agent script to default" }, null,"Dragon-Hook"));
		setDescription("Reset the agent javascript file  of the DragonHook plugin that will be fed to frida (<DefaultUserSettingsDir>/DragonHookPlugin_files/<version>/DragonHook_plugin_agent.js), to its default value.");
	}
	
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

	@Override
	public void actionPerformed(ActionContext context) {
        CreatorOfNecessaryFiles.createAllNecessaryFiles();
        CreatorOfNecessaryFiles.resetAgentFile();
        CreatorOfNecessaryFiles.createAllNecessaryFiles();
		this.current_program = (this.current_program==null) ? getCurrentProgram() : this.current_program;
		JSAgentPreparer.agent_has_been_updated_with_current_program=false;
		JSAgentPreparer.prepare_agent_file_if_not_already_prepared(this.current_program);
		
		ConsolePrinter cp=new ConsolePrinter(this.tool);
		cp.print_to_console("DragonHook Frida Agent has been reset.");
		
	}

}
