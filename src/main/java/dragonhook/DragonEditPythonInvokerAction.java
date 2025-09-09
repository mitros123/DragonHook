package dragonhook;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.FileAndDirOpener;
import dragonhook.util.JSAgentPreparer;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class DragonEditPythonInvokerAction extends DockingAction {

    protected PluginTool tool;
    protected Program current_program;
    protected ProgramSelection incoming_selection;
    protected Plugin incoming_plugin;

    
    public DragonEditPythonInvokerAction(DragonHookPlugin plugin) {
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
            new MenuData(new String[] { "DragonHook Config...", "Edit python invoker script..." }, null,"Dragon-Hook"));
        setDescription("Edit the python invoker file  of the DragonHook plugin that will launch frida (<DefaultUserSettingsDir>/DragonHookPlugin_files/DragonHook_python_invoker.py) using the default editor.");
    }
    
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    @Override
    public void actionPerformed(ActionContext context) {
        CreatorOfNecessaryFiles.createAllNecessaryFiles();
        String path_for_python_invoker_as_str = CreatorOfNecessaryFiles.createPythonInvokerFile();
        this.current_program = (this.current_program==null) ? getCurrentProgram() : this.current_program;
        JSAgentPreparer.prepare_agent_file_if_not_already_prepared(this.current_program);

        FileAndDirOpener.openFile(path_for_python_invoker_as_str);

    }

}


