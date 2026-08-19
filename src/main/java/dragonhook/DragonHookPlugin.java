/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dragonhook;

import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.DOSLimitsTracker;
import dragonhook.util.JSAgentPreparer;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = MiscellaneousPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Two way communication with Frida.",
    description = "This plugin allows Ghidra to send custom scripts to Frida, and receive dynamic information automatically."
)
//@formatter:on
public class DragonHookPlugin extends ProgramPlugin {

    public Program currentprogram;
    public DragonSelectionAction selectionAction;
    public DragonEditConfigAction editConfigAction;
    public DragonEditFridaAgentAction editFridaScriptAction;
    public DragonEditPythonInvokerAction editPythonInvokerAction;
    public DragonHookRunAgentAction runAgentAction;
    public DragonForceStopAgentAction forceStopAgentAction;
    public DragonResetFridaAgentAction resetFridaScriptAction;
    public DragonResetAllConfigsAction resetAllConfigsAction;
    public DragonResetDOSLimitsAction resetDOSlimitsAction;
    public DragonStartHTTPServerAction startHTTPServerAction;
    public DragonStopHTTPServerAction stopHTTPServerAction;
    public static String  DragonHook_plugin_version="0.2.0";


    /**
     * Plugin constructor.
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public DragonHookPlugin(PluginTool tool) {
        super(tool);

        String pluginName = getName();
        this.currentprogram=getCurrentProgram();
        
       
        
        selectionAction = new DragonSelectionAction(this,this.getProgramSelection());
        tool.addAction(selectionAction);
        
        runAgentAction = new DragonHookRunAgentAction(this);
        tool.addAction(runAgentAction);

        //sits right next to "Run Agent", and is only enabled while an agent is actually running
        forceStopAgentAction = new DragonForceStopAgentAction(this);
        tool.addAction(forceStopAgentAction);
        
        
        tool.setMenuGroup(new String[] { "DragonHook Config..." }, "Dragon-Hook");
        
        editConfigAction = new DragonEditConfigAction(this);
        tool.addAction(editConfigAction);

        editFridaScriptAction = new DragonEditFridaAgentAction(this);
        tool.addAction(editFridaScriptAction);
        
        editPythonInvokerAction = new DragonEditPythonInvokerAction(this);
        tool.addAction(editPythonInvokerAction);
        
        resetFridaScriptAction=new DragonResetFridaAgentAction(this);
        tool.addAction(resetFridaScriptAction);
        
        resetAllConfigsAction= new DragonResetAllConfigsAction(this);
        tool.addAction(resetAllConfigsAction);
        
        resetDOSlimitsAction= new DragonResetDOSLimitsAction(this);
        tool.addAction(resetDOSlimitsAction);
        
        startHTTPServerAction = new DragonStartHTTPServerAction(this);
        tool.addAction(startHTTPServerAction);
        
        stopHTTPServerAction=new DragonStopHTTPServerAction(this);
        tool.addAction(stopHTTPServerAction);
        
        init();
    }
    
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    //ProgramPlugin calls these whenever the user switches program in Ghidra. Without them,
    //currentprogram was whatever was open when the plugin was constructed, FOREVER: open program A, use
    //DragonHook, open program B, use DragonHook, and every image base, function range, offset, comment and
    //xref was still computed against A - so results were silently written into the wrong program's
    //database. The actions each keep their own copy, so they are told as well.
    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        this.currentprogram=program;
        push_current_program_to_all_actions(program);
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        if (this.currentprogram==program)
        {
            this.currentprogram=null;
            push_current_program_to_all_actions(null);
        }
    }

    //The agent file is prepared once per program (module name and ghidra image base are baked into it),
    //so switching program has to force that preparation to happen again for the new one.
    private void push_current_program_to_all_actions(Program program)
    {
        JSAgentPreparer.agent_has_been_updated_with_current_program=false;

        //The per-codeunit DOS counters are keyed by Address, and Address.equals() compares the address SPACE
        //and the offset - not the owning program. Two programs that both contain ram:00401000 therefore
        //produce EQUAL keys, so counters accumulated against program A would silently apply to program B and
        //the agent would be refused updates for addresses it had never touched. Reset them on every switch.
        DOSLimitsTracker.reset_DOS_limits();

        if (selectionAction!=null) { selectionAction.set_current_program(program); }
        if (runAgentAction!=null) { runAgentAction.set_current_program(program); }
        if (forceStopAgentAction!=null) { forceStopAgentAction.set_current_program(program); }
        if (editConfigAction!=null) { editConfigAction.set_current_program(program); }
        if (editFridaScriptAction!=null) { editFridaScriptAction.set_current_program(program); }
        if (editPythonInvokerAction!=null) { editPythonInvokerAction.set_current_program(program); }
        if (resetFridaScriptAction!=null) { resetFridaScriptAction.set_current_program(program); }
        if (resetAllConfigsAction!=null) { resetAllConfigsAction.set_current_program(program); }
        if (resetDOSlimitsAction!=null) { resetDOSlimitsAction.set_current_program(program); }
        if (startHTTPServerAction!=null) { startHTTPServerAction.set_current_program(program); }
        if (stopHTTPServerAction!=null) { stopHTTPServerAction.set_current_program(program); }
    }

    @Override
    public void init() {
        super.init();

        CreatorOfNecessaryFiles.createAllNecessaryFiles();
    }


}
