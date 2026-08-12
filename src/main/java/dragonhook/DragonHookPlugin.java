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
    public DragonResetFridaAgentAction resetFridaScriptAction;
    public DragonResetAllConfigsAction resetAllConfigsAction;
    public DragonResetDOSLimitsAction resetDOSlimitsAction;
    public DragonStartHTTPServerAction startHTTPServerAction;
    public DragonStopHTTPServerAction stopHTTPServerAction;
    public static String  DragonHook_plugin_version="0.1.5";


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

    @Override
    public void init() {
        super.init();

        CreatorOfNecessaryFiles.createAllNecessaryFiles();
    }


}
