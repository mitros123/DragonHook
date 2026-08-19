package dragonhook;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import dragonhook.util.ConsolePrinter;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

//Kills the running agent immediately, without going through the escalation ladder in
//DragonAgentRunnerTask.shut_the_python_process_down(). That ladder deliberately gives python time to unload
//the agent, detach, and optionally kill the target, which is the right default but can take up to 18
//seconds. When the user does not want to wait - or when python is wedged - this is the way out.
//
//It is offered as a menu action rather than a button in Ghidra's task dialog because that dialog's buttons
//are not ours to add. The agent task is deliberately non modal (isModal=false in its constructor), so this
//menu stays reachable while the agent is running, which is what makes this usable at all.
//
//The action is only ENABLED while an agent process is actually alive, so it cannot be pressed at a moment
//when it would do nothing.
public class DragonForceStopAgentAction extends DockingAction {

    protected PluginTool tool;
    protected Program current_program;
    protected Plugin incoming_plugin;

    //Called by DragonHookPlugin.programActivated/programDeactivated. Without this the program captured
    //when the action was constructed was used forever, so after switching program in Ghidra every offset
    //and every comment went to the WRONG program's database.
    public void set_current_program(Program incoming_program) {
        this.current_program=incoming_program;
    }

    public DragonForceStopAgentAction(DragonHookPlugin plugin) {
        super("DragonHookPlugin", plugin.getName());
        this.tool = plugin.getTool();
        this.current_program = plugin.currentprogram; //may be null initially
        this.incoming_plugin=plugin;
        init();
    }

    private void init() {
        setPopupMenuData(
            new MenuData(new String[] { "DragonHook FORCE STOP agent" }, null,"Dragon-Hook"));
        setDescription("Immediately kill the running DragonHook agent, and any process it spawned, without"
                + " waiting for the orderly shutdown. Use this instead of Cancel when you do not want to wait,"
                + " or when the agent is not responding. The examined process is left instrumented: Stalker may"
                + " still be following its threads and hardware watchpoints may still be armed, so restart it"
                + " if that matters.");
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    //Only offered while there is something to stop. Ghidra calls this often, so it stays a pure test with
    //no side effects.
    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return DragonAgentRunnerTask.is_an_agent_running();
    }

    @Override
    public void actionPerformed(ActionContext context) {
        ConsolePrinter cp=new ConsolePrinter(this.tool);
        Process process_to_kill=DragonAgentRunnerTask.the_running_python_process;
        if (process_to_kill==null || !process_to_kill.isAlive())
        {
            cp.print_to_console("No DragonHook agent is running, nothing to stop.");
            return;
        }
        //Say what will ACTUALLY happen. This message used to claim unconditionally that the examined process
        //is left as it is, which stopped being true when KILL_TARGET_PROCESS_ON_CANCEL gained its "auto"
        //default: a target we spawned ourselves is now stopped along with the agent.
        boolean the_target_goes_too=DragonAgentRunnerTask.should_the_target_be_stopped_with_the_agent();
        if (the_target_goes_too)
        {
            cp.print_to_console("FORCE STOPPING the DragonHook agent immediately, skipping the orderly shutdown."
                    + " The examined process will be stopped with it, because KILL_TARGET_PROCESS_ON_CANCEL asks"
                    + " for that. Its own instrumentation is not unwound first, so it gets no chance to run an"
                    + " orderly exit.");
        }
        else
        {
            cp.print_to_console("FORCE STOPPING the DragonHook agent immediately, skipping the orderly shutdown."
                    + " The examined process is left running - frida's agent inside it notices that its client"
                    + " has gone and unloads itself, so the instrumentation is reverted.");
        }
        //Tell the escalation ladder that this was a force stop, so that if it is mid-wait it does not report
        //the process vanishing as a clean shutdown.
        DragonAgentRunnerTask.the_agent_was_force_stopped=true;
        DragonAgentRunnerTask.force_stop_the_agent_process(process_to_kill,cp);
        //The agent task's own loop notices the process is gone within 100ms and finishes normally, so the
        //task dialog closes by itself and the output files are still flushed by the reader threads.
    }
}
