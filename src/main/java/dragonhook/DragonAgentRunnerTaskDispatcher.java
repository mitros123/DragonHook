package dragonhook;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class DragonAgentRunnerTaskDispatcher {
    
    private PluginTool incoming_plugintool;
    private ProgramSelection incoming_selection;
    private Program current_program;
    private Boolean is_this_an_API_call;

    public DragonAgentRunnerTaskDispatcher(PluginTool plugintool, Program incoming_program,Boolean is_this_an_API_call)
    {
        this.incoming_plugintool=plugintool;
        this.current_program=incoming_program;
        this.is_this_an_API_call=is_this_an_API_call;
    }
    
    public void perform_runagent_task()
    {
        DragonAgentRunnerTask agent_runner_task=new DragonAgentRunnerTask("Running frida agent",this.current_program,this.incoming_plugintool);
        this.incoming_plugintool.execute(agent_runner_task); //Execute the task
        if (agent_runner_task.is_cancelled)
        {
            return;
        }

    }
}
