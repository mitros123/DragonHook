package dragonhook;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.Map;

import dragonhook.util.ConfigFileParser;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.DOSLimitsTracker;
import generic.json.JSONParser;
import generic.json.JSONToken;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DragonAgentRunnerTask extends Task {


    //volatile primitive, matching the other two task classes. Nothing outside this class reads it today, but
    //it is written on the ghidra task thread and the escalation ladder runs alongside the reader threads.
    protected volatile boolean is_cancelled;
    protected PluginTool incoming_plugintool;
    protected Program current_program;
    public static StringBuilder stdoutContent;
    public static StringBuilder stderrContent;
    public static int maxlength_of_stringbuilder=30000000; //so that memory does not explode

    //Sentinel written to the python process's stdin to ask it to shut down in an orderly way. Ghidra
    //cannot reach the target itself - it may be on a USB or remote device - so only python, which holds
    //the frida handles, can unload the agent, detach, and optionally kill the target.
    public static final String shutdown_sentinel_for_python="DRAGONHOOK_SHUTDOWN";
    //How long to let python do that before escalating to SIGTERM, and then to SIGKILL.
    //Kept SHORT on purpose. Python's teardown calls script.unload(), which can block inside frida's C
    //extension while holding the GIL - and when it does, python cannot help itself: none of its own timeouts
    //or watchdogs can run, because no python thread can run at all. Waiting a long time for an interpreter
    //that is frozen is pure delay, and SIGTERM works regardless of the GIL, since the default disposition is
    //handled by the kernel rather than by a python signal handler.
    //The "FORCE STOP agent" menu action skips this wait entirely when the user does not want it.
    public static int seconds_to_wait_for_orderly_python_shutdown=10;
    public static int seconds_to_wait_after_sigterm=3;

    //used when PATH_OF_PYTHON_BINARY is absent from the config, instead of handing null to ProcessBuilder
    public static final String default_python_binary="python3";

    //super(title, canCancel, hasProgress, isModal). The one argument Task(String) constructor sets
    //canCancel to FALSE, which made monitor.isCancelled() permanently false and left the whole cancel
    //branch below dead: a running agent could not be stopped from the task dialog at all, and an agent
    //stalking a live process may never exit on its own.
    public DragonAgentRunnerTask(String title, Program incoming_program, PluginTool tool) {
        super(title, true, false, false);
        this.current_program=incoming_program;
        this.incoming_plugintool=tool;
        this.is_cancelled=false;
        stdoutContent = new StringBuilder();
        stderrContent = new StringBuilder();
    }


    //uses the Ghidra builtin JSONParser(). Luckily Ghidra also comes with gson.
    //https://github.com/NationalSecurityAgency/ghidra/issues/1982
    @SuppressWarnings("unchecked")
    public Map<String,Object> return_json_as_map(String jsonData) throws Exception
    {
        JSONParser parser = new JSONParser();
        LinkedList<JSONToken> tokens = new LinkedList<>();
        switch (parser.parse(jsonData.toCharArray(), tokens)) {
            case JSMN_ERROR_INVAL:
                throw new Exception("JSON contains invalid character");
            case JSMN_ERROR_NOMEM:
                throw new Exception("Not enough tokens");
            case JSMN_ERROR_PART:
                throw new Exception("Malformed or missing JSON data");
            case JSMN_SUCCESS:
                break;
        }
        return (Map<String, Object>) parser.convert(jsonData.toCharArray(), tokens);
    }
    
    //The python process while it is running, so that the "Force stop the running agent" menu action can
    //reach it without waiting for the escalation ladder. volatile because it is written by the task thread
    //and read from the Swing thread.
    public static volatile Process the_running_python_process=null;

    //Set by the FORCE STOP action so that the escalation ladder does not report a force kill as a clean
    //shutdown. Without it, the ladder simply saw the process vanish and printed "Agent shut down cleanly",
    //which is exactly the wrong thing to read in the log you consult when a shutdown misbehaves.
    public static volatile boolean the_agent_was_force_stopped=false;

    public static boolean is_an_agent_running()
    {
        Process process_right_now=the_running_python_process;
        return (process_right_now!=null && process_right_now.isAlive());
    }


    //Waits up to the given number of seconds for the process to exit, WITHOUT using an interruptible wait.
    //Process.waitFor() and Thread.sleep() both throw InterruptedException, and Ghidra interrupts the task
    //thread on cancel - so an interruptible wait here would abandon the escalation halfway and leave the
    //python process running, which is exactly the bug this replaces. Interrupts are absorbed on purpose.
    public static boolean wait_for_the_process_to_exit(Process process,int seconds_to_wait)
    {
        long deadline_in_nanos=System.nanoTime()+((long) seconds_to_wait)*1000000000L;
        while (System.nanoTime()<deadline_in_nanos)
        {
            if (!process.isAlive())
            {
                return true;
            }
            try { Thread.sleep(100); }
            catch (InterruptedException e) { Thread.interrupted(); }   //deliberately swallowed, see above
        }
        return !process.isAlive();
    }


    //Three state reading of KILL_TARGET_PROCESS_ON_CANCEL, kept identical to should_the_target_be_killed()
    //in the python invoker so that the orderly path and the force path can never disagree about it.
    //"auto" - the default - answers the question by asking who OWNS the target: if SPAWN_PROCESS_FROM_FRIDA
    //is set then the process exists only because we asked for it, and leaving it behind is a leak that breaks
    //the next run of any single instance application. If we merely attached, it is the user's and is left
    //strictly alone.
    public static boolean should_the_target_be_stopped_with_the_agent()
    {
        try
        {
            Map<String, Object> json_map_with_config=ConfigFileParser.extract_config_file_as_map();
            Object raw_value=json_map_with_config.get("KILL_TARGET_PROCESS_ON_CANCEL");
            String text_from_config=(raw_value==null) ? "auto" : (""+raw_value).trim().toLowerCase();
            if (text_from_config.equals("true") || text_from_config.equals("1") || text_from_config.equals("yes"))
            {
                return true;
            }
            if (text_from_config.equals("false") || text_from_config.equals("0") || text_from_config.equals("no"))
            {
                return false;
            }
            //"auto", and also the safe reading of anything unrecognised
            Object raw_spawn=json_map_with_config.get("SPAWN_PROCESS_FROM_FRIDA");
            if (raw_spawn instanceof Boolean)
            {
                return ((Boolean) raw_spawn).booleanValue();
            }
            String spawn_as_text=(raw_spawn==null) ? "false" : (""+raw_spawn).trim().toLowerCase();
            return (spawn_as_text.equals("true") || spawn_as_text.equals("1") || spawn_as_text.equals("yes"));
        }
        catch (Exception e)
        {
            return false;   //an unreadable config must never lead to killing something
        }
    }


    //SIGKILLs the python process, and stops the target it spawned ONLY if the config asks for that. Named
    //for what it always does rather than for the optional part: with KILL_TARGET_PROCESS_ON_CANCEL left at
    //"auto" and an ATTACHED target, no child is touched at all, so the old name overstated it.
    //
    //SIGKILL of python cannot be designed away: if python freezes inside frida's C extension it holds the
    //GIL, no python thread runs, and nothing inside the process can rescue it. So the goal is not to avoid
    //SIGKILL but to make it harmless - and it is harmless, because when its client dies frida's injected
    //agent notices the lost peer and unloads itself, reverting the instrumentation in the target. Killing
    //python does not leave the target instrumented.
    //
    //Whether the target goes with it is decided by KILL_TARGET_PROCESS_ON_CANCEL, using the same three
    //state rule as the python side so the two can never disagree. This path used to kill it regardless,
    //which contradicted the setting on exactly the path where a surprise is least welcome.
    //Grandchildren are never touched: see the note below.
    public static void force_stop_the_agent_process(Process process,ConsolePrinter cp)
    {
        if (process==null)
        {
            return;
        }
        boolean the_target_should_be_stopped_too=should_the_target_be_stopped_with_the_agent();

        if (!the_target_should_be_stopped_too)
        {
            cp.print_to_console("Killing the agent process only. The examined process is left running:"
                    + " frida's agent inside it notices that its client has gone and unloads itself, so the"
                    + " instrumentation is reverted. Set KILL_TARGET_PROCESS_ON_CANCEL to stop it as well.");
            process.destroyForcibly();
            return;
        }

        try
        {
            //children(), NOT descendants().
            //
            //descendants() is the TRANSITIVE closure, and using it did real damage: a frida spawned target is
            //a direct child of python, but the target's OWN helper processes are grandchildren. Killing those
            //tore a multi process application apart from the inside - with gimp it killed the script-fu
            //plug-in process, gimp then found its wire protocol pipe dead and reported
            //"gimp_wire_read() error" as a crash. Nothing had actually segfaulted; we had killed its
            //children out from under it.
            //Killing only the direct child, and terminating rather than killing, lets the target shut its own
            //helpers down the way it normally would.
            //
            //TERMINATE first, kill only if that is refused. SIGKILLing an instrumented process outright gives
            //it no chance to run its own exit path; SIGTERM lets it go quietly.
            java.util.List<ProcessHandle> children_to_stop=process.children().collect(java.util.stream.Collectors.toList());
            for (ProcessHandle handle : children_to_stop)
            {
                try
                {
                    cp.print_to_console("Terminating process "+handle.pid()+" spawned by the agent.");
                    handle.destroy();
                }
                catch (Exception ignored) { }
            }
            if (children_to_stop.size()>0)
            {
                //one short grace period for all of them together, not one each
                long deadline_in_nanos=System.nanoTime()+2000000000L;
                while (System.nanoTime()<deadline_in_nanos)
                {
                    boolean any_still_alive=false;
                    for (ProcessHandle handle : children_to_stop)
                    {
                        if (handle.isAlive()) { any_still_alive=true; break; }
                    }
                    if (!any_still_alive) { break; }
                    try { Thread.sleep(100); }
                    catch (InterruptedException e) { Thread.interrupted(); }
                }
                for (ProcessHandle handle : children_to_stop)
                {
                    try
                    {
                        if (handle.isAlive())
                        {
                            cp.print_to_console("Process "+handle.pid()+" ignored the terminate, killing it.");
                            handle.destroyForcibly();
                        }
                    }
                    catch (Exception ignored) { }
                }
            }
        }
        catch (Exception e)
        {
            cp.print_to_console("Could not enumerate the agent's child processes: "+e);
        }
        process.destroyForcibly();
    }


    //Refuses to launch a second agent while one is alive. There is exactly ONE the_running_python_process
    //static, so a second run overwrote it - and then the FIRST run's finally cleared it to null while the
    //second was still going, which left FORCE STOP with nothing to kill and is_an_agent_running() lying.
    //Two runs would also truncate each other's agent_stdout.txt, which is a fixed path.
    //Called from DragonHookRunAgentAction before the task is dispatched.
    public static boolean refuse_to_start_because_an_agent_is_already_running(PluginTool tool)
    {
        if (!is_an_agent_running())
        {
            return false;
        }
        new ConsolePrinter(tool).print_to_console("A DragonHook agent is already running. Stop it first"
                + " (Cancel on its task, or \"DragonHook FORCE STOP agent\") before starting another one.");
        return true;
    }


    //The escalation ladder, gentlest first. Python holds the frida device/session/script handles, so only it
    //can unload the agent (which unfollows stalked threads and disarms hardware watchpoints), detach, and -
    //if KILL_TARGET_PROCESS_ON_CANCEL is set - kill a target that may be on another device. Killing python
    //outright would skip all of that and leave the target instrumented.
    //Nothing in here throws a checked exception, and no wait in here is interruptible, so once we are in
    //this method the ladder always runs to completion.
    public void shut_the_python_process_down(Process process,ConsolePrinter cp,TaskMonitor monitor)
    {
        monitor.setMessage("Asking the agent to shut down cleanly...");
        cp.print_to_console("Cancel requested. Asking python to unload the agent and detach.");
        try
        {
            OutputStream stdin_of_python=process.getOutputStream();
            stdin_of_python.write((shutdown_sentinel_for_python+System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
            stdin_of_python.flush();
        }
        catch (Exception e)
        {
            cp.print_to_console("Could not ask python to shut down ("+e+"), escalating.");
        }

        if (wait_for_the_process_to_exit(process,seconds_to_wait_for_orderly_python_shutdown))
        {
            if (the_agent_was_force_stopped)
            {
                cp.print_to_console("Agent was force stopped while the orderly shutdown was still in progress.");
            }
            else
            {
                cp.print_to_console("Agent shut down cleanly.");
            }
            return;
        }

        monitor.setMessage("Agent did not stop cleanly, terminating it...");
        cp.print_to_console("Python did not shut down within "+seconds_to_wait_for_orderly_python_shutdown
                +" seconds, sending a terminate signal. The target may be left instrumented.");
        process.destroy();
        if (wait_for_the_process_to_exit(process,seconds_to_wait_after_sigterm))
        {
            cp.print_to_console("Agent terminated.");
            return;
        }

        monitor.setMessage("Force killing the agent...");
        cp.print_to_console("Python is still alive, force killing it and anything it spawned.");
        force_stop_the_agent_process(process,cp);
        wait_for_the_process_to_exit(process,2);
    }


    public String run_python_process_which_calls_frida(String python_path,String path_of_py_file_which_spawns_frida,
            String path_of_dragonhook_settings_dir,TaskMonitor monitor)
    {
        try {
            //(re-)initialize the DOS limit variables for each agent run
            DOSLimitsTracker.reset_DOS_limits();
            
            ConsolePrinter cp=new ConsolePrinter(this.incoming_plugintool);
            cp.print_to_console("Spawning python which will launch frida...");
            //-u is unbuffered output
            cp.print_to_console("Command run: \""+python_path+"\" -u \""+path_of_py_file_which_spawns_frida+"\" \""+path_of_dragonhook_settings_dir+"\"");
            ProcessBuilder builder = new ProcessBuilder(python_path,"-u",path_of_py_file_which_spawns_frida,path_of_dragonhook_settings_dir);
            builder.redirectErrorStream(false); // Keep stdout and stderr separate

            DragonAgentRunnerTask.stdoutContent = new StringBuilder();
            DragonAgentRunnerTask.stderrContent = new StringBuilder();
            
            
            //also prepare the writers for the output data
            Path tmp_dir = CreatorOfNecessaryFiles.get_ghidra_user_temp_dir().toPath();
            Path stdout_txt_filepath=tmp_dir.resolve("agent_stdout.txt");
            Path stderr_txt_filepath=tmp_dir.resolve("agent_stderr.txt");
            String stdout_txt_filepath_as_str=stdout_txt_filepath.toString();
            String stderr_txt_filepath_as_str=stderr_txt_filepath.toString();
            cp.print_to_console("Stdout filename: "+stdout_txt_filepath_as_str);
            cp.print_to_console("Stderr filename: "+stderr_txt_filepath_as_str);
            Process process = builder.start();
            //published so that the "Force stop the running agent" action can reach it immediately, instead
            //of the user having to sit through the escalation ladder
            the_running_python_process=process;

            cp.print_to_console("Spawned python which will launch frida.");

            //Each reader thread OWNS its writer, in a try-with-resources whose scope is exactly the
            //thread body. Creating the writers outside and closing them at the end of this method leaked
            //both handles on every path that threw, and could also close a writer while the reader thread
            //was still using it, because the joins below are bounded.
            // Thread for stdout
            Thread stdoutThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                     BufferedWriter stdout_writer = new BufferedWriter(new FileWriter(stdout_txt_filepath_as_str, false))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        //System.out.println("[STDOUT] " + line);
                        DragonAgentRunnerTask.stdoutContent.append(line+"\n");
                        stdout_writer.write(line);stdout_writer.newLine();stdout_writer.flush();
                        //check for excessive size
                        if (DragonAgentRunnerTask.stdoutContent.length()>maxlength_of_stringbuilder)
                        {
                            System.out.println("Trimming stdoutContent StringBuilder.");
                            DragonAgentRunnerTask.stdoutContent = new StringBuilder();
                            System.gc();
                        }
                        if (line.contains("[!] Exception: process not found"))
                        {
                            cp.print_to_console("Detected 'Process not found'. Make sure the correct information is set inside the config file. You may also need to run the above command with higher privileges, depending on the environment. In case of manual invokations of the python script, ensure that between the runs the DOS limits are either updated inside the config file, or reset from the related right click option.");
                        }
                        if (line.contains("HARDWARE WATCHPOINT TRIGGERED") ||
                            line.contains("hardware watchpoints are not supported."))
                        {
                            cp.print_to_console(line);
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });

            // Thread for stderr, owning its own writer for the same reason
            Thread stderrThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                     BufferedWriter stderr_writer = new BufferedWriter(new FileWriter(stderr_txt_filepath_as_str, false))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.err.println("[STDERR] " + line);
                        stderrContent.append(line+"\n");
                        stderr_writer.write(line);stderr_writer.newLine();stderr_writer.flush();
                        //check for excessive size
                        if (stderrContent.length()>maxlength_of_stringbuilder)
                        {
                            System.out.println("Trimming stderrContent StringBuilder.");
                            DragonAgentRunnerTask.stderrContent = new StringBuilder();
                            System.gc();
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });

            // Start both threads
            stdoutThread.start();
            stderrThread.start();
            
            //enter loop until either process ends or monitor is cancelled
            int exitCode=-1000;
            boolean the_user_asked_to_cancel=false;
            while (true)
            {
                if (!process.isAlive())
                {
                    exitCode=process.exitValue();
                    break;
                }

                if (monitor.isCancelled())
                {
                    the_user_asked_to_cancel=true;
                    break;
                }

                try
                {
                    Thread.sleep(100);
                }
                catch (InterruptedException e)
                {
                    //Ghidra INTERRUPTS the task thread when the user cancels, so this is a cancel signal
                    //and not an error. It used to propagate out of this loop to the catch at the bottom of
                    //the method, which meant the shutdown below never ran at all: no sentinel was written,
                    //no terminate signal was sent, and the python process was simply left running for ever.
                    //Every wait from here on is uninterruptible for the same reason.
                    the_user_asked_to_cancel=true;
                    Thread.interrupted();   //clear the flag, so the waits during shutdown are not pre-interrupted
                    break;
                }
            }

            if (the_user_asked_to_cancel)
            {
                //is_cancelled had stopped being set anywhere when this loop was restructured, so the field
                //silently reported false for a cancelled run. It is set here rather than left to rot,
                //because a field that lies is worse than no field at all.
                this.is_cancelled=true;
                shut_the_python_process_down(process,cp,monitor);
                monitor.cancel();
            }
            cp.print_to_console("Python process ended.");

            // Ensure both threads finish reading output. Generous, because these threads own the output
            // files now and a truncated join means a truncated agent_stdout.txt.
            stdoutThread.join(5000);
            stderrThread.join(5000);
            if (stdoutThread.isAlive() || stderrThread.isAlive())
            {
                System.out.println("Warning: an output reader thread did not finish, the agent output files may be incomplete.");
            }

            if (exitCode!=-1000)
            {
                System.out.println("Process exited with code " + exitCode);
            }
            else
            {
                System.out.println("Process was killed");
            }
            
            
            //the writers are closed by the threads that own them, see the try-with-resources above

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        finally
        {
            //cleared unconditionally, so the force-stop action never offers to kill a process that is gone
            the_running_python_process=null;
        }

        return "";
    }
    

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {

        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Map<String, Object> json_map_with_config=ConfigFileParser.extract_config_file_as_map();

        //extract_config_file_as_map() now returns an empty map rather than null for an unreadable config,
        //which stopped the NPE happening HERE - but a missing setting would then have handed null to
        //ProcessBuilder and thrown there instead, which is no more informative. Fall back and say so.
        Object raw_python_path=json_map_with_config.get("PATH_OF_PYTHON_BINARY");
        String python_path=(raw_python_path==null) ? "" : ((String) raw_python_path).trim();
        if (python_path.isEmpty())
        {
            python_path=default_python_binary;
            new ConsolePrinter(this.incoming_plugintool).print_to_console(
                    "DragonHook: PATH_OF_PYTHON_BINARY is missing or empty in the config file, falling back to \""
                    +default_python_binary+"\". Set it from \"DragonHook Config... -> Edit config...\" if that"
                    +" is not the interpreter you want.");
        }
        String path_of_py_file_which_spawns_frida=CreatorOfNecessaryFiles.createPythonInvokerFile();
        
        
        // agent output should be put in a file for further processing.
        // Also, the agent should be allowed to manually invoke ghidra functionalities.
        // The user may place custom code in the JS script to invoke these functionalities.
        
        monitor.setMessage("Invoking frida ... ");
        run_python_process_which_calls_frida(python_path,path_of_py_file_which_spawns_frida, path_for_dragonhook_dir.toString(), monitor);
        
    }

}
