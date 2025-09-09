package dragonhook;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import dragonhook.util.AddressRangeMinMaxContainer;
import dragonhook.util.ConfigFileParser;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.DOSLimitsTracker;
import generic.json.JSONParser;
import generic.json.JSONToken;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import java.io.StringReader;
import java.lang.reflect.Type;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import java.io.Reader;

public class DragonAgentRunnerTask extends Task {


    protected Boolean is_cancelled;
    protected PluginTool incoming_plugintool;
    protected Program current_program;
    public static StringBuilder stdoutContent;
    public static StringBuilder stderrContent;
    public static int maxlength_of_stringbuilder=30000000; //so that memory does not explode

    public DragonAgentRunnerTask(String title, Program incoming_program, PluginTool tool) {
        super(title);
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
            BufferedWriter stdout_writer = new BufferedWriter(new FileWriter(stdout_txt_filepath_as_str, false));
            BufferedWriter stderr_writer = new BufferedWriter(new FileWriter(stderr_txt_filepath_as_str, false));
            
            
            Process process = builder.start();
            
            cp.print_to_console("Spawned python which will launch frida.");

            // Thread for stdout
            Thread stdoutThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
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

            // Thread for stderr
            Thread stderrThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
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
            while (true)
            {
                if (process.isAlive())
                {
                    ;
                }
                else
                {
                    exitCode=process.exitValue();
                    break;
                }
                
                if (monitor.isCancelled())
                {
                    process.destroy();
                    Thread.sleep(200);
                    if (process.isAlive())
                    {
                        process.destroyForcibly();
                    }
                    monitor.cancel();
                    break;
                }
                
                Thread.sleep(100);
            }
            cp.print_to_console("Python process ended.");

            // Ensure both threads finish reading output
            //TODO: extract stdout if process is forcibly killed
            stdoutThread.join(300);
            stderrThread.join(300);

            if (exitCode!=-1000)
            {
                System.out.println("Process exited with code " + exitCode);
            }
            else
            {
                System.out.println("Process was killed");
            }
            
            
            stdout_writer.close();
            stderr_writer.close();

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        return "";
    }
    

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {

        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Map<String, Object> json_map_with_config=ConfigFileParser.extract_config_file_as_map();

        String python_path=(String) json_map_with_config.get("PATH_OF_PYTHON_BINARY");
        String path_of_py_file_which_spawns_frida=CreatorOfNecessaryFiles.createPythonInvokerFile();
        
        
        // agent output should be put in a file for further processing.
        // Also, the agent should be allowed to manually invoke ghidra functionalities.
        // The user may place custom code in the JS script to invoke these functionalities.
        
        monitor.setMessage("Invoking frida ... ");
        run_python_process_which_calls_frida(python_path,path_of_py_file_which_spawns_frida, path_for_dragonhook_dir.toString(), monitor);
        
    }

}
