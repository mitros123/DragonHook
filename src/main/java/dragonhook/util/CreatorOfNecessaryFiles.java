package dragonhook.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import dragonhook.DragonHookPlugin;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.ApplicationProperties;
import utility.application.ApplicationUtilities;

public class CreatorOfNecessaryFiles {

    public static String config_file_name="DragonHook_plugin_config.json";
    public static String agent_file_name="DragonHook_plugin_agent.js";
    public static String python_invoker_file_name="DragonHook_python_invoker.py";
    protected static String initial_value_for_config="";
    protected static String initial_value_for_agent="";
    protected static String initial_value_for_python_invoker="";
    
    
    //This fetches the settings dir, using the builtin methods
    //https://github.com/NationalSecurityAgency/ghidra/blob/7765e8338bb9f866ce31ba98059243f0af2ca80d/Ghidra/RuntimeScripts/Common/support/launch.properties#L86-L127
    //NEVER returns null. It used to return null on failure and get_dir_for_DragonhookPlugin_files() then
    //called .toPath() on it, so a settings directory that could not be resolved surfaced as a bare
    //NullPointerException with no hint about what had actually gone wrong. There is no sensible fallback -
    //every file this plugin owns lives under that directory - so fail loudly and say why.
    public static File get_ghidra_settings_dir()
    {
    	ApplicationProperties app_properties = Application.getApplicationLayout().getApplicationProperties();
    	ResourceFile installation_directory=Application.getInstallationDirectory();
    	File settings_dir=null;
    	try {
			settings_dir=ApplicationUtilities.getDefaultUserSettingsDir(app_properties, installation_directory);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	if (settings_dir==null)
    	{
    	    String errorstr="DragonHook: could not determine Ghidra's user settings directory, so the"
    	            +" plugin cannot create its config, agent or python invoker files. See the exception"
    	            +" printed above this message.";
    	    System.out.println(errorstr);
    	    throw new RuntimeException(errorstr);
    	}
    	return settings_dir;
    }
    
    public static Path get_dir_for_DragonhookPlugin_files()
    {
    	Path ghidra_settings_dir_path=CreatorOfNecessaryFiles.get_ghidra_settings_dir().toPath();
        Path path_for_dragonhook_dir=ghidra_settings_dir_path.resolve("DragonHookPlugin_files").resolve(DragonHookPlugin.DragonHook_plugin_version);
        return path_for_dragonhook_dir;
    }
    
    //Same reasoning as get_ghidra_settings_dir(): DragonAgentRunnerTask calls .toPath() on the result
    //straight away, so returning null only moved the failure somewhere less informative.
    public static File get_ghidra_user_temp_dir()
    {
        File tmp_dir=null;
        try {
            tmp_dir=ApplicationUtilities.getDefaultUserTempDir("Ghidra_DragonHookPlugin");
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if (tmp_dir==null)
        {
            String errorstr="DragonHook: could not determine Ghidra's user temp directory, so the agent"
                    +" stdout/stderr files cannot be written. See the exception printed above this message.";
            System.out.println(errorstr);
            throw new RuntimeException(errorstr);
        }
        return tmp_dir;
    }
    
    
    public static String read_text_from_resource(String resourcepath)
    {
        String retval="";
        InputStream inputStream =CreatorOfNecessaryFiles.class.getResourceAsStream(resourcepath);
        if (inputStream==null)
        {
            //used to be a NullPointerException here. Now that the agent is assembled from several
            //resources, a renamed or unpackaged module is a realistic mistake and has to be reported.
            System.out.println("DragonHook: resource not found in the extension: "+resourcepath);
            return retval;
        }
        String file_text="";
        try {
            file_text = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        retval=file_text;
        return retval;
    }
    
    public static String read_text_file_from_disk(String path_in_disk) throws FileNotFoundException, IOException
    {
        try (InputStream inputStream = new FileInputStream(path_in_disk)) {
            StringBuilder content = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            return content.toString();
        } 
    }
    
    public static String create_file_in_local_settings_dir(String filename, String contents)
    {
        
        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Path path_for_file = path_for_dragonhook_dir.resolve(filename);
        String path_for_file_as_str=path_for_file.toString();
        File file = new File(path_for_file_as_str);
        file.getParentFile().mkdirs(); //make parent directories
        boolean fileexists=false;
        try {
            fileexists = !( file.createNewFile() ); //negation
        } catch (IOException e) {
            e.printStackTrace();
        } // if file already exists will do nothing

        //A file that exists but is empty counts as missing. Without this, one failed assembly (a
        //renamed or unpackaged agent module, for instance) would leave a zero byte agent behind that
        //is never rewritten, and every later run would silently load nothing.
        if (fileexists && file.length()==0)
        {
            fileexists=false;
        }

        if (!fileexists)
        {
            //try-with-resources, so the handle is released on the failing path too. It used to be a bare
            //new/write/close, which leaked the writer whenever write() threw and, worse, could leave a
            //PARTIALLY written file behind: non-zero length, so the empty-file guard above considered it
            //valid from then on and it was never rewritten. Delete the remains so the next run retries.
            try (BufferedWriter writer = Files.newBufferedWriter(path_for_file)) {
                writer.write(contents);
                writer.flush();
            } catch (IOException e) {
                System.out.println("DragonHook: could not write \""+path_for_file_as_str+"\": "+e
                        +" . Removing the partial file so that it is recreated on the next attempt.");
                e.printStackTrace();
                try { Files.deleteIfExists(path_for_file); } catch (IOException e2) { e2.printStackTrace(); }
            }
        }
        return path_for_file_as_str;
    }
    
    
    public static String createConfigFile()
    {
        initial_value_for_config=read_text_from_resource("/script_templates/"+config_file_name);
        String path_for_config_as_str= create_file_in_local_settings_dir(config_file_name,initial_value_for_config);
        return path_for_config_as_str;
    }
    
    public static String resetConfigFile()
    {
        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Path path_for_config = path_for_dragonhook_dir.resolve(config_file_name);
        String path_for_config_as_str = path_for_config.toString();
        delete_file_for_reset(path_for_config);
        path_for_config_as_str = CreatorOfNecessaryFiles.createConfigFile();
        return path_for_config_as_str;
    }
    
    //Deleting the file is the whole of a "reset": createXFile() only writes when the file is absent or
    //empty, so if the delete silently fails - locked by an editor on windows, read only, wrong owner - the
    //reset reports success and changes nothing at all. Report it instead.
    private static boolean delete_file_for_reset(Path path_for_file)
    {
        File file_to_delete=path_for_file.toFile();
        if (!file_to_delete.exists())
        {
            return true;   //nothing to remove, which is the state a reset wants anyway
        }
        boolean the_file_was_deleted=file_to_delete.delete();
        if (!the_file_was_deleted)
        {
            System.out.println("DragonHook: could not delete \""+path_for_file.toString()+"\", so it was NOT"
                    +" reset to its default. It may be open in another program, or read only. Close it and"
                    +" try again, or delete it by hand.");
        }
        return the_file_was_deleted;
    }


    //The agent is kept as separate modules so that it can be worked on in pieces, and they are
    //concatenated into the single file that the python invoker loads and that JSAgentPreparer patches.
    //
    //THE ORDER OF THIS ARRAY IS PART OF THE AGENT'S CORRECTNESS, it is not cosmetic:
    // - function declarations hoist across the whole assembled script, so their order is free, but
    //   "var" initialisers and top level statements run in file order
    // - 01 must come first: its first line is the one JSAgentPreparer rewrites with the module name
    //   and the ghidra image base, and the console.log override has to exist before anything logs
    // - 05 reads ghidra_base_of_module_to_hook and module_name_to_hook at declaration time, so it
    //   must follow 01
    // - 08 holds the "PREPARATION STEPS" marker, the top level block that sets
    //   is_generally_stalking_enabled, and the module/thread observers. Everything it reads must be
    //   declared before it, and the observers must be registered after the preparation steps
    // - 09 holds intercept_identified_module_DragonHook() with the "DRAGONHOOK CODE GOES HERE" marker
    //   and rpc.exports, and must come last
    public static String[] agent_module_files_in_order = {
            "01_header_and_python_interaction.js",
            "02_ghidra_api.js",
            "03_function_and_address_info.js",
            "04_custom_backtracer.js",
            "05_dynamic_call_stalking.js",
            "06_string_reference_resolution.js",
            "07_hardware_watchpoints.js",
            "08_preparation_and_observers.js",
            "09_interceptors_and_rpc_exports.js"
    };

    //Always concatenates EVERY module in agent_module_files_in_order, unconditionally. There is no
    //notion of "only the modules this run needs": the features are switched on by the flags that
    //JSAgentPreparer patches, and those flags live inside the modules, so all of them must be present.
    //
    //If any single module is missing or empty the whole thing returns "", so that nothing is written
    //and the empty file guard in create_file_in_local_settings_dir() retries next time. Appending a
    //partial agent would cache a file that parses but silently lacks whole features.
    public static String assemble_agent_from_modules()
    {
        StringBuilder sb=new StringBuilder(131072);
        boolean a_module_is_missing=false;
        for (int i=0;i<agent_module_files_in_order.length;i++)
        {
            String contents_of_module=read_text_from_resource(
                    "/script_templates/agent_modules/"+agent_module_files_in_order[i]);
            if (contents_of_module==null || contents_of_module.isEmpty())
            {
                System.out.println("DragonHook: agent module "+agent_module_files_in_order[i]
                        +" is missing or empty, refusing to assemble a partial agent");
                a_module_is_missing=true;
                continue;   //keep going so that every missing module gets reported, not just the first
            }
            sb.append(contents_of_module);
        }
        if (a_module_is_missing)
        {
            System.out.println("DragonHook: the agent was NOT assembled. Rebuild and reinstall the"
                    +" extension, and make sure every file listed in agent_module_files_in_order is"
                    +" packaged under /script_templates/agent_modules/");
            return "";
        }
        return sb.toString();
    }

    //Same rule create_file_in_local_settings_dir() applies: a file that is absent or zero length has
    //to be produced, anything else is left alone so that a user's manual edits survive.
    public static boolean does_file_in_local_settings_dir_need_creating(String filename)
    {
        Path path_for_file=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files().resolve(filename);
        File file = path_for_file.toFile();
        return ( (!file.exists()) || file.length()==0 );
    }

    //Only writes when the file does not already exist, which is what keeps a user's manual edits to
    //the assembled agent from being thrown away.
    //
    //The existence check happens BEFORE assembling on purpose. Almost every menu action calls
    //createAllNecessaryFiles(), and several call createAgentFile() again right after, so assembling
    //first meant reading nine resources and building a ~110 KB string several times per action only to
    //throw it away because the file was already there. It also meant the "module missing" diagnostic
    //fired on every single action instead of only when the agent is actually being produced.
    public static String createAgentFile()
    {
        Path path_for_agent=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files().resolve(agent_file_name);
        if (!does_file_in_local_settings_dir_need_creating(agent_file_name))
        {
            return path_for_agent.toString();
        }
        initial_value_for_agent=assemble_agent_from_modules();
        String path_for_agent_as_str= create_file_in_local_settings_dir(agent_file_name,initial_value_for_agent);
        return path_for_agent_as_str;
    }
    
    public static String resetAgentFile()
    {
        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Path path_for_agent = path_for_dragonhook_dir.resolve(agent_file_name);
        String path_for_agent_as_str = path_for_agent.toString();
        delete_file_for_reset(path_for_agent);
        path_for_agent_as_str = CreatorOfNecessaryFiles.createAgentFile();
        return path_for_agent_as_str;
    }
    
    
    public static String createPythonInvokerFile()
    {
        initial_value_for_python_invoker=read_text_from_resource("/script_templates/"+python_invoker_file_name);
        String path_for_python_invoker_as_str= create_file_in_local_settings_dir(python_invoker_file_name,initial_value_for_python_invoker);
        return path_for_python_invoker_as_str;
    }
    
    public static String resetPythonInvokerFile()
    {
        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Path path_for_python_invoker = path_for_dragonhook_dir.resolve(python_invoker_file_name);
        String path_for_python_invoker_as_str = path_for_python_invoker.toString();
        delete_file_for_reset(path_for_python_invoker);
        path_for_python_invoker_as_str = CreatorOfNecessaryFiles.createPythonInvokerFile();
        return path_for_python_invoker_as_str;
    }
    
    public static void createAllNecessaryFiles()
    {
        CreatorOfNecessaryFiles.createConfigFile();
        CreatorOfNecessaryFiles.createAgentFile();
        CreatorOfNecessaryFiles.createPythonInvokerFile();
        DOSLimitsTracker.initialize_max_limits_from_config();
    }
    
}
