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
import java.util.Map;

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
    	return settings_dir;
    }
    
    public static Path get_dir_for_DragonhookPlugin_files()
    {
    	Path ghidra_settings_dir_path=CreatorOfNecessaryFiles.get_ghidra_settings_dir().toPath();
        Path path_for_dragonhook_dir=ghidra_settings_dir_path.resolve("DragonHookPlugin_files").resolve(DragonHookPlugin.DragonHook_plugin_version);
        return path_for_dragonhook_dir;
    }
    
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
        return tmp_dir;
    }
    
    
    public static String read_text_from_resource(String resourcepath)
    {
        String retval="";
        InputStream inputStream =CreatorOfNecessaryFiles.class.getResourceAsStream(resourcepath);
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
        if (!fileexists)
        {
            try {
                BufferedWriter writer = Files.newBufferedWriter(path_for_file);
                writer.write(contents);
                writer.flush();
                writer.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
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
        File config_file_obj = new File(path_for_config_as_str);
        config_file_obj.delete();
        path_for_config_as_str = CreatorOfNecessaryFiles.createConfigFile();
        return path_for_config_as_str;
    }
    
    public static String createAgentFile()
    {
        initial_value_for_agent=read_text_from_resource("/script_templates/"+agent_file_name);
        String path_for_agent_as_str= create_file_in_local_settings_dir(agent_file_name,initial_value_for_agent);
        return path_for_agent_as_str;
    }
    
    public static String resetAgentFile()
    {
        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Path path_for_agent = path_for_dragonhook_dir.resolve(agent_file_name);
        String path_for_agent_as_str = path_for_agent.toString();
        File agent_file_obj = new File(path_for_agent_as_str);
        agent_file_obj.delete();
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
        File python_invoker_file_obj = new File(path_for_python_invoker_as_str);
        python_invoker_file_obj.delete();
        path_for_python_invoker_as_str = CreatorOfNecessaryFiles.createPythonInvokerFile();
        return path_for_python_invoker_as_str;
    }
    
    public static void createAllNecessaryFiles()
    {
        String path_for_config_as_str = CreatorOfNecessaryFiles.createConfigFile();
        String path_for_agent_as_str = CreatorOfNecessaryFiles.createAgentFile();
        String path_for_python_invoker_as_str = CreatorOfNecessaryFiles.createPythonInvokerFile();
        DOSLimitsTracker.initialize_max_limits_from_config();
    }
    
}
