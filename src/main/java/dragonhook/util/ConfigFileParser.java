package dragonhook.util;

import java.io.FileReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class ConfigFileParser {

    
 
    //NEVER returns null. Every caller immediately does map.get(...), so returning null on failure turned
    //an editable text file - which users are invited to edit, and where one stray comma is enough - into
    //an opaque NullPointerException somewhere else entirely. An empty map instead means the callers hit
    //their own "setting missing" handling, and the real cause is printed here once, clearly.
    public static Map<String,Object> extract_config_file_as_map()
    {
        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Path path_for_file = path_for_dragonhook_dir.resolve(CreatorOfNecessaryFiles.config_file_name);
        String path_for_file_as_str=path_for_file.toString();

        Map<String, Object> json_map_with_data=null;
        Gson gson = new Gson();
        try (Reader reader = new FileReader(path_for_file_as_str)) {
            // Define the type for the Map
            Type type = new TypeToken<Map<String, Object>>(){}.getType();
            // Deserialize JSON to Map
            json_map_with_data = gson.fromJson(reader, type);

        } catch (Exception e) {
            System.out.println("DragonHook: could not read the config file \""+path_for_file_as_str
                    +"\". It is either missing or not valid JSON - a stray comma or a missing quote is"
                    +" enough. Fix it, or use the right click option \"DragonHook Config... -> Reset all"
                    +" config files to default\". Reported error: "+e);
            e.printStackTrace();
        }

        if (json_map_with_data==null)
        {
            //gson also returns null for a file that exists but is empty
            System.out.println("DragonHook: the config file \""+path_for_file_as_str+"\" produced no"
                    +" settings at all, so every setting will fall back to its default or be reported as"
                    +" missing.");
            json_map_with_data=new HashMap<String,Object>();
        }

        return json_map_with_data;
    }
}
