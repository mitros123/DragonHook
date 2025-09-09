package dragonhook.util;

import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.file.Path;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class ConfigFileParser {

    
 
    public static Map<String,Object> extract_config_file_as_map()
    {
        Path path_for_dragonhook_dir=CreatorOfNecessaryFiles.get_dir_for_DragonhookPlugin_files();
        Path path_for_file = path_for_dragonhook_dir.resolve(CreatorOfNecessaryFiles.config_file_name);
        String path_for_file_as_str=path_for_file.toString();
        File file = new File(path_for_file_as_str);
        
        
        Map<String, Object> json_map_with_data=null;
        Gson gson = new Gson();
        try (Reader reader = new FileReader(path_for_file_as_str)) {
            // Define the type for the Map
            Type type = new TypeToken<Map<String, Object>>(){}.getType();
            // Deserialize JSON to Map
            json_map_with_data = gson.fromJson(reader, type);

        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return json_map_with_data;
    }
}
