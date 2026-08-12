package dragonhook.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

public class HttpUtils {

    public static long badlong=-567824390162L;
    public static String badstring="badstring, what a pity";
    public static byte[] badbytes= new byte[0];

    //Hard cap on the request body we are willing to buffer. The largest legitimate body is a
    //CHANGE_BYTES_INSIDE_GHIDRADB payload: 20 MB of raw bytes -> ~26.7 MB of base64 -> ~29 MB once
    //form-encoded, so 64 MB leaves plenty of headroom while bounding what a hostile client can make
    //Ghidra allocate. Without a cap, readAllBytes() will happily buffer whatever is sent.
    public static int max_POST_body_size=64*1024*1024;


    //splits one "key=value" pair and stores it. The value may itself contain '=' (base64 padding,
    //for instance), so the split is limited to 2 parts instead of dropping the whole parameter.
    private static void parse_and_store_one_param(String param_kv, Map<String, String> retval)
    {
        String[] arr_with_kv_split = param_kv.split("=", 2);
        if (arr_with_kv_split.length == 2)
        {
            try
            {
                String param = URLDecoder.decode(arr_with_kv_split[0], StandardCharsets.UTF_8);
                String value = URLDecoder.decode(arr_with_kv_split[1], StandardCharsets.UTF_8);
                retval.put(param, value);
            } catch (Exception e) {
                System.out.println("Error in parameter decode "+param_kv+" "+ e);
            }
        }
    }


    public static Map<String, String> parse_GET_params(HttpExchange httpexchange)
    {
        Map<String, String> retval = new HashMap<>();
        String GET_params_as_str=httpexchange.getRequestURI().getQuery(); // after the ? part
        if (GET_params_as_str != null)
        {
            String[] param_kvs = GET_params_as_str.split("&");
            for (int i=0; i<param_kvs.length; i++)
            {
                parse_and_store_one_param(param_kvs[i], retval);
            }
        }
        return retval;
    }


    public static Map<String, String> parse_POST_params(HttpExchange httpexchange) throws IOException
    {
        Map<String, String> retval = new HashMap<>();
        InputStream body_inpstream=httpexchange.getRequestBody();
        //read one byte more than the cap, so that we can tell "exactly at the cap" from "over it"
        byte[] body_arr=body_inpstream.readNBytes(max_POST_body_size+1);
        if (body_arr.length > max_POST_body_size)
        {
            System.out.println("Request body larger than the allowed "+max_POST_body_size+" bytes, ignoring it.");
            return retval; //empty map, the endpoint will reply with its usual parameter error
        }
        String body_as_str= new String(body_arr,StandardCharsets.UTF_8);
        if (!body_as_str.isEmpty())
        {
            String[] param_kvs = body_as_str.split("&");
            for (int i=0; i<param_kvs.length; i++)
            {
                parse_and_store_one_param(param_kvs[i], retval);
            }
        }
        return retval;
    }
    
    

    public static void provide_httpserver_reply(HttpExchange httpexchange, String str_to_sendback) throws IOException 
    {
        byte[] bytes_to_sendback = str_to_sendback.getBytes(StandardCharsets.UTF_8);
        try
        {
            Headers headers_to_sendback =httpexchange.getResponseHeaders();
            headers_to_sendback.set("Content-Type", "application/json");
            httpexchange.sendResponseHeaders(200, bytes_to_sendback.length);
            OutputStream body_to_write_into=httpexchange.getResponseBody();
            body_to_write_into.write(bytes_to_sendback);
            body_to_write_into.close();
        }
        catch (IOException e)
        {
            System.out.println("Error with sending httpserver reply: "+e);
            e.printStackTrace();
        }
        finally
        {
            httpexchange.close(); //memory leak without it
        }
    }
    
    public static long provide_safe_long_from_params(Map<String, String> extracted_param_map, String param_name)
    {
        long retval=badlong;
        try
        {
            String param_val_as_str=extracted_param_map.get(param_name);
            if (param_val_as_str==null)
            {
                return badlong;
            }
            if (param_val_as_str.startsWith("0x") || param_val_as_str.startsWith("0X"))
            {
                param_val_as_str=param_val_as_str.substring(2); //remove 0x
                retval=Long.parseLong(param_val_as_str,16);
            }
            else
            {
                retval=Long.parseLong(param_val_as_str);
            }
        }
        catch (Exception e) {
            retval=badlong;
        }
        return retval;
    }
    
    //NEVER returns null: a missing parameter yields badstring. Map.get() does not throw for a
    //missing key, it returns null, so without this check the callers would NPE on .equals() and the
    //endpoint would die without ever sending a reply.
    public static String provide_string_from_params(Map<String, String> extracted_param_map, String param_name)
    {
        String retval=badstring;
        try
        {
            String value_from_map=extracted_param_map.get(param_name);
            retval=(value_from_map==null) ? badstring : value_from_map;
        }
        catch (Exception e) {
            retval=badstring;
        }
        return retval;
    }
    
    
    public static byte[] provide_b64decoded_bytes_from_params(Map<String, String> extracted_param_map, String param_name)
    {
        byte[] retval=badbytes;
        String retval_as_str;
        retval_as_str=provide_string_from_params(extracted_param_map,param_name);
        if (retval_as_str.equals(badstring))
        {
            return badbytes;
        }
        try 
        {
            retval=Base64.getDecoder().decode(retval_as_str);
        }
        catch (Exception e) {
            retval=badbytes;
        }
        
        return retval;
    }
 
    
}
