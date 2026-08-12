package dragonhook;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Map;

import com.sun.net.httpserver.HttpServer;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import dragonhook.util.ConfigFileParser;
import dragonhook.util.ConsolePrinter;
import dragonhook.util.CreatorOfNecessaryFiles;
import dragonhook.util.DOSLimitsTracker;
import dragonhook.util.HttpUtils;
import dragonhook.util.JSAgentPreparer;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class DragonStartHTTPServerAction extends DockingAction {

    protected PluginTool tool;
    protected Program current_program;
    protected ProgramSelection incoming_selection;
    protected Plugin incoming_plugin;
    public static HttpServer httpserver; 
    private int httpserver_errors;

    
    public DragonStartHTTPServerAction(DragonHookPlugin plugin) {
        super("DragonHookPlugin", plugin.getName());
        this.tool = plugin.getTool();
        this.current_program = plugin.currentprogram; //may be null initially
        this.incoming_plugin=plugin;
        httpserver=null;
        this.httpserver_errors=0;
        init();
    }
    
    @Override
    public boolean isEnabledForContext(ActionContext context) {
        return true;
    }
    
    private void init() {
        setPopupMenuData(
            new MenuData(new String[] { "DragonHook Config...", "Start HTTP server" }, null,"Dragon-Hook"));
        setDescription("Starts the DragonHook HTTP server which processes commands coming from Frida.");
    }
    
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    @Override
    public void actionPerformed(ActionContext context) {
        CreatorOfNecessaryFiles.createAllNecessaryFiles();
        this.current_program = (this.current_program==null) ? getCurrentProgram() : this.current_program;
        JSAgentPreparer.prepare_agent_file_if_not_already_prepared(this.current_program);
        
        ConsolePrinter cp=new ConsolePrinter(this.tool);
        
        try {
            this.httpserver_errors=0;
            startServer();
            if (this.httpserver_errors==0)
            {
                cp.print_to_console("DragonHook HTTP server has started.");
            }
            else
            {
                ; //exception will be thrown and printed inside startServer();
            }

        }
        catch (IOException e) {
            cp.print_to_console("Could not start DragonHook HTTP server. "+e);
        }
        
    }
    
    private void startServer() throws IOException 
    {
        
        // Extract the configured port
        Map<String, Object> json_map_with_config=ConfigFileParser.extract_config_file_as_map();
        int port = Integer.parseInt((String) json_map_with_config.get("GHIDRA_HTTP_SERVER_PORT"));
        String interface_ip = (String) json_map_with_config.get("GHIDRA_HTTP_SERVER_INTERFACE_IP");
        httpserver = HttpServer.create(new InetSocketAddress(interface_ip,port), 0);
        DOSLimitsTracker.reset_DOS_limits();

        create_httpserver_endpoints();
        
        httpserver.setExecutor(null);
        
        Thread httpserver_thread=new Thread(() -> 
        {
            ConsolePrinter cp=new ConsolePrinter(this.tool);
            try {
                httpserver.start();
            } catch (Exception e) {
                cp.print_to_console("Could not start DragonHook HTTP server. "+e);
                httpserver = null; 
                this.httpserver_errors=1;
            }
        }, "DragonHook_HTTP_Server");
        httpserver_thread.start();
    }
    
    private void create_httpserver_endpoints()
    {
     
        DragonGhidraAPIImplementation api_impl= new DragonGhidraAPIImplementation(this.incoming_plugin,this.current_program);
        httpserver.createContext("/FUN_DATA_GIVEN_ADDR_OFFSET", httpexchange -> 
        {
            Map<String, String> extracted_param_map = HttpUtils.parse_GET_params(httpexchange);
            long addr_offset=0;
            addr_offset=HttpUtils.provide_safe_long_from_params(extracted_param_map, "address_offset");
            if (addr_offset==HttpUtils.badlong)
            {
                System.out.println("Error in FUN_DATA_GIVEN_ADDR_OFFSET, problem with offset parsing.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with offset parsing");
                return;
            }

            //implement
            String retval= api_impl.FUN_DATA_GIVEN_ADDR_OFFSET(addr_offset,true);
            HttpUtils.provide_httpserver_reply(httpexchange,retval);

        });
        
        httpserver.createContext("/ALL_FUN_DATA_SORTED_BY_RANGESTART", httpexchange -> 
        {
            String retval="";
            //check for limits
            if (DOSLimitsTracker.allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART<=0)
            {
                retval="The ALL_FUN_DATA_SORTED_BY_RANGESTART endpoint is not allowed to be called.";
                HttpUtils.provide_httpserver_reply(httpexchange,retval);
                return;
            }
            if (DOSLimitsTracker.number_of_times_ALL_FUN_DATA_SORTED_BY_RANGESTART_has_been_called>=DOSLimitsTracker.allowed_times_ALL_FUN_DATA_SORTED_BY_RANGESTART)
            {
                retval="The ALL_FUN_DATA_SORTED_BY_RANGESTART endpoint has reached the maximum amount of times to be called per agent execution.";
                HttpUtils.provide_httpserver_reply(httpexchange,retval);
                return;
            }
            DOSLimitsTracker.number_of_times_ALL_FUN_DATA_SORTED_BY_RANGESTART_has_been_called+=1;
            retval= api_impl.ALL_FUN_DATA_SORTED_BY_RANGESTART();
            HttpUtils.provide_httpserver_reply(httpexchange,retval);
        });
        
        
        httpserver.createContext("/UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR", httpexchange -> 
        {
            Map<String, String> extracted_param_map = HttpUtils.parse_POST_params(httpexchange);
            long addr_offset=0;
            addr_offset=HttpUtils.provide_safe_long_from_params(extracted_param_map, "address_offset");
            if (addr_offset==HttpUtils.badlong)
            {
                System.out.println("Error in UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR, problem with offset parsing.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with offset parsing");
                return;
            }
            String comment=HttpUtils.provide_string_from_params(extracted_param_map, "comment");
            if (comment.equals(HttpUtils.badstring))
            {
                System.out.println("Error in UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR, problem with comment.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with comment");
                return;
            }
            //implement
            String retval= api_impl.UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR(addr_offset,comment);
            HttpUtils.provide_httpserver_reply(httpexchange,retval);

        });
        
        httpserver.createContext("/UPDATE_GHIDRADB_WITH_XREF", httpexchange -> 
        {
            Map<String, String> extracted_param_map = HttpUtils.parse_GET_params(httpexchange);
            long addr_offset_from=0;
            addr_offset_from=HttpUtils.provide_safe_long_from_params(extracted_param_map, "address_offset_from");
            if (addr_offset_from==HttpUtils.badlong)
            {
                System.out.println("Error in UPDATE_GHIDRADB_WITH_XREF, problem with address_offset_from parsing.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with address_offset_from parsing");
                return;
            }
            long addr_offset_to=0;
            addr_offset_to=HttpUtils.provide_safe_long_from_params(extracted_param_map, "address_offset_to");
            if (addr_offset_to==HttpUtils.badlong)
            {
                System.out.println("Error in UPDATE_GHIDRADB_WITH_XREF, problem with address_offset_to parsing.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with address_offset_to parsing");
                return;
            }

            String type_of_xref=HttpUtils.provide_string_from_params(extracted_param_map, "RefType");
            if (type_of_xref.equals(HttpUtils.badstring))
            {
                System.out.println("Error in UPDATE_GHIDRADB_WITH_XREF, problem with RefType.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with RefType");
                return;
            }
            
            String retval= api_impl.UPDATE_GHIDRADB_WITH_XREF(addr_offset_from,addr_offset_to,type_of_xref,true);
            HttpUtils.provide_httpserver_reply(httpexchange,retval);
            
        });
        
        
        httpserver.createContext("/CODEUNIT_DATA_GIVEN_ADDR_OFFSET", httpexchange -> 
        {
            Map<String, String> extracted_param_map = HttpUtils.parse_GET_params(httpexchange);
            long addr_offset=0;
            addr_offset=HttpUtils.provide_safe_long_from_params(extracted_param_map, "address_offset");
            if (addr_offset==HttpUtils.badlong)
            {
                System.out.println("Error in CODEUNIT_DATA_GIVEN_ADDR_OFFSET, problem with offset parsing.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with offset parsing");
                return;
            }
            //implement
            String retval= api_impl.CODEUNIT_DATA_GIVEN_ADDR_OFFSET(addr_offset);
            HttpUtils.provide_httpserver_reply(httpexchange,retval);
        });
        
        httpserver.createContext("/CHANGE_BYTES_INSIDE_GHIDRADB", httpexchange -> 
        {
            Map<String, String> extracted_param_map = HttpUtils.parse_POST_params(httpexchange);
            long addr_offset=0;
            addr_offset=HttpUtils.provide_safe_long_from_params(extracted_param_map, "address_offset");
            if (addr_offset==HttpUtils.badlong)
            {
                System.out.println("Error in CHANGE_BYTES_INSIDE_GHIDRADB, problem with offset parsing.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with offset parsing");
                return;
            }
            byte[] decoded_bytes=HttpUtils.provide_b64decoded_bytes_from_params(extracted_param_map,"content_as_b64");
            if (Arrays.equals(decoded_bytes,HttpUtils.badbytes))
            {
                System.out.println("Error in CHANGE_BYTES_INSIDE_GHIDRADB, problem with content base64 decode.");
                HttpUtils.provide_httpserver_reply(httpexchange,"error with offcontent base64 decode");
                return;
            }
            String retval="";
            
            //Check for limits
            if (DOSLimitsTracker.allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB<=0)
            {
                retval="The CHANGE_BYTES_INSIDE_GHIDRADB endpoint is not allowed to be called.";
                HttpUtils.provide_httpserver_reply(httpexchange,retval);
                return;
            }
            if (DOSLimitsTracker.number_of_times_CHANGE_BYTES_INSIDE_GHIDRADB_has_been_called>=DOSLimitsTracker.allowed_times_CHANGE_BYTES_INSIDE_GHIDRADB)
            {
                retval="The CHANGE_BYTES_INSIDE_GHIDRADB endpoint has reached the maximum amount of times to be called per agent execution.";
                HttpUtils.provide_httpserver_reply(httpexchange,retval);
                return;
            }
            DOSLimitsTracker.number_of_times_CHANGE_BYTES_INSIDE_GHIDRADB_has_been_called+=1;
            
            
            
            //implement
            retval= api_impl.CHANGE_BYTES_INSIDE_GHIDRADB(addr_offset,decoded_bytes);
            HttpUtils.provide_httpserver_reply(httpexchange,retval);
            
        });
        
    }

}
