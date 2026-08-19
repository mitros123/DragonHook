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

    //Called by DragonHookPlugin.programActivated/programDeactivated. Without this the program captured
    //when the action was constructed was used forever, so after switching program in Ghidra every offset
    //and every comment went to the WRONG program's database.
    //This one does more than the other actions': it also retargets a RUNNING http server, whose handlers
    //captured the api implementation when their contexts were created. See point_the_running_server_at().
    public void set_current_program(Program incoming_program) {
        this.current_program=incoming_program;
        point_the_running_server_at(incoming_program);
    }
    protected ProgramSelection incoming_selection;
    protected Plugin incoming_plugin;
    //volatile: both of these are written by the server thread started in startServer() and read by the
    //action thread right afterwards. Without it there is no guarantee the reader ever observes the write.
    public static volatile HttpServer httpserver;
    private volatile int httpserver_errors;

    //used when the config file does not carry the setting, instead of throwing out of startServer()
    public static final int default_http_server_port=8124;
    public static final String default_http_server_interface_ip="127.0.0.1";

    
    public DragonStartHTTPServerAction(DragonHookPlugin plugin) {
        super("DragonHookPlugin", plugin.getName());
        this.tool = plugin.getTool();
        this.current_program = plugin.currentprogram; //may be null initially
        this.incoming_plugin=plugin;
        //httpserver is deliberately NOT reset here. It used to be, and that is how a running server became
        //unstoppable: the field is STATIC, and constructing this action - which happens again whenever another
        //DragonHookPlugin instance is created, for instance when Ghidra opens a program in a second tool -
        //threw away the only reference to a server that was already listening. The server thread stayed alive
        //with the port still bound, while "Stop HTTP server" looked at a null field and reported that it could
        //not find one running. A constructor must not destroy global state that may belong to something live.
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
    
    //The api implementation the running server's handlers are bound to. Kept so that a program change can
    //retarget it: the handlers capture this object once, when the contexts are created, so without this the
    //server would keep serving the program that was open when it was started - writing comments and xrefs
    //into the wrong database after the user switched program.
    public static volatile DragonGhidraAPIImplementation api_implementation_serving_requests=null;

    //Called by DragonHookPlugin.programActivated, via set_current_program below.
    public static void point_the_running_server_at(Program incoming_program)
    {
        DragonGhidraAPIImplementation api_impl=api_implementation_serving_requests;
        if (api_impl!=null)
        {
            api_impl.set_current_program(incoming_program);
        }
    }

    private void startServer() throws IOException
    {
        //Refuse to start a second one. Without this the new server would fail to bind the port anyway, but
        //the static reference would already have been overwritten and the first server would be orphaned -
        //exactly the state that makes it impossible to stop.
        if (httpserver!=null)
        {
            new ConsolePrinter(this.tool).print_to_console("The DragonHook HTTP server is already running."
                    + " Stop it first if you want to restart it on a different port or interface.");
            //Marked as an error so that actionPerformed() does not go on to announce "has started" straight
            //after this message, which is what it used to do.
            this.httpserver_errors=1;
            return;
        }

        // Extract the configured port
        Map<String, Object> json_map_with_config=ConfigFileParser.extract_config_file_as_map();

        //A missing or unusable setting used to reach Integer.parseInt as null and throw
        //NumberFormatException out of a method that only declares IOException, so the user got a raw
        //stack trace instead of being told which setting is wrong.
        Object raw_port=json_map_with_config.get("GHIDRA_HTTP_SERVER_PORT");
        int port=default_http_server_port;
        try
        {
            if (raw_port instanceof Number) { port=((Number) raw_port).intValue(); }
            else if (raw_port!=null) { port=Integer.parseInt(((String) raw_port).trim()); }
            else { throw new NumberFormatException("setting is absent"); }
        }
        catch (Exception e)
        {
            new ConsolePrinter(this.tool).print_to_console("DragonHook: GHIDRA_HTTP_SERVER_PORT is missing or"
                    +" unusable (\""+raw_port+"\"), falling back to "+default_http_server_port+".");
            port=default_http_server_port;
        }

        Object raw_interface_ip=json_map_with_config.get("GHIDRA_HTTP_SERVER_INTERFACE_IP");
        String interface_ip=(raw_interface_ip==null) ? default_http_server_interface_ip : ((String) raw_interface_ip).trim();
        if (interface_ip.isEmpty())
        {
            interface_ip=default_http_server_interface_ip;
        }
        httpserver = HttpServer.create(new InetSocketAddress(interface_ip,port), 0);
        DOSLimitsTracker.reset_DOS_limits();

        create_httpserver_endpoints();
        
        //Deliberately serial: setExecutor(null) makes com.sun HttpServer run every handler on its own
        //dispatch thread, one at a time. That is what Ghidra's transaction model wants, but it also means
        //the python side's worker pool buys ordering rather than parallelism - a slow update still delays
        //a query behind it, which is why every python call has a timeout now.
        httpserver.setExecutor(null);

        Thread httpserver_thread=new Thread(() ->
        {
            ConsolePrinter cp=new ConsolePrinter(this.tool);
            try {
                httpserver.start();
            } catch (Exception e) {
                cp.print_to_console("Could not start DragonHook HTTP server. "+e);
                //The handle MUST be released here. Keeping it meant a dead server object stayed in the static,
                //and the double-start guard then refused every later attempt with "already running" - the
                //server was unstartable until the user thought to press Stop first. Nulling it is safe
                //because every reader null-checks, and stop(0) on a server that never started is harmless.
                try { httpserver.stop(0); } catch (Exception ignored) { }
                httpserver=null;
                api_implementation_serving_requests=null;
                this.httpserver_errors=1;
            }
        }, "DragonHook_HTTP_Server");
        httpserver_thread.start();
    }
    
    private void create_httpserver_endpoints()
    {
     
        DragonGhidraAPIImplementation api_impl= new DragonGhidraAPIImplementation(this.incoming_plugin,this.current_program);
        //published so that a later program change can retarget the handlers, which capture this object once
        api_implementation_serving_requests=api_impl;
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
