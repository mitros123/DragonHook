package dragonhook.util;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;

public class ConsolePrinter {

    private PluginTool incoming_plugintool;
    private ConsoleService console_service;
    
    public ConsolePrinter(PluginTool incoming_plugintool)
    {
        this.incoming_plugintool=incoming_plugintool;
        this.console_service=this.incoming_plugintool.getService(ConsoleService.class);
    }
    
    public void print_to_console(String str_to_print)
    {
        if (this.console_service != null)
        {
            this.console_service.println(str_to_print);
        }        
    }
}
