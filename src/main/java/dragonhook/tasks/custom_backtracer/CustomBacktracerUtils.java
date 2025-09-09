package dragonhook.tasks.custom_backtracer;



import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.regex.Pattern;

import javax.swing.JTextField;

import dragonhook.util.ConsolePrinter;
import dragonhook.util.PackageChecker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

public class CustomBacktracerUtils {
    
    public static String error_plugin_not_loaded="Error, Frida Hook Generator plugin is not loaded";
    
    public static String return_offset_for_addr(Address in_addr, Program current_program) {
        return "0x"+Long.toHexString(in_addr.getOffset() - current_program.getImageBase().getOffset());
    }
    
    
    //call with a list of ghidra addresses such as "0073b575,0073b5a0"
    public static String invoke_FridaHookGenerator(Program current_program, PluginTool incoming_plugintool, String list_of_ghidra_addresses, String backtracer_type)
    {
        
        /*
         * Python sample code:
        advdialog=AdvancedHookOptionsDialog(state.getTool(),currentProgram)
        advdialog.isReferencestoFunctionCheckboxchecked=True
        advdialog.isFunctionsReferencingFunctionCheckboxchecked=True
        advdialog.IncludeCustomTextTextField.setText("console.log('currentaddr:'+this.context.pc)")
        advdialog.isIncludeCustomTextcheckboxchecked=True
        apihandler=FridaHookGeneratorAPIHandler(state.getTool(),currentProgram,"0073b575,0073b5a0",advdialog);
        hook_str=apihandler.perform_hook_generation()
        print(hook_str)
        */
        
        
        String retval="";
        ConsolePrinter cp=new ConsolePrinter(incoming_plugintool);
        
        if (!PackageChecker.isClassAvailable("fridahookgenerator.FridaHookGeneratorPlugin"))
        {
            String errorstr=error_plugin_not_loaded;
            cp.print_to_console(errorstr);
            System.out.println(errorstr);
            return errorstr;
        }
        
        //If the plugin is loaded, then the rest should be done using reflection
        // Try to load the classes
        Class<?> clazz_advhookoptionsdialog = null;
        try {
            clazz_advhookoptionsdialog = Class.forName("fridahookgenerator.AdvancedHookOptionsDialog");
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        Class<?> clazz_apihandler=null;
        try {
            clazz_apihandler = Class.forName("fridahookgenerator.FridaHookGeneratorAPIHandler");
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        

        // If needed, create instance via reflection
        Object instance_advhookoptionsdialog=null;
        try {
            instance_advhookoptionsdialog = clazz_advhookoptionsdialog.getDeclaredConstructor(PluginTool.class,Program.class)
                                                                                                  .newInstance(incoming_plugintool,current_program);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        
        //set the fields
        Field field1=null;
        try {
            field1 = clazz_advhookoptionsdialog.getField("IncludeCustomTextTextField");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        Field field2=null;
        try {
            field2 = clazz_advhookoptionsdialog.getField("isIncludeCustomTextcheckboxchecked");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        Field field3=null;
        try {
            field3 = clazz_advhookoptionsdialog.getField("isIncludeInterceptorTryCatchcheckboxchecked");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        Field field4=null;
        try {
            field4 = clazz_advhookoptionsdialog.getField("isCustomFunInterceptorHookOutputCheckboxchecked");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        
        JTextField field1_value=null;
        try {
            field1_value = (JTextField) field1.get(instance_advhookoptionsdialog);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        field1_value.setText("console.log(custom_backtracer(this.context,"+backtracer_type+"));");
        

        try {
            field2.set(instance_advhookoptionsdialog, true);
            field3.set(instance_advhookoptionsdialog, true);
            //field4.set(instance_advhookoptionsdialog, true); //let's not enable
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 

        
        
        Object instance_apihandler=null;
        try {
            instance_apihandler = clazz_apihandler.getDeclaredConstructor(PluginTool.class,Program.class,String.class,clazz_advhookoptionsdialog)
                                                                             .newInstance(incoming_plugintool,current_program, list_of_ghidra_addresses ,instance_advhookoptionsdialog);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        
        //now invoke the method
        Method perform_hook_generation_method=null;
        try {
            perform_hook_generation_method = clazz_apihandler.getMethod("perform_hook_generation");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 
        
        
        
        try {
            retval=(String) perform_hook_generation_method.invoke(instance_apihandler);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 
        
        

        
        return retval;
    }
    
    
    
    public static String extract_elements_of_hashset_as_address_str(HashSet<Address>hashset_of_collected_addresses)
    {

        StringBuilder sb=new StringBuilder();
        Iterator<Address> it = hashset_of_collected_addresses.iterator();
        {
            while (it.hasNext()) {

                Address nextaddr=it.next();
                sb.append(nextaddr.toString()+",");
                if(it.hasNext())
                {
                    sb.append(",");
                }
            }
        }
        return sb.toString();
    }
    
    
    
    

    public static String extract_str_with_hook_addresses_from_selection(Program current_program,ArrayList<AddressRange> incoming_addressrange_list, TaskMonitor incoming_monitor, boolean should_hook_function_starts_only)
    {
        String retval="";
        HashSet<Address> hashset_of_collected_addresses= new HashSet<Address>();
        Iterator<AddressRange> list_iter=incoming_addressrange_list.iterator();
        Listing current_program_listing=current_program.getListing();
        int list_cnt=0;
        int cnt_for_gc=0;
        while (list_iter.hasNext())
        {
            AddressRange current_address_range = list_iter.next();
            list_cnt++;
            if (incoming_monitor.isCancelled())
            {
                incoming_monitor.cancel();
                retval="";
                System.out.println("Extraction of addresses to hook is cancelled");
                return retval;
            }
            incoming_monitor.setMessage("Extracting addresses to hook from selection ... "+Long.toString(list_cnt)+"/"+Long.toString(incoming_addressrange_list.size()));
            
            AddressSet addr_set = new AddressSet(current_address_range);
            Iterator<CodeUnit> codeunit_iterator= current_program_listing.getCodeUnits(addr_set,true);
            
            int cnt_for_addressrange=0;
            
            while (codeunit_iterator!=null && codeunit_iterator.hasNext())
            {
                CodeUnit codeunit_in_question=codeunit_iterator.next();
                cnt_for_addressrange+=1;
                cnt_for_gc+=1;
                if (cnt_for_addressrange % 10000 == 0)
                {
                    if (incoming_monitor.isCancelled())
                    {
                        incoming_monitor.cancel();
                        retval="";
                        System.out.println("Extraction of addresses to hook is cancelled");
                        return retval;
                    }
                    incoming_monitor.setMessage("Extracting addresses to hook from selection .... "+Long.toString(list_cnt)+"/"+Long.toString(incoming_addressrange_list.size())+", "+Long.toString(cnt_for_addressrange)+"/"+Long.toString(current_address_range.getLength()));
                }
                if (cnt_for_gc % 2000000 == 0)
                {
                    System.out.println("Invoking garbage collector to reduce memory footprint...");
                    System.gc();
                }
                
                boolean is_instruction=false;
                if (codeunit_in_question instanceof Instruction)
                {
                    is_instruction=true;
                }
                if (is_instruction)
                {
                    Instruction instr=(Instruction) codeunit_in_question;
                    if (should_hook_function_starts_only)
                    {
                        Function container_function=current_program_listing.getFunctionContaining(codeunit_in_question.getMinAddress());
                        if (container_function!=null && !hashset_of_collected_addresses.contains(container_function.getEntryPoint()))
                        {
                            hashset_of_collected_addresses.add(container_function.getEntryPoint());
                        }
                    }
                    else
                    {
                        //hook everything
                        if (!hashset_of_collected_addresses.contains(codeunit_in_question.getMinAddress()))
                        {
                            hashset_of_collected_addresses.add(codeunit_in_question.getMinAddress());
                        } 
                    }
                    
                }
            }
        }
        
        //now let's extract the elements

        retval=extract_elements_of_hashset_as_address_str(hashset_of_collected_addresses);
        
        
        
        System.out.println(retval);
        return retval;
    }
    
    
    
    public static String extract_str_with_hook_addresses_for_function_regex(Program current_program, TaskMonitor incoming_monitor, String regex_for_fun_name)
    {

        Pattern pattern= Pattern.compile(regex_for_fun_name,Pattern.CASE_INSENSITIVE);
        FunctionIterator fun_iter=current_program.getListing().getFunctions(true);
        int num_of_functions_processed=0;
        HashSet<Address> hashset_of_collected_addresses= new HashSet<Address>();

        
        
        if (incoming_monitor.isCancelled()) {return "";}
        incoming_monitor.setMessage("Extracting functions by regex...");
        
        while(fun_iter!=null && fun_iter.hasNext())
        {
            Function newfun=fun_iter.next();
            num_of_functions_processed++;
            String name_of_newfun=newfun.getName(true);
            
            if (pattern.matcher(name_of_newfun).matches())
            {
                hashset_of_collected_addresses.add(newfun.getEntryPoint());        
            }
            if (num_of_functions_processed%100==0 && incoming_monitor.isCancelled()) {return "";} //check for cancellation by the user
        }
        

        String retval=extract_elements_of_hashset_as_address_str(hashset_of_collected_addresses);
        
        incoming_monitor.setMessage("Extracted functions by regex");

        
        System.out.println(retval);
        return retval;
            
    }
    
    
}


    
   

