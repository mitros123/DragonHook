package dragonhook.tasks.custom_backtracer;



import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Set;
import java.util.TreeSet;
import java.util.Iterator;
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

        
        //FAIL FAST HERE. Every reflection step above catches its exception and carries on with a null, so
        //a single renamed field in the Frida Hook Generator cascaded: null class -> NPE caught -> null
        //instance -> NPE caught -> null field -> and then the setText() below, which is NOT inside a try,
        //threw an uncaught NullPointerException out of the whole task. PackageChecker only proves the
        //plugin class exists, not that its fields still do, so say plainly what is incompatible instead.
        if (clazz_advhookoptionsdialog==null || clazz_apihandler==null || instance_advhookoptionsdialog==null
            || field1==null || field2==null || field3==null)
        {
            String errorstr="Error, the installed Frida Hook Generator plugin does not expose the API"
                    +" DragonHook expects (missing class, constructor or field). Its version is probably"
                    +" incompatible with this version of DragonHook.";
            cp.print_to_console(errorstr);
            System.out.println(errorstr);
            return errorstr;
        }

        JTextField field1_value=null;
        try {
            field1_value = (JTextField) field1.get(instance_advhookoptionsdialog);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if (field1_value==null)
        {
            String errorstr="Error, could not read IncludeCustomTextTextField from the Frida Hook Generator"
                    +" dialog, so the backtracer hook cannot be generated.";
            cp.print_to_console(errorstr);
            System.out.println(errorstr);
            return errorstr;
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

        //same reasoning as above: do not invoke on a null handle and let an NPE escape the task
        if (instance_apihandler==null || perform_hook_generation_method==null)
        {
            String errorstr="Error, could not reach FridaHookGeneratorAPIHandler.perform_hook_generation()."
                    +" The installed Frida Hook Generator plugin is probably an incompatible version.";
            cp.print_to_console(errorstr);
            System.out.println(errorstr);
            return errorstr;
        }

        try {
            retval=(String) perform_hook_generation_method.invoke(instance_apihandler);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 
        
        

        
        return retval;
    }
    
    
    
    public static String extract_elements_of_hashset_as_address_str(Set<Address>hashset_of_collected_addresses)
    {

        //The Frida Hook Generator API expects "0073b575,0073b5a0". This used to append a comma after
        //EVERY address and then a second one whenever another address followed, producing "A,,B,,C," -
        //doubled separators plus a trailing one, so the address list handed to the hook generator was full
        //of empty entries. Only put a separator BETWEEN addresses.
        StringBuilder sb=new StringBuilder();
        Iterator<Address> it = hashset_of_collected_addresses.iterator();
        while (it.hasNext())
        {
            Address nextaddr=it.next();
            sb.append(nextaddr.toString());
            if (it.hasNext())
            {
                sb.append(",");
            }
        }
        return sb.toString();
    }
    
    
    
    

    //Returns null when the user cancelled, and "" when the selection genuinely held no instructions.
    //Returning "" for both made a cancelled extraction indistinguishable from "nothing to hook", so the
    //run carried on and quietly generated no hooks. Same convention as extract_strings_from_selection().
    public static String extract_str_with_hook_addresses_from_selection(Program current_program,ArrayList<AddressRange> incoming_addressrange_list, TaskMonitor incoming_monitor, boolean should_hook_function_starts_only)
    {
        String retval="";
        //TreeSet for a deterministic, address sorted hook list - see the note in the regex variant below.
        TreeSet<Address> hashset_of_collected_addresses= new TreeSet<Address>();
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
                System.out.println("Extraction of addresses to hook is cancelled");
                return null;
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
                        System.out.println("Extraction of addresses to hook is cancelled");
                        return null;
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
                        if (container_function!=null)
                        {
                            //add() already deduplicates, the contains() check that used to guard it was
                            //a second lookup for no benefit
                            hashset_of_collected_addresses.add(container_function.getEntryPoint());
                        }
                    }
                    else
                    {
                        //hook everything
                        hashset_of_collected_addresses.add(codeunit_in_question.getMinAddress());
                    }
                    
                }
            }
        }
        
        //now let's extract the elements

        retval=extract_elements_of_hashset_as_address_str(hashset_of_collected_addresses);
        
        
        
        System.out.println(retval);
        return retval;
    }
    
    
    
    //Returns null when the user cancelled or when the regex itself is unusable, and "" when no function
    //name matched.
    public static String extract_str_with_hook_addresses_for_function_regex(Program current_program, TaskMonitor incoming_monitor, String regex_for_fun_name)
    {
        //The pattern comes straight from a GUI text field, so an unbalanced bracket is entirely likely.
        //Pattern.compile() throws PatternSyntaxException, which nothing caught, so it escaped the whole
        //task as a stack trace instead of telling the user their regex is wrong.
        Pattern pattern=null;
        try
        {
            pattern=Pattern.compile(regex_for_fun_name,Pattern.CASE_INSENSITIVE);
        }
        catch (Exception e)
        {
            System.out.println("Error, \""+regex_for_fun_name+"\" is not a valid regular expression: "+e.getMessage()
                    +" . Note that the whole function name has to match, so use something like .*init.* rather than init.");
            return null;
        }

        FunctionIterator fun_iter=current_program.getListing().getFunctions(true);
        int num_of_functions_processed=0;
        //TreeSet, not HashSet: iteration order is then sorted by address instead of unspecified, so two
        //identical runs emit the same hook list and the output can be diffed. The cost is O(log n) per
        //insert instead of O(1), which is nothing next to the getFunctionContaining() database lookup that
        //the selection path performs for every single instruction.
        TreeSet<Address> hashset_of_collected_addresses= new TreeSet<Address>();

        if (incoming_monitor.isCancelled()) {return null;}
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
            if (num_of_functions_processed%100==0 && incoming_monitor.isCancelled()) {return null;} //check for cancellation by the user
        }
        

        String retval=extract_elements_of_hashset_as_address_str(hashset_of_collected_addresses);
        
        incoming_monitor.setMessage("Extracted functions by regex");

        
        System.out.println(retval);
        return retval;
            
    }
    
    
}


    
   

