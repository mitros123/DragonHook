package dragonhook.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

public class GeneratorOfFunctionStartEndStructure {

    public static String sanitize_str(String incoming_str)
    {
        String characters_allowed_in_variable_name="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        return incoming_str.replaceAll("[^"+characters_allowed_in_variable_name+"]", "_");
    }
    
    public static String return_offset_for_addr(Address in_addr, Program current_program) {
        return "0x"+Long.toHexString(in_addr.getOffset() - current_program.getImageBase().getOffset());
    }
        

    
    //Generates javascript code for all the functions, specifying their start, end, and name
    public static String generatestructure(Program current_program)
    {
        String retval="";
        StringBuilder sb = new StringBuilder();
        String prelude="""
        /var function_ranges_sample_structure = [
        //  { start: 10, end: 20, data: {"fun_name":"fun1", ... } },
        //  { start: 21, end: 30, data: {"fun_name":"fun2", ... } },
        //  { start: 35, end: 40, data: {"fun_name":"fun3", ... } }
        //];
        
        function binarySearchFunRange(ranges, value) {
          let low = 0;
          let high = ranges.length - 1;
          while (low <= high) {
            const mid = Math.floor((low + high) / 2);
            const range = ranges[mid];
            if (value < range.start) {
              high = mid - 1;
            } else if (value > range.end) {
              low = mid + 1;
            } else {
              // Found the value in the range
              return range;
            }
          }
          // Not found
          return null;
        }
                """;
        sb.append(prelude);
        
        String current_program_name_sanitized=sanitize_str(current_program.getName());
        sb.append("\n\nvar address_ranges_for_functions_of_module_"+current_program_name_sanitized+" = [\n");
        
        
        FunctionIterator fun_iter = current_program.getFunctionManager().getFunctions(true);
        while (fun_iter!=null && fun_iter.hasNext())
        {
            Function current_function=fun_iter.next();
            String name_of_fun=sanitize_str(current_function.getName(true));
            Address start_of_fun=current_function.getEntryPoint();
            String start_of_fun_offset=return_offset_for_addr(start_of_fun,current_program);
            AddressRangeIterator current_function_ranges_iter= current_function.getBody().getAddressRanges(true);
            while (current_function_ranges_iter!=null && current_function_ranges_iter.hasNext())
            {
                AddressRange current_function_range=current_function_ranges_iter.next();
                String start_of_range_offset=return_offset_for_addr(current_function_range.getMinAddress(),current_program);
                String end_of_range_offset=return_offset_for_addr(current_function_range.getMaxAddress(),current_program);
                String addcomma=",";
                if (!fun_iter.hasNext() && !current_function_ranges_iter.hasNext())
                {
                    addcomma="";
                }
                sb.append("{ start: "+start_of_range_offset+", end: "+end_of_range_offset+", data: {\"fun_name\":\""+name_of_fun+"\",\"entrypoint_offset\":"+start_of_fun_offset+", \"range_start\":"+start_of_range_offset+",\"range_end\":"+end_of_range_offset+"}}"+addcomma+"\n");    
            }
        }

        sb.append("]\n\n\n");
        
        String helper_funs1="function get_offset_from_base_of_module_"+current_program_name_sanitized+"(in_addr)\n"
                           +"{\n"
                           +"    var base_of_module=Process.getModuleByName(\""+current_program.getName()+"\").base\n"
                           +"    return in_addr.sub(base_of_module);\n"
                           +"}\n\n";

        String helper_funs2="function extract_function_info_from_address_for_module_"+current_program_name_sanitized+"(in_addr) \n"
        					+"{\n"
                            +"    var base_of_module=Process.getModuleByName(\""+current_program.getName()+"\").base\n"
                            +"    var offset_of_addr_str=\"\"+in_addr.sub(base_of_module)\n"
                            +"    var offset_of_addr_as_number=parseInt(offset_of_addr_str, 16)\n"
                            +"    var found=false\n"
                            +"    var name_of_current_function=\"\"\n"
                            +"    var start_addr_of_function=\"\"\n"
                            +"    var object_from_binsearch=binarySearchFunRange(address_ranges_for_functions_of_module_"+current_program_name_sanitized+", offset_of_addr_as_number) \n"
                            +"    if (object_from_binsearch)\n"
                            +"    {\n"
                            +"        found=true\n"
                            +"        return object_from_binsearch.data\n"
                            +"    }\n"
                            +"    return null;\n"
                            +"}\n\n\n";
        
        String helper_funs3="function custom_backtracer_for_module_"+current_program_name_sanitized+"(context)\n"
        	               +"{\n"
        	               +"    var base_of_module=Process.getModuleByName(\""+current_program.getName()+"\").base\n"
        	               +"    var addresses_of_backtrace=Thread.backtrace(context, Backtracer.ACCURATE)\n"
        	               +"    var classic_backtrace_str=addresses_of_backtrace.map(DebugSymbol.fromAddress);\n"
        	               +"    for (var i=0;i<addresses_of_backtrace.length;i++)\n"
        	               +"    {\n"
        	               +"        var current_addr=ptr(addresses_of_backtrace[i])\n"
        	               +"        var function_data=extract_function_info_from_address_for_module_"+current_program_name_sanitized+"(current_addr)\n"
        	               +"        if (function_data)\n"
        	               +"        {\n"
        	               +"            var current_function_start_addr=ptr(base_of_module.add(function_data[\"entrypoint_offset\"]))\n"
        	               +"            var current_function_name=function_data[\"fun_name\"]\n"
        	               +"            var offset_from_start_of_current_function=current_addr.sub(current_function_start_addr)\n"
        	               +"            console.log(classic_backtrace_str[i]+\"   ,function name in module "+current_program_name_sanitized+":\"+current_function_name+\", offset from start of function:\"+offset_from_start_of_current_function)\n"
        	               +"        }\n"
        	               +"        else\n"
        	               +"        {\n"
        	               +"            console.log(classic_backtrace_str[i])\n"
        	               +"        }\n"
        	               +"    }\n"
        	               +"}\n\n\n";
        
        sb.append(helper_funs1);
        sb.append(helper_funs2);
        sb.append(helper_funs3);
        
        retval=sb.toString();
        return retval;
    }
}
