package dragonhook.tasks.string_reference_resolution;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

public class StringReferenceResolutionUtils {

    public static int max_length_of_string_preview=60;

    //Guards against walking a huge primitive array component by component
    public static int max_components_to_walk=65536;
    public static int max_recursion_depth_into_composites=8;

    //The preview ends up inside a JSON string, inside the |||DH_GHIDRA_API_CALL||| protocol line and
    //inside a ghidra comment, so no quotes, no backslashes and no pipes may survive.
    private static final Pattern pattern_for_string_preview=
            Pattern.compile("[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_\\ \\,\\!\\+\\-\\#\\[\\]\\:\\.\\(\\)\\~\\$\\%\\@\\/\\=\\?\\*\\&\\;]");

    public static String sanitize_string_preview(String incoming_str)
    {
        if (incoming_str==null)
        {
            return "";
        }
        String truncated=incoming_str;
        if (truncated.length()>max_length_of_string_preview)
        {
            truncated=truncated.substring(0,max_length_of_string_preview)+"...";
        }
        return pattern_for_string_preview.matcher(truncated).replaceAll("_");
    }


    private static String return_preview_for_data(Data incoming_data)
    {
        try
        {
            Object value_of_data=incoming_data.getValue();
            if (value_of_data instanceof String)
            {
                return sanitize_string_preview((String) value_of_data);
            }
            return sanitize_string_preview(incoming_data.getDefaultValueRepresentation());
        }
        catch (Exception e)
        {
            return "";
        }
    }


    //A string is not always a top level data item: it is very often a char[] member inside a struct,
    //or an element of an array of structs. Testing hasStringValue() only on the item the listing hands
    //us therefore misses every string that lives inside a composite, which on a C++ or Objective C
    //binary is a large fraction of them.
    private static void collect_strings_from_data(Data incoming_data, ArrayList<Data> collected, int depth)
    {
        if (incoming_data==null || depth>max_recursion_depth_into_composites)
        {
            return;
        }
        if (incoming_data.hasStringValue())
        {
            collected.add(incoming_data);
            return;   //a char[] is itself the string, do not descend into its characters
        }

        DataType type_of_data=incoming_data.getDataType();
        boolean we_should_descend=false;
        if (type_of_data instanceof Composite)
        {
            we_should_descend=true;
        }
        else if (type_of_data instanceof Array)
        {
            DataType type_of_element=((Array) type_of_data).getDataType();
            //a char[]/wchar[] was already caught above; only descend into arrays whose elements can
            //themselves contain a string
            if (type_of_element instanceof Composite || type_of_element instanceof Array)
            {
                we_should_descend=true;
            }
        }
        if (!we_should_descend)
        {
            return;
        }

        int number_of_components=incoming_data.getNumComponents();
        if (number_of_components>max_components_to_walk)
        {
            return;
        }
        for (int i=0;i<number_of_components;i++)
        {
            collect_strings_from_data(incoming_data.getComponent(i), collected, depth+1);
        }
    }


    //The strings the user selected. By default only the ones nothing references are kept, because
    //those are the ones worth resolving at runtime: a string that already has references is understood
    //by ghidra, whereas one with none is either dead or reached through an address static analysis
    //missed. Pass also_include_strings_with_references to keep both kinds.
    //
    //A string that is only partially inside the selection still counts, so selecting a byte in the
    //middle of one is enough to pick it.
    //
    //Returns null if the user cancelled.
    public static ArrayList<Data> extract_strings_from_selection(Program current_program,
                                                                ArrayList<AddressRange> incoming_addressrange_list,
                                                                TaskMonitor incoming_monitor,
                                                                boolean also_include_strings_with_references)
    {
        ArrayList<Data> retval=new ArrayList<Data>();
        HashSet<Address> addresses_of_strings_already_added=new HashSet<Address>();
        Listing current_program_listing=current_program.getListing();
        ReferenceManager reference_manager=current_program.getReferenceManager();
        int number_of_ranges_examined=0;
        int number_of_strings_skipped_because_they_have_references=0;

        incoming_monitor.setMessage("Looking for strings inside the selection...");

        for (int i=0;i<incoming_addressrange_list.size();i++)
        {
            AddressRange current_address_range=incoming_addressrange_list.get(i);
            number_of_ranges_examined+=1;

            if (incoming_monitor.isCancelled())
            {
                incoming_monitor.cancel();
                System.out.println("Extraction of strings from the selection is cancelled");
                return null;
            }
            incoming_monitor.setMessage("Looking for strings inside the selection ... range "
                    +Integer.toString(number_of_ranges_examined)+"/"+Integer.toString(incoming_addressrange_list.size())
                    +" , found "+Integer.toString(retval.size()));

            AddressSet addr_set=new AddressSet(current_address_range);

            //a string whose first byte is before the selection, but which the selection reaches into
            ArrayList<Data> candidate_data_items=new ArrayList<Data>();
            Data data_containing_the_range_start=current_program_listing.getDataContaining(current_address_range.getMinAddress());
            if (data_containing_the_range_start!=null)
            {
                candidate_data_items.add(data_containing_the_range_start);
            }

            //and every defined data item that starts inside the selection
            DataIterator data_iterator=current_program_listing.getDefinedData(addr_set,true);
            while (data_iterator!=null && data_iterator.hasNext())
            {
                candidate_data_items.add(data_iterator.next());
            }

            //flatten each candidate into the strings it actually contains
            ArrayList<Data> string_data_items=new ArrayList<Data>();
            for (int j=0;j<candidate_data_items.size();j++)
            {
                collect_strings_from_data(candidate_data_items.get(j), string_data_items, 0);
            }

            for (int j=0;j<string_data_items.size();j++)
            {
                Data current_data=string_data_items.get(j);
                if (addresses_of_strings_already_added.contains(current_data.getMinAddress()))
                {
                    continue;
                }
                if (!also_include_strings_with_references
                    && reference_manager.hasReferencesTo(current_data.getMinAddress()))
                {
                    number_of_strings_skipped_because_they_have_references+=1;
                    continue;   //ghidra already knows who uses it
                }
                addresses_of_strings_already_added.add(current_data.getMinAddress());
                retval.add(current_data);
            }
        }

        System.out.println("Selected "+Integer.toString(retval.size())+" strings for reference resolution, skipped "
                +Integer.toString(number_of_strings_skipped_because_they_have_references)
                +" that already have references");
        return retval;
    }


    //Same compact shape as the function range table: one description per string, plus a range array
    //sorted by start so that the agent can binary search it. The ranges let a reference that points
    //INTO a string still be attributed, not only one that points at its first byte.
    //
    //  {"strings":[{"offset":"0x1234","len":13,"had_refs":false,"preview":"hello world"}, ...],
    //   "ranges":[[4660,4672,0], ...]}          each range is [start, end_inclusive, index]
    public static String return_selected_strings_as_js_object(ArrayList<Data> incoming_list, Program current_program)
    {
        long image_base_offset=current_program.getImageBase().getOffset();
        ReferenceManager reference_manager=current_program.getReferenceManager();
        ArrayList<String> string_entries=new ArrayList<String>();
        ArrayList<long[]> range_entries=new ArrayList<long[]>();

        for (int i=0;i<incoming_list.size();i++)
        {
            Data current_data=incoming_list.get(i);
            long start_offset=current_data.getMinAddress().getOffset() - image_base_offset;
            int length_of_string=current_data.getLength();
            if (length_of_string<1)
            {
                length_of_string=1;
            }
            boolean the_string_already_has_references=reference_manager.hasReferencesTo(current_data.getMinAddress());
            string_entries.add("{\"offset\":\"0x"+Long.toHexString(start_offset)+"\""
                    +",\"len\":"+Integer.toString(length_of_string)
                    +",\"had_refs\":"+(the_string_already_has_references ? "true" : "false")
                    +",\"preview\":\""+return_preview_for_data(current_data)+"\"}");
            range_entries.add(new long[]{start_offset, start_offset+length_of_string-1, i});
        }

        Collections.sort(range_entries, new Comparator<long[]>() {
            @Override
            public int compare(long[] first_range, long[] second_range) {
                return Long.compare(first_range[0], second_range[0]);
            }
        });

        StringBuilder sb=new StringBuilder(64 + string_entries.size()*112 + range_entries.size()*28);
        sb.append("{\"strings\":[");
        for (int i=0;i<string_entries.size();i++)
        {
            if (i>0) { sb.append(","); }
            sb.append(string_entries.get(i));
        }
        sb.append("],\"ranges\":[");
        for (int i=0;i<range_entries.size();i++)
        {
            long[] current_range=range_entries.get(i);
            if (i>0) { sb.append(","); }
            sb.append('[').append(current_range[0]).append(',')
              .append(current_range[1]).append(',').append(current_range[2]).append(']');
        }
        sb.append("]}");
        return sb.toString();
    }

}
