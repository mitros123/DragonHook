//------------------------ FOR RESOLUTION OF STRING REFERENCES ------------------------
//The user selects the STRINGS whose references are wanted, and ghidra hands them to us here. While
//the target runs we look at every instruction inside the examined module and try to work out which
//address it forms or touches. When that address lands inside one of those strings we have found a
//reference, and we write it into the ghidra db.
//
//The code is NOT restricted to a selection: the whole point is that we do not know where the
//reference lives. Most string references in compiled code are PC relative (x64 "lea rax,[rip+disp]",
//arm64 "adrp"+"add") and those are fully determined at COMPILE time, so they cost nothing at
//runtime: we resolve them inside transform() and never emit a callout. Only addresses built from
//registers need a callout, and that is what also_instrument_register_based_memory_accesses controls.
var string_reference_resolution_is_enabled=false; // UPDATED FROM DRAGONHOOK PLUGIN
var max_times_to_log_each_string_reference=1; // UPDATED FROM DRAGONHOOK PLUGIN
var also_instrument_register_based_memory_accesses=true; // UPDATED FROM DRAGONHOOK PLUGIN
var strings_to_resolve_compact={"DRAGONHOOK_STRINGS_TO_RESOLVE":true}; // UPDATED FROM DRAGONHOOK PLUGIN

//How long the expensive register based tier is allowed to run, in seconds, counted from the moment the
//examined module is found. 0 means "never switch it off".
var seconds_before_register_based_instrumentation_is_dropped=0; // UPDATED FROM DRAGONHOOK PLUGIN
var register_based_instrumentation_has_been_dropped=false;
var timer_for_dropping_register_based_instrumentation=null;

//expanded from strings_to_resolve_compact, see load_strings_to_resolve()
var string_range_starts=[];   //numbers, sorted ascending
var string_range_ends=[];     //numbers, inclusive
var string_range_index=[];    //index into string_infos
var string_infos=[];          //{offset, len, preview}
var strings_to_resolve_are_loaded=false;

var times_a_string_reference_was_logged_for_code_offset={};
var scale_to_shift_for_string_refs={1:0,2:1,4:2,8:3};


//Expands the string table the plugin baked in into the parallel arrays the search uses.
//Called once from begin_stalking_as_soon_as_module_is_found().
function load_strings_to_resolve()
{
    if (strings_to_resolve_are_loaded)
    {
        return string_range_starts.length;
    }
    if ( ! ("strings" in strings_to_resolve_compact) || ! ("ranges" in strings_to_resolve_compact))
    {
        console.log("string reference resolution: the string table was not filled in by the plugin");
        return 0;
    }
    string_infos=strings_to_resolve_compact["strings"];
    var ranges_from_ghidra=strings_to_resolve_compact["ranges"];
    var number_of_ranges=ranges_from_ghidra.length;
    string_range_starts=new Array(number_of_ranges);
    string_range_ends=new Array(number_of_ranges);
    string_range_index=new Array(number_of_ranges);
    for (var i=0;i<number_of_ranges;i++)
    {
        string_range_starts[i]=ranges_from_ghidra[i][0];
        string_range_ends[i]=ranges_from_ghidra[i][1];
        string_range_index[i]=ranges_from_ghidra[i][2];
    }
    strings_to_resolve_are_loaded=true;
    console.log("string reference resolution: loaded "+string_infos.length+" strings to resolve, over "
        +number_of_ranges+" ranges");
    if (Process.arch!=="x64" && Process.arch!=="ia32" && Process.arch!=="arm64")
    {
        console.log("string reference resolution: operand decoding is implemented for x64, x86 (ia32) and"
            +" arm64. On \""+Process.arch+"\" only the immediate forms are likely to resolve.");
    }
    if (Process.arch==="ia32" && !also_instrument_register_based_memory_accesses)
    {
        console.log("string reference resolution: on 32 bit x86 there is no PC relative addressing, so"
            +" position independent code forms string addresses from a GOT base register. With register"
            +" based resolution switched off, only non PIC absolute immediates will be found.");
    }
    return number_of_ranges;
}


//binary search, so a reference pointing into the middle of a string is still attributed to it
//Single point lookup. Superseded by the overlap search below for detection, kept as a utility.
function find_string_to_resolve_containing(offset_as_number)
{
    var low=0;
    var high=string_range_starts.length-1;
    while (low<=high)
    {
        var mid=(low+high)>>1;
        if (offset_as_number<string_range_starts[mid])
        {
            high=mid-1;
        }
        else if (offset_as_number>string_range_ends[mid])
        {
            low=mid+1;
        }
        else
        {
            return string_infos[string_range_index[mid]];
        }
    }
    return null;
}


//largest index whose range start is <= the given offset, or -1
//Helper for the overlap search below.
function return_index_of_last_string_range_starting_at_or_before(offset_as_number)
{
    var low=0;
    var high=string_range_starts.length-1;
    var result=-1;
    while (low<=high)
    {
        var mid=(low+high)>>1;
        if (string_range_starts[mid]<=offset_as_number)
        {
            result=mid;
            low=mid+1;
        }
        else
        {
            high=mid-1;
        }
    }
    return result;
}


//An instruction touches the bytes [offset, offset+size). A point test on the base address misses a
//wide load whose base is aligned DOWN below the string start, for example a 16 byte SIMD load of
//[string_start-4]. String ranges are disjoint and sorted, so we find the last range starting at or
//before the final touched byte and walk backwards while the ranges still reach the first byte.
//Called from check_one_candidate_address_for_a_string() for every candidate address.
function find_strings_to_resolve_overlapping(offset_as_number,size_of_access)
{
    var overlapping=[];
    if (string_range_starts.length===0)
    {
        return overlapping;
    }
    if (!size_of_access || size_of_access<1) { size_of_access=1; }
    var offset_of_last_touched_byte=offset_as_number+size_of_access-1;
    var index=return_index_of_last_string_range_starting_at_or_before(offset_of_last_touched_byte);
    while (index>=0 && string_range_ends[index]>=offset_as_number)
    {
        overlapping.push(string_infos[string_range_index[index]]);
        index-=1;
    }
    return overlapping;
}


//---- how many bytes an instruction touches. On x86 capstone reports it on the memory operand, on
//---- arm64 it has to be derived from the mnemonic and the width of the data register.

//Width in bytes of one arm64 register, from its name.
//Called from return_access_size_arm64().
function return_register_width_arm64(name_of_register)
{
    var name=(""+name_of_register).toLowerCase();
    //these have to be tested BEFORE the first-letter switch, otherwise "sp" is read as an "s" (4 byte)
    //register, which is the bug the same table has in other implementations
    if (name==="sp" || name==="fp" || name==="lr" || name==="xzr") { return 8; }
    if (name==="wsp" || name==="wzr") { return 4; }
    switch (name.charAt(0))
    {
        case "q": return 16;
        case "d": return 8;
        case "s": return 4;
        case "h": return 2;
        case "b": return 1;
        case "x": return 8;
        case "w": return 4;
    }
    return 8;
}

//How many bytes an arm64 load or store touches, derived from the mnemonic and the data register.
//Called from return_access_size_for_instruction().
function return_access_size_arm64(instruction)
{
    var mnemonic=(""+instruction.mnemonic).toLowerCase();
    if (/^(ldrsb|ldarb|stlrb|ldxrb|stxrb|ldaxrb|stlxrb|ldrb|strb)/.test(mnemonic)) { return 1; }
    if (/^(ldrsh|ldarh|stlrh|ldxrh|stxrh|ldaxrh|stlxrh|ldrh|strh)/.test(mnemonic)) { return 2; }
    if (/^ldrsw/.test(mnemonic)) { return 4; }
    if (/^(ld|st)[1-4]/.test(mnemonic)) { return 16; }   //vector table load/store
    var size_of_access=8;
    var operands=instruction.operands;
    if (operands)
    {
        for (var i=0;i<operands.length;i++)
        {
            if (operands[i].type==="reg")
            {
                size_of_access=return_register_width_arm64(operands[i].value);
                break;
            }
        }
    }
    if (/^(ld|st)n?p/.test(mnemonic)) { size_of_access*=2; }   //a pair touches two elements
    return size_of_access;
}

//Bytes the instruction touches, per architecture. Called from the transform and from
//collect_static_candidate_addresses(), so that the overlap test uses the real access span.
function return_access_size_for_instruction(instruction)
{
    var operands=instruction.operands;
    if (Process.arch==="arm64" || Process.arch==="arm")
    {
        return return_access_size_arm64(instruction);
    }
    if (operands)
    {
        for (var i=0;i<operands.length;i++)
        {
            if (operands[i].type==="mem" && typeof operands[i].size==="number" && operands[i].size>0)
            {
                return operands[i].size;
            }
        }
    }
    return 1;
}


//True once this code offset has been reported its allowed number of times. Called from the transform
//gate (so we stop instrumenting) and from inside the callout (so we stop reporting).
function have_we_logged_enough_string_references_for(code_offset_as_str)
{
    var times_logged=times_a_string_reference_was_logged_for_code_offset[code_offset_as_str];
    if (times_logged===undefined)
    {
        return false;
    }
    return (times_logged>=max_times_to_log_each_string_reference);
}


//in_addr may be anywhere; only addresses inside our module can be a string in this program
//Called from check_one_candidate_address_for_a_string() to reject candidates outside our module.
function return_offset_inside_our_module_or_null(in_addr)
{
    if (in_addr===null || in_addr===undefined)
    {
        return null;
    }
    if (in_addr.compare(baseaddr_of_modulename_to_stalk)<0 ||
        in_addr.compare(endaddr_of_modulename_to_stalk)>=0)
    {
        return null;
    }
    return in_addr.sub(baseaddr_of_modulename_to_stalk);
}


//Writes the discovered reference: a comment on the code, a comment on the string, and a DATA xref.
//Called from check_one_candidate_address_for_a_string(), and counts against the per offset limit.
function update_ghidradb_with_comment_and_xref_for_string_reference(code_offset,string_info,how_it_was_found)
{
    var code_offset_as_str=code_offset.toString();
    var times_logged=times_a_string_reference_was_logged_for_code_offset[code_offset_as_str];
    if (times_logged===undefined) { times_logged=0; }
    if (times_logged>=max_times_to_log_each_string_reference)
    {
        return;
    }
    times_a_string_reference_was_logged_for_code_offset[code_offset_as_str]=times_logged+1;

    var string_offset=ptr(string_info.offset);
    var ghidra_addr_of_code=ghidra_base_addr.add(code_offset);
    var ghidra_addr_of_string=ghidra_base_addr.add(string_offset);

    //comment on the code, saying which string it forms
    var how_ghidra_saw_it=(string_info.had_refs ? "which ghidra already had references for"
                                                : "which had no static references");
    var commentstr_to_add_to_ghidradb="References the string \""+string_info.preview+"\" at ghidra address "
        +ghidra_addr_of_string+" (offset "+string_offset+" , length "+string_info.len
        +"), "+how_ghidra_saw_it+". Found through "+how_it_was_found;
    update_ghidradb_with_comment_at_addr(code_offset,commentstr_to_add_to_ghidradb);

    //comment on the string, saying who reached it
    var function_data_for_the_referencing_code=null;
    if (function_ranges_are_loaded)
    {
        function_data_for_the_referencing_code=extract_function_info_from_address_for_our_module(
            baseaddr_of_modulename_to_stalk.add(code_offset));
    }
    if (function_data_for_the_referencing_code!=null)
    {
        commentstr_to_add_to_ghidradb="Referenced at runtime from ghidra address "+ghidra_addr_of_code
            +" inside function "+function_data_for_the_referencing_code.fun_name+" of curent module";
    }
    else
    {
        commentstr_to_add_to_ghidradb="Referenced at runtime from ghidra address "+ghidra_addr_of_code+" of curent module";
    }
    update_ghidradb_with_comment_at_addr(string_offset,commentstr_to_add_to_ghidradb);

    //and the xref itself. DATA is the reftype ghidra uses for code that points at data.
    update_ghidradb_with_xref(code_offset,string_offset,"DATA");

    console.log("STRING REFERENCE RESOLVED: ghidra address "+ghidra_addr_of_code+" references \""
        +string_info.preview+"\" at "+ghidra_addr_of_string+" (found through "+how_it_was_found+")");
}


//size_of_access is how many bytes the instruction touches from candidate_address onwards. Pass 1 for
//an address that is merely FORMED (lea, adrp+add) rather than dereferenced.
//Called for every candidate address, from both the compile time and the runtime path.
function check_one_candidate_address_for_a_string(code_offset,candidate_address,size_of_access,how_it_was_found)
{
    var offset_of_candidate=return_offset_inside_our_module_or_null(candidate_address);
    if (offset_of_candidate===null)
    {
        return false;
    }
    var overlapping_strings=find_strings_to_resolve_overlapping(
        parseInt(offset_of_candidate.toString(),16), size_of_access);
    if (overlapping_strings.length===0)
    {
        return false;
    }
    for (var i=0;i<overlapping_strings.length;i++)
    {
        update_ghidradb_with_comment_and_xref_for_string_reference(code_offset,overlapping_strings[i],how_it_was_found);
    }
    return true;
}


//Only these can plausibly carry an ADDRESS in an immediate operand. Treating every immediate as a
//candidate meant that an ordinary constant, for instance the 0x404010 in "cmp dword [rbp-4],0x404010",
//was checked against the string table, and in a non PIE module (where the runtime base equals the
//ghidra image base) such a constant can land inside a selected string and produce an xref for a
//reference the code never makes.
var mnemonics_that_can_carry_an_address_immediate={
    "mov":true,"movabs":true,"movl":true,"movq":true,"movz":true,"movk":true,
    "push":true,"lea":true,"adr":true
};


//An adrp result is only valid until something else writes that register. Without this, a stale entry
//made every later "ldr x2,[x0,#imm]" compute an address from a page base that x0 no longer holds,
//which is a pure false positive generator on arm64 where adrp registers are reused constantly.
//Called at the end of collect_static_candidate_addresses() for each instruction.
function forget_page_bases_clobbered_by(instruction,page_base_in_register,registers_we_just_set)
{
    var registers_written=null;
    try { registers_written=instruction.regsWritten; } catch (err) { registers_written=null; }

    if (registers_written && registers_written.length)
    {
        for (var i=0;i<registers_written.length;i++)
        {
            var name_of_register=(""+registers_written[i]).toLowerCase();
            if (registers_we_just_set[name_of_register]) { continue; }
            if (name_of_register in page_base_in_register) { delete page_base_in_register[name_of_register]; }
        }
        return;
    }

    //no register detail from capstone, fall back to the destination operand
    var operands=instruction.operands;
    if (operands && operands.length>0 && operands[0].type==="reg")
    {
        var name_of_destination=(""+operands[0].value).toLowerCase();
        if (!registers_we_just_set[name_of_destination] && (name_of_destination in page_base_in_register))
        {
            delete page_base_in_register[name_of_destination];
        }
    }
}


//Addresses an instruction forms that are already known while the block is being compiled: PC relative
//memory operands, address bearing immediates, and the arm64 adrp/adr page computations.
//page_base_in_register carries adrp results forward inside the block so that the following add/ldr
//can be completed, and is pruned as soon as a register is clobbered.
//Called from the transform, once per instruction while the block is being compiled.
function collect_static_candidate_addresses(instruction,page_base_in_register)
{
    var candidates=[];
    var operands=instruction.operands;
    if (!operands)
    {
        return candidates;
    }
    var address_after_instruction=instruction.address.add(instruction.size);
    var mnemonic=(""+instruction.mnemonic).toLowerCase();
    var registers_we_just_set={};
    //An address that is merely FORMED points AT the string, so only one byte need overlap. Using the
    //operand width here instead would make "lea rax,[rip+x]" match a string starting up to 7 bytes
    //after the formed address.
    var the_instruction_only_forms_an_address=(mnemonic==="lea" || mnemonic==="adr"
                                              || mnemonic==="adrp" || mnemonic==="add");
    var size_for_a_real_access=return_access_size_for_instruction(instruction);

    for (var i=0;i<operands.length;i++)
    {
        var op=operands[i];

        if (op.type==="imm")
        {
            //arm64 adr/adrp: capstone hands us the already resolved absolute address or page base
            if (mnemonic==="adrp")
            {
                if (operands.length>0 && operands[0].type==="reg")
                {
                    var register_holding_the_page=(""+operands[0].value).toLowerCase();
                    page_base_in_register[register_holding_the_page]=ptr(op.value);
                    registers_we_just_set[register_holding_the_page]=true;
                }
                continue;   //the page base on its own is not a string address
            }
            //x86 "mov eax, 0x404000" / "push 0x404000" in non PIC code, and arm64 "adr"
            if (mnemonic in mnemonics_that_can_carry_an_address_immediate)
            {
                candidates.push({address:ptr(op.value), size:1});   //an immediate address is a pointer
            }
            continue;
        }

        if (op.type==="mem")
        {
            var m=op.value;
            var base_register=m.base ? (""+m.base).toLowerCase() : null;
            if (base_register==="rip" || base_register==="eip" || base_register==="pc")
            {
                candidates.push({address:address_after_instruction.add(m.disp || 0),
                                 size:(the_instruction_only_forms_an_address ? 1 : size_for_a_real_access)});
            }
            else if (base_register!==null && (base_register in page_base_in_register))
            {
                //arm64 "adrp x0,#page" followed by "ldr x1,[x0,#lo12]"
                candidates.push({address:page_base_in_register[base_register].add(m.disp || 0),
                                 size:(the_instruction_only_forms_an_address ? 1 : size_for_a_real_access)});
            }
        }
    }

    //arm64 "adrp x0,#page" followed by "add x0,x0,#lo12", which is the usual way to form a string address
    if (mnemonic==="add" && operands.length===3 &&
        operands[1].type==="reg" && operands[2].type==="imm" &&
        ((""+operands[1].value).toLowerCase() in page_base_in_register))
    {
        var completed_address=page_base_in_register[(""+operands[1].value).toLowerCase()].add(operands[2].value);
        candidates.push({address:completed_address, size:1});   //adrp+add forms the address
        if (operands[0].type==="reg")
        {
            var name_of_destination=(""+operands[0].value).toLowerCase();
            page_base_in_register[name_of_destination]=completed_address;
            registers_we_just_set[name_of_destination]=true;
        }
    }

    forget_page_bases_clobbered_by(instruction,page_base_in_register,registers_we_just_set);
    return candidates;
}


//arm64 sign/zero extends the index register before scaling it: "ldr x0,[x1,w2,uxtw #2]" uses only
//the low 32 bits of x2. Applying just the shift to the full 64 bit view computes a wrong address
//whenever the upper half is non zero.
//Called from apply_arm64_extend_to_index() for the sxt* forms.
function sign_extend_pointer(value_as_pointer,number_of_bits)
{
    var mask=ptr(1).shl(number_of_bits).sub(1);
    var masked_value=value_as_pointer.and(mask);
    var sign_bit=ptr(1).shl(number_of_bits-1);
    if (!masked_value.and(sign_bit).isNull())
    {
        return masked_value.sub(ptr(1).shl(number_of_bits));
    }
    return masked_value;
}

//Applies an arm64 uxt*/sxt* extend to an index register value before it is scaled.
//Called from inside the runtime resolver closure, on the stalked thread.
function apply_arm64_extend_to_index(value_as_pointer,name_of_extend)
{
    switch (name_of_extend)
    {
        case "uxtb": return value_as_pointer.and(ptr(0xff));
        case "uxth": return value_as_pointer.and(ptr(0xffff));
        case "uxtw": return value_as_pointer.and(ptr("0xffffffff"));
        case "sxtb": return sign_extend_pointer(value_as_pointer,8);
        case "sxth": return sign_extend_pointer(value_as_pointer,16);
        case "sxtw": return sign_extend_pointer(value_as_pointer,32);
        default:     return value_as_pointer;   //uxtx / sxtx / none
    }
}


//Returns a closure that computes the effective address of the instruction's memory operand from a
//live CpuContext, or null when there is no register based memory operand to resolve.
//Called from the transform. The closure it returns is what the callout runs on every execution.
function build_runtime_memory_address_resolver(instruction)
{
    var operands=instruction.operands;
    if (!operands)
    {
        return null;
    }
    for (var i=0;i<operands.length;i++)
    {
        var op=operands[i];
        if (op.type!=="mem")
        {
            continue;
        }
        var m=op.value;
        //x86 segment relative accesses (fs:/gs:, so TLS and the stack cookie). The segment base is
        //not recoverable from the CpuContext, so computing base+disp and ignoring it would yield an
        //address in the wrong space entirely, which is a false positive waiting to happen.
        var name_of_segment=m.segment ? (""+m.segment).toLowerCase() : null;
        if (name_of_segment!==null && name_of_segment!=="ds" && name_of_segment!=="cs"
            && name_of_segment!=="ss" && name_of_segment!=="es")
        {
            continue;
        }
        var base_register=m.base || null;
        var index_register=m.index || null;
        if (base_register===null && index_register===null)
        {
            continue;
        }
        if (base_register==="rip" || base_register==="eip" || base_register==="pc")
        {
            continue;   //already handled statically
        }
        var displacement=m.disp || 0;
        //x86 expresses index scaling as a scale factor on the memory operand, arm64 as a shift on the
        //operand itself ("ldr x0,[x1,x2,lsl #3]"). Reading only m.scale computed x1+x2 instead of
        //x1+(x2<<3) on arm64, which is simply the wrong address.
        var shift_for_index=scale_to_shift_for_string_refs[m.scale || 1];
        if (shift_for_index===undefined) { shift_for_index=0; }
        var name_of_extend_for_index=op.ext ? (""+op.ext).toLowerCase() : null;
        if (op.shift && typeof op.shift.value==="number")
        {
            var type_of_shift=(""+op.shift.type).toLowerCase();
            if (type_of_shift.indexOf("lsl")>=0)
            {
                shift_for_index=op.shift.value;
            }
            else if (name_of_extend_for_index===null)
            {
                //on some frida versions the extend arrives as the shift type rather than in op.ext
                name_of_extend_for_index=type_of_shift;
                shift_for_index=op.shift.value;
            }
        }
        //a "w" index with no explicit extend is still only 32 bits wide
        if (name_of_extend_for_index===null && index_register!==null
            && (""+index_register).toLowerCase().charAt(0)==="w")
        {
            name_of_extend_for_index="uxtw";
        }

        return function (context) {
            var effective_address;
            if (base_register!==null)
            {
                var value_of_base=return_register_value_from_context(context,base_register);
                if (value_of_base===undefined) { return null; }
                effective_address=ptr(value_of_base);
            }
            else
            {
                effective_address=ptr(0);
            }
            if (index_register!==null)
            {
                var value_of_index=return_register_value_from_context(context,index_register);
                if (value_of_index===undefined) { return null; }
                var index_after_extend=apply_arm64_extend_to_index(ptr(value_of_index),name_of_extend_for_index);
                effective_address=effective_address.add(index_after_extend.shl(shift_for_index));
            }
            return effective_address.add(displacement);
        };
    }
    return null;
}


//Switching the flag off only stops NEW blocks from receiving a callout. The callouts already compiled
//into the code cache stay where they are, and frida has no "invalidate everything" call, so the way to
//be rid of them is to throw the cache away: unfollow each stalked thread and follow it again. The
//transform then runs afresh with the flag off and emits no callouts at all.
//Called by the time box timer, on frida's JS thread.
function drop_register_based_string_instrumentation()
{
    if (register_based_instrumentation_has_been_dropped)
    {
        return;
    }
    register_based_instrumentation_has_been_dropped=true;
    also_instrument_register_based_memory_accesses=false;

    var number_of_threads_refollowed=0;
    for (var thread_id_to_str in dict_with_threadIds_that_are_being_stalked)
    {
        if (dict_with_threadIds_that_are_being_stalked[thread_id_to_str]!==true)
        {
            continue;
        }
        var thread_id_as_number=parseInt(thread_id_to_str,10);
        try
        {
            Stalker.unfollow(thread_id_as_number);
            //clear the followed flag first, otherwise the guard inside startStalker refuses to refollow
            dict_with_threadIds_that_are_being_stalked[thread_id_to_str]=false;
            startStalker(thread_id_as_number,modulename_to_stalk);
            number_of_threads_refollowed+=1;
        }
        catch (err)
        {
            console.log("Could not refollow "+describe_thread_by_id(thread_id_to_str)
                +" after dropping the register based instrumentation: "+err);
        }
    }
    Stalker.flush();

    console.log("string reference resolution: the register based tier is now OFF after "
        +seconds_before_register_based_instrumentation_is_dropped+" seconds, "+number_of_threads_refollowed
        +" thread(s) refollowed to drop their callouts. Compile time resolution (rip relative on x64,"
        +" adrp+add on arm64, absolute immediates) keeps running for the rest of the session.");
}


//Starts the countdown that later switches the register based tier off, when the dialog asked for one.
//Called once from begin_stalking_as_soon_as_module_is_found().
function arm_the_timer_for_dropping_register_based_instrumentation()
{
    if (!string_reference_resolution_is_enabled) { return; }
    if (!also_instrument_register_based_memory_accesses) { return; }
    if (seconds_before_register_based_instrumentation_is_dropped<=0)
    {
        return;   //0 means the tier stays on for the whole session
    }
    if (timer_for_dropping_register_based_instrumentation!==null) { return; }

    //setTimeout runs on frida's own JS thread, which holds no target lock, so the unfollow/refollow
    //dance does not happen on a stalked thread
    timer_for_dropping_register_based_instrumentation=setTimeout(
        drop_register_based_string_instrumentation,
        seconds_before_register_based_instrumentation_is_dropped*1000);
    console.log("string reference resolution: the register based tier will be switched off in "
        +seconds_before_register_based_instrumentation_is_dropped+" seconds");
}


//Follows one thread and examines every instruction in our module for string references, resolving
//what it can at compile time and emitting a callout only for register based addresses.
//Called from startStalker() when string reference resolution is the selected feature.
function stalker_follow_and_resolve_string_references(threadId)
{
    Stalker.follow(threadId, {
        transform: function (iterator) {
            var instruction;
            var page_base_in_register={};   //arm64 adrp state, valid only inside this block
            while ((instruction = iterator.next()) !== null)
            {
                if (strings_to_resolve_are_loaded && modulename_to_stalk_has_been_loaded &&
                    instruction.address.compare(baseaddr_of_modulename_to_stalk)>=0 &&
                    instruction.address.compare(endaddr_of_modulename_to_stalk)<0)
                {
                    //"let", not "var", for everything the callout further down closes over. transform()
                    //runs at COMPILE time and the callout runs later, on every execution, so a single
                    //function scoped "var" would be shared by every callout in this block and they would
                    //all read the LAST instruction's values. "let" in the loop body gives each iteration
                    //its own binding, which is what makes each callout report its own instruction.
                    let code_offset=instruction.address.sub(baseaddr_of_modulename_to_stalk);
                    let code_offset_as_str=code_offset.toString();

                    if (!have_we_logged_enough_string_references_for(code_offset_as_str))
                    {
                        //"lea" (and arm64 adr/adrp/add) only FORM an address, so a single byte has to
                        //overlap the string. Everything else really touches size_of_access bytes.
                        let mnemonic_of_instruction=(""+instruction.mnemonic).toLowerCase();
                        let size_of_access=1;
                        try
                        {
                            size_of_access=(mnemonic_of_instruction==="lea") ? 1
                                : return_access_size_for_instruction(instruction);
                        }
                        catch (err) { size_of_access=1; }

                        //compile time resolution, free at runtime
                        try
                        {
                            //"var" is fine for these two: they are consumed here and now, during the
                            //compile, and no callout closes over them
                            var static_candidates=collect_static_candidate_addresses(instruction,page_base_in_register);
                            for (var ind_cand=0;ind_cand<static_candidates.length;ind_cand++)
                            {
                                check_one_candidate_address_for_a_string(code_offset,
                                    static_candidates[ind_cand].address,
                                    static_candidates[ind_cand].size,
                                    "static analysis of the instruction");
                            }
                        }
                        catch (err) { /* an operand shape we do not understand, keep going */ }

                        //runtime resolution, only for addresses that are built from registers
                        if (also_instrument_register_based_memory_accesses)
                        {
                            let resolve_memory_address=null;   //let: the callout below closes over it
                            try { resolve_memory_address=build_runtime_memory_address_resolver(instruction); }
                            catch (err) { resolve_memory_address=null; }

                            if (resolve_memory_address!==null)
                            {
                                //let: captured by the callout, so it must be one binding per instruction
                                let instruction_address=instruction.address;
                                iterator.putCallout(function (context) {
                                    if (have_we_logged_enough_string_references_for(code_offset_as_str))
                                    {
                                        Stalker.invalidate(instruction_address);   //stop paying for it
                                        return;
                                    }
                                    //declared inside the callout, so every execution gets its own
                                    var candidate_address=null;
                                    try { candidate_address=resolve_memory_address(context); }
                                    catch (err) { return; }
                                    if (candidate_address===null) { return; }
                                    if (check_one_candidate_address_for_a_string(code_offset,candidate_address,
                                            size_of_access,"a memory access observed at runtime"))
                                    {
                                        if (have_we_logged_enough_string_references_for(code_offset_as_str))
                                        {
                                            Stalker.invalidate(instruction_address);
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
                iterator.keep();
            }
        }
    });
}

//------------------- END: FOR RESOLUTION OF STRINGS WITHOUT STATIC REFERENCES ---------


