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

//Strips x86 instruction prefixes (e.g. rep, repe, repz, repne, repnz, lock, bnd, notrack).
//Capstone prepends prefixes directly into instruction.mnemonic (e.g. "rep movsb" or "lock cmpxchg"),
//which prevents direct string/regex equality matches without prior normalization.
function strip_x86_prefixes(mnemonic)
{
    return (""+mnemonic).toLowerCase().replace(/^(rep|repe|repz|repne|repnz|lock|bnd|notrack)\s+/, "");
}

//Strips ARM/Thumb 2-letter conditional execution suffixes (eq, ne, cs, cc, mi, pl, vs, vc, hi, ls, ge, lt, gt, le, al).
//In ARM32, almost all instructions can be conditionally executed (e.g. "ldreq", "movweq", "addeq").
//Stripping these condition codes normalizes the mnemonic for instruction table and opcode matching.
function strip_arm_condition_codes(mnemonic)
{
    var m=(""+mnemonic).toLowerCase();
    return m.replace(/(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)$/, "");
}

//Width in bytes of one arm64 register, from its name.
//Called from return_access_size_arm64().
function return_register_width_arm64(name_of_register)
{
    var name=(""+name_of_register).toLowerCase();
    //Special 64-bit and 32-bit registers must be checked before the first-letter switch,
    //otherwise "sp" would match 's' (single precision floating point = 4 bytes) instead of 8 bytes.
    if (name==="sp" || name==="fp" || name==="lr" || name==="xzr") { return 8; }
    if (name==="wsp" || name==="wzr") { return 4; }
    switch (name.charAt(0))
    {
        case "q": return 16; //128-bit quadword vector/FP
        case "d": return 8;  //64-bit doubleword vector/FP
        case "s": return 4;  //32-bit single precision vector/FP
        case "h": return 2;  //16-bit half precision vector/FP
        case "b": return 1;  //8-bit byte vector/FP
        case "x": return 8;  //64-bit general purpose register
        case "w": return 4;  //32-bit general purpose sub-register
        case "z": return 16; //SVE scalable vector register (at least 128-bit)
        case "v":            //NEON vector arrangements (e.g. v0.16b, v1.4s, etc.)
            if (name.indexOf("16b")>=0 || name.indexOf("8h")>=0 || name.indexOf("4s")>=0 || name.indexOf("2d")>=0) { return 16; }
            if (name.indexOf("8b")>=0 || name.indexOf("4h")>=0 || name.indexOf("2s")>=0 || name.indexOf("1d")>=0) { return 8; }
            if (name.indexOf("4b")>=0 || name.indexOf("2h")>=0 || name.indexOf("1s")>=0) { return 4; }
            return 16;
    }
    return 8;
}

//How many bytes an arm64 load, store, atomic, or vector operation touches, derived from mnemonic and data registers.
//Called from return_access_size_for_instruction().
function return_access_size_arm64(instruction)
{
    var mnemonic=(""+instruction.mnemonic).toLowerCase();
    //1-byte atomics, sign/zero extending byte loads/stores
    if (/^(ldrsb|ldursb|ldarb|stlrb|ldxrb|stxrb|ldaxrb|stlxrb|ldrb|strb|ldurb|sturb|swpb|casb|casab|caslb|casalb|ldaddb|ldclrb|ldeorb|ldsetb|ldsmaxb|ldsminb|ldumaxb|lduminb|staddb|stclrb|steorb|stsetb|stsmaxb|stsminb|stumaxb|stuminb|ldaprb)/.test(mnemonic)) { return 1; }
    //2-byte halfword atomics, sign/zero extending halfword loads/stores
    if (/^(ldrsh|ldursh|ldarh|stlrh|ldxrh|stxrh|ldaxrh|stlxrh|ldrh|strh|ldurh|sturh|swph|cash|casah|caslh|casalh|ldaddh|ldclrh|ldeorh|ldseth|ldsmaxh|ldsminh|ldumaxh|lduminh|staddh|stclrh|steorh|stseth|stsmaxh|stsminh|stumaxh|stuminh|ldaprh)/.test(mnemonic)) { return 2; }
    //4-byte signed word loads
    if (/^(ldrsw|ldursw)/.test(mnemonic)) { return 4; }
    //Prefetch operations touch 1 byte cache lines
    if (/^prfm/.test(mnemonic)) { return 1; }
    //Vector single structure loads (ld1r, ld2, ld3, ld4)
    if (/^ld1r/.test(mnemonic)) { return 16; }
    if (/^(ld|st)2/.test(mnemonic)) { return 32; }
    if (/^(ld|st)3/.test(mnemonic)) { return 48; }
    if (/^(ld|st)4/.test(mnemonic)) { return 64; }
    if (/^(ld|st)1/.test(mnemonic)) { return 16; }

    //Derive standard load/store width from the first destination/source register operand
    var size_of_access=8;
    var operands=instruction.operands;
    var reg_count=0;
    if (operands)
    {
        for (var i=0;i<operands.length;i++)
        {
            if (operands[i].type==="reg")
            {
                reg_count++;
                if (reg_count===1)
                {
                    size_of_access=return_register_width_arm64(operands[i].value);
                }
            }
        }
    }
    //Load/store pair instructions (ldp/stp/ldnp/stnp/casp) access two consecutive registers (2x width)
    if (/^(ld|st)n?p|casp/.test(mnemonic)) { size_of_access*=2; }
    return size_of_access;
}

//How many bytes an ARM32 / Thumb load or store touches.
//Called from return_access_size_for_instruction().
function return_access_size_arm32(instruction)
{
    var raw_mnemonic=(""+instruction.mnemonic).toLowerCase();
    var mnemonic=strip_arm_condition_codes(raw_mnemonic);
    if (/^(ldrb|ldrsb|strb|ldrexeb|strexb|tbb)/.test(mnemonic)) { return 1; }
    if (/^(ldrh|ldrsh|strh|ldrexh|strexh|tbh)/.test(mnemonic)) { return 2; }
    if (/^(ldrd|strd)/.test(mnemonic)) { return 8; }
    //Block data transfer instructions (LDM, STM, PUSH, POP) touch 4 bytes per register transferred
    if (/^(ldm|stm|push|pop|vldm|vstm)/.test(mnemonic))
    {
        var operands=instruction.operands;
        var reg_operands=0;
        if (operands)
        {
            for (var i=0;i<operands.length;i++)
            {
                if (operands[i].type==="reg") { reg_operands++; }
            }
        }
        return Math.max(4, reg_operands * 4);
    }
    if (/^vld1/.test(mnemonic)) { return 16; }
    if (/^vld2/.test(mnemonic)) { return 32; }
    if (/^vld3/.test(mnemonic)) { return 48; }
    if (/^vld4/.test(mnemonic)) { return 64; }
    if (/^vldr|vstr/.test(mnemonic))
    {
        var ops=instruction.operands;
        if (ops && ops.length>0 && ops[0].type==="reg")
        {
            var rname=(""+ops[0].value).toLowerCase();
            if (rname.charAt(0)==="d") { return 8; }
            if (rname.charAt(0)==="s") { return 4; }
        }
        return 4;
    }
    return 4;
}

//How many bytes an x86/x64 instruction touches, covering memory operands, string instructions, and vector moves.
//Called from return_access_size_for_instruction().
function return_access_size_x86(instruction)
{
    var raw_mnemonic=(""+instruction.mnemonic).toLowerCase();
    var mnemonic=strip_x86_prefixes(raw_mnemonic);
    //String & table instructions
    if (/^(movsb|lodsb|stosb|cmpsb|scasb|insb|outsb|xlatb?)$/.test(mnemonic)) { return 1; }
    if (/^(movsw|lodsw|stosw|cmpsw|scasw|insw|outsw)$/.test(mnemonic)) { return 2; }
    if (/^(movsd|lodsd|stosd|cmpsd|scasd|insd|outsd)$/.test(mnemonic)) { return 4; }
    if (/^(movsq|lodsq|stosq|cmpsq|scasq)$/.test(mnemonic)) { return 8; }
    if (mnemonic==="maskmovq") { return 8; }
    if (mnemonic==="maskmovdqu" || mnemonic==="vmaskmovdqu") { return 16; }

    var operands=instruction.operands;
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
    if (/^vmov(dqu|dqa|ups|apd|ntdq|ntps|ntpd)512/.test(mnemonic)) { return 64; }
    if (/^vmov(dqu|dqa|ups|apd|ntdq|ntps|ntpd)256/.test(mnemonic) || /^[vy]/.test(mnemonic)) { return 32; }
    if (/^mov(dqu|dqa|ups|apd|ntdq|ntps|ntpd|aps)/.test(mnemonic) || /^[x]/.test(mnemonic)) { return 16; }
    return 1;
}

//Bytes the instruction touches, per architecture. Called from the transform and from
//collect_static_candidate_addresses(), so that the overlap test uses the real access span.
function return_access_size_for_instruction(instruction)
{
    if (Process.arch==="arm64")
    {
        return return_access_size_arm64(instruction);
    }
    if (Process.arch==="arm")
    {
        return return_access_size_arm32(instruction);
    }
    if (Process.arch==="x64" || Process.arch==="ia32")
    {
        return return_access_size_x86(instruction);
    }
    var operands=instruction.operands;
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
    try
    {
        var ptr_addr = (typeof in_addr.compare === "function") ? in_addr : ptr(in_addr);
        if (ptr_addr.compare(baseaddr_of_modulename_to_stalk)<0 ||
            ptr_addr.compare(endaddr_of_modulename_to_stalk)>=0)
        {
            return null;
        }
        return ptr_addr.sub(baseaddr_of_modulename_to_stalk);
    }
    catch (err)
    {
        return null;
    }
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
//an address that is merely FORMED (lea, adrp+add, movw+movt) rather than dereferenced.
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


//Mnemonics that can plausibly carry an ADDRESS in an immediate operand across architectures.
var mnemonics_that_can_carry_an_address_immediate={
    //x86 / x64
    "mov":true,"movabs":true,"movabsq":true,"movl":true,"movq":true,"movz":true,"movk":true,
    "movzx":true,"movsx":true,"movsxd":true,
    "push":true,"pushq":true,"pushl":true,
    "lea":true,"leaq":true,"leal":true,
    "cmp":true,"cmpq":true,"cmpl":true,"test":true,"testq":true,"testl":true,
    //arm64
    "adr":true,"adrp":true,"ldr":true,"ldrsw":true,"prfm":true,
    //arm32
    "movw":true,"movt":true
};


//An adrp or movw result is only valid until something else writes that register. Without this, a stale entry
//made every later access compute an address from a page/halfword base that the register no longer holds.
//Called at the end of collect_static_candidate_addresses() for each instruction.
function forget_page_bases_and_halfwords_clobbered_by(instruction,page_base_in_register,halfword_in_register,registers_we_just_set)
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
            if (name_of_register in halfword_in_register) { delete halfword_in_register[name_of_register]; }
        }
        return;
    }

    //no register detail from capstone, fall back to the destination operand
    var operands=instruction.operands;
    if (operands && operands.length>0 && operands[0].type==="reg")
    {
        var name_of_destination=(""+operands[0].value).toLowerCase();
        if (!registers_we_just_set[name_of_destination])
        {
            if (name_of_destination in page_base_in_register) { delete page_base_in_register[name_of_destination]; }
            if (name_of_destination in halfword_in_register) { delete halfword_in_register[name_of_destination]; }
        }
    }
}


//Addresses an instruction forms that are already known while the block is being compiled: PC relative
//memory operands (x64 rip, arm pc), address bearing immediates, arm64 adrp/adr computations, and arm32 movw/movt pairs.
//Called from the transform, once per instruction while the block is being compiled.
function collect_static_candidate_addresses(instruction,page_base_in_register,halfword_in_register)
{
    var candidates=[];
    var operands=instruction.operands;
    if (!operands)
    {
        return candidates;
    }
    var address_after_instruction=instruction.address.add(instruction.size);
    var raw_mnemonic=(""+instruction.mnemonic).toLowerCase();
    var mnemonic=(Process.arch==="arm") ? strip_arm_condition_codes(raw_mnemonic) : strip_x86_prefixes(raw_mnemonic);
    var registers_we_just_set={};
    var the_instruction_only_forms_an_address=(mnemonic==="lea" || mnemonic==="leaq" || mnemonic==="leal"
                                              || mnemonic==="adr" || mnemonic==="adrp"
                                              || mnemonic==="add" || mnemonic==="movw" || mnemonic==="movt");
    var size_for_a_real_access=return_access_size_for_instruction(instruction);

    for (var i=0;i<operands.length;i++)
    {
        var op=operands[i];

        if (op.type==="imm")
        {
            //arm64 adrp: capstone hands us the already resolved absolute page base
            if (mnemonic==="adrp")
            {
                if (operands.length>0 && operands[0].type==="reg")
                {
                    var register_holding_the_page=(""+operands[0].value).toLowerCase();
                    page_base_in_register[register_holding_the_page]=ptr(op.value);
                    registers_we_just_set[register_holding_the_page]=true;
                }
                continue;
            }

            //arm32 movw: sets low 16-bits
            if (mnemonic==="movw" && operands.length>=2 && operands[0].type==="reg")
            {
                var movw_reg=(""+operands[0].value).toLowerCase();
                var imm_val=typeof op.value==="number" ? op.value : parseInt(""+op.value, 16);
                halfword_in_register[movw_reg]=imm_val & 0xffff;
                registers_we_just_set[movw_reg]=true;
                continue;
            }

            //arm32 movt: sets high 16-bits, completing full 32-bit address
            if (mnemonic==="movt" && operands.length>=2 && operands[0].type==="reg")
            {
                var movt_reg=(""+operands[0].value).toLowerCase();
                if (movt_reg in halfword_in_register)
                {
                    var high_val=typeof op.value==="number" ? op.value : parseInt(""+op.value, 16);
                    var low_val=halfword_in_register[movt_reg];
                    var full_32bit_addr=(((high_val & 0xffff) * 65536) + (low_val & 0xffff)) >>> 0;
                    candidates.push({address:ptr(full_32bit_addr), size:1,
                                     how_it_was_found:"arm32 movw+movt address pair"});
                }
                continue;
            }

            //immediate address operand across architectures
            if (mnemonic in mnemonics_that_can_carry_an_address_immediate)
            {
                var candidate_imm_val=ptr(op.value);
                candidates.push({address:candidate_imm_val,
                                 size:(the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                                 how_it_was_found:"immediate operand of "+mnemonic});
            }
            continue;
        }

        if (op.type==="mem")
        {
            var m=op.value;
            var base_register=m.base ? (""+m.base).toLowerCase() : null;
            if (base_register==="rip" || base_register==="eip")
            {
                candidates.push({address:address_after_instruction.add(m.disp || 0),
                                 size:(the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                                 how_it_was_found:"rip/eip-relative addressing"});
            }
            else if (base_register==="pc")
            {
                //arm32 / thumb pc-relative addressing
                var pc_val;
                if (Process.arch==="arm")
                {
                    var is_thumb=(instruction.size===2 || (instruction.address.toInt32() & 1) !== 0);
                    pc_val=is_thumb ? ptr((instruction.address.toInt32() & ~3) + 4) : instruction.address.add(8);
                }
                else
                {
                    pc_val=instruction.address.add(instruction.size);
                }
                candidates.push({address:pc_val.add(m.disp || 0),
                                 size:(the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                                 how_it_was_found:"pc-relative memory operand"});
            }
            else if (base_register===null && typeof m.disp==="number" && m.disp!==0)
            {
                //literal load with offset relative to PC (ARM64 ldr literal)
                candidates.push({address:instruction.address.add(m.disp),
                                 size:(the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                                 how_it_was_found:"pc-relative literal operand"});
            }
            else if (base_register!==null && (base_register in page_base_in_register))
            {
                //arm64 "adrp x0,#page" followed by "ldr/str/ldur/stur/ldp/stp"
                candidates.push({address:page_base_in_register[base_register].add(m.disp || 0),
                                 size:(the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                                 how_it_was_found:"arm64 adrp page + memory displacement"});
            }
        }
    }

    //arm64 "adrp x0,#page" followed by "add x0,x0,#lo12"
    if ((mnemonic==="add" || mnemonic==="adds") && operands.length===3 &&
        operands[1].type==="reg" && operands[2].type==="imm" &&
        ((""+operands[1].value).toLowerCase() in page_base_in_register))
    {
        var completed_address=page_base_in_register[(""+operands[1].value).toLowerCase()].add(operands[2].value);
        candidates.push({address:completed_address, size:1,
                         how_it_was_found:"arm64 adrp+add address composition"});
        if (operands[0].type==="reg")
        {
            var name_of_destination=(""+operands[0].value).toLowerCase();
            page_base_in_register[name_of_destination]=completed_address;
            registers_we_just_set[name_of_destination]=true;
        }
    }

    forget_page_bases_and_halfwords_clobbered_by(instruction,page_base_in_register,halfword_in_register,registers_we_just_set);
    return candidates;
}


//Sign-extends an N-bit value in a NativePointer across the full pointer width (32-bit or 64-bit).
//ARM64 sign-extends index registers before scaling: for example, "ldr x0, [x1, w2, sxtw #2]"
//interprets the 32-bit value in w2 as signed. If bit 31 is set, it must be sign-extended to 64-bits
//so that adding it to base x1 subtracts the appropriate offset rather than adding 0x00000000FFFFFFFF.
function sign_extend_pointer(value_as_pointer,number_of_bits)
{
    var mask=ptr(1).shl(number_of_bits).sub(1);
    var masked_value=value_as_pointer.and(mask);
    var sign_bit=ptr(1).shl(number_of_bits-1);
    if (!masked_value.and(sign_bit).isNull())
    {
        //Subtracting 2^N propagates sign bits through the entire 64-bit pointer
        return masked_value.sub(ptr(1).shl(number_of_bits));
    }
    return masked_value;
}

//Applies index extensions (uxt*/sxt*) and shifts (lsl, lsr, asr, ror) across ARM32 and ARM64.
//Called from inside the runtime resolver closure on the stalked thread.
function apply_index_transform(value_as_pointer,name_of_extend,name_of_shift,shift_val)
{
    var p=value_as_pointer;
    //1. Apply zero or sign extension across sub-word index registers
    if (name_of_extend)
    {
        switch (name_of_extend)
        {
            case "uxtb": p=p.and(ptr(0xff)); break;          //Unsigned extend byte (low 8 bits)
            case "uxth": p=p.and(ptr(0xffff)); break;        //Unsigned extend halfword (low 16 bits)
            case "uxtw": p=p.and(ptr("0xffffffff")); break;  //Unsigned extend word (low 32 bits)
            case "sxtb": p=sign_extend_pointer(p,8); break;  //Signed extend byte (sign bit 7)
            case "sxth": p=sign_extend_pointer(p,16); break; //Signed extend halfword (sign bit 15)
            case "sxtw": p=sign_extend_pointer(p,32); break; //Signed extend word (sign bit 31)
        }
    }
    //2. Apply directional shift or rotation
    if (shift_val && shift_val>0)
    {
        var stype=name_of_shift ? name_of_shift.toLowerCase() : "lsl";
        if (stype.indexOf("lsr")>=0)
        {
            //Logical Shift Right: fills vacated high bits with zeros
            p=p.shr(shift_val);
        }
        else if (stype.indexOf("asr")>=0)
        {
            //Arithmetic Shift Right: must preserve the sign bit.
            //Note: Frida's NativePointer class does NOT implement .sar().
            //We emulate ASR by:
            //  a) Testing if the highest bit ((Process.pointerSize * 8) - 1) is 1.
            //  b) Performing a logical shift right (.shr).
            //  c) If negative, synthesizing a high-bit mask ((1 << shift_val) - 1) << (total_bits - shift_val)
            //     and bitwise-ORing it into the result.
            var is_negative = !p.and(ptr(1).shl((Process.pointerSize * 8) - 1)).isNull();
            p = p.shr(shift_val);
            if (is_negative)
            {
                var mask = ptr(1).shl(shift_val).sub(1).shl((Process.pointerSize * 8) - shift_val);
                p = p.or(mask);
            }
        }
        else if (stype.indexOf("ror")>=0)
        {
            //Rotate Right: bits shifted off the right wrap around to the high bits
            var bits=Process.pointerSize * 8;
            var s=shift_val % bits;
            p=p.shr(s).or(p.shl(bits - s));
        }
        else
        {
            //Logical Shift Left (default for lsl and unscaled index multipliers)
            p=p.shl(shift_val);
        }
    }
    return p;
}


//Returns a closure that computes the effective address(es) of the instruction's memory access(es) from a
//live CpuContext, covering explicit memory operands, multiple memory operands, and implicit string/table instructions.
//Returns null when there is no register based memory access to resolve.
//Called from the transform. The closure it returns is what the callout runs on every execution.
function build_runtime_memory_address_resolver(instruction)
{
    var operands=instruction.operands;
    var raw_mnemonic=(""+instruction.mnemonic).toLowerCase();
    var mnemonic=(Process.arch==="arm") ? strip_arm_condition_codes(raw_mnemonic) : strip_x86_prefixes(raw_mnemonic);
    var mem_resolvers=[];

    //--- 1. EXPLICIT MEMORY OPERANDS:
    //Iterates over all operands parsed by Capstone. Instructions can have 1 or more memory operands
    //(e.g., AVX gather instructions or ARM64 ldp/stp with pre/post-indexed addressing).
    if (operands)
    {
        for (var i=0;i<operands.length;i++)
        {
            var op=operands[i];
            if (op.type!=="mem")
            {
                continue;
            }
            var m=op.value;
            //x86 Segment Overrides:
            //Ignore Thread-Local Storage (TLS) and stack protector canaries on fs: (x86_64) or gs: (ia32).
            //Standard segments (ds, cs, ss, es) are normal flat data references.
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
            //RIP/EIP/PC-relative addresses are already extracted at compile time (free)
            if (base_register==="rip" || base_register==="eip" || base_register==="pc")
            {
                continue;
            }

            let base_reg=base_register;
            let index_reg=index_register;
            let displacement=m.disp || 0;
            let op_size=typeof op.size==="number" && op.size>0 ? op.size : return_access_size_for_instruction(instruction);

            //Extract scale multiplier / shift
            var shift_val_for_index=scale_to_shift_for_string_refs[m.scale || 1];
            if (shift_val_for_index===undefined) { shift_val_for_index=0; }
            var name_of_shift_for_index="lsl";
            var name_of_extend_for_index=op.ext ? (""+op.ext).toLowerCase() : null;

            //ARM64 explicit shift descriptors on the index operand
            if (op.shift && typeof op.shift.value==="number")
            {
                var type_of_shift=(""+op.shift.type).toLowerCase();
                name_of_shift_for_index=type_of_shift;
                shift_val_for_index=op.shift.value;
            }
            //ARM64 w-register indices default to uxtw (zero-extended 32-bit to 64-bit)
            if (name_of_extend_for_index===null && index_reg!==null
                && (""+index_reg).toLowerCase().charAt(0)==="w")
            {
                name_of_extend_for_index="uxtw";
            }

            let captured_shift_val=shift_val_for_index;
            let captured_shift_type=name_of_shift_for_index;
            let captured_extend=name_of_extend_for_index;

            //Push resolver closure evaluating this explicit memory operand against a CpuContext
            mem_resolvers.push(function (context) {
                var effective_address;
                if (base_reg!==null)
                {
                    var value_of_base=return_register_value_from_context(context,base_reg);
                    if (value_of_base===undefined) { return null; }
                    effective_address=ptr(value_of_base);
                }
                else
                {
                    effective_address=ptr(0);
                }
                if (index_reg!==null)
                {
                    var value_of_index=return_register_value_from_context(context,index_reg);
                    if (value_of_index===undefined) { return null; }
                    var index_transformed=apply_index_transform(ptr(value_of_index),captured_extend,captured_shift_type,captured_shift_val);
                    effective_address=effective_address.add(index_transformed);
                }
                return {
                    address: effective_address.add(displacement),
                    size: op_size,
                    how_it_was_found: "memory operand ["+(base_reg||"")+(index_reg?("+"+index_reg):"")+"]"
                };
            });
        }
    }

    //--- 2. IMPLICIT MEMORY OPERANDS (x86/x64 String & Table Instructions, ARM32 Multiple Load/Stores)
    if (Process.arch==="x64" || Process.arch==="ia32")
    {
        //x86 String Instructions (Source: RSI / ESI):
        //movs (move string), lods (load string), cmps (compare string), outs (output to port)
        if (/^(movs|lods|cmps|outs)/.test(mnemonic))
        {
            let str_size=1;
            if (/^(movsb|lodsb|cmpsb|outsb)$/.test(mnemonic)) { str_size=1; }
            else if (/^(movsw|lodsw|cmpsw|outsw)$/.test(mnemonic)) { str_size=2; }
            else if (/^(movsd|lodsd|cmpsd|outsd)$/.test(mnemonic)) { str_size=4; }
            else if (/^(movsq|lodsq|cmpsq|outsq)$/.test(mnemonic)) { str_size=8; }

            mem_resolvers.push(function (context) {
                var val_rsi=return_register_value_from_context(context, Process.arch==="x64" ? "rsi" : "esi");
                if (val_rsi===undefined) { return null; }
                return { address: ptr(val_rsi), size: str_size, how_it_was_found: "implicit string source ("+mnemonic+")" };
            });
        }

        //x86 String Instructions (Destination: RDI / EDI):
        //movs (move string), stos (store string), cmps (compare string), scas (scan string), ins (input from port)
        if (/^(movs|stos|cmps|scas|ins)/.test(mnemonic))
        {
            let str_size=1;
            if (/^(movsb|stosb|cmpsb|scasb|insb)$/.test(mnemonic)) { str_size=1; }
            else if (/^(movsw|stosw|cmpsw|scasw|insw)$/.test(mnemonic)) { str_size=2; }
            else if (/^(movsd|stosd|cmpsd|scasd|insd)$/.test(mnemonic)) { str_size=4; }
            else if (/^(movsq|stosq|cmpsq|scasq)$/.test(mnemonic)) { str_size=8; }

            mem_resolvers.push(function (context) {
                var val_rdi=return_register_value_from_context(context, Process.arch==="x64" ? "rdi" : "edi");
                if (val_rdi===undefined) { return null; }
                return { address: ptr(val_rdi), size: str_size, how_it_was_found: "implicit string target ("+mnemonic+")" };
            });
        }

        //x86 XLAT / XLATB (Table Lookup):
        //Loads a byte into AL from the translation table at address [RBX/EBX + AL].
        if (mnemonic==="xlat" || mnemonic==="xlatb")
        {
            mem_resolvers.push(function (context) {
                var val_rbx=return_register_value_from_context(context, Process.arch==="x64" ? "rbx" : "ebx");
                var val_al=return_register_value_from_context(context, "al");
                if (val_rbx===undefined || val_al===undefined) { return null; }
                return { address: ptr(val_rbx).add(ptr(val_al)), size: 1, how_it_was_found: "table lookup ("+mnemonic+")" };
            });
        }

        //x86 MASKMOVQ / MASKMOVDQU (Conditional Byte Write):
        //Implicitly writes vector bytes into memory starting at address [RDI / EDI].
        if (mnemonic==="maskmovq" || mnemonic==="maskmovdqu" || mnemonic==="vmaskmovdqu")
        {
            let mask_size=(mnemonic==="maskmovq") ? 8 : 16;
            mem_resolvers.push(function (context) {
                var val_rdi=return_register_value_from_context(context, Process.arch==="x64" ? "rdi" : "edi");
                if (val_rdi===undefined) { return null; }
                return { address: ptr(val_rdi), size: mask_size, how_it_was_found: "masked vector write ("+mnemonic+")" };
            });
        }
    }

    //ARM32 LDM / STM / PUSH / POP multiple load/store instructions:
    //Transfers a list of registers to/from memory addressed by a base register or SP.
    if (Process.arch==="arm" && /^(ldm|stm|push|pop)/.test(mnemonic))
    {
        if (mnemonic==="push" || mnemonic==="pop")
        {
            let total_bytes=Math.max(1, operands ? operands.length : 1) * 4;
            mem_resolvers.push(function (context) {
                var val_sp=return_register_value_from_context(context, "sp");
                if (val_sp===undefined) { return null; }
                return { address: ptr(val_sp), size: total_bytes, how_it_was_found: "stack operation ("+mnemonic+")" };
            });
        }
        else if (operands && operands.length>0 && operands[0].type==="reg")
        {
            let base_rname=(""+operands[0].value).toLowerCase();
            let num_regs=Math.max(1, operands.length - 1);
            let total_bytes=num_regs * 4;
            mem_resolvers.push(function (context) {
                var val_base=return_register_value_from_context(context, base_rname);
                if (val_base===undefined) { return null; }
                return { address: ptr(val_base), size: total_bytes, how_it_was_found: "multiple load/store ("+mnemonic+")" };
            });
        }
    }

    if (mem_resolvers.length===0)
    {
        return null;
    }

    //Return composite dispatcher returning all resolved memory items
    return function (context) {
        var results=[];
        for (var idx=0;idx<mem_resolvers.length;idx++)
        {
            var res=mem_resolvers[idx](context);
            if (res!==null && res.address!==null && res.address!==undefined)
            {
                results.push(res);
            }
        }
        return results;
    };
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


//Safely invalidates a Stalker translated basic block containing inst_address.
//Why this is needed:
//Frida's Stalker JIT-compiles basic blocks into a private execution cache. When a callout is emitted
//via iterator.putCallout(), that callout runs every time the instruction executes.
//Once a given instruction's string reference has been resolved max_times_to_log_each_string_reference times,
//we invalidate the block so Frida recompiles it WITHOUT the callout, completely eliminating runtime overhead.
//Different Frida API versions support either Stalker.invalidate(thread_id, address) or Stalker.invalidate(address).
function safe_stalker_invalidate(thread_id, inst_address)
{
    try
    {
        Stalker.invalidate(thread_id, inst_address);
    }
    catch (e1)
    {
        try
        {
            Stalker.invalidate(inst_address);
        }
        catch (e2) {}
    }
}


//Follows one thread and examines every instruction in our module for string references, resolving
//what it can at compile time and emitting a callout for register based addresses and implicit memory operations.
//Called from startStalker() when string reference resolution is the selected feature.
function stalker_follow_and_resolve_string_references(threadId)
{
    Stalker.follow(threadId, {
        transform: function (iterator) {
            var instruction;
            var page_base_in_register={};   //arm64 adrp state, valid only inside this block
            var halfword_in_register={};    //arm32 movw state, valid only inside this block
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
                        //compile time resolution, free at runtime
                        try
                        {
                            var static_candidates=collect_static_candidate_addresses(instruction,page_base_in_register,halfword_in_register);
                            for (var ind_cand=0;ind_cand<static_candidates.length;ind_cand++)
                            {
                                check_one_candidate_address_for_a_string(code_offset,
                                    static_candidates[ind_cand].address,
                                    static_candidates[ind_cand].size,
                                    static_candidates[ind_cand].how_it_was_found || "static analysis of the instruction");
                            }
                        }
                        catch (err) { /* an operand shape we do not understand, keep going */ }

                        //runtime resolution, for addresses that are built from registers or implicit instructions
                        if (also_instrument_register_based_memory_accesses)
                        {
                            let resolve_memory_addresses=null;
                            try { resolve_memory_addresses=build_runtime_memory_address_resolver(instruction); }
                            catch (err) { resolve_memory_addresses=null; }

                            if (resolve_memory_addresses!==null)
                            {
                                let instruction_address=instruction.address;
                                iterator.putCallout(function (context) {
                                    if (have_we_logged_enough_string_references_for(code_offset_as_str))
                                    {
                                        safe_stalker_invalidate(threadId, instruction_address);
                                        return;
                                    }
                                    var candidate_list=null;
                                    try { candidate_list=resolve_memory_addresses(context); }
                                    catch (err) { return; }
                                    if (!candidate_list || candidate_list.length===0) { return; }

                                    for (var ind_mem=0;ind_mem<candidate_list.length;ind_mem++)
                                    {
                                        var cand_item=candidate_list[ind_mem];
                                        if (!cand_item || !cand_item.address) { continue; }
                                        if (check_one_candidate_address_for_a_string(code_offset,cand_item.address,
                                                cand_item.size,cand_item.how_it_was_found || "a memory access observed at runtime"))
                                        {
                                            if (have_we_logged_enough_string_references_for(code_offset_as_str))
                                            {
                                                safe_stalker_invalidate(threadId, instruction_address);
                                                break;
                                            }
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


