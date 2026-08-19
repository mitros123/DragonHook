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
var string_refs_instrument_call_arguments=false; // UPDATED FROM DRAGONHOOK PLUGIN
var string_refs_instrument_register_arithmetic=false; // UPDATED FROM DRAGONHOOK PLUGIN
var string_refs_stalk_other_modules=false; // UPDATED FROM DRAGONHOOK PLUGIN
var strings_to_resolve_compact={"DRAGONHOOK_STRINGS_TO_RESOLVE":true}; // UPDATED FROM DRAGONHOOK PLUGIN

//How long the expensive register based tier is allowed to run, in seconds, counted from the moment the
//examined module is found. 0 means "never switch it off".
var seconds_before_register_based_instrumentation_is_dropped=0; // UPDATED FROM DRAGONHOOK PLUGIN
var register_based_instrumentation_has_been_dropped=false;
var timer_for_dropping_register_based_instrumentation=null;

//expanded from strings_to_resolve_compact, see load_strings_to_resolve()
var string_range_starts = [];   //numbers, sorted ascending
var string_range_ends = [];     //numbers, inclusive
var string_range_index = [];    //index into string_infos
var string_infos = [];          //{offset, len, preview}
var strings_to_resolve_are_loaded = false;

var times_a_string_reference_was_logged_for_code_offset = {};
var scale_to_shift_for_string_refs = { 1: 0, 2: 1, 4: 2, 8: 3 };

//An instruction whose callout never finds anything keeps that callout for the life of the process: the
//success budget above can only retire an instruction that DOES resolve a string, so an "add rax, rbx" or
//a "push" on a hot path stays instrumented forever. This is the budget for fruitless work. The count is
//reset whenever the instruction does produce a reference, so it measures executions SINCE the last hit
//and never abandons a productive instruction. 0 disables the mechanism.
var max_callout_attempts_per_code_offset_without_a_hit = 200;
var number_of_callout_attempts_since_last_hit_for_code_offset = {};
var code_offsets_we_gave_up_on = {};
var number_of_code_offsets_we_gave_up_on = 0;

//Stopping the moment every selected string has been seen once is only right if "seen once" really means
//the job is done, and usually it does not: a string is often referenced from several places and only the
//first has been reached. So this is OFF by default and the instrumentation keeps running; flip it to true
//when one reference per string is all that is wanted and the target should go back to full speed as soon
//as possible.
var stop_string_reference_resolution_when_all_strings_are_resolved = false;

//Which of the selected strings have already been found, so we can tell when there is nothing left to do.
var offsets_of_strings_that_have_been_resolved = {};
var number_of_strings_that_have_been_resolved = 0;
var string_reference_resolution_has_been_stopped_because_it_is_complete = false;


//Expands the string table the plugin baked in into the parallel arrays the search uses.
//Called once from begin_stalking_as_soon_as_module_is_found().
function load_strings_to_resolve() {
    if (strings_to_resolve_are_loaded) {
        return string_range_starts.length;
    }
    if (!("strings" in strings_to_resolve_compact) || !("ranges" in strings_to_resolve_compact)) {
        console.log("string reference resolution: the string table was not filled in by the plugin");
        return 0;
    }
    string_infos = strings_to_resolve_compact["strings"];
    var ranges_from_ghidra = strings_to_resolve_compact["ranges"];
    var number_of_ranges = ranges_from_ghidra.length;
    string_range_starts = new Array(number_of_ranges);
    string_range_ends = new Array(number_of_ranges);
    string_range_index = new Array(number_of_ranges);
    for (var i = 0; i < number_of_ranges; i++) {
        string_range_starts[i] = ranges_from_ghidra[i][0];
        string_range_ends[i] = ranges_from_ghidra[i][1];
        string_range_index[i] = ranges_from_ghidra[i][2];
    }
    strings_to_resolve_are_loaded = true;
    console.log("string reference resolution: loaded " + string_infos.length + " strings to resolve, over "
        + number_of_ranges + " ranges");
    if (Process.arch !== "x64" && Process.arch !== "ia32" && Process.arch !== "arm64" && Process.arch !== "arm") {
        console.log("string reference resolution: operand decoding is implemented for x64, x86 (ia32), arm and"
            + " arm64. On \"" + Process.arch + "\" only the immediate forms are likely to resolve.");
    }
    if (Process.arch === "ia32" && !also_instrument_register_based_memory_accesses) {
        console.log("string reference resolution: on 32 bit x86 there is no PC relative addressing, so"
            + " position independent code forms string addresses from a GOT base register. With register"
            + " based resolution switched off, only non PIC absolute immediates will be found.");
    }
    return number_of_ranges;
}


//binary search, so a reference pointing into the middle of a string is still attributed to it
//Single point lookup. Superseded by the overlap search below for detection, kept as a utility.
function find_string_to_resolve_containing(offset_as_number) {
    var low = 0;
    var high = string_range_starts.length - 1;
    while (low <= high) {
        var mid = (low + high) >> 1;
        if (offset_as_number < string_range_starts[mid]) {
            high = mid - 1;
        }
        else if (offset_as_number > string_range_ends[mid]) {
            low = mid + 1;
        }
        else {
            return string_infos[string_range_index[mid]];
        }
    }
    return null;
}


//largest index whose range start is <= the given offset, or -1
//Helper for the overlap search below.
function return_index_of_last_string_range_starting_at_or_before(offset_as_number) {
    var low = 0;
    var high = string_range_starts.length - 1;
    var result = -1;
    while (low <= high) {
        var mid = (low + high) >> 1;
        if (string_range_starts[mid] <= offset_as_number) {
            result = mid;
            low = mid + 1;
        }
        else {
            high = mid - 1;
        }
    }
    return result;
}


//An instruction touches the bytes [offset, offset+size). A point test on the base address misses a
//wide load whose base is aligned DOWN below the string start, for example a 16 byte SIMD load of
//[string_start-4]. String ranges are disjoint and sorted, so we find the last range starting at or
//before the final touched byte and walk backwards while the ranges still reach the first byte.
//Called from check_one_candidate_address_for_a_string() for every candidate address.
function find_strings_to_resolve_overlapping(offset_as_number, size_of_access) {
    var overlapping = [];
    if (string_range_starts.length === 0) {
        return overlapping;
    }
    if (!size_of_access || size_of_access < 1) { size_of_access = 1; }
    var offset_of_last_touched_byte = offset_as_number + size_of_access - 1;
    var index = return_index_of_last_string_range_starting_at_or_before(offset_of_last_touched_byte);
    while (index >= 0 && string_range_ends[index] >= offset_as_number) {
        overlapping.push(string_infos[string_range_index[index]]);
        index -= 1;
    }
    return overlapping;
}


//---- how many bytes an instruction touches. On x86 capstone reports it on the memory operand, on
//---- arm64 it has to be derived from the mnemonic and the width of the data register.

//Strips x86 instruction prefixes (e.g. rep, repe, repz, repne, repnz, lock, bnd, notrack).
//Capstone prepends prefixes directly into instruction.mnemonic (e.g. "rep movsb" or "lock cmpxchg"),
//which prevents direct string/regex equality matches without prior normalization.
function strip_x86_prefixes(mnemonic) {
    var m = ("" + mnemonic).toLowerCase();
    var previous_value = null;
    //Capstone can stack more than one decoration on a single instruction ("lock bnd cmpxchg",
    //"rep data16 movsw"), and a single replace() removed only the first one, leaving a mnemonic that
    //matched nothing. Repeat until it stops changing.
    while (previous_value !== m) {
        previous_value = m;
        m = m.replace(/^(rep|repe|repz|repne|repnz|lock|bnd|notrack|xacquire|xrelease|data16|data32|addr16|addr32|rex64|rex\.w)\s+/, "");
    }
    return m;
}

//The arm32 mnemonics this module tests for, as a prefix pattern. Used to decide whether a trailing
//two letter sequence really is a condition code or just the end of the base mnemonic.
var regex_for_arm32_mnemonics_we_recognize = /^(ldr|str|ldm|stm|push|pop|vldm|vstm|vldr|vstr|vld[1-4]|mov|movw|movt|add|adds|sub|subs|adr|cmp|bl|blx|b|tb)/;

//Strips ARM/Thumb 2-letter conditional execution suffixes (eq, ne, cs, cc, mi, pl, vs, vc, hi, ls, ge, lt, gt, le, al).
//In ARM32, almost all instructions can be conditionally executed (e.g. "ldreq", "movweq", "addeq").
//Stripping these condition codes normalizes the mnemonic for instruction table and opcode matching.
function strip_arm_condition_codes(mnemonic) {
    var m = ("" + mnemonic).toLowerCase();

    //Thumb-2 wide/narrow qualifier. Capstone emits "add.w", "ldr.w", "sub.w", and since most arm32 code
    //in the wild is thumb, leaving it on meant the exact comparisons further down (mnemonic === "add",
    //=== "sub", === "movw") simply never matched there.
    m = m.replace(/\.(w|n)$/, "");

    //Condition code, but only when what is left is a mnemonic this module actually recognizes. Stripping
    //unconditionally mangled base mnemonics whose own last two letters happen to spell a condition:
    //smlal->sml, umlal->uml, muls->mu, mls->m, teq->t, svc->s, vmls->vm. None of those stems collided
    //with anything we test for, so nothing was misidentified, but the next mnemonic added here could
    //easily have been silently destroyed.
    var stem = m.replace(/(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)$/, "");
    if (stem !== m && stem.length > 0 && regex_for_arm32_mnemonics_we_recognize.test(stem)) {
        return stem;
    }
    return m;
}

//Removes whatever decoration the current architecture puts on a mnemonic: x86 carries prefixes at the
//front, arm32 carries condition codes and thumb qualifiers at the back, arm64 carries neither.
//Called wherever a mnemonic is about to be compared against a name or pattern.
function normalize_mnemonic_for_current_arch(raw_mnemonic) {
    var m = ("" + raw_mnemonic).toLowerCase();
    if (Process.arch === "arm") {
        return strip_arm_condition_codes(m);
    }
    if (Process.arch === "x64" || Process.arch === "ia32") {
        return strip_x86_prefixes(m);
    }
    return m;   //arm64 mnemonics are already bare
}

//Width in bytes of one arm64 register, from its name.
//Called from return_access_size_arm64().
function return_register_width_arm64(name_of_register) {
    var name = ("" + name_of_register).toLowerCase();
    //Special 64-bit and 32-bit registers must be checked before the first-letter switch,
    //otherwise "sp" would match 's' (single precision floating point = 4 bytes) instead of 8 bytes.
    if (name === "sp" || name === "fp" || name === "lr" || name === "xzr") { return 8; }
    if (name === "wsp" || name === "wzr") { return 4; }
    switch (name.charAt(0)) {
        case "q": return 16; //128-bit quadword vector/FP
        case "d": return 8;  //64-bit doubleword vector/FP
        case "s": return 4;  //32-bit single precision vector/FP
        case "h": return 2;  //16-bit half precision vector/FP
        case "b": return 1;  //8-bit byte vector/FP
        case "x": return 8;  //64-bit general purpose register
        case "w": return 4;  //32-bit general purpose sub-register
        case "z": return 16; //SVE scalable vector register (at least 128-bit)
        case "v":            //NEON vector arrangements (e.g. v0.16b, v1.4s, etc.)
            if (name.indexOf("16b") >= 0 || name.indexOf("8h") >= 0 || name.indexOf("4s") >= 0 || name.indexOf("2d") >= 0) { return 16; }
            if (name.indexOf("8b") >= 0 || name.indexOf("4h") >= 0 || name.indexOf("2s") >= 0 || name.indexOf("1d") >= 0) { return 8; }
            if (name.indexOf("4b") >= 0 || name.indexOf("2h") >= 0 || name.indexOf("1s") >= 0) { return 4; }
            return 16;
    }
    return 8;
}

//How many bytes an arm64 load, store, atomic, or vector operation touches, derived from mnemonic and data registers.
//Called from return_access_size_for_instruction().
function return_access_size_arm64(instruction) {
    var mnemonic = ("" + instruction.mnemonic).toLowerCase();
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
    var size_of_access = 8;
    var operands = instruction.operands;
    var reg_count = 0;
    if (operands) {
        for (var i = 0; i < operands.length; i++) {
            if (operands[i].type === "reg") {
                reg_count++;
                if (reg_count === 1) {
                    size_of_access = return_register_width_arm64(operands[i].value);
                }
            }
        }
    }
    //Load/store pair instructions (ldp/stp/ldnp/stnp/casp) access two consecutive registers (2x width)
    if (/^(ld|st)n?p|casp/.test(mnemonic)) { size_of_access *= 2; }
    return size_of_access;
}

//How many bytes an ARM32 / Thumb load or store touches.
//Called from return_access_size_for_instruction().
function return_access_size_arm32(instruction) {
    var raw_mnemonic = ("" + instruction.mnemonic).toLowerCase();
    var mnemonic = strip_arm_condition_codes(raw_mnemonic);
    if (/^(ldrb|ldrsb|strb|ldrexeb|strexb|tbb)/.test(mnemonic)) { return 1; }
    if (/^(ldrh|ldrsh|strh|ldrexh|strexh|tbh)/.test(mnemonic)) { return 2; }
    if (/^(ldrd|strd)/.test(mnemonic)) { return 8; }
    //Block data transfer instructions (LDM, STM, PUSH, POP, VLDM, VSTM) touch 4 bytes per register transferred
    if (/^(ldm|stm|push|pop|vldm|vstm)/.test(mnemonic)) {
        var operands = instruction.operands;
        var reg_operands = 0;
        if (operands) {
            for (var i = 0; i < operands.length; i++) {
                if (operands[i].type === "reg") { reg_operands++; }
            }
        }
        return Math.max(4, reg_operands * 4);
    }
    if (/^vld1/.test(mnemonic)) { return 16; }
    if (/^vld2/.test(mnemonic)) { return 32; }
    if (/^vld3/.test(mnemonic)) { return 48; }
    if (/^vld4/.test(mnemonic)) { return 64; }
    if (/^vldr|vstr/.test(mnemonic)) {
        var ops = instruction.operands;
        if (ops && ops.length > 0 && ops[0].type === "reg") {
            var rname = ("" + ops[0].value).toLowerCase();
            if (rname.charAt(0) === "d") { return 8; }
            if (rname.charAt(0) === "s") { return 4; }
        }
        return 4;
    }
    return 4;
}

//How many bytes an x86/x64 instruction touches, covering memory operands, string instructions, and vector moves.
//Called from return_access_size_for_instruction().
function return_access_size_x86(instruction) {
    var raw_mnemonic = ("" + instruction.mnemonic).toLowerCase();
    var mnemonic = strip_x86_prefixes(raw_mnemonic);
    //String & table instructions
    if (/^(movsb|lodsb|stosb|cmpsb|scasb|insb|outsb|xlatb?)$/.test(mnemonic)) { return 1; }
    if (/^(movsw|lodsw|stosw|cmpsw|scasw|insw|outsw)$/.test(mnemonic)) { return 2; }
    if (/^(movsd|lodsd|stosd|cmpsd|scasd|insd|outsd)$/.test(mnemonic)) { return 4; }
    if (/^(movsq|lodsq|stosq|cmpsq|scasq)$/.test(mnemonic)) { return 8; }
    if (mnemonic === "maskmovq") { return 8; }
    if (mnemonic === "maskmovdqu" || mnemonic === "vmaskmovdqu") { return 16; }

    var operands = instruction.operands;
    if (operands) {
        for (var i = 0; i < operands.length; i++) {
            if (operands[i].type === "mem" && typeof operands[i].size === "number" && operands[i].size > 0) {
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
function return_access_size_for_instruction(instruction) {
    if (Process.arch === "arm64") {
        return return_access_size_arm64(instruction);
    }
    if (Process.arch === "arm") {
        return return_access_size_arm32(instruction);
    }
    if (Process.arch === "x64" || Process.arch === "ia32") {
        return return_access_size_x86(instruction);
    }
    var operands = instruction.operands;
    if (operands) {
        for (var i = 0; i < operands.length; i++) {
            if (operands[i].type === "mem" && typeof operands[i].size === "number" && operands[i].size > 0) {
                return operands[i].size;
            }
        }
    }
    return 1;
}


//True once this code offset has been reported its allowed number of times. Called from the transform
//gate (so we stop instrumenting) and from inside the callout (so we stop reporting).
function have_we_logged_enough_string_references_for(code_offset_as_str) {
    var times_logged = times_a_string_reference_was_logged_for_code_offset[code_offset_as_str];
    if (times_logged === undefined) {
        return false;
    }
    return (times_logged >= max_times_to_log_each_string_reference);
}


//Counts one callout execution against an offset and says whether it has been fruitless for too long.
//Called at the top of the callout, before any address is resolved.
function should_we_give_up_on_instrumenting_code_offset(code_offset_as_str) {
    if (max_callout_attempts_per_code_offset_without_a_hit <= 0) {
        return false;
    }
    var attempts = number_of_callout_attempts_since_last_hit_for_code_offset[code_offset_as_str];
    if (attempts === undefined) { attempts = 0; }
    attempts += 1;
    number_of_callout_attempts_since_last_hit_for_code_offset[code_offset_as_str] = attempts;
    return (attempts > max_callout_attempts_per_code_offset_without_a_hit);
}

//Clears the fruitless run for an offset that just produced a reference, so an instruction that keeps
//finding strings is never abandoned merely for being executed a lot.
//Called from update_ghidradb_with_comment_and_xref_for_string_reference() on every successful write.
function reset_callout_attempts_for_code_offset(code_offset_as_str) {
    if (code_offset_as_str in number_of_callout_attempts_since_last_hit_for_code_offset) {
        number_of_callout_attempts_since_last_hit_for_code_offset[code_offset_as_str] = 0;
    }
}

//Records that an offset is not worth instrumenting again. The transform consults this before emitting a
//callout, which is what makes the invalidate stick: on its own, invalidating a block just gets it
//recompiled with the same callout back in place.
//Called from the callout when the fruitless budget runs out.
function give_up_on_instrumenting_code_offset(code_offset_as_str) {
    if (!(code_offset_as_str in code_offsets_we_gave_up_on)) {
        code_offsets_we_gave_up_on[code_offset_as_str] = true;
        number_of_code_offsets_we_gave_up_on += 1;
        if ((number_of_code_offsets_we_gave_up_on % 500) === 0) {
            console.log("string reference resolution: " + number_of_code_offsets_we_gave_up_on
                + " instructions have been abandoned after "
                + max_callout_attempts_per_code_offset_without_a_hit + " fruitless executions each");
        }
    }
    delete number_of_callout_attempts_since_last_hit_for_code_offset[code_offset_as_str];
}


//in_addr may be anywhere; only addresses inside our module can be a string in this program
//Called from check_one_candidate_address_for_a_string() to reject candidates outside our module.
function return_offset_inside_our_module_or_null(in_addr) {
    if (in_addr === null || in_addr === undefined) {
        return null;
    }
    try {
        var ptr_addr = (typeof in_addr.compare === "function") ? in_addr : ptr(in_addr);
        //Strip PAC (Pointer Authentication Codes) if present on ARM64 platforms (Apple Silicon / ARMv8.3+)
        if (typeof ptr_addr.strip === "function") {
            ptr_addr = ptr_addr.strip();
        }
        else if (typeof Process.stripPointer === "function") {
            ptr_addr = Process.stripPointer(ptr_addr);
        }
        if (ptr_addr.compare(baseaddr_of_modulename_to_stalk) < 0 ||
            ptr_addr.compare(endaddr_of_modulename_to_stalk) >= 0) {
            return null;
        }
        return ptr_addr.sub(baseaddr_of_modulename_to_stalk);
    }
    catch (err) {
        return null;
    }
}


//Writes the discovered reference: a comment on the code, a comment on the string, and a DATA xref.
//When the referencing instruction is in our module: logs comment on code, comment on string, and DATA xref in Ghidra DB.
//When the referencing instruction is in an external module: logs a comment on the string with the external module name,
//offset from start of the external module, and debug symbol, without creating an invalid out-of-bounds xref in Ghidra DB.
function update_ghidradb_with_comment_and_xref_for_string_reference(instruction_addr, string_info, how_it_was_found) {
    var inst_addr_ptr = (typeof instruction_addr.compare === "function") ? instruction_addr : ptr(instruction_addr);
    var is_in_our_module = (modulename_to_stalk_has_been_loaded &&
        inst_addr_ptr.compare(baseaddr_of_modulename_to_stalk) >= 0 &&
        inst_addr_ptr.compare(endaddr_of_modulename_to_stalk) < 0);

    var code_offset_as_str = is_in_our_module ? inst_addr_ptr.sub(baseaddr_of_modulename_to_stalk).toString() : inst_addr_ptr.toString();
    var times_logged = times_a_string_reference_was_logged_for_code_offset[code_offset_as_str];
    if (times_logged === undefined) { times_logged = 0; }
    if (times_logged >= max_times_to_log_each_string_reference) {
        return;
    }
    times_a_string_reference_was_logged_for_code_offset[code_offset_as_str] = times_logged + 1;
    reset_callout_attempts_for_code_offset(code_offset_as_str);

    //once every selected string has been seen there is nothing left to look for
    if (!(string_info.offset in offsets_of_strings_that_have_been_resolved)) {
        offsets_of_strings_that_have_been_resolved[string_info.offset] = true;
        number_of_strings_that_have_been_resolved += 1;
        //the count is kept regardless, because it is what the log line below reports; only the acting on
        //it is behind the guard
        if (stop_string_reference_resolution_when_all_strings_are_resolved
            && string_infos.length > 0 && number_of_strings_that_have_been_resolved >= string_infos.length) {
            stop_string_reference_resolution_because_everything_is_resolved();
        }
    }

    var string_offset = ptr(string_info.offset);
    var ghidra_addr_of_string = ghidra_base_addr.add(string_offset);

    if (is_in_our_module) {
        var code_offset = inst_addr_ptr.sub(baseaddr_of_modulename_to_stalk);
        var ghidra_addr_of_code = ghidra_base_addr.add(code_offset);

        //comment on the code, saying which string it forms
        var how_ghidra_saw_it = (string_info.had_refs ? "which ghidra already had references for"
            : "which had no static references");
        var commentstr_to_add_to_ghidradb = "References the string \"" + string_info.preview + "\" at ghidra address "
            + ghidra_addr_of_string + " (offset " + string_offset + " , length " + string_info.len
            + "), " + how_ghidra_saw_it + ". Found through " + how_it_was_found;
        update_ghidradb_with_comment_at_addr(code_offset, commentstr_to_add_to_ghidradb);

        //comment on the string, saying who reached it
        var function_data_for_the_referencing_code = null;
        if (function_ranges_are_loaded) {
            function_data_for_the_referencing_code = extract_function_info_from_address_for_our_module(
                baseaddr_of_modulename_to_stalk.add(code_offset));
        }
        if (function_data_for_the_referencing_code != null) {
            commentstr_to_add_to_ghidradb = "Referenced at runtime from ghidra address " + ghidra_addr_of_code
                + " inside function " + function_data_for_the_referencing_code.fun_name + " of curent module";
        }
        else {
            commentstr_to_add_to_ghidradb = "Referenced at runtime from ghidra address " + ghidra_addr_of_code + " of curent module";
        }
        update_ghidradb_with_comment_at_addr(string_offset, commentstr_to_add_to_ghidradb);

        //and the xref itself. DATA is the reftype ghidra uses for code that points at data.
        update_ghidradb_with_xref(code_offset, string_offset, "DATA");

        console.log("STRING REFERENCE RESOLVED: ghidra address " + ghidra_addr_of_code + " references \""
            + string_info.preview + "\" at " + ghidra_addr_of_string + " (found through " + how_it_was_found + ")");
    }
    else {
        //Referenced from code in an external module (when stalking other modules is enabled)
        var module_containing_code = modulemap_for_all_modules.find(inst_addr_ptr);
        var module_name = module_containing_code ? module_containing_code.name : "external_module";
        var offset_from_module = module_containing_code ? inst_addr_ptr.sub(module_containing_code.base) : ptr(0);
        var debug_info = extract_DebugSymbol_fromAddress_data(inst_addr_ptr);

        var commentstr_to_add_to_ghidradb = "Referenced at runtime from offset " + offset_from_module
            + " of external module " + module_name + " , debuginfo: " + debug_info + ". Found through " + how_it_was_found;
        update_ghidradb_with_comment_at_addr(string_offset, commentstr_to_add_to_ghidradb);

        console.log("STRING REFERENCE RESOLVED: external module " + module_name + " at offset " + offset_from_module
            + " references \"" + string_info.preview + "\" at " + ghidra_addr_of_string + " (found through " + how_it_was_found + ")");
    }
}


//size_of_access is how many bytes the instruction touches from candidate_address onwards. Pass 1 for
//an address that is merely FORMED (lea, adrp+add, movw+movt) rather than dereferenced.
//Called for every candidate address, from both the compile time and the runtime path.
function check_one_candidate_address_for_a_string(instruction_addr, candidate_address, size_of_access, how_it_was_found) {
    var offset_of_candidate = return_offset_inside_our_module_or_null(candidate_address);
    if (offset_of_candidate === null) {
        return false;
    }
    var overlapping_strings = find_strings_to_resolve_overlapping(
        parseInt(offset_of_candidate.toString(), 16), size_of_access);
    if (overlapping_strings.length === 0) {
        return false;
    }
    for (var i = 0; i < overlapping_strings.length; i++) {
        update_ghidradb_with_comment_and_xref_for_string_reference(instruction_addr, overlapping_strings[i], how_it_was_found);
    }
    return true;
}


//Mnemonics that can plausibly carry an ADDRESS in an immediate operand across architectures.
var mnemonics_that_can_carry_an_address_immediate = {
    //x86 / x64
    "mov": true, "movabs": true, "movabsq": true, "movl": true, "movq": true, "movz": true, "movk": true,
    "movzx": true, "movsx": true, "movsxd": true,
    "push": true, "pushq": true, "pushl": true,
    "lea": true, "leaq": true, "leal": true,
    "cmp": true, "cmpq": true, "cmpl": true, "test": true, "testq": true, "testl": true,
    //arm64
    "adr": true, "adrp": true, "ldr": true, "ldrsw": true, "prfm": true,
    //arm32
    "movw": true, "movt": true
};


//An adrp or movw result is only valid until something else writes that register. Without this, a stale entry
//made every later access compute an address from a page/halfword base that the register no longer holds.
//Called at the end of collect_static_candidate_addresses() for each instruction.
function forget_page_bases_and_halfwords_clobbered_by(instruction, page_base_in_register, halfword_in_register,
                                                     value_being_built_in_register, registers_we_just_set) {
    var registers_written = null;
    try { registers_written = instruction.regsWritten; } catch (err) { registers_written = null; }

    if (registers_written && registers_written.length) {
        for (var i = 0; i < registers_written.length; i++) {
            var name_of_register = ("" + registers_written[i]).toLowerCase();
            if (registers_we_just_set[name_of_register]) { continue; }
            if (name_of_register in page_base_in_register) { delete page_base_in_register[name_of_register]; }
            if (name_of_register in halfword_in_register) { delete halfword_in_register[name_of_register]; }
            if (name_of_register in value_being_built_in_register) { delete value_being_built_in_register[name_of_register]; }
        }
        return;
    }

    //no register detail from capstone, fall back to the destination operand
    var operands = instruction.operands;
    if (operands && operands.length > 0 && operands[0].type === "reg") {
        var name_of_destination = ("" + operands[0].value).toLowerCase();
        if (!registers_we_just_set[name_of_destination]) {
            if (name_of_destination in page_base_in_register) { delete page_base_in_register[name_of_destination]; }
            if (name_of_destination in halfword_in_register) { delete halfword_in_register[name_of_destination]; }
            if (name_of_destination in value_being_built_in_register) { delete value_being_built_in_register[name_of_destination]; }
        }
    }
}


//A load carries the string address INDIRECTLY as often as it carries it directly. "ldr r0,[pc,#8]" reads
//a word inside .text whose CONTENT is the address, and on arm32 that literal pool is the usual way a
//string is reached at all; the arm64 "ldr x0, literal" and the x64 "mov rax,[rip+disp]" GOT load have the
//same shape. Every candidate collected so far is the SLOT, not the string, so those references were
//missed completely. The slot is ordinary mapped module data, so it can simply be read here, while the
//block is being compiled, at no runtime cost whatsoever.
//Called at the end of collect_static_candidate_addresses().
function add_candidates_for_pointers_stored_at_the_candidates(candidates, the_instruction_only_forms_an_address) {
    //lea/adr/adrp/add compute a pointer without reading memory, so there is no slot to look inside
    if (the_instruction_only_forms_an_address) {
        return;
    }
    var number_of_candidates_before_we_started = candidates.length;
    for (var i = 0; i < number_of_candidates_before_we_started; i++) {
        var candidate_being_examined = candidates[i];
        //a byte or halfword load cannot be holding a pointer
        if (!candidate_being_examined.size || candidate_being_examined.size < Process.pointerSize) {
            continue;
        }
        var address_of_the_slot = candidate_being_examined.address;
        try {
            //only slots inside the examined module: those are the literal pools and relocated pointer
            //tables that belong to the program we are analysing
            if (return_offset_inside_our_module_or_null(address_of_the_slot) === null) {
                continue;
            }
            var pointer_stored_in_the_slot = address_of_the_slot.readPointer();
            if (pointer_stored_in_the_slot.isNull()) {
                continue;
            }
            candidates.push({
                address: pointer_stored_in_the_slot,
                size: 1,
                how_it_was_found: "pointer stored at " + address_of_the_slot + ", reached by "
                    + candidate_being_examined.how_it_was_found
            });
        }
        catch (err) {
            //unmapped or unreadable slot, nothing to learn from it
        }
    }
}


//Whether an arm32 instruction is a Thumb one. Frida exposes no flag for this, so this is a disjunction of
//three independent signals, and each one is a PROOF of Thumb on its own:
//  - a 2 byte instruction can only be Thumb, because every A32 instruction is exactly 4 bytes;
//  - an address that is not 4 byte aligned can only be Thumb, because A32 instructions are 4 byte aligned;
//  - capstone tags an instruction with the "thumb" / "thumb2" / "thumb1only" feature group when the
//    encoding requires Thumb.
//The commonly suggested "address & 1" test is deliberately NOT here. Bit 0 is the interworking flag on a
//BRANCH TARGET or an elf symbol value, where it genuinely does say which instruction set to decode, and
//that is why it is the usual test in frida scripts. A decoded instruction address is never tagged that
//way, though: Thumb instructions are 2 byte aligned so bit 0 is always 0 on the addresses stalker hands
//us, and the test can never fire.
//This can only ever prove Thumb, never ARM. A 4 byte, 4 byte aligned Thumb-2 instruction that capstone
//does not tag still reads as ARM here, so the pc base derived from it can still be wrong. Proving ARM
//needs either an Instruction.parse(address.or(1)) round trip, or the TMode information from ghidra.
//Called from collect_static_candidate_addresses(), wherever an arm32 pc relative address is computed.
function is_this_an_arm32_thumb_instruction(instruction) {
    //A32 is fixed width, so anything narrower is Thumb
    if (instruction.size === 2) {
        return true;
    }
    //A32 is 4 byte aligned, so a halfword aligned instruction is Thumb
    try {
        if (!instruction.address.and(ptr(2)).isNull()) {
            return true;
        }
    }
    catch (err) { }
    //capstone's feature groups. Present for encodings that REQUIRE Thumb, absent for encodings valid in
    //both, which is why this is a hint that can only add certainty and never remove it.
    try {
        var groups_of_the_instruction = instruction.groups;
        if (groups_of_the_instruction && groups_of_the_instruction.length) {
            for (var ind_group = 0; ind_group < groups_of_the_instruction.length; ind_group++) {
                var name_of_group = ("" + groups_of_the_instruction[ind_group]).toLowerCase();
                if (name_of_group === "thumb" || name_of_group === "thumb2" || name_of_group === "thumb1only") {
                    return true;
                }
            }
        }
    }
    catch (err) { }
    return false;
}


//Addresses an instruction forms that are already known while the block is being compiled: PC relative
//memory operands (x64 rip, arm pc), address bearing immediates, arm64 adrp/adr computations, and arm32 movw/movt pairs.
//Called from the transform, once per instruction while the block is being compiled.
function collect_static_candidate_addresses(instruction, page_base_in_register, halfword_in_register,
                                            value_being_built_in_register) {
    var candidates = [];
    var operands = instruction.operands;
    if (!operands) {
        return candidates;
    }
    var address_after_instruction = instruction.address.add(instruction.size);
    var raw_mnemonic = ("" + instruction.mnemonic).toLowerCase();
    var mnemonic = normalize_mnemonic_for_current_arch(raw_mnemonic);
    var registers_we_just_set = {};
    //"forms an address" means the instruction computes a pointer without dereferencing it, so the candidate
    //should be measured as 1 byte rather than as the width of a memory access.
    //"add" belongs here only on arm, where "adrp"+"add" is the address forming idiom. On x86 "add" is plain
    //arithmetic, and treating it as address forming gave "add eax,[0x1000]" a size of 1 instead of its real
    //access width, which can miss an overlap that begins at the last bytes of a string.
    var the_instruction_only_forms_an_address = (mnemonic === "lea" || mnemonic === "leaq" || mnemonic === "leal"
        || mnemonic === "adr" || mnemonic === "adrp"
        || ((Process.arch === "arm" || Process.arch === "arm64") && mnemonic === "add")
        || mnemonic === "movw" || mnemonic === "movt");
    var size_for_a_real_access = return_access_size_for_instruction(instruction);

    for (var i = 0; i < operands.length; i++) {
        var op = operands[i];

        if (op.type === "imm") {
            //arm64 adrp: capstone hands us the already resolved absolute page base
            if (mnemonic === "adrp") {
                if (operands.length > 0 && operands[0].type === "reg") {
                    var register_holding_the_page = ("" + operands[0].value).toLowerCase();
                    page_base_in_register[register_holding_the_page] = ptr(op.value);
                    registers_we_just_set[register_holding_the_page] = true;
                }
                continue;
            }

            //arm64 movz/movk: a 64 bit absolute address is built 16 bits at a time. movz starts a fresh
            //value with the rest of the register zeroed, and each movk patches one more halfword into it,
            //so only the ACCUMULATED value is ever a real address - the individual 16 bit immediates are
            //not. The arm32 movw/movt pair just below already worked this way; this is its arm64 twin, and
            //without it a non position independent arm64 binary (or JIT emitted code) formed string
            //addresses that we never saw.
            if (Process.arch === "arm64" && (mnemonic === "movz" || mnemonic === "movk")
                && operands.length >= 2 && operands[0].type === "reg") {
                var register_being_built = ("" + operands[0].value).toLowerCase();
                var immediate_for_the_halfword = typeof op.value === "number" ? op.value : parseInt("" + op.value, 16);
                var shift_for_the_halfword = 0;
                if (op.shift && typeof op.shift.value === "number") {
                    shift_for_the_halfword = op.shift.value;
                }
                var halfword_as_pointer = ptr(immediate_for_the_halfword & 0xffff).shl(shift_for_the_halfword);
                if (mnemonic === "movz") {
                    value_being_built_in_register[register_being_built] = halfword_as_pointer;
                }
                else {
                    var value_accumulated_so_far = value_being_built_in_register[register_being_built];
                    if (value_accumulated_so_far === undefined) {
                        continue;   //a movk with no movz before it: the other 48 bits are unknown
                    }
                    //clear that 16 bit field, then put the new halfword in its place
                    var mask_for_the_field = ptr(0xffff).shl(shift_for_the_halfword);
                    value_being_built_in_register[register_being_built] =
                        value_accumulated_so_far.sub(value_accumulated_so_far.and(mask_for_the_field))
                            .or(halfword_as_pointer);
                }
                registers_we_just_set[register_being_built] = true;
                //Every step of the chain is offered as a candidate, not just the last one: we cannot know
                //where the chain ends, and a partially built value is almost always outside the module and
                //rejected anyway. This is what lets a two instruction movz+movk pair resolve.
                candidates.push({
                    address: value_being_built_in_register[register_being_built],
                    size: 1,
                    how_it_was_found: "arm64 " + mnemonic + " chain building an absolute address"
                });
                continue;
            }

            //arm32 movw: sets low 16-bits
            if (mnemonic === "movw" && operands.length >= 2 && operands[0].type === "reg") {
                var movw_reg = ("" + operands[0].value).toLowerCase();
                var imm_val = typeof op.value === "number" ? op.value : parseInt("" + op.value, 16);
                halfword_in_register[movw_reg] = imm_val & 0xffff;
                registers_we_just_set[movw_reg] = true;
                continue;
            }

            //arm32 movt: sets high 16-bits, completing full 32-bit address
            if (mnemonic === "movt" && operands.length >= 2 && operands[0].type === "reg") {
                var movt_reg = ("" + operands[0].value).toLowerCase();
                if (movt_reg in halfword_in_register) {
                    var high_val = typeof op.value === "number" ? op.value : parseInt("" + op.value, 16);
                    var low_val = halfword_in_register[movt_reg];
                    var full_32bit_addr = (((high_val & 0xffff) * 65536) + (low_val & 0xffff)) >>> 0;
                    candidates.push({
                        address: ptr(full_32bit_addr), size: 1,
                        how_it_was_found: "arm32 movw+movt address pair"
                    });
                }
                continue;
            }

            //immediate address operand across architectures. "add reg, imm32" is included on x86 only:
            //non position independent code can form a string address by adding a constant to a base, and
            //on arm the adrp+add path above already handles the equivalent properly.
            var the_mnemonic_can_carry_an_address_immediate =
                (mnemonic in mnemonics_that_can_carry_an_address_immediate)
                || ((Process.arch === "x64" || Process.arch === "ia32")
                    && (mnemonic === "add" || mnemonic === "addq" || mnemonic === "addl"));
            if (the_mnemonic_can_carry_an_address_immediate) {
                var candidate_imm_val = ptr(op.value);
                candidates.push({
                    address: candidate_imm_val,
                    size: (the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                    how_it_was_found: "immediate operand of " + mnemonic
                });
            }
            continue;
        }

        if (op.type === "mem") {
            var m = op.value;
            var base_register = m.base ? ("" + m.base).toLowerCase() : null;
            if (base_register === "rip" || base_register === "eip") {
                candidates.push({
                    address: address_after_instruction.add(m.disp || 0),
                    size: (the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                    how_it_was_found: "rip/eip-relative addressing"
                });
            }
            else if (base_register === "pc") {
                //arm32 / thumb pc-relative addressing
                var pc_val;
                if (Process.arch === "arm") {
                    //Pointer arithmetic rather than toInt32(): toInt32() is a SIGNED 32 bit conversion, so
                    //an arm32 module mapped at or above 2 GB came back negative and the alignment maths
                    //below then produced a wrong address.
                    var address_aligned_down_to_4 = instruction.address.sub(instruction.address.and(ptr(3)));
                    var is_thumb = is_this_an_arm32_thumb_instruction(instruction);
                    pc_val = is_thumb ? address_aligned_down_to_4.add(4) : instruction.address.add(8);
                }
                else {
                    pc_val = instruction.address.add(instruction.size);
                }
                candidates.push({
                    address: pc_val.add(m.disp || 0),
                    size: (the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                    how_it_was_found: "pc-relative memory operand"
                });
            }
            else if (base_register === null && typeof m.disp === "number"
                     && (m.index === null || m.index === undefined)) {
                //No base and no index register. On x86 that is ABSOLUTE addressing: "mov eax,[0x404000]"
                //carries the whole address in the displacement, so adding the instruction address to it
                //produced a nonsense candidate which could still land on an unrelated string and write a
                //false xref. On arm and arm64 the same operand shape is a pc relative literal, which is
                //what this branch was originally written for.
                //An index register with no base ("[eax*4+disp]") depends on a register value, so it is the
                //runtime tier's job, not something to guess at compile time.
                if (Process.arch === "x64" || Process.arch === "ia32") {
                    candidates.push({
                        address: ptr(m.disp),
                        size: (the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                        how_it_was_found: "absolute memory operand"
                    });
                }
                else {
                    candidates.push({
                        address: instruction.address.add(m.disp),
                        size: (the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                        how_it_was_found: "pc-relative literal operand"
                    });
                }
            }
            else if (base_register !== null && (base_register in page_base_in_register)
                     && (m.index === null || m.index === undefined)) {
                //arm64 "adrp x0,#page" followed by "ldr/str/ldur/stur/ldp/stp".
                //Only when there is no index register: with one, the real address is page+disp+index and
                //the index is not known until the instruction runs, so emitting page+disp here would be a
                //guess that can land on an unrelated string.
                candidates.push({
                    address: page_base_in_register[base_register].add(m.disp || 0),
                    size: (the_instruction_only_forms_an_address ? 1 : size_for_a_real_access),
                    how_it_was_found: "arm64 adrp page + memory displacement"
                });
            }
        }
    }

    //arm32 / thumb pc-relative address calculations (e.g. "add r0, pc, #12", "sub r0, pc, #8", "adr r0, #12")
    if (Process.arch === "arm" && (mnemonic === "add" || mnemonic === "adds" || mnemonic === "sub" || mnemonic === "subs" || mnemonic === "adr") &&
        operands.length >= 2) {
        var is_pc_rel_arm32 = false;
        var imm_op_arm32 = null;
        if (operands.length >= 3 && operands[1].type === "reg" && ("" + operands[1].value).toLowerCase() === "pc" && operands[2].type === "imm") {
            is_pc_rel_arm32 = true;
            imm_op_arm32 = operands[2];
        }
        else if (mnemonic === "adr" && operands[1].type === "imm") {
            is_pc_rel_arm32 = true;
            imm_op_arm32 = operands[1];
        }

        if (is_pc_rel_arm32 && imm_op_arm32 !== null) {
            //same signed conversion hazard as above, done with pointer arithmetic instead
            var address_aligned_down_to_4_for_arith = instruction.address.sub(instruction.address.and(ptr(3)));
            var is_thumb_mode = is_this_an_arm32_thumb_instruction(instruction);
            var pc_base_val = is_thumb_mode ? address_aligned_down_to_4_for_arith.add(4) : instruction.address.add(8);
            var imm_num_val = typeof imm_op_arm32.value === "number" ? imm_op_arm32.value : parseInt("" + imm_op_arm32.value, 16);
            var formed_target_addr = mnemonic.indexOf("sub") >= 0 ? pc_base_val.sub(imm_num_val) : pc_base_val.add(imm_num_val);
            candidates.push({
                address: formed_target_addr, size: 1,
                how_it_was_found: "arm32 pc-relative " + mnemonic + " address formation"
            });
        }
    }

    //arm64 "adrp x0,#page" followed by "add x0,x0,#lo12"
    if ((mnemonic === "add" || mnemonic === "adds") && operands.length === 3 &&
        operands[1].type === "reg" && operands[2].type === "imm" &&
        (("" + operands[1].value).toLowerCase() in page_base_in_register)) {
        var completed_address = page_base_in_register[("" + operands[1].value).toLowerCase()].add(operands[2].value);
        candidates.push({
            address: completed_address, size: 1,
            how_it_was_found: "arm64 adrp+add address composition"
        });
        if (operands[0].type === "reg") {
            var name_of_destination = ("" + operands[0].value).toLowerCase();
            page_base_in_register[name_of_destination] = completed_address;
            registers_we_just_set[name_of_destination] = true;
        }
    }

    //a load may have named a slot that CONTAINS the address rather than the address itself
    add_candidates_for_pointers_stored_at_the_candidates(candidates, the_instruction_only_forms_an_address);

    forget_page_bases_and_halfwords_clobbered_by(instruction, page_base_in_register, halfword_in_register,
        value_being_built_in_register, registers_we_just_set);
    return candidates;
}


//Sign-extends an N-bit value in a NativePointer across the full pointer width (32-bit or 64-bit).
//ARM64 sign-extends index registers before scaling: for example, "ldr x0, [x1, w2, sxtw #2]"
//interprets the 32-bit value in w2 as signed. If bit 31 is set, it must be sign-extended to 64-bits
//so that adding it to base x1 subtracts the appropriate offset rather than adding 0x00000000FFFFFFFF.
function sign_extend_pointer(value_as_pointer, number_of_bits) {
    var mask = ptr(1).shl(number_of_bits).sub(1);
    var masked_value = value_as_pointer.and(mask);
    var sign_bit = ptr(1).shl(number_of_bits - 1);
    if (!masked_value.and(sign_bit).isNull()) {
        //Subtracting 2^N propagates sign bits through the entire 64-bit pointer
        return masked_value.sub(ptr(1).shl(number_of_bits));
    }
    return masked_value;
}

//Applies index extensions (uxt*/sxt*) and shifts (lsl, lsr, asr, ror) across ARM32 and ARM64.
//Called from inside the runtime resolver closure on the stalked thread.
function apply_index_transform(value_as_pointer, name_of_extend, name_of_shift, shift_val) {
    var p = value_as_pointer;
    //1. Apply zero or sign extension across sub-word index registers
    if (name_of_extend) {
        switch (name_of_extend) {
            case "uxtb": p = p.and(ptr(0xff)); break;          //Unsigned extend byte (low 8 bits)
            case "uxth": p = p.and(ptr(0xffff)); break;        //Unsigned extend halfword (low 16 bits)
            case "uxtw": p = p.and(ptr("0xffffffff")); break;  //Unsigned extend word (low 32 bits)
            case "sxtb": p = sign_extend_pointer(p, 8); break;  //Signed extend byte (sign bit 7)
            case "sxth": p = sign_extend_pointer(p, 16); break; //Signed extend halfword (sign bit 15)
            case "sxtw": p = sign_extend_pointer(p, 32); break; //Signed extend word (sign bit 31)
        }
    }
    //2. Apply directional shift or rotation
    if (shift_val && shift_val > 0) {
        var stype = name_of_shift ? name_of_shift.toLowerCase() : "lsl";
        if (stype.indexOf("lsr") >= 0) {
            //Logical Shift Right: fills vacated high bits with zeros
            p = p.shr(shift_val);
        }
        else if (stype.indexOf("asr") >= 0) {
            //Arithmetic Shift Right: must preserve the sign bit.
            //Note: Frida's NativePointer class does NOT implement .sar().
            //We emulate ASR by:
            //  a) Testing if the highest bit ((Process.pointerSize * 8) - 1) is 1.
            //  b) Performing a logical shift right (.shr).
            //  c) If negative, synthesizing a high-bit mask ((1 << shift_val) - 1) << (total_bits - shift_val)
            //     and bitwise-ORing it into the result.
            var is_negative = !p.and(ptr(1).shl((Process.pointerSize * 8) - 1)).isNull();
            p = p.shr(shift_val);
            if (is_negative) {
                var mask = ptr(1).shl(shift_val).sub(1).shl((Process.pointerSize * 8) - shift_val);
                p = p.or(mask);
            }
        }
        else if (stype.indexOf("ror") >= 0) {
            //Rotate Right: bits shifted off the right wrap around to the high bits
            var bits = Process.pointerSize * 8;
            var s = shift_val % bits;
            p = p.shr(s).or(p.shl(bits - s));
        }
        else {
            //Logical Shift Left (default for lsl and unscaled index multipliers)
            p = p.shl(shift_val);
        }
    }
    return p;
}


//True for the architectural stack pointer. Anything computed from it is a stack address, and the strings
//we look for are static data inside the module, so such a candidate can never match.
//Deliberately does NOT include rbp/ebp: without a frame pointer those are ordinary general registers.
function is_stack_pointer_register(name_of_register) {
    var n = ("" + name_of_register).toLowerCase();
    return (n === "rsp" || n === "esp" || n === "sp" || n === "wsp");
}

//Registers whose "push" is a prologue save rather than an argument. Consulted on x64 only: there the
//first arguments travel in registers, so a push is nearly always a callee saved register being spilled,
//and these six are exactly the System V callee saved set. On ia32 push IS how arguments are passed, so
//nothing is skipped there.
var registers_that_are_only_pushed_to_save_them = {
    "rbp": true, "rbx": true, "r12": true, "r13": true, "r14": true, "r15": true
};

//32 bit register names, whose arithmetic produces a 32 bit result.
function is_32_bit_register_name(name_of_register) {
    var n = ("" + name_of_register).toLowerCase();
    if (Process.arch === "arm64") {
        return (n.charAt(0) === "w");
    }
    if (n.charAt(0) === "e" && n.length === 3) { return true; }          //eax, ebx, esi ...
    if (/^r(8|9|1[0-5])d$/.test(n)) { return true; }                     //r8d .. r15d
    return false;
}

//Whether a 32 bit value could point into the examined module at all. When the module is mapped above
//4 GB it cannot, so instrumenting 32 bit arithmetic there is guaranteed wasted work.
//Called at compile time, so the saving is a callout that is never emitted.
function can_a_32_bit_value_point_into_our_module() {
    try {
        if (!modulename_to_stalk_has_been_loaded) {
            return true;   //not known yet, do not skip anything on a guess
        }
        return (baseaddr_of_modulename_to_stalk.compare(ptr("0xffffffff")) <= 0);
    }
    catch (err) {
        return true;
    }
}


//Returns a closure that computes the effective address(es) of the instruction's memory access(es) from a
//live CpuContext, covering explicit memory operands, multiple memory operands, and implicit string/table instructions.
//Returns null when there is no register based memory access to resolve.
//Called from the transform. The closure it returns is what the callout runs on every execution.
function build_runtime_memory_address_resolver(instruction) {
    var operands = instruction.operands;
    var raw_mnemonic = ("" + instruction.mnemonic).toLowerCase();
    var mnemonic = normalize_mnemonic_for_current_arch(raw_mnemonic);
    var mem_resolvers = [];

    //--- 1. EXPLICIT MEMORY OPERANDS & 2. IMPLICIT MEMORY OPERANDS
    //Active when also_instrument_register_based_memory_accesses is enabled.
    if (also_instrument_register_based_memory_accesses) {
        //--- 1. EXPLICIT MEMORY OPERANDS:
        //Iterates over all operands parsed by Capstone. Instructions can have 1 or more memory operands
        //(e.g., AVX gather instructions or ARM64 ldp/stp with pre/post-indexed addressing).
    if (operands) {
        for (var i = 0; i < operands.length; i++) {
            var op = operands[i];
            if (op.type !== "mem") {
                continue;
            }
            var m = op.value;
            //x86 Segment Overrides:
            //Ignore Thread-Local Storage (TLS) and stack protector canaries on fs: (x86_64) or gs: (ia32).
            //Standard segments (ds, cs, ss, es) are normal flat data references.
            var name_of_segment = m.segment ? ("" + m.segment).toLowerCase() : null;
            if (name_of_segment !== null && name_of_segment !== "ds" && name_of_segment !== "cs"
                && name_of_segment !== "ss" && name_of_segment !== "es") {
                continue;
            }
            var base_register = m.base || null;
            var index_register = m.index || null;
            if (base_register === null && index_register === null) {
                continue;
            }
            //RIP/EIP/PC-relative addresses are already extracted at compile time (free)
            if (base_register === "rip" || base_register === "eip" || base_register === "pc") {
                continue;
            }

            let base_reg = base_register;
            let index_reg = index_register;
            let displacement = m.disp || 0;
            let op_size = typeof op.size === "number" && op.size > 0 ? op.size : return_access_size_for_instruction(instruction);

            //Extract scale multiplier / shift
            var shift_val_for_index = scale_to_shift_for_string_refs[m.scale || 1];
            if (shift_val_for_index === undefined) { shift_val_for_index = 0; }
            var name_of_shift_for_index = "lsl";
            var name_of_extend_for_index = op.ext ? ("" + op.ext).toLowerCase() : (m.ext ? ("" + m.ext).toLowerCase() : null);

            //ARM64 / ARM32 explicit shift descriptors on the index operand
            var shift_obj = op.shift || m.shift || null;
            if (shift_obj && typeof shift_obj.value === "number") {
                var type_of_shift = ("" + shift_obj.type).toLowerCase();
                name_of_shift_for_index = type_of_shift;
                shift_val_for_index = shift_obj.value;
            }
            //ARM64 w-register indices default to uxtw (zero-extended 32-bit to 64-bit)
            if (name_of_extend_for_index === null && index_reg !== null
                && ("" + index_reg).toLowerCase().charAt(0) === "w") {
                name_of_extend_for_index = "uxtw";
            }

            var is_subtracted_index = Boolean(op.subtracted || m.subtracted);

            let captured_shift_val = shift_val_for_index;
            let captured_shift_type = name_of_shift_for_index;
            let captured_extend = name_of_extend_for_index;
            let captured_is_subtracted = is_subtracted_index;

            //Push resolver closure evaluating this explicit memory operand against a CpuContext
            mem_resolvers.push(function (context) {
                var effective_address;
                if (base_reg !== null) {
                    var value_of_base = return_register_value_from_context(context, base_reg);
                    if (value_of_base === undefined) { return null; }
                    effective_address = ptr(value_of_base);
                }
                else {
                    effective_address = ptr(0);
                }
                if (index_reg !== null) {
                    var value_of_index = return_register_value_from_context(context, index_reg);
                    if (value_of_index === undefined) { return null; }
                    var index_transformed = apply_index_transform(ptr(value_of_index), captured_extend, captured_shift_type, captured_shift_val);
                    effective_address = captured_is_subtracted ? effective_address.sub(index_transformed) : effective_address.add(index_transformed);
                }
                return {
                    address: effective_address.add(displacement),
                    size: op_size,
                    how_it_was_found: "memory operand [" + (base_reg || "") + (index_reg ? ((captured_is_subtracted ? "-" : "+") + index_reg) : "") + "]"
                };
            });
        }
    }

    //--- 2. IMPLICIT MEMORY OPERANDS (x86/x64 String & Table Instructions, ARM32 Multiple Load/Stores)
    if (Process.arch === "x64" || Process.arch === "ia32") {
        //x86 String Instructions (Source: RSI / ESI):
        //movs (move string), lods (load string), cmps (compare string), outs (output to port)
        if (/^(movs|lods|cmps|outs)/.test(mnemonic)) {
            let str_size = 1;
            if (/^(movsb|lodsb|cmpsb|outsb)$/.test(mnemonic)) { str_size = 1; }
            else if (/^(movsw|lodsw|cmpsw|outsw)$/.test(mnemonic)) { str_size = 2; }
            else if (/^(movsd|lodsd|cmpsd|outsd)$/.test(mnemonic)) { str_size = 4; }
            else if (/^(movsq|lodsq|cmpsq|outsq)$/.test(mnemonic)) { str_size = 8; }

            mem_resolvers.push(function (context) {
                var val_rsi = return_register_value_from_context(context, Process.arch === "x64" ? "rsi" : "esi");
                if (val_rsi === undefined) { return null; }
                return { address: ptr(val_rsi), size: str_size, how_it_was_found: "implicit string source (" + mnemonic + ")" };
            });
        }

        //x86 String Instructions (Destination: RDI / EDI):
        //movs (move string), stos (store string), cmps (compare string), scas (scan string), ins (input from port)
        if (/^(movs|stos|cmps|scas|ins)/.test(mnemonic)) {
            let str_size = 1;
            if (/^(movsb|stosb|cmpsb|scasb|insb)$/.test(mnemonic)) { str_size = 1; }
            else if (/^(movsw|stosw|cmpsw|scasw|insw)$/.test(mnemonic)) { str_size = 2; }
            else if (/^(movsd|stosd|cmpsd|scasd|insd)$/.test(mnemonic)) { str_size = 4; }
            else if (/^(movsq|stosq|cmpsq|scasq)$/.test(mnemonic)) { str_size = 8; }

            mem_resolvers.push(function (context) {
                var val_rdi = return_register_value_from_context(context, Process.arch === "x64" ? "rdi" : "edi");
                if (val_rdi === undefined) { return null; }
                return { address: ptr(val_rdi), size: str_size, how_it_was_found: "implicit string target (" + mnemonic + ")" };
            });
        }

        //x86 XLAT / XLATB (Table Lookup):
        //Loads a byte into AL from the translation table at address [RBX/EBX + AL].
        if (mnemonic === "xlat" || mnemonic === "xlatb") {
            mem_resolvers.push(function (context) {
                var val_rbx = return_register_value_from_context(context, Process.arch === "x64" ? "rbx" : "ebx");
                var val_al = return_register_value_from_context(context, "al");
                if (val_rbx === undefined || val_al === undefined) { return null; }
                return { address: ptr(val_rbx).add(ptr(val_al)), size: 1, how_it_was_found: "table lookup (" + mnemonic + ")" };
            });
        }

        //x86 MASKMOVQ / MASKMOVDQU (Conditional Byte Write):
        //Implicitly writes vector bytes into memory starting at address [RDI / EDI].
        if (mnemonic === "maskmovq" || mnemonic === "maskmovdqu" || mnemonic === "vmaskmovdqu") {
            let mask_size = (mnemonic === "maskmovq") ? 8 : 16;
            mem_resolvers.push(function (context) {
                var val_rdi = return_register_value_from_context(context, Process.arch === "x64" ? "rdi" : "edi");
                if (val_rdi === undefined) { return null; }
                return { address: ptr(val_rdi), size: mask_size, how_it_was_found: "masked vector write (" + mnemonic + ")" };
            });
        }
    }

    //ARM32 LDM / STM / PUSH / POP multiple load/store instructions:
    //Transfers a list of registers to/from memory addressed by a base register or SP.
    if (Process.arch === "arm" && /^(ldm|stm|push|pop|vldm|vstm)/.test(mnemonic)) {
        if (mnemonic === "push" || mnemonic === "pop") {
            let total_bytes = Math.max(1, operands ? operands.length : 1) * 4;
            mem_resolvers.push(function (context) {
                var val_sp = return_register_value_from_context(context, "sp");
                if (val_sp === undefined) { return null; }
                return { address: ptr(val_sp), size: total_bytes, how_it_was_found: "stack operation (" + mnemonic + ")" };
            });
        }
        else if (operands && operands.length > 0 && operands[0].type === "reg") {
            let base_rname = ("" + operands[0].value).toLowerCase();
            let num_regs = Math.max(1, operands.length - 1);
            let total_bytes = num_regs * 4;
            mem_resolvers.push(function (context) {
                var val_base = return_register_value_from_context(context, base_rname);
                if (val_base === undefined) { return null; }
                return { address: ptr(val_base), size: total_bytes, how_it_was_found: "multiple load/store (" + mnemonic + ")" };
            });
        }
    }
    }

    //--- 3. FUNCTION CALL ARGUMENT REGISTERS (when string_refs_instrument_call_arguments is enabled)
    //Resolves string references passed directly in calling convention registers to external or internal functions
    //(e.g., puts, printf, strcmp, strlen, syslog, fopen). Even when external modules are not stalked,
    //inspecting the argument registers at the call site within our module captures the string reference.
    if (string_refs_instrument_call_arguments) {
        //"bx" is deliberately NOT here. bx is a plain branch and "bx lr" is the standard arm32 RETURN,
        //so treating it as a call put argument register callouts on every function exit: double the
        //callout volume, and any string pointer sitting in r0 at that point is a RETURN VALUE, which was
        //then written into ghidra labelled "function call argument register (r0)".
        var is_call_op = (mnemonic === "call" || mnemonic === "callq" || mnemonic === "bl"
            || mnemonic === "blr" || mnemonic === "blx");
        if (is_call_op) {
            var call_arg_regs = [];
            if (Process.arch === "x64") {
                //Windows x64 ABI uses rcx, rdx, r8, r9. System V AMD64 (Linux, macOS, Android) uses rdi, rsi, rdx, rcx, r8, r9
                //Exact match, not indexOf: "darwin".indexOf("win") is 3, so the substring test picked the
                //WINDOWS abi on macOS. That dropped rdi and rsi, i.e. arguments 1 and 2, which is where
                //puts(str), printf(fmt,..) and strcmp(a,b) carry the string on every System V platform.
                if (Process.platform === "windows") {
                    call_arg_regs = ["rcx", "rdx", "r8", "r9"];
                }
                else {
                    call_arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
                }
            }
            else if (Process.arch === "arm64") {
                //AAPCS64 standard argument registers x0 - x7
                call_arg_regs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
            }
            else if (Process.arch === "arm") {
                //AAPCS standard argument registers r0 - r3
                call_arg_regs = ["r0", "r1", "r2", "r3"];
            }
            else if (Process.arch === "ia32") {
                //Only fastcall and thiscall pass arguments in registers on x86 32 bit, and they use ecx
                //and edx. cdecl and stdcall, which is nearly everything, pass on the STACK: those are
                //caught by the push handler further down, not here.
                //eax was removed: it is the return value register, never an argument in any of these
                //conventions, so inspecting it only produced noise.
                call_arg_regs = ["ecx", "edx"];
            }

            for (var ind_arg = 0; ind_arg < call_arg_regs.length; ind_arg++) {
                let arg_reg_name = call_arg_regs[ind_arg];
                mem_resolvers.push(function (context) {
                    var val_arg = return_register_value_from_context(context, arg_reg_name);
                    if (val_arg === undefined || val_arg === null) { return null; }
                    var ptr_val = ptr(val_arg);
                    if (ptr_val.isNull()) { return null; }
                    return {
                        address: ptr_val,
                        size: 1,
                        how_it_was_found: "function call argument register (" + arg_reg_name + ") at " + mnemonic
                    };
                });
            }

            //If the call instruction is indirect through a register (e.g. "call rax", "blr x3", "blx r2"),
            //also inspect the indirect target register as a candidate pointer.
            if (operands && operands.length > 0 && operands[0].type === "reg") {
                let target_reg_name = ("" + operands[0].value).toLowerCase();
                mem_resolvers.push(function (context) {
                    var val_t = return_register_value_from_context(context, target_reg_name);
                    if (val_t === undefined || val_t === null) { return null; }
                    var ptr_t = ptr(val_t);
                    if (ptr_t.isNull()) { return null; }
                    return {
                        address: ptr_t,
                        size: 1,
                        how_it_was_found: "indirect call target register (" + target_reg_name + ")"
                    };
                });
            }
        }

        //x86 / x64 Stack Push of registers (passing arguments on the stack, e.g. "push eax", "push rdi")
        if ((Process.arch === "x64" || Process.arch === "ia32") &&
            (mnemonic === "push" || mnemonic === "pushq" || mnemonic === "pushl") &&
            operands && operands.length > 0 && operands[0].type === "reg"
            //SKIP: a prologue save, not an argument. "push rbp" opens almost every function on x64.
            && !(Process.arch === "x64"
                 && (("" + operands[0].value).toLowerCase() in registers_that_are_only_pushed_to_save_them))) {
            let push_rname = ("" + operands[0].value).toLowerCase();
            mem_resolvers.push(function (context) {
                var val_p = return_register_value_from_context(context, push_rname);
                if (val_p === undefined || val_p === null) { return null; }
                var ptr_p = ptr(val_p);
                if (ptr_p.isNull()) { return null; }
                return {
                    address: ptr_p,
                    size: 1,
                    how_it_was_found: "pushed stack argument register (" + push_rname + ")"
                };
            });
        }
    }

    //--- 4. DYNAMIC REGISTER ARITHMETIC (when string_refs_instrument_register_arithmetic is enabled)
    //Resolves addresses formed dynamically through register-to-register arithmetic without explicit memory operands
    //(e.g., dynamic table lookups, calculated string pointer offsets).
    if (string_refs_instrument_register_arithmetic) {
        var is_arithmetic_op = (mnemonic === "add" || mnemonic === "adds" || mnemonic === "sub" || mnemonic === "subs");

        //SKIP: stack pointer arithmetic. "sub rsp, 0x20" / "add sp, sp, #16" adjust the stack frame, and
        //every function with locals has one, so this removes a great many callouts for nothing lost.
        var the_arithmetic_touches_the_stack_pointer = false;
        if (is_arithmetic_op && operands) {
            for (var ind_sp = 0; ind_sp < operands.length; ind_sp++) {
                if (operands[ind_sp].type === "reg" && is_stack_pointer_register(operands[ind_sp].value)) {
                    the_arithmetic_touches_the_stack_pointer = true;
                    break;
                }
            }
        }

        if (is_arithmetic_op && !the_arithmetic_touches_the_stack_pointer && operands && operands.length >= 2) {
            var is_subtraction = mnemonic.indexOf("sub") >= 0;
            //2-operand form (x86: add dst, src -> dst = dst + src; or ARM 2-reg)
            var the_result_is_32_bit_and_cannot_reach_our_module =
                (is_32_bit_register_name(operands[0].value) && !can_a_32_bit_value_point_into_our_module());

            //SKIP: a 32 bit result cannot point into a module mapped above 4 GB, so the callout could
            //never match no matter what the registers hold.
            if (the_result_is_32_bit_and_cannot_reach_our_module) {
                //nothing to instrument for this instruction
            }
            else if (operands.length === 2 && operands[0].type === "reg" && operands[1].type === "reg") {
                let r_dst = ("" + operands[0].value).toLowerCase();
                let r_src = ("" + operands[1].value).toLowerCase();
                mem_resolvers.push(function (context) {
                    var val_d = return_register_value_from_context(context, r_dst);
                    var val_s = return_register_value_from_context(context, r_src);
                    if (val_d === undefined || val_s === undefined || val_d === null || val_s === null) { return null; }
                    var res_ptr = is_subtraction ? ptr(val_d).sub(ptr(val_s)) : ptr(val_d).add(ptr(val_s));
                    if (res_ptr.isNull()) { return null; }
                    return {
                        address: res_ptr,
                        size: 1,
                        how_it_was_found: "dynamic register arithmetic (" + r_dst + (is_subtraction ? "-" : "+") + r_src + ")"
                    };
                });
            }
            //3-operand form (ARM/ARM64: add dst, src1, src2 -> dst = src1 + src2)
            else if (operands.length >= 3 && operands[0].type === "reg" && operands[1].type === "reg" && operands[2].type === "reg") {
                let r_src1 = ("" + operands[1].value).toLowerCase();
                let r_src2 = ("" + operands[2].value).toLowerCase();

                //"add x0, x1, x2, lsl #3" is one of the commonest table index forms on arm64, and the
                //"lsl #3" is a descriptor on the THIRD operand. Ignoring it computed x1+x2 instead of
                //x1+(x2<<3): usually that simply misses the string, but it can also land on an unrelated
                //one and write a FALSE xref. Read from exactly where the explicit memory operand path
                //reads them, and when both are absent apply_index_transform() is a no op, so an
                //instruction without a shift behaves exactly as it did before.
                var shift_obj_for_src2 = operands[2].shift || null;
                let shift_type_for_src2 = "lsl";
                let shift_val_for_src2 = 0;
                if (shift_obj_for_src2 && typeof shift_obj_for_src2.value === "number") {
                    shift_type_for_src2 = ("" + shift_obj_for_src2.type).toLowerCase();
                    shift_val_for_src2 = shift_obj_for_src2.value;
                }
                let extend_for_src2 = operands[2].ext ? ("" + operands[2].ext).toLowerCase() : null;

                //"add w0, w1, w2" produces a 32 bit result and the cpu zeroes the top half of x0, so the
                //full width sum would be a value the register never actually holds.
                let result_is_32_bit = is_32_bit_register_name(operands[0].value);

                mem_resolvers.push(function (context) {
                    var val_s1 = return_register_value_from_context(context, r_src1);
                    var val_s2 = return_register_value_from_context(context, r_src2);
                    if (val_s1 === undefined || val_s2 === undefined || val_s1 === null || val_s2 === null) { return null; }
                    var src2_transformed = apply_index_transform(ptr(val_s2), extend_for_src2,
                        shift_type_for_src2, shift_val_for_src2);
                    var res_ptr3 = is_subtraction ? ptr(val_s1).sub(src2_transformed) : ptr(val_s1).add(src2_transformed);
                    if (result_is_32_bit) { res_ptr3 = res_ptr3.and(ptr("0xffffffff")); }
                    if (res_ptr3.isNull()) { return null; }
                    return {
                        address: res_ptr3,
                        size: 1,
                        how_it_was_found: "dynamic register arithmetic (" + r_src1 + (is_subtraction ? "-" : "+") + r_src2
                            + (shift_val_for_src2 > 0 ? (" " + shift_type_for_src2 + " #" + shift_val_for_src2) : "") + ")"
                    };
                });
            }
        }
    }

    if (mem_resolvers.length === 0) {
        return null;
    }

    //Return composite dispatcher returning all resolved memory items
    return function (context) {
        var results = [];
        var addresses_already_collected = {};
        for (var idx = 0; idx < mem_resolvers.length; idx++) {
            var res = mem_resolvers[idx](context);
            if (res !== null && res.address !== null && res.address !== undefined) {
                //Different resolvers legitimately land on the SAME address: the argument register list
                //inspects six registers at once and a call such as strcmp(s,s), or any pointer that is
                //live in two argument registers, yields the identical pointer twice. Reporting it twice
                //writes the same comment twice and spends the per instruction log budget twice on what is
                //a single discovery. Keyed on the resolved address, so genuinely different candidates from
                //the same instruction are all kept.
                var address_as_key = "" + res.address;
                if (address_as_key in addresses_already_collected) { continue; }
                addresses_already_collected[address_as_key] = true;
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
//Called when the timer armed by arm_the_timer_for_dropping_register_based_instrumentation() expires.
function drop_register_based_string_instrumentation() {
    if (!string_reference_resolution_is_enabled) {
        return;
    }
    if (register_based_instrumentation_has_been_dropped) {
        return;
    }
    register_based_instrumentation_has_been_dropped = true;
    also_instrument_register_based_memory_accesses = false;
    string_refs_instrument_call_arguments = false;
    string_refs_instrument_register_arithmetic = false;

    var number_of_threads_refollowed = 0;
    for (var thread_id_to_str in dict_with_threadIds_that_are_being_stalked) {
        if (dict_with_threadIds_that_are_being_stalked[thread_id_to_str] !== true) {
            continue;
        }
        var thread_id_as_number = parseInt(thread_id_to_str, 10);
        try {
            Stalker.unfollow(thread_id_as_number);
            //clear the followed flag first, otherwise the guard inside startStalker refuses to refollow
            dict_with_threadIds_that_are_being_stalked[thread_id_to_str] = false;
            startStalker(thread_id_as_number, modulename_to_stalk);
            number_of_threads_refollowed += 1;
        }
        catch (err) {
            console.log("Could not refollow " + describe_thread_by_id(thread_id_to_str)
                +" after dropping the register based instrumentation: " + err);
        }
    }
    Stalker.flush();

    console.log("string reference resolution: the register based tier is now OFF after "
        + seconds_before_register_based_instrumentation_is_dropped + " seconds, " + number_of_threads_refollowed
        + " thread(s) refollowed to drop their callouts. Compile time resolution (rip relative on x64,"
        + " adrp+add on arm64, absolute immediates) keeps running for the rest of the session.");
}


//Every selected string has been found, so there is nothing left to look for and the target may as well
//run at full speed. Called from the update path the instant the last string is resolved, which means it
//runs INSIDE a stalker callout on a target thread: unfollowing from there would tear down the code cache
//that the current thread is executing out of, so the actual work is deferred to frida's own JS thread.
function stop_string_reference_resolution_because_everything_is_resolved() {
    if (string_reference_resolution_has_been_stopped_because_it_is_complete) {
        return;
    }
    string_reference_resolution_has_been_stopped_because_it_is_complete = true;
    console.log("string reference resolution: all " + string_infos.length
        + " selected string(s) have been resolved, so the instrumentation is being removed.");
    setTimeout(function () { stop_stalking_for_string_reference_resolution(); }, 0);
}


//Unfollows every stalked thread. Unlike drop_register_based_string_instrumentation() this does NOT
//refollow: the compile time tier has nothing left to find either, so stalking entirely stops.
//Called deferred, from the function above.
function stop_stalking_for_string_reference_resolution() {
    var number_of_threads_unfollowed = 0;
    for (var thread_id_to_str in dict_with_threadIds_that_are_being_stalked) {
        if (dict_with_threadIds_that_are_being_stalked[thread_id_to_str] !== true) {
            continue;
        }
        try {
            Stalker.unfollow(parseInt(thread_id_to_str, 10));
            dict_with_threadIds_that_are_being_stalked[thread_id_to_str] = false;
            number_of_threads_unfollowed += 1;
        }
        catch (err) {
            console.log("Could not unfollow " + describe_thread_by_id(thread_id_to_str)
                + " after string reference resolution finished: " + err);
        }
    }
    Stalker.flush();
    try { Stalker.garbageCollect(); } catch (err) { }
    console.log("string reference resolution: unfollowed " + number_of_threads_unfollowed
        + " thread(s); the target now runs uninstrumented.");
}


//Starts the countdown that later switches the register based tier off, when the dialog asked for one.
//Called once from begin_stalking_as_soon_as_module_is_found().
function arm_the_timer_for_dropping_register_based_instrumentation() {
    if (!string_reference_resolution_is_enabled) { return; }
    if (!also_instrument_register_based_memory_accesses
        && !string_refs_instrument_call_arguments
        && !string_refs_instrument_register_arithmetic) {
        return;
    }
    if (seconds_before_register_based_instrumentation_is_dropped <= 0) {
        return;   //0 means the tier stays on for the whole session
    }
    if (timer_for_dropping_register_based_instrumentation !== null) { return; }

    //setTimeout runs on frida's own JS thread, which holds no target lock, so the unfollow/refollow
    //dance does not happen on a stalked thread
    timer_for_dropping_register_based_instrumentation = setTimeout(
        drop_register_based_string_instrumentation,
        seconds_before_register_based_instrumentation_is_dropped * 1000);
    console.log("string reference resolution: the register based tier will be switched off in "
        + seconds_before_register_based_instrumentation_is_dropped + " seconds");
}


//Safely invalidates a Stalker translated basic block containing inst_address.
//Why this is needed:
//Frida's Stalker JIT-compiles basic blocks into a private execution cache. When a callout is emitted
//via iterator.putCallout(), that callout runs every time the instruction executes.
//Once a given instruction's string reference has been resolved max_times_to_log_each_string_reference times,
//we invalidate the block so Frida recompiles it WITHOUT the callout, completely eliminating runtime overhead.
//Different Frida API versions support either Stalker.invalidate(thread_id, address) or Stalker.invalidate(address).
function safe_stalker_invalidate(thread_id, inst_address) {
    //The GLOBAL form first, deliberately. Stalker keeps a separate compiled copy of every block per
    //THREAD, so the two argument form only discards the calling thread's copy. Every retirement decision
    //in this agent is global - it lives in a process wide dictionary that the transform re-reads - so
    //eight threads running the same hot site each had to execute their own callout, notice the budget was
    //already spent, and invalidate their own copy: O(threads) wasted callout executions per site.
    //The one argument form invalidates for all threads at once, which matches the decision being global
    //and makes retirement O(1). The per thread form is kept as the fallback for frida versions that only
    //accept that signature.
    try {
        Stalker.invalidate(inst_address);
    }
    catch (e1) {
        try {
            Stalker.invalidate(thread_id, inst_address);
        }
        catch (e2) { }
    }
}


//Follows one thread and examines every instruction in our module for string references, resolving
//what it can at compile time and emitting a callout for register based addresses and implicit memory operations.
//Called from startStalker() when string reference resolution is the selected feature.
function stalker_follow_and_resolve_string_references(threadId) {
    if (string_reference_resolution_has_been_stopped_because_it_is_complete) {
        //everything was already resolved, so a thread that appears now does not need instrumenting
        return;
    }
    Stalker.follow(threadId, {
        transform: function (iterator) {
            var instruction;
            var page_base_in_register = {};   //arm64 adrp state, valid only inside this block
            var halfword_in_register = {};    //arm32 movw state, valid only inside this block
            var value_being_built_in_register = {};   //arm64 movz/movk state, valid only inside this block
            while ((instruction = iterator.next()) !== null) {
                var is_in_our_module = (modulename_to_stalk_has_been_loaded &&
                    instruction.address.compare(baseaddr_of_modulename_to_stalk) >= 0 &&
                    instruction.address.compare(endaddr_of_modulename_to_stalk) < 0);

                if (strings_to_resolve_are_loaded && (is_in_our_module || string_refs_stalk_other_modules)) {
                    //"let", not "var", for everything the callout further down closes over. transform()
                    //runs at COMPILE time and the callout runs later, on every execution, so a single
                    //function scoped "var" would be shared by every callout in this block and they would
                    //all read the LAST instruction's values. "let" in the loop body gives each iteration
                    //its own binding, which is what makes each callout report its own instruction.
                    let inst_addr = instruction.address;
                    let tracking_key = is_in_our_module ? instruction.address.sub(baseaddr_of_modulename_to_stalk).toString() : instruction.address.toString();

                    if (!have_we_logged_enough_string_references_for(tracking_key)) {
                        //compile time resolution, free at runtime
                        try {
                            var static_candidates = collect_static_candidate_addresses(instruction,
                                page_base_in_register, halfword_in_register, value_being_built_in_register);
                            for (var ind_cand = 0; ind_cand < static_candidates.length; ind_cand++) {
                                check_one_candidate_address_for_a_string(inst_addr,
                                    static_candidates[ind_cand].address,
                                    static_candidates[ind_cand].size,
                                    static_candidates[ind_cand].how_it_was_found || "static analysis of the instruction");
                            }
                        }
                        catch (err) { /* an operand shape we do not understand, keep going */ }

                        //runtime resolution, for addresses that are built from registers, call arguments, or register arithmetic
                        //Deliberately gates only the CALLOUT, not the static resolution above: giving up
                        //means "the runtime probe on this instruction never pays for itself", and compile
                        //time resolution costs nothing at runtime either way.
                        if ((also_instrument_register_based_memory_accesses
                            || string_refs_instrument_call_arguments
                            || string_refs_instrument_register_arithmetic)
                            && !(tracking_key in code_offsets_we_gave_up_on)) {
                            let resolve_memory_addresses = null;
                            try { resolve_memory_addresses = build_runtime_memory_address_resolver(instruction); }
                            catch (err) { resolve_memory_addresses = null; }

                            if (resolve_memory_addresses !== null) {
                                iterator.putCallout(function (context) {
                                    if (have_we_logged_enough_string_references_for(tracking_key)) {
                                        safe_stalker_invalidate(threadId, inst_addr);
                                        return;
                                    }
                                    //fruitless for too long: abandon this instruction so its callout stops
                                    //costing anything for the rest of the session
                                    if (should_we_give_up_on_instrumenting_code_offset(tracking_key)) {
                                        give_up_on_instrumenting_code_offset(tracking_key);
                                        safe_stalker_invalidate(threadId, inst_addr);
                                        return;
                                    }
                                    var candidate_list = null;
                                    try { candidate_list = resolve_memory_addresses(context); }
                                    catch (err) { return; }
                                    if (!candidate_list || candidate_list.length === 0) { return; }

                                    for (var ind_mem = 0; ind_mem < candidate_list.length; ind_mem++) {
                                        var cand_item = candidate_list[ind_mem];
                                        if (!cand_item || !cand_item.address) { continue; }
                                        if (check_one_candidate_address_for_a_string(inst_addr, cand_item.address,
                                            cand_item.size, cand_item.how_it_was_found || "a memory access observed at runtime")) {
                                            if (have_we_logged_enough_string_references_for(tracking_key)) {
                                                safe_stalker_invalidate(threadId, inst_addr);
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
