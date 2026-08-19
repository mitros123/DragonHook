import frida
import sys
import os
from pathlib import Path
import json
import threading
import queue
import requests
import base64

entire_send_log_of_script=[]
store_entire_send_log_in_mem=False
session=None
exit_event=None
script=None
DragonHook_config={}
frida_script_contents=""
dragonhook_config_dir_pathstr=""
dragonhook_api_callword="DH_GHIDRA_API_CALL"

#---------------------- WORKER POOL FOR THE GHIDRA HTTP CALLS ----------------------
#frida delivers every message on a single reactor thread. Doing a blocking HTTP request there
#serialises the whole pipeline: while one comment is being written to the Ghidra DB, no other
#message from the agent can be processed, including the reply that a blocked recv().wait() in a
#stalked thread is waiting for. So the reactor thread only enqueues, and these workers do the I/O.
#
#Updates are partitioned by target address so that two updates for the SAME address are still
#applied in order, while updates for different addresses run in parallel.
#Queries (the calls the agent actually blocks on) get their own queue so they can never end up
#stuck behind a backlog of updates.
number_of_update_workers=4
#queue.put() below has no timeout, so reaching this cap BLOCKS frida's reactor thread - which would be a
#deadlock rather than backpressure, because the reactor is also what delivers the replies a target thread
#blocked in recv().wait() is waiting for. It is left as a blocking put deliberately: one hundred thousand
#queued updates is not a state a real run reaches, since the ghidra side answers far faster than that
#backlog could build, and dropping updates silently instead would be worse. If it ever IS reached, the
#symptom is the agent going quiet with python still alive, and this is the first place to look.
max_queued_api_calls=100000
query_api_calls={"FUN_DATA_GIVEN_ADDR_OFFSET",
                 "ALL_FUN_DATA_SORTED_BY_RANGESTART",
                 "CODEUNIT_DATA_GIVEN_ADDR_OFFSET"}
query_queue=queue.Queue(maxsize=max_queued_api_calls)
update_queues=[]
worker_threads=[]
thread_local_storage=threading.local()


#EVERY http call to the Ghidra server needs a timeout. Without one, requests waits forever, the worker
#never posts a reply, and any agent thread sitting in recv().wait() for that reply is blocked for the
#rest of the process's life. That is the same hang that the bulk fetch used to cause, and until now the
#bulk fetch was the only call that had been given a timeout.
#The values differ by how much work Ghidra has to do:
#  - the bulk fetch walks every function and every body range in the program, so it gets the largest;
#  - a single function lookup still has to find the containing function and enumerate its ranges, so it
#    gets a generous one too;
#  - a codeunit lookup and the update calls are cheap, and only need enough slack for a Ghidra that is
#    briefly busy in another transaction.
def timeout_from_config(name_of_setting,default_in_seconds):
    #every other value in the config file is a JSON string, so a timeout added there by hand is far
    #more likely to be "120" than 120. requests needs a number, so coerce here and fall back to the
    #default rather than letting a TypeError escape into a worker thread.
    try:
        return float(DragonHook_config.get(name_of_setting,default_in_seconds))
    except (TypeError,ValueError):
        return float(default_in_seconds)

def timeout_for_bulk_function_data():
    return timeout_from_config("TIMEOUT_FOR_BULK_FUNCTION_DATA_FETCH",600)

def timeout_for_function_data():
    return timeout_from_config("TIMEOUT_FOR_FUNCTION_DATA_FETCH",120)

def timeout_for_short_api_calls():
    return timeout_from_config("TIMEOUT_FOR_SHORT_API_CALLS",60)


#one requests.Session per worker thread, so connections to the Ghidra HTTP server are kept alive
#instead of being torn down and re-established for every single comment/xref
def get_session():
    existing_session=getattr(thread_local_storage,"http_session",None)
    if existing_session is None:
        existing_session=requests.Session()
        thread_local_storage.http_session=existing_session
    return existing_session


#sys.stdout=open(sys.stdout.fileno(),mode='w',buffering=1)
#sys.stderr=open(sys.stderr.fileno(),mode='w',buffering=1)

#override print
#https://stackoverflow.com/questions/73250160/how-to-override-the-builtin-method-print
try:
    import __builtin__
except ImportError:
    import builtins as __builtin__

def print(*args, **kwargs):
    __builtin__.print('FROM PYTHON: ', end='')
    return __builtin__.print(*args, **kwargs)


def ghidra_server_url(endpoint):
    return "http://"+DragonHook_config["GHIDRA_HTTP_SERVER_INTERFACE_IP"]+":"+DragonHook_config["GHIDRA_HTTP_SERVER_PORT"]+"/"+endpoint


def return_function_data_given_address_offset(paramlist):
    value_of_param=paramlist[0]
    #the agent BLOCKS in recv().wait() on this one, so an untimed request here freezes a target thread
    response=get_session().get(ghidra_server_url("FUN_DATA_GIVEN_ADDR_OFFSET"),params={"address_offset":value_of_param},timeout=timeout_for_function_data())
    return response.text

def return_codeunit_data_given_address_offset(paramlist):
    value_of_param=paramlist[0]
    #the agent BLOCKS in recv().wait() on this one too
    response=get_session().get(ghidra_server_url("CODEUNIT_DATA_GIVEN_ADDR_OFFSET"),params={"address_offset":value_of_param},timeout=timeout_for_short_api_calls())
    return response.text


def return_all_function_data_by_ranges(paramlist):
    #This one can legitimately take a long time on a big program: Ghidra has to walk every function
    #and every function body range. A short timeout here used to abort the request, the exception
    #escaped on_message(), no reply was ever posted, and the agent stayed blocked in recv().wait()
    #for the rest of the session. Keep it generous, and see the try/except in run_api_call().
    response=get_session().get(ghidra_server_url("ALL_FUN_DATA_SORTED_BY_RANGESTART"),params={},timeout=timeout_for_bulk_function_data())
    print("text length:"+str(len(response.text)))
    return response.text

def update_ghidradb_with_comment_at_addr(paramlist):
    address_offset=paramlist[0]
    comment_to_set=paramlist[1]
    #an update that hangs holds one of the four update workers forever, so four of them stall the whole
    #update pipeline even though queries have their own queue
    response=get_session().post(ghidra_server_url("UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR"),data={"address_offset":address_offset,"comment":comment_to_set},timeout=timeout_for_short_api_calls())
    return response.text

def update_ghidradb_with_xref(paramlist):
    address_offset_from=paramlist[0]
    address_offset_to=paramlist[1]
    type_of_xref=paramlist[2]
    response=get_session().get(ghidra_server_url("UPDATE_GHIDRADB_WITH_XREF"),params={"address_offset_from":address_offset_from,"address_offset_to":address_offset_to,"RefType":type_of_xref},timeout=timeout_for_short_api_calls())
    return response.text

def update_bytes_in_ghidradb(paramlist):
    address_offset=paramlist[0]
    decimalarray=paramlist[1]
    try:
        int_list=[int(x.strip()) for x in decimalarray.replace("[","").replace("]","").split(",")]
        byte_data=bytes(int_list)
        b64_encoded=base64.b64encode(byte_data).decode('utf-8')
    except:
        return "Error from python, in decimalarray to base64 conversion"
    response=get_session().post(ghidra_server_url("CHANGE_BYTES_INSIDE_GHIDRADB"),data={"address_offset":address_offset,"content_as_b64":b64_encoded},timeout=timeout_for_short_api_calls())
    return response.text

defined_dragonhook_api_calls={
    "FUN_DATA_GIVEN_ADDR_OFFSET":{"num_of_params":1, "handler":return_function_data_given_address_offset},
    "ALL_FUN_DATA_SORTED_BY_RANGESTART":{"num_of_params":0, "handler":return_all_function_data_by_ranges},
    "UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR":{"num_of_params":2, "handler":update_ghidradb_with_comment_at_addr},
    "UPDATE_GHIDRADB_WITH_XREF":{"num_of_params":3, "handler":update_ghidradb_with_xref},
    "CODEUNIT_DATA_GIVEN_ADDR_OFFSET":{"num_of_params":1, "handler":return_codeunit_data_given_address_offset},
    "CHANGE_BYTES_INSIDE_GHIDRADB":{"num_of_params":2, "handler":update_bytes_in_ghidradb}
}



def identify_and_return_api_call(line):
    if "|||"+dragonhook_api_callword in line:
        try:
            api_call_str=line.split("|||")[1]
            jsonstr_with_api_call_data=api_call_str.split(dragonhook_api_callword+":")[1]
            jsondict_with_api_call_data=json.loads(jsonstr_with_api_call_data)
            dh_api_call_functionstr=jsondict_with_api_call_data["FUNCTION"]
            if dh_api_call_functionstr not in defined_dragonhook_api_calls:
                print("Unknown DragonHook API Call: "+dh_api_call_functionstr)
                return (None,None)
            else:
                parameters_list= jsondict_with_api_call_data["PARAMS"]
                if (len(parameters_list)!=defined_dragonhook_api_calls[dh_api_call_functionstr]["num_of_params"]):
                    print("Invalid number of params")
                    return (None,None)
                return (dh_api_call_functionstr,parameters_list)
        except:
            print("Malformed DragonHook API Call command: "+line)
            return (None,None)
    return (None,None)




def install_frida_dependencies():
    pm = frida.PackageManager()
    #The reason dependencies will probablly need to be installed is because the user will be expecting them to be there. They are not (right now) needed by the DragonHook plugin
    result = pm.install(specs=["frida-java-bridge","frida-swift-bridge","frida-objc-bridge"])
    #result = pm.install(specs=["frida-itrace","frida-il2cpp-bridge","frida-stack"])


def return_reply_type_for_api_call(fun_name,params):
    if (fun_name=="UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR" or fun_name=="CHANGE_BYTES_INSIDE_GHIDRADB" ):
        #in this case the entire comment will not be put inside the type
        return "api-response-"+fun_name+"-['"+str(params[0])+"']"
    return "api-response-"+fun_name+"-"+str(params)


def run_api_call(fun_name,params):
    print("Invoking DragonHook API call "+fun_name + " with paramlist: "+str(params))
    #A reply MUST be posted on every path. The agent registers a recv() handler for every call and,
    #depending on the *_are_asynchronous flags, may be blocked in recv().wait() on a stalked thread.
    #If an exception escaped here the reply would never be sent and that thread would hang forever.
    try:
        returned_data_as_str=str(defined_dragonhook_api_calls[fun_name]["handler"](params))
    except Exception as e:
        returned_data_as_str="Error from python while invoking "+fun_name+": "+repr(e)
        print(returned_data_as_str)
    if (len(returned_data_as_str)>2000):
        print("Sending data back to JS: "+returned_data_as_str[:2000]+".....")
    else:
        print("Sending data back to JS: "+returned_data_as_str)
    try:
        script.post({"type":return_reply_type_for_api_call(fun_name,params),"payload":returned_data_as_str})
    except Exception as e:
        print("Could not post the reply for "+fun_name+": "+repr(e))


def api_call_worker(incoming_queue):
    while True:
        item=incoming_queue.get()
        if item is None:        #shutdown sentinel
            incoming_queue.task_done()
            return
        (fun_name,params)=item
        try:
            run_api_call(fun_name,params)
        finally:
            incoming_queue.task_done()


def start_api_call_workers():
    global update_queues
    global worker_threads
    update_queues=[queue.Queue(maxsize=max_queued_api_calls) for _ in range(number_of_update_workers)]
    all_queues=[query_queue]+update_queues
    for current_queue in all_queues:
        worker=threading.Thread(target=api_call_worker,args=(current_queue,),daemon=True)
        worker.start()
        worker_threads.append(worker)


def stop_api_call_workers():
    for current_queue in [query_queue]+update_queues:
        try:
            current_queue.put_nowait(None)
        except queue.Full:
            pass


def enqueue_api_call(fun_name,params):
    if fun_name in query_api_calls:
        query_queue.put((fun_name,params))
        return
    #Updates are partitioned on their FIRST parameter, which for a comment is the address being commented and
    #for an xref is the FROM address. So the guarantee this actually provides is: every update whose first
    #parameter is the same address is handled by one worker, in order. That is the guarantee that matters,
    #because it is the one that keeps successive COMMENTS on an address in the order the agent produced them -
    #comment text is appended, so order is visible in the result.
    #It does NOT order an xref against the comments on its TO address, and it does not need to: those are
    #different ghidra objects and neither depends on the other's ordering. The earlier wording here claimed
    #ordering for "the same address" without qualification, which was broader than the truth.
    partition_key=str(params[0]) if len(params)>0 else ""
    update_queues[hash(partition_key) % number_of_update_workers].put((fun_name,params))


def on_message(message, data):
    if message['type'] == 'send':
        #print("[*] Message from script:", message['payload'])
        print("Received message from JS: "+str(message))
        if 'payload' in message:
            incoming_message=message['payload']
            if store_entire_send_log_in_mem:
                entire_send_log_of_script.append(incoming_message)
            for incoming_line in str(incoming_message).split("\n"):
                (fun_name,params)=identify_and_return_api_call(incoming_line)
                if (fun_name,params)==(None,None):
                    pass
                else:
                    #do NOT do the HTTP call on frida's reactor thread, see the worker pool above
                    enqueue_api_call(fun_name,params)
    elif message['type'] == 'error':
        print("[!] Script error:", message['stack'])
    else:
        print(str(message))


def on_detached(reason,crash):
    global exit_event
    print("Process detached, reason: "+ str(reason))
    if crash:
        print("Crash info: "+ str(crash))
    exit_event.set()


#---------------------- ORDERLY SHUTDOWN ----------------------
#Ghidra cannot reach the target itself: the target may be on a USB or remote device, and only this
#process holds the frida device/session/script handles. So when the user cancels the agent task, Ghidra
#writes a sentinel line to our stdin and WE do the teardown. Ghidra only force kills us as a last resort,
#which is why the graceful path matters: a SIGKILL here would leave the agent loaded in the target, with
#Stalker still following threads and hardware watchpoints still armed in their debug registers.
shutdown_sentinel_from_ghidra="DRAGONHOOK_SHUTDOWN"
#Ghidra has ASKED us to stop. Set by the stdin watcher thread, read by the main thread.
shutdown_has_been_requested=False
#The teardown has actually run. Separate from the request flag, because the thread that receives the request
#is not the thread that performs the teardown - see the note on watch_stdin_for_shutdown_request().
the_teardown_has_run=False

#How long any ONE teardown step may take before we give up on it and move to the next, and how long the
#whole shutdown may take before we exit the hard way. Both must stay comfortably below Ghidra's own grace
#period, so that Ghidra terminating us really is the last resort and not the normal path.
#Three steps at 2 seconds each is 6 in the worst case, and the hard exit at 7 covers that with a margin -
#which in turn has to stay under Ghidra's own window, or Ghidra would terminate us mid-teardown and its
#escalation would become the normal path instead of the last resort. See
#DragonAgentRunnerTask.seconds_to_wait_for_orderly_python_shutdown, which is 10.
seconds_for_each_shutdown_step=2
seconds_before_hard_exit_after_shutdown=7


def run_shutdown_step_with_timeout(description,function_to_run,timeout_in_seconds):
    #Runs one teardown step on its own thread and waits a bounded time for it.
    #
    #IMPORTANT, and learned the hard way: this bound is NOT absolute. Every step here is a call into frida's
    #C extension, and a blocking C call can hold the python GIL. While the GIL is held no python thread runs
    #at all - not this wait, not the hard exit watchdog - so the timeout simply never fires and the whole
    #interpreter is frozen. That is exactly what happened with script.unload(): the "Unloading the agent"
    #line was printed and nothing else ever ran.
    #So this helper genuinely bounds two things - a step that RAISES, and a step that blocks while having
    #RELEASED the GIL - and it cannot bound a step that blocks holding it. The only thing that can is a
    #signal from outside the process, which is why Ghidra keeps its own escalation ladder, and why the step
    #most likely to freeze (the unload) is now opt-in rather than the default.
    step_finished=threading.Event()
    def runner():
        try:
            function_to_run()
        except Exception as e:
            print("  "+description+" raised: "+repr(e))
        step_finished.set()
    threading.Thread(target=runner,daemon=True,name="dragonhook_shutdown_step").start()
    if not step_finished.wait(timeout_in_seconds):
        print("  "+description+" did not finish within "+str(timeout_in_seconds)
              +" seconds (it is probably blocked in a cross-thread ptrace operation), moving on")
        return False
    print("  "+description+" done")
    return True


def arm_the_hard_exit_watchdog():
    #Last line of defence. Even once the teardown is done and exit_event is set, the interpreter can be held
    #open by a thread we do not own - frida runs its own reactor - and Ghidra would then have to terminate
    #us. Exiting on our own terms is strictly better: our output has already been flushed, and os._exit()
    #skips the interpreter shutdown that may itself be what is stuck.
    def watchdog():
        #a fresh Event is never set, so wait() is just a sleep that needs no extra import
        threading.Event().wait(seconds_before_hard_exit_after_shutdown)
        print("Shutdown did not complete within "+str(seconds_before_hard_exit_after_shutdown)
              +" seconds, exiting the hard way so that Ghidra does not have to terminate us.")
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)
    threading.Thread(target=watchdog,daemon=True,name="dragonhook_hard_exit").start()


def should_the_agent_be_unloaded_before_detaching():
    #ON by default, and this default is not negotiable for safety.
    #
    #Skipping the unload was tried and it CRASHED THE TARGET with a segfault. The reason: while Stalker is
    #following a thread, that thread is executing out of Stalker's code cache - memory owned by the script,
    #not the original code. script.unload() runs the agent's dispose(), which calls Stalker.unfollow() and
    #gets each thread back onto its original instructions. Without that, detaching frees the code cache
    #while a thread's program counter is still inside it, and the target dies immediately.
    #
    #The unload CAN still block: dispose() also removes hardware watchpoints, which is a cross thread ptrace
    #operation, and a blocking call inside frida's C extension can hold the python GIL - at which point no
    #python thread runs and none of our own timeouts can fire. That is survivable now for two reasons:
    #dispose() does the Stalker teardown FIRST, so the thing that prevents the crash has already happened by
    #the time anything risky runs; and Ghidra's escalation ladder terminates us from outside the process,
    #which works regardless of the GIL.
    #
    #So: leave this on. If the shutdown does freeze, the agent variable remove_watchpoints_on_dispose can be
    #set to false to skip only the risky step, rather than skipping the unload and crashing the target.
    value_from_config=DragonHook_config.get("UNLOAD_AGENT_BEFORE_DETACHING",True)
    if isinstance(value_from_config,bool):
        return value_from_config
    return str(value_from_config).strip().lower() in ("true","1","yes")


def should_the_target_be_killed():
    #Three states: "auto" (the default), "true", "false".
    #
    #"auto" exists because the right answer depends on WHO OWNS the target, and SPAWN_PROCESS_FROM_FRIDA
    #already tells us:
    #  * we SPAWNED it - it exists only because we asked for it, so leaving it behind is a leak. For a single
    #    instance application it is worse than a leak: the orphan keeps holding its D-Bus name and the NEXT
    #    run cannot start. Observed with gimp - "the name org.gimp.GIMP.UI could not be acquired on the bus",
    #    then a segfault in the newly spawned instance, which was in fact the OLD one still running.
    #  * we ATTACHED to it - it is the user's own process and stopping it would destroy their session, so it
    #    is never touched.
    #"true" and "false" stay available as explicit overrides for anyone who wants one rule for both cases.
    value_from_config=DragonHook_config.get("KILL_TARGET_PROCESS_ON_CANCEL","auto")
    if isinstance(value_from_config,bool):
        return value_from_config
    text_from_config=str(value_from_config).strip().lower()
    if text_from_config in ("true","1","yes"):
        return True
    if text_from_config in ("false","0","no"):
        return False
    #"auto", and also the safe reading of anything unrecognised
    was_the_target_spawned_by_us=DragonHook_config.get("SPAWN_PROCESS_FROM_FRIDA",False)
    if not isinstance(was_the_target_spawned_by_us,bool):
        was_the_target_spawned_by_us=str(was_the_target_spawned_by_us).strip().lower() in ("true","1","yes")
    return was_the_target_spawned_by_us


def perform_orderly_shutdown(device,pid):
    #Order matters. Unloading the script first runs rpc.exports.dispose() inside the agent, which
    #unfollows every stalked thread and unsets every hardware watchpoint. Detaching first instead would
    #leave debug registers armed and Stalker's code cache in place, relying on frida's own cleanup.
    #MUST be called from the MAIN thread, the one that created the device, session and script.
    #
    #It used to be called straight from the stdin watcher thread, and that is a thread frida knows nothing
    #about. Calling into frida's C bindings from an arbitrary thread while its reactor is running is asking
    #for a deadlock, and the symptom fitted exactly: "Unloading the agent" was printed and nothing further
    #ever ran - not the next step, not the per step timeout, not the hard exit watchdog. With no options
    #selected the agent's dispose() is a no-op (nothing is stalked, no watchpoints are armed, nothing is
    #injected at the markers), so script.unload() had nothing of OURS to wait for. The thread it was called
    #from is the remaining difference.
    #The watcher now only records the request and wakes the main thread, which does this work.
    global the_teardown_has_run
    #Idempotent: the sentinel and a later stdin EOF can both arrive, and on_detached can fire in the middle.
    #Running script.unload() twice would raise, and re-running would reset the watchdog.
    if the_teardown_has_run:
        return
    the_teardown_has_run=True

    #armed FIRST, so that it covers the teardown itself and not just what comes after it
    arm_the_hard_exit_watchdog()

    if script is not None and should_the_agent_be_unloaded_before_detaching():
        #Deliberately one line. If it turns out to be the LAST line, that itself is the diagnosis: the
        #interpreter is frozen inside frida holding the GIL, no timeout here can fire, and Ghidra terminates
        #us from outside. dispose() does the Stalker teardown first, so the target is already safe by then.
        print("Unloading the agent (unfollows stalked threads, removes watchpoints)...")
        sys.stdout.flush()
        run_shutdown_step_with_timeout("agent unload",script.unload,seconds_for_each_shutdown_step)
    else:
        print("WARNING: skipping the agent unload. Stalked threads are left executing out of Stalker's code")
        print("  cache, and detaching frees it underneath them - this is known to SEGFAULT the target.")
        sys.stdout.flush()
    if session is not None:
        print("Detaching from the target...")
        run_shutdown_step_with_timeout("session detach",session.detach,seconds_for_each_shutdown_step)
    if should_the_target_be_killed():
        if device is not None and pid is not None:
            print("KILL_TARGET_PROCESS_ON_CANCEL is set, killing target pid "+str(pid))
            run_shutdown_step_with_timeout("target kill",lambda: device.kill(pid),seconds_for_each_shutdown_step)
    else:
        #State the ACTUAL reason. This used to always say "we attached to it", which was a lie whenever the
        #target had been spawned and the user had simply set the flag to false.
        was_the_target_spawned_by_us=DragonHook_config.get("SPAWN_PROCESS_FROM_FRIDA",False)
        if not isinstance(was_the_target_spawned_by_us,bool):
            was_the_target_spawned_by_us=str(was_the_target_spawned_by_us).strip().lower() in ("true","1","yes")
        if was_the_target_spawned_by_us:
            print("Leaving the target process running because KILL_TARGET_PROCESS_ON_CANCEL says so. Note that"
                  +" we spawned it, so it will outlive this run - a single instance application may then refuse"
                  +" to start next time.")
        else:
            print("Leaving the target process running: we attached to it rather than spawning it, so it is not"
                  +" ours to stop. Set KILL_TARGET_PROCESS_ON_CANCEL to true to stop it anyway.")
    sys.stdout.flush()
    if exit_event is not None:
        exit_event.set()


def watch_stdin_for_shutdown_request(device,pid):
    #A daemon thread, because a blocking readline() on stdin must not keep the process alive once the
    #target has gone away on its own.
    #
    #This thread does NOT do the teardown. All it does is record the request and wake the main thread, which
    #owns the frida handles. Doing the teardown here meant calling frida's C bindings from a thread frida
    #does not know about, and that is where the shutdown hung.
    def request_shutdown_from_the_main_thread(reason):
        global shutdown_has_been_requested
        print(reason)
        sys.stdout.flush()
        shutdown_has_been_requested=True
        if exit_event is not None:
            exit_event.set()

    def reader():
        #readline() rather than "for line in sys.stdin": iterating a file object is allowed to read ahead,
        #and this has to react to a single line the moment it arrives, because it is the user pressing
        #cancel. An empty string means Ghidra closed our stdin, which is also a reason to stop.
        try:
            while True:
                line=sys.stdin.readline()
                if line=="":
                    request_shutdown_from_the_main_thread("Ghidra closed our stdin, shutting the agent down.")
                    return
                if shutdown_sentinel_from_ghidra in line:
                    request_shutdown_from_the_main_thread("Shutdown requested by Ghidra.")
                    return
        except Exception as e:
            print("stdin watcher stopped: "+repr(e))
    threading.Thread(target=reader,daemon=True,name="dragonhook_stdin_watcher").start()


def parse_config():
    global DragonHook_config
    dragonhook_config_dir_path = Path(dragonhook_config_dir_pathstr)
    config_file_location= dragonhook_config_dir_path / "DragonHook_plugin_config.json"
    contents_of_config = config_file_location.read_text()
    DragonHook_config= json.loads(contents_of_config)


def read_frida_script():
    global frida_script_contents
    dragonhook_config_dir_path = Path(dragonhook_config_dir_pathstr)
    script_file_location= dragonhook_config_dir_path / "DragonHook_plugin_agent.js"
    frida_script_contents = script_file_location.read_text()


def start_hooking():
    global session
    global exit_event
    global script
    
    try:
        device=None
        if (DragonHook_config["DEVICE_ID_OF_DEVICE_TO_ATTACH_TO"]=="" or 
            DragonHook_config["DEVICE_ID_OF_DEVICE_TO_ATTACH_TO"].upper()=="LOCAL"):
            device=frida.get_local_device()
        elif (DragonHook_config["DEVICE_ID_OF_DEVICE_TO_ATTACH_TO"].upper()=="USB"):
            device=frida.get_usb_device()
        elif ("REMOTE-" in DragonHook_config["DEVICE_ID_OF_DEVICE_TO_ATTACH_TO"].upper()): #REMOTE-8.8.8.8-27042
            IP=DragonHook_config["DEVICE_ID_OF_DEVICE_TO_ATTACH_TO"].split("-")[1]
            PORT=DragonHook_config["DEVICE_ID_OF_DEVICE_TO_ATTACH_TO"].split("-")[2]
            device=frida.get_device_manager().add_remote_device(IP+":"+PORT)
        else:
            device=frida.get_device(DragonHook_config["DEVICE_ID_OF_DEVICE_TO_ATTACH_TO"])



        pid=None
        if (DragonHook_config["SPAWN_PROCESS_FROM_FRIDA"]):
            # Spawn and attach to the process
            pid = device.spawn(DragonHook_config["PATH_OF_PROCESS_TO_HOOK"])
            session = device.attach(pid)
        else:
            #only attach to process
            pid = int(DragonHook_config["PID_OF_PROCESS_TO_ATTACH"])
            session = device.attach(pid)
        
        

        # Create and load the script.
        # The workers must be running before load(), because the agent may issue a blocking
        # API call (e.g. the bulk function data fetch) from its top-level code during load().
        start_api_call_workers()
        script = session.create_script(frida_script_contents)
        script.on('message', on_message)
        script.load()

        if (DragonHook_config["SPAWN_PROCESS_FROM_FRIDA"]):
            # Resume the target process
            device.resume(pid)

        # Call the exported RPC function from Python
        #print("[*] Calling Frida function...")
        #result = script.exports.return_total_script_output_api_call()
        #print("[+] Frida responded:", result)

        # Keep python script alive until hooked process ends
        exit_event = threading.Event()
        session.on('detached',on_detached)

        #Ghidra asks us to shut down by writing a sentinel line to our stdin. Started only now, because
        #the teardown needs the device and pid that were resolved above.
        watch_stdin_for_shutdown_request(device,pid)

        exit_event.wait(); #blocks until the target detaches, or until Ghidra asks us to stop

        if shutdown_has_been_requested:
            #Deliberately on THIS thread, the one that created the device, session and script. See the note
            #on perform_orderly_shutdown().
            print("Agent stopped at Ghidra's request, tearing down on the main thread.")
            sys.stdout.flush()
            perform_orderly_shutdown(device,pid)
        else:
            #The watchdog is armed here too, not only on the cancel path. If frida's own cleanup wedges while
            #the interpreter is shutting down there is no cancel in flight to trigger Ghidra's ladder, so
            #without this the process would just sit there with nothing to save it.
            arm_the_hard_exit_watchdog()
            print("Target process has exited.")
        #input("[*] Press Enter to exit...") #effectively blocks for ever

    except Exception as e:
        print("[!] Exception:", e)
    finally:
        stop_api_call_workers()


if __name__ == "__main__":
    print("Inside python frida invoker")
    if (len(sys.argv)<2):
        print("Run the python invoker script as instructed by Ghidra in the Ghidra Console window.")
        sys.exit(-1)
    dragonhook_config_dir_pathstr=sys.argv[1]
    install_frida_dependencies()
    parse_config()
    read_frida_script()
    print(DragonHook_config)
    start_hooking()

