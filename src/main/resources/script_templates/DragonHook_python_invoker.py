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
max_queued_api_calls=100000            #backpressure: enqueueing blocks past this point
query_api_calls={"FUN_DATA_GIVEN_ADDR_OFFSET",
                 "ALL_FUN_DATA_SORTED_BY_RANGESTART",
                 "CODEUNIT_DATA_GIVEN_ADDR_OFFSET"}
query_queue=queue.Queue(maxsize=max_queued_api_calls)
update_queues=[]
worker_threads=[]
thread_local_storage=threading.local()


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
    response=get_session().get(ghidra_server_url("FUN_DATA_GIVEN_ADDR_OFFSET"),params={"address_offset":value_of_param})
    return response.text

def return_codeunit_data_given_address_offset(paramlist):
    value_of_param=paramlist[0]
    response=get_session().get(ghidra_server_url("CODEUNIT_DATA_GIVEN_ADDR_OFFSET"),params={"address_offset":value_of_param})
    return response.text


def return_all_function_data_by_ranges(paramlist):
    #This one can legitimately take a long time on a big program: Ghidra has to walk every function
    #and every function body range. A short timeout here used to abort the request, the exception
    #escaped on_message(), no reply was ever posted, and the agent stayed blocked in recv().wait()
    #for the rest of the session. Keep it generous, and see the try/except in run_api_call().
    timeout_for_bulk_fetch=DragonHook_config.get("TIMEOUT_FOR_BULK_FUNCTION_DATA_FETCH",600)
    response=get_session().get(ghidra_server_url("ALL_FUN_DATA_SORTED_BY_RANGESTART"),params={},timeout=timeout_for_bulk_fetch)
    print("text length:"+str(len(response.text)))
    return response.text

def update_ghidradb_with_comment_at_addr(paramlist):
    address_offset=paramlist[0]
    comment_to_set=paramlist[1]
    response=get_session().post(ghidra_server_url("UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR"),data={"address_offset":address_offset,"comment":comment_to_set})
    return response.text

def update_ghidradb_with_xref(paramlist):
    address_offset_from=paramlist[0]
    address_offset_to=paramlist[1]
    type_of_xref=paramlist[2]
    response=get_session().get(ghidra_server_url("UPDATE_GHIDRADB_WITH_XREF"),params={"address_offset_from":address_offset_from,"address_offset_to":address_offset_to,"RefType":type_of_xref})
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
    response=get_session().post(ghidra_server_url("CHANGE_BYTES_INSIDE_GHIDRADB"),data={"address_offset":address_offset,"content_as_b64":b64_encoded})
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
    #updates: keep same-address updates on the same worker so they are applied in order
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
        
        exit_event.wait(); #effectively blocks for ever, until target is detached
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

