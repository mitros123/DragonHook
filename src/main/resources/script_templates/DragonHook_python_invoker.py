import frida
import sys
import os
from pathlib import Path
import json
import threading
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


def return_function_data_given_address_offset(paramlist):
    value_of_param=paramlist[0]
    response=requests.get("http://"+DragonHook_config["GHIDRA_HTTP_SERVER_INTERFACE_IP"]+":"+DragonHook_config["GHIDRA_HTTP_SERVER_PORT"]+"/FUN_DATA_GIVEN_ADDR_OFFSET",params={"address_offset":value_of_param})
    return response.text

def return_codeunit_data_given_address_offset(paramlist):
    value_of_param=paramlist[0]
    response=requests.get("http://"+DragonHook_config["GHIDRA_HTTP_SERVER_INTERFACE_IP"]+":"+DragonHook_config["GHIDRA_HTTP_SERVER_PORT"]+"/CODEUNIT_DATA_GIVEN_ADDR_OFFSET",params={"address_offset":value_of_param})
    return response.text


def return_all_function_data_by_ranges(paramlist):
    response=requests.get("http://"+DragonHook_config["GHIDRA_HTTP_SERVER_INTERFACE_IP"]+":"+DragonHook_config["GHIDRA_HTTP_SERVER_PORT"]+"/ALL_FUN_DATA_SORTED_BY_RANGESTART",params={},timeout=25)
    print("text length:"+str(len(response.text)))
    return response.text

def update_ghidradb_with_comment_at_addr(paramlist):
    address_offset=paramlist[0]
    comment_to_set=paramlist[1]
    response=requests.post("http://"+DragonHook_config["GHIDRA_HTTP_SERVER_INTERFACE_IP"]+":"+DragonHook_config["GHIDRA_HTTP_SERVER_PORT"]+"/UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR",data={"address_offset":address_offset,"comment":comment_to_set})
    return response.text

def update_ghidradb_with_xref(paramlist):
    address_offset_from=paramlist[0]
    address_offset_to=paramlist[1]
    type_of_xref=paramlist[2]
    response=requests.get("http://"+DragonHook_config["GHIDRA_HTTP_SERVER_INTERFACE_IP"]+":"+DragonHook_config["GHIDRA_HTTP_SERVER_PORT"]+"/UPDATE_GHIDRADB_WITH_XREF",params={"address_offset_from":address_offset_from,"address_offset_to":address_offset_to,"RefType":type_of_xref})
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
    response=requests.post("http://"+DragonHook_config["GHIDRA_HTTP_SERVER_INTERFACE_IP"]+":"+DragonHook_config["GHIDRA_HTTP_SERVER_PORT"]+"/CHANGE_BYTES_INSIDE_GHIDRADB",data={"address_offset":address_offset,"content_as_b64":b64_encoded})
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
                    print("Invoking DragonHook API call "+fun_name + " with paramlist: "+str(params))
                    #invoke the function
                    returned_data_from_fun=defined_dragonhook_api_calls[fun_name]["handler"](params)
                    returned_data_as_str=str(returned_data_from_fun)
                    if (len(returned_data_as_str)>2000):
                        print("Sending data back to JS: "+returned_data_as_str[:2000]+".....")
                    else:
                        print("Sending data back to JS: "+returned_data_as_str)
                    if (fun_name=="UPDATE_GHIDRADB_WITH_COMMENT_AT_ADDR" or fun_name=="CHANGE_BYTES_INSIDE_GHIDRADB" ):
                        #in this case the entire comment will not be put inside the type
                        script.post({"type":"api-response-"+fun_name+"-['"+str(params[0])+"']","payload":returned_data_as_str})
                    else:
                        script.post({"type":"api-response-"+fun_name+"-"+str(params),"payload":returned_data_as_str})
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
        
        

        # Create and load the script
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

