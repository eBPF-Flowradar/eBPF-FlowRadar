from ipaddress import ip_address
import struct
import pickle

TCP="TCP"
UDP="UDP"
IPPROTO_TCP=6
IPPROTO_UDP=17

format_string='<BHHII'



def decode(flow_string:str):

    flow_bytes=bytes.fromhex(flow_string.rjust(26,"0"))
    flow={}

    protocol,dest_port,src_port,dest_ip,src_ip=struct.unpack(format_string,flow_bytes)

    flow["src_ip"]=str(ip_address(src_ip))
    flow["dest_ip"]=str(ip_address(dest_ip))


    flow["src_port"]=src_port
    flow["dest_port"]=dest_port

    if protocol==IPPROTO_TCP:
        flow["protocol"]=TCP
    elif protocol==IPPROTO_UDP:
        flow["protocol"]=UDP
    else:
        flow["protocol"]="unknown"

    return flow



SD_FILE="sd_logs.csv"
PKL_FILE="flows.pkl"

sd_flows=set()


with open(SD_FILE) as file:
    for flow in file:
        sd_flows.add(flow.strip())

with open(PKL_FILE, "rb") as file:
    actual_flows = pickle.load(file)


sd_flow_count=len(sd_flows)
actual_flow_count=len(actual_flows)

print(f"Single Decode Flow Count: {sd_flow_count}")
print(f"Actual Flow Count: {actual_flow_count}\n")

if sd_flows==actual_flows:
    print("Equal, all flows are decoded successfully")
else:
    sd_actual=sd_flows-actual_flows
    actual_sd=actual_flows-sd_flows

    print(f"Number of flows in Single Decode but not in Actual flows: {len(sd_actual)} (zero expected)")
    for flow in sd_actual: 
        print(f"{flow} {decode(flow)}")

    print(f"\nNumber of undecodable flows: {len(actual_sd)}")
    for flow in actual_sd: 
        print(f"{flow} {decode(flow)}")

