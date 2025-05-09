from ipaddress import ip_address
import struct
import pickle
import sys

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
        flow["protocol"]=protocol

    return flow



SD_FILE="sd_logs.csv"
PKL_FILE="flows.pkl"
DECODABLE_CSV_FILE="decodable.csv"

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
    with open(DECODABLE_CSV_FILE,"a") as file:
        file.write(f"0,100,{sys.argv[1]}\n")
else:
    sd_actual=sd_flows-actual_flows
    actual_sd=actual_flows-sd_flows

    print(f"Number of flows in Single Decode but not in Actual flows: {len(sd_actual)} (zero expected)")
    for flow in sd_actual: 
        print(f"{flow} {decode(flow)}")

    undec_num=len(actual_sd)
    print(f"\nNumber of undecodable flows: {undec_num}")
    for flow in actual_sd: 
        print(f"{flow} {decode(flow)}")

    dec_num=sd_flow_count-len(sd_actual)
    print(f"\nNumber of decodable flows: {dec_num}")

    undec_percent=(undec_num/actual_flow_count)*100
    dec_percent=(dec_num/actual_flow_count)*100

    print(f"\nDecodable flows :{dec_percent}%")
    print(f"Undecodable flows :{undec_percent}%")

    with open(DECODABLE_CSV_FILE,"a") as file:
        file.write(f"{undec_percent},{dec_percent},{sys.argv[1]}\n")
