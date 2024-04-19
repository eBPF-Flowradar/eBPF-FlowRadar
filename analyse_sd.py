from ipaddress import ip_address
import struct

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
SNIFF_FILE="sniff.csv"

sd_flows=set()
sniff_flows=set()


with open(SD_FILE) as file:
    for flow in file:
        sd_flows.add(flow.strip())

with open(SNIFF_FILE) as file:
    for line in file:
        _,flow_id=line.strip().split(',')
        sniff_flows.add(flow_id)

sd_flow_count=len(sd_flows)
sniff_flow_count=len(sniff_flows)

print(f"Single Decode Flow Count: {sd_flow_count}")
print(f"Sniff Flow Count: {sniff_flow_count}\n")

if sd_flows==sniff_flows:
    print("Equal, all flows are decoded successfully")
else:
    sd_sniff=sd_flows-sniff_flows
    sniff_sd=sniff_flows-sd_flows

    print(f"Number of flows in Single Decode but not in Sniffed flows: {len(sd_sniff)} (zero expected)")
    for flow in sd_sniff: 
        print(f"{flow} {decode(flow)}")

    print(f"Number of undecodable flows: {len(sniff_sd)}")
    for flow in sniff_sd: 
        print(f"{flow} {decode(flow)}")
    
    print(f"\nNumber of decodable flows: {sd_flow_count-len(sd_sniff)}")


