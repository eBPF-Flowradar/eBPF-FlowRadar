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


CD_FLOWS_KEY='Keys only in cd_flows'
SNF_FLOWS_KEY='Keys only in sniff_flows'
DIFF_VALUES='Different values'




def dict_differences(dict1, dict2):
    # Keys in dict1 but not in dict2
    keys_only_in_dict1 = dict1.keys() - dict2.keys()

    # Keys in dict2 but not in dict1
    keys_only_in_dict2 = dict2.keys() - dict1.keys()

    # Keys in both with different values
    common_keys = dict1.keys() & dict2.keys()
    different_values = {key: (dict1[key], dict2[key]) for key in common_keys if dict1[key] != dict2[key]}

    # Summary of differences
    differences = {
        CD_FLOWS_KEY: keys_only_in_dict1,
        SNF_FLOWS_KEY: keys_only_in_dict2,
        DIFF_VALUES: different_values
    }

    return differences




CD_FILE="cd_logs.csv"
SNIFF_FILE="sniff.csv"

cd_flows={}
sniff_flows={}

cd_pkt_count=0
sniff_pkt_count=0

with open(CD_FILE) as file:
    for line in file:
        _,flow_id,pkt_count=line.strip().split(',')
        cd_flows[flow_id]=cd_flows.get(flow_id,0)+int(pkt_count)  
        cd_pkt_count+=int(pkt_count)

with open(SNIFF_FILE) as file:
    for line in file:
        _,flow_id=line.strip().split(',')
        sniff_flows[flow_id]=sniff_flows.get(flow_id,0)+1
        sniff_pkt_count+=1

print(f"Counter Decode Pkt Count: {cd_pkt_count}")
print(f"Sniff Pkt Count: {sniff_pkt_count}\n")

if cd_flows==sniff_flows:
    print("Equal")
else:
    differences=dict_differences(cd_flows,sniff_flows)

    print(CD_FLOWS_KEY)
    for flow in differences[CD_FLOWS_KEY]: 
        print(f"{flow} {decode(flow)}")
    print()

    print(SNF_FLOWS_KEY)
    for flow in differences[SNF_FLOWS_KEY]: 
        print(f"{flow} {decode(flow)}")
    print()

    print(DIFF_VALUES)
    for flow in differences[DIFF_VALUES]:
        print(f"{flow} {decode(flow)}")
        print(f"cd_flows:{differences[DIFF_VALUES][flow][0]}")
        print(f"sniff_flows:{differences[DIFF_VALUES][flow][1]}")
        print()
