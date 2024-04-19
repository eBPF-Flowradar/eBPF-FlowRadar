from scapy.all import PcapReader
from ipaddress import ip_address
import struct
import pickle

"""
Currently only IPv4 packets are tested
"""


IP="IP"
TCP="TCP"
UDP="UDP"
# IPPROTO_TCP=6
# IPPROTO_UDP=17
PCAP_FILE="./110k_24k_caida.pcap"
PKL_FILE="flows.pkl"

#format_string='<IIHHB'
format_string='<BHHII'

def flow_id_from_packet(packet):
    
    values=[]

    if IP in packet:
        values.append(int(ip_address(packet[IP].src)))
        values.append(int(ip_address(packet[IP].dst)))

        if TCP in packet:
            values.append(packet[TCP].sport)
            values.append(packet[TCP].dport)
            # values.append(IPPROTO_TCP)
        elif UDP in packet:
            values.append(packet[UDP].sport)
            values.append(packet[UDP].dport)
            # values.append(IPPROTO_UDP)
        else:
            values.append(0)
            values.append(0)

        #append the transport layer protocol
        values.append(packet[IP].proto)
        values.reverse()
        raw_bytes=struct.pack(format_string,*values)
        hex_value=raw_bytes.hex().lstrip('0')  #to match with log from ebpf program

        return hex_value
    
    return None

flows=set()

print("Generating flows")
for packet in PcapReader(PCAP_FILE):
    flow_id=flow_id_from_packet(packet)
    if flow_id:
        flows.add(flow_id)


print("Writing  to file")
with open(PKL_FILE, "wb") as file:
    pickle.dump(flows, file)
print("Done")
