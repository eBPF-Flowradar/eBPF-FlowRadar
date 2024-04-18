from scapy.all import sniff
from ipaddress import ip_address
import struct
from time import time
import os



IP="IP"
TCP="TCP"
UDP="UDP"
IPPROTO_TCP=6
IPPROTO_UDP=17
LOG_FILE="sniff.csv"

#format_string='<IIHHB'
format_string='<BHHII'

def packet_callback(packet):
    
    values=[]

    if IP in packet:
        values.append(int(ip_address(packet[IP].src)))
        values.append(int(ip_address(packet[IP].dst)))

        if TCP in packet:
            values.append(packet[TCP].sport)
            values.append(packet[TCP].dport)
            values.append(IPPROTO_TCP)
        elif UDP in packet:
            values.append(packet[UDP].sport)
            values.append(packet[UDP].dport)
            values.append(IPPROTO_UDP)
        else:
            return

        values.reverse()
        raw_bytes=struct.pack(format_string,*values)
        hex_value=raw_bytes.hex().lstrip('0')  #to match with log from ebpf program

        print(hex_value)

        #write to file
        with open(LOG_FILE,"a") as file:
            file.write(f"{int(time())},{hex_value}\n")

#        print(packet.summary())

#delete the previous log file if it exists
try:
    os.remove(LOG_FILE)
except OSError:
    pass


# Replace 'eth0' with the interface you want to listen on
sniff(iface='veth2', prn=packet_callback, store=0)

