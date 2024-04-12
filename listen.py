from scapy.all import sniff
from ipaddress import ip_address
import struct



IP="IP"
TCP="TCP"
UDP="UDP"
IPPROTO_TCP=6
IPPROTO_UDP=17

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

        print(raw_bytes.hex())
#        print(packet.summary())

# Replace 'eth0' with the interface you want to listen on
sniff(iface='veth2', prn=packet_callback, store=0)

