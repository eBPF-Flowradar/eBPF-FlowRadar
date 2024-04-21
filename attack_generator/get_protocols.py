from scapy.all import *
import time

packets = PcapReader('caida_trace/110k_24k_caida.pcap')
output_file = PcapWriter('attack_generator/other.pcap')

IPx = 'IP'
#TCPx = 'TCP'
#UDPx = 'UDP'
#ESPx = 'ESP'
#GREx = 'GRE'
#ICMPx = 'ICMP'
#IPv4x = 'IPv4'
#IPv6x = 'IPv6'

output = []
for pkt in packets:
    if IPx in pkt:
        output.append(pkt)

random.shuffle(output)
timed_output = []

timestamp = time.time()

for pkt in output:
    pkt.time = timestamp;
    timestamp += random.randint(1,40)/1000000
    timed_output.append(pkt)

output_file.write(timed_output)
