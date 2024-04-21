from scapy.all import *

packets = PcapReader('caida_trace/110k_24k_caida.pcap')
output_file = PcapWriter('attack_generator/other.pcap')

IPx = 'IP'
TCPx = 'TCP'
UDPx = 'UDP'
#ESPx = 'ESP'
#GREx = 'GRE'
#ICMPx = 'ICMP'
#IPv4x = 'IPv4'
#IPv6x = 'IPv6'

output = []
for pkt in packets:
    eth_header = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    new_pkt = None
    if IPx in pkt:
        if TCPx in pkt or UDPx in pkt:
            output.append(pkt)
    
output_file.write(output)