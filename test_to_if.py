from scapy.all import PcapReader,sendp,Ether, PcapWriter

# Open the pcap file for reading
pcap_file = "univ_pt1/univ1_pt1.pcap"
packets = PcapReader(pcap_file)

num_packets=0

IP="IP"
TCP="TCP"
UDP="UDP"

# Define the interface to send the packets to
interface = "wlp6s0"  # Change this to your desired interface

# Send each packet in the pcap file to the specified interface

#custom ethernet header with type set to IP
ethernet_header=Ether(dst="ff:ff:ff:ff:ff:ff", src="f0:a6:54:b0:3b:1d", type=0x0800)

print("Starting to send packets")
o_pcap_file = PcapWriter('sample.pcap', append=True)

for packet in packets:
    if IP in packet and (TCP in packet or UDP in packet):
        packet=ethernet_header/packet
        
        o_pcap_file.write(packet)

        print(packet.summary())
        sendp(packet, iface=interface)
        num_packets+=1

print("Write Complete")
