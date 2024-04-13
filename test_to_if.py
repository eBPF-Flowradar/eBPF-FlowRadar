from scapy.all import PcapReader,sendp,Ether

# Open the pcap file for reading
pcap_file = "./110k_24k_caida.pcap"
packets = PcapReader(pcap_file)

#num_packets=0

IP="IP"
TCP="TCP"
UDP="UDP"

# Define the interface to send the packets to
interface = "veth1"  # Change this to your desired interface

# Send each packet in the pcap file to the specified interface

#custom ethernet header with type set to IP
ethernet_header=Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800)

print("Starting to send packets")
for packet in packets:

#    if num_packets==10:
#        break

    if IP in packet and (TCP in packet or UDP in packet):
        packet=ethernet_header/packet
        #print(packet.summary())
        sendp(packet, iface=interface)
#