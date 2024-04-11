from scapy.all import PcapReader,sendp,Ether

# Open the pcap file for reading
pcap_file = "./110k_24k_caida.pcap"
packets = PcapReader(pcap_file)

# Define the interface to send the packets to
interface = "veth1"  # Change this to your desired interface

# Send each packet in the pcap file to the specified interface

#custom ethernet header with type set to IP
ethernet_header=Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800)

print("Starting to send packets")
for packet in packets:
    if "IP" in packet:
        packet=ethernet_header/packet
        sendp(packet, iface=interface)
