from scapy.all import rdpcap,sendp

# Open the pcap file for reading
pcap_file = "./110k_24k_caida.pcap"
packets = rdpcap(pcap_file)

# Define the interface to send the packets to
interface = "s1-eth1"  # Change this to your desired interface

# Send each packet in the pcap file to the specified interface
print("Starting to send packets")
for packet in packets:
    sendp(packet, iface=interface)

