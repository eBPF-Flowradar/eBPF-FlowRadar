from scapy.all import PcapReader, wrpcap
from scapy.layers.l2 import Ether

def add_ethernet_header(packet):
    """
    This function takes a packet without an Ethernet header and prepends a new Ethernet header.
    Modify `src` and `dst` MAC addresses as per your requirements.
    """
    new_packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / packet
    new_packet.time = packet.time
    return new_packet

def process_pcap(input_file, output_file):
    """
    Reads a pcap file, adds Ethernet headers to each packet, and writes them to a new pcap file.
    """
    # Read packets from the original pcap file
    packets = PcapReader(input_file)

    # Create a list to hold modified packets
    modified_packets = []

    for packet in packets:
        # Check if packet already has an Ethernet layer
        if not packet.haslayer(Ether):
            # Add Ethernet header
            packet_with_eth = add_ethernet_header(packet)
            modified_packets.append(packet_with_eth)
        else:
            # If packet already has Ethernet layer, just append as is
            print("Packet with ethernet layer found")
            modified_packets.append(packet)

    # Write the modified packets to a new pcap file
    wrpcap(output_file, modified_packets)


# Specify the input and output PCAP file names
input_pcap = "110k_24k_caida.pcap"
output_pcap = "output_with_eth.pcap"

# Process the PCAP file
process_pcap(input_pcap, output_pcap)
print("Done")

