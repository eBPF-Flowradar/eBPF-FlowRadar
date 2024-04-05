from scapy.all import PcapReader,send

def send_packets_from_pcap(pcap_file, dst_ip):
    packets = PcapReader(pcap_file)  # Read packets from pcap file
    for packet in packets:
        if "IP" in packet:
            # Update the destination IP address of each packet
            packet["IP"].dst = dst_ip
            # Send the modified packet
            send(packet)

# Example usage
pcap_file = '110k_24k_caida.pcap'
destination_ip = '192.168.122.246'
send_packets_from_pcap(pcap_file, destination_ip)

