import argparse
from scapy.all import *
import socket
import os
from random import shuffle
import requests

TCP = 'TCP'
UDP = 'UDP'
IP = 'IP'

def parse_arguments():

    parser = argparse.ArgumentParser()

    parser.add_argument('--interface', type=str, default='wlp6s0', help='Interface to which the network packets are to be sent')
    parser.add_argument('--packetcount', type=int, default=1400, help= 'Number of packets to be sent')

    args = parser.parse_args()

    return args

# Define the packet generator function


def pkt_tracer(file_path: str):
    packets = PcapReader(filename=file_path)    
    return packets


# get network interface names

def interface_in_sys(iface: str):
    if iface in os.listdir('/sys/class/net/'):
        return True
    else:
        return False


def get_current_ip_addr():
    # return the ip address of the host machine
    return socket.gethostbyname(socket.gethostname())


def process_packets(packet_generator, args):
    iface = args.interface
    packet_list: list = []

    packet_count: int = args.packetcount

    for pkt in packet_generator:
        if IP in pkt and TCP in pkt:
            packet_list.append(pkt)
        elif IP in pkt and UDP in pkt: 
            packet_list.append(pkt)

    shuffle(packet_list)

    for packet in packet_list[:packet_count]:
        packet[IP].dst = get_current_ip_addr()
        print(f"Sending packet: {packet.summary}")
        sendp(packet, iface=iface)        
    


# define packet generator
if __name__ == '__main__':
    pkt_gen = pkt_tracer('110k_24k_caida.pcap')
    process_packets(packet_generator=pkt_gen, args=parse_arguments())



