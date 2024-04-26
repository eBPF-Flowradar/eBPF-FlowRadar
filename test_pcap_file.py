from scapy.all import *
from argparse import ArgumentParser

def main():
    parser = ArgumentParser()
    parser.add_argument('--pcap', type= str, help='File Path of the PCAP File to be Parsed')
    parser.add_argument('--iface', type=str, help='Interface to which the packets are to be sent')

    