import mmh3 #Murmur3 Hash function.
import bitarray
import random
from scapy.layers.l2 import Ether
from scapy.all import *
from argparse import ArgumentParser

import time

IPx = "IP"
TCPx = "TCP"
UDPx = "UDP"
ESPx = 'ESP'
GREx = 'GRE'
ICMPx = 'ICMP'
IPv4x = 'IPv4'
RSVPx = 'RSVP'
     
def count_unique_flows(filename):
    packets = PcapReader(filename=filename)
    flow_set = set()
    source_ips = set()
    dest_ips = set()
    for pkt in packets:
        if IPx in pkt:

            source_ips.add(pkt[IPx].src)
            dest_ips.add(pkt[IPx].dst)

            if TCPx in pkt:
                flow_set.add((pkt[IPx].src, pkt[IPx].dst, pkt[TCPx].sport, pkt[TCPx].dport, 6))
            elif UDPx in pkt:
                flow_set.add((pkt[IPx].src, pkt[IPx].dst, pkt[UDPx].sport, pkt[UDPx].dport, 17))
            elif RSVPx in pkt:
                flow_set.add((pkt[IPx].src, pkt[IPx].dst, 'RSVP'))
            elif GREx in pkt:
                flow_set.add((pkt[IPx].src, pkt[IPx].dst, 'GRE'))
            elif ICMPx in pkt:
                flow_set.add((pkt[IPx].src, pkt[IPx].dst, 'ICMP'))
            elif ESPx in pkt:
                flow_set.add((pkt[IPx].src, pkt[IPx].dst, 'ESP'))
            else:
                flow_set.add((pkt[IPx].src, pkt[IPx].dst, 'Prot'))
    print(f"Number of Unique_packets: {len(flow_set)}")
    return len(flow_set), list(source_ips), list(dest_ips)

try:
	import bitarray
except ImportError:
	raise ImportError('pybloom requires bitarray >= 0.3.4')


FLOW_FILTER_BITS_PER_SLICE = 32486
FLOW_FILTER_SIZE = 227402
NUM_HASH_FUNCS = 7

def make_hashfuncs(num_slices, num_bits):

        seeds = [i for i in range(1,num_slices+1)]

        def _make_hashfuncs(key):
            if isinstance(key, str): #For Python 3
                key = key.encode('utf-8')
            else:
                key = str(key)
            rval = []
            rval.extend(int(abs(mmh3.hash(key, seed))%num_bits) for seed in seeds)
            
            del rval[num_slices:]
            return rval
        return _make_hashfuncs
    

class flow_filter:
    
    def __init__(self, flow_filter_size: int, bits_per_slice: int, num_slices: int):
        self.ff = bitarray.bitarray(flow_filter_size,endian='little')
        self.ff_size = flow_filter_size
        self.num_slices = num_slices
        self.bits_per_slice = bits_per_slice
    
    def all_bit_unset(self, key):
        make_hashes  = make_hashfuncs(num_slices=self.num_slices, num_bits=self.bits_per_slice)
        hashes = make_hashes(key)
        print(hashes)
        hashes = [int(hashes[i] + self.bits_per_slice * i) for i in range(self.num_slices)]
        print(hashes)
        for h in hashes:
            if self.ff[h] is True:
                return False
    
        return True
    
    
    def all_bit_set(self, key):
        make_hashes  = make_hashfuncs(num_slices=self.num_slices, num_bits=self.bits_per_slice)
        hashes = make_hashes(key)
        print(hashes)
        hashes = [int(hashes[i] + self.bits_per_slice * i) for i in range(self.num_slices)]
        print(hashes)
        for h in hashes:
            if self.ff[h] is False:
                return False
        return True

    def insert_into_flow_filter(self,key):
        make_hashes  = make_hashfuncs(num_slices=self.num_slices, num_bits=self.bits_per_slice)
        hashes = make_hashes(key)
        hashes = [int(hashes[i] + self.bits_per_slice * i) for i in range(self.num_slices)]
        for h in hashes:
            self.ff[h] = True


def convert_to_hex(data):
	"""
		INPUT: Pandas.DataFrame OR list() as input.
		OUTPUT: Disctionary of {"KEY":["SRC_IP_IN_HEX", "DST_IP_IN_HEX", "SRC_PORT_IN_HEX", "DST_PORT_IN_HEX", "PROTO_IN_HEX"]}

		If IP addresses are in IPv6. It gives "-1" as OUTPUT.
		Update:15/10/2022: Now IPv6 is supporting.
	"""

	flow_details = {} # Flow ID to five tuples.
	# print("TYPE: ", type(data), data)

	if(isinstance(data, list)):
			if len(data) == 5:
				if data[0].count('.') == 3 and data[1].count('.') == 3:
					src_ip_str = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, data[0].split('.')))
					dst_ip_str = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, data[1].split('.')))
				else:
					return -1
					#Put a check at the receiving side.
				src_port_str = format(int(data[2]),'x')
				dst_port_str = format(int(data[3]),'x')
				proto_str = format(int(data[4]),'x')
				items = str(src_ip_str)+str(dst_ip_str)+str(src_port_str)+str(dst_port_str)+str(proto_str)
				flow_details[items] = [src_ip_str,dst_ip_str,src_port_str,dst_port_str,proto_str]
				# flow_details[items] = [str(row[0]),str(row[1]),str(row[2]),str(row[3]),str(row[4])]
	else:
		sip = data['src_ip'].to_list()
		dip = data['dst_ip'].to_list()
		sport = data['src_port'].to_list()
		dport = data['dst_port'].to_list()
		proto = data['protocol'].to_list()

		for row in zip(sip, dip, sport, dport, proto):
			# Only for IPv4
			if row[0].count('.') == 3 and row[1].count('.') == 3:
				src_ip_str = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, row[0].split('.')))
				dst_ip_str = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, row[1].split('.')))
			elif ':' in row[0] or ':' in row[0]:
				# print("IPv6 not supported as of now.")
				src_ip_str = src_ip_str.replace(":","")
				dst_ip_str = dst_ip_str.replace(":","")
				continue

			src_port_str = format(int(row[2]),'x')
			dst_port_str = format(int(row[3]),'x')
			proto_str = format(int(row[4]),'x')
			items = str(src_ip_str)+str(dst_ip_str)+str(src_port_str)+str(dst_port_str)+str(proto_str)
			# flow_details[items] = [str(row[0]),str(row[1]),str(row[2]),str(row[3]),str(row[4])]
			flow_details[items] = [src_ip_str,dst_ip_str,src_port_str,dst_port_str,proto_str]

	return flow_details

def get_flow_counts(file_name):
    packets = PcapReader(filename=file_name)
    flow_freq_map = {}
    for pkt in packets:
        if IP in pkt:
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            proto = None
            sport = None
            dport = None
            if TCPx in pkt:
                sport = int(pkt[TCPx].sport)
                dport = int(pkt[TCPx].dport)
                proto = 6
            elif UDPx in pkt:
                sport = int(pkt[UDPx].sport)
                dport = int(pkt[UDPx].dport)
                proto = 17
            else:
                sport = 0
                dport = 0
                proto = 0
            flow_key = list(convert_to_hex([src_ip, dst_ip, sport, dport, proto]).keys())[0]
            if flow_key not in flow_freq_map.keys():
                flow_freq_map[flow_key] = 1
            else:
                flow_freq_map[flow_key] += 1
    return list(flow_freq_map.values())
    


def generate_malicious_flows(input_file: str, mal_flow_count: int, flow_filter:flow_filter, source_ips: list, dest_ips: list):
    protocols = [6, 17]
    count = 0;
    with PcapReader(filename=input_file) as packets:
        for pkt in packets:
            print(f"Packet {count}")
            if IPx in pkt:
                if pkt[IPx].src not in source_ips:
                    source_ips.append(pkt[IPx].src)
                if pkt[IPx].dst not in dest_ips:
                    dest_ips.append(pkt[IPx].dst)
            print(pkt.summary())
            count = count + 1
    item_pool = []
    polluting_items = []

    while(len(polluting_items) < mal_flow_count):
        ran_ip_src = random.choice(source_ips)
        ran_ip_dst = random.choice(dest_ips)

        ran_port_src = random.randint(22, 65535)
        ran_port_dst = random.randint(22, 65535)

        proto = random.choice(protocols)

        flow = [ran_ip_src, ran_ip_dst, ran_port_src, ran_port_dst, proto]
        print(f"Generated Flow {flow}")
        key = list(convert_to_hex(flow).keys())[0]

        if flow_filter.all_bit_set(key) is True:
            if key not in polluting_items:
                item_pool.append(flow)
                print(flow)
                polluting_items.append(key)
                print(key)
                flow_filter.insert_into_flow_filter(key)
    return item_pool

def generate_packet_map(input_flows: list, flow_counts: list):
    flow_counts.sort(reverse=True)
    flow_freq_map = dict()
    idx = int(len(flow_counts)/3)
    i = 0
    generated_flow_counts = []
    while i < len(flow_counts):
        generated_flow_counts.append(random.choice(flow_counts[0:idx]))
        generated_flow_counts.append(random.choice(flow_counts[idx:2*idx]))
        generated_flow_counts.append(random.choice(flow_counts[2*idx:]))
        i = i + 3
    pkt = 0
    packet_len = len(flow_counts)

    for flow in input_flows:
        flow_key = list(convert_to_hex(flow).keys())[0]
        flow_freq_map[flow_key] = generated_flow_counts[pkt]
        pkt = (pkt+1)% packet_len

    return flow_freq_map


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('--pcap', type=str, help="File Name for Pcap file generation", default='')
    parser.add_argument('--percent_malflows', type=float, help="Percentage of Malicious Flows to be Generated",default=0)
    parser.add_argument('--output_file', type=str, help="Output file where packets are stored", default='qoa.pcap')
    args = parser.parse_args()
    return args

if __name__ == '__main__':

    ff = flow_filter(FLOW_FILTER_SIZE, FLOW_FILTER_BITS_PER_SLICE, NUM_HASH_FUNCS)
    args = parse_args()
    
    # file_meta_data = json.load(open('attack_generator/pcap_metadata.json'))

    file_name = args.pcap
    mal_flow_pct = args.percent_malflows
    unique_flows, source_ips, dest_ips = count_unique_flows(filename=file_name)
    mal_flow_count = args.percent_malflows/100 * unique_flows

    output_flows = generate_malicious_flows(file_name, mal_flow_count, ff, source_ips=source_ips, dest_ips=dest_ips)
    output_file = PcapWriter(f'attack_generator/qoa/{args.output_file}', append=True)
    packets = PcapReader(filename=file_name)
    output = []
    timestamp = time.time()
    
    flow_counts = get_flow_counts('caida_trace/110k_24k_caida.pcap')
    packet_freq_map = generate_packet_map(output_flows, flow_counts)

    for flow in output_flows:
        packet = None
        ip_packet = IP(src=flow[0], dst= flow[1])          
        
        flow_key = list(convert_to_hex(flow).keys())[0]

        num_packets = packet_freq_map[flow_key]
        
        for i in range(num_packets):
            
            if int(flow[4]) == 6:
                tcp_packet = TCP(sport=int(flow[2]), dport=int(flow[3]))
                eth_header = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                packet = eth_header / ip_packet / tcp_packet

            elif int(flow[4]) == 17:
                tcp_packet = UDP(sport=int(flow[2]), dport=int(flow[3]))
                eth_header = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                packet = eth_header / ip_packet / tcp_packet
            
            if packet != None:
                print(packet.summary())
                output.append(packet)        
    
    for pkt in packets:
        eth_header = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        new_pkt = eth_header / pkt
        output.append(new_pkt)

    random.shuffle(output)

    timed_output = []
    for pkt in output:
        pkt.time = timestamp;
        timestamp += random.randint(1,5)/1000000
        timed_output.append(pkt)

    output_file.write(timed_output)

