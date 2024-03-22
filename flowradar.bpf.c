#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>


#define BLOOM_FILTER_HASH_COUNT 7
#define COUNTING_TABLE_HASH_COUNT 4
#define BLOOM_FILTER_SIZE 240000
#define COUNTING_TABLE_SIZE 30000
#define FLOW_KEY_SIZE 13

struct network_flow{
	__u32 source_ip;
	__u32 dest_ip;
	__u16 source_port;
	__u16 dest_port;
	__u8 protocol;
};

struct counting_table_entry {
	__u32 flowXOR;
	__u32 flowCount;
	__u32 packetCount;
};

static __always_inline
void print_flow(struct network_flow netflow) {
	__u32 src_ip = netflow.source_ip;
	
	__u8 octet0 = src_ip % 256;
	src_ip/=256;
	__u8 octet1 = src_ip % 256;
	src_ip/=256;
	__u8 octet2 = src_ip % 256;
	src_ip/=256;
	__u8 octet3 = src_ip % 256;

	__u32 dst_ip = netflow.dest_ip;

	__u8 octet4 = dst_ip % 256;
	dst_ip /= 256;
	__u8 octet5 = dst_ip % 256;
	dst_ip /= 256;
	__u8 octet6 = dst_ip % 256;
	dst_ip /= 256;
	__u8 octet7 = dst_ip % 256;

	bpf_printk("%u.%u.%u.%-3u\t%u.%u.%u.%-3u\t%-3u\t%-3u\t%-3u",octet0, octet1, octet2, octet3, octet4, octet5, octet6, octet7, netflow.source_port, netflow.dest_port, netflow.protocol);
}

// Define the Bloom Filter
struct {
	__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
	__type(value, struct network_flow);
	__uint(max_entries, BLOOM_FILTER_SIZE);
	__uint(map_extra, BLOOM_FILTER_HASH_COUNT);
} bloom_filter SEC(".maps");

// Define the Counting Table 
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct counting_table_entry);
	__uint(max_entries, COUNTING_TABLE_SIZE);
} counting_table SEC(".maps");

// k = seed value // which slice
// hostID = host Num;
// flow sh;

SEC("xdp")
int xdp_parse_flow(struct xdp_md * ctx) {
	void * data_end = (void *)(long) ctx->data_end;
	void * data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u16 h_proto;

	// Packet Does not Contain Ethernet Header
	if (data + sizeof(struct ethhdr) >= data_end)
		return XDP_PASS;

	h_proto = eth->h_proto;
	
	// Packet is not IP Packet
	if(h_proto!=htons(ETH_P_IP)){
		return XDP_PASS;
	}

	// Data Does not Contain IP Header
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) >= data_end) {
		return XDP_PASS;
	}

	struct iphdr *ip = data + sizeof(struct ethhdr);
	// Source and Destination IP Address
	__u32 source_ip = ip->saddr;
	__u32 dest_ip = ip->daddr;
	__u32 protocol = ip->protocol;
	
	// Extracting the port data;
	__u32 source_port = 0;
	__u32 dest_port = 0;

	if(ip->protocol == IPPROTO_TCP){
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) >= data_end){
			return XDP_PASS;
		}
		struct tcphdr * tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		source_port = tcp->source;
		dest_port = tcp->dest;
	}
	else if(ip->protocol == IPPROTO_UDP){
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) >= data_end) {
			return XDP_PASS;
		}
		struct udphdr * udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		source_port = udp->source;
		dest_port = udp->dest;
	}
	else if(ip->protocol == IPPROTO_ICMP) {
		bpf_printk("ICMP Packet");
		return XDP_PASS;
	}
	
	// bpf_printk("Flow: %-3u %-3u %-3u %-3u %-3u", source_ip, dest_ip, source_port, dest_port, protocol);
	
	// generate_flow_key();
	struct network_flow nflow = (struct network_flow){.source_ip = source_ip, .dest_ip = dest_ip, .source_port = source_port, .dest_port = dest_port, .protocol = protocol};
	print_flow(nflow);
	struct network_flow * nf = NULL;

	int ret = bpf_map_peek_elem(&bloom_filter, &nf);
	
	if(ret==0){
		bpf_printk("Flow Already exists");
	} else {
		bpf_printk("Adding a new flow");
		bpf_map_push_elem(&bloom_filter, &nflow, BPF_ANY);
	}

	return XDP_PASS;
}




char LICENSE[] SEC("license") = "Dual BSD/GPL";



