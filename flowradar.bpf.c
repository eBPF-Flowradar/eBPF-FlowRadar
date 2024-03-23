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
#include <stdbool.h>
#include <linux/icmp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include "hashutils.h"


#define BLOOM_FILTER_HASH_COUNT 4
#define COUNTING_TABLE_HASH_COUNT 2
#define BLOOM_FILTER_SIZE 240
#define COUNTING_TABLE_SIZE 16
#define FLOW_KEY_SIZE 13
#define BUCKET_SIZE 7500

struct network_flow{
	__u32 source_ip;
	__u32 dest_ip;
	__u16 source_port;
	__u16 dest_port;
	__u8 protocol;
};

struct counting_table_entry {
	__u128 flowXOR;
	__u32 flowCount;
	__u32 packetCount;
};

// Define the Bloom Filter
struct {
	__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
	__type(value, __u128);
	__uint(max_entries, BLOOM_FILTER_SIZE);
	__uint(map_extra, BLOOM_FILTER_HASH_COUNT);
} bloom_filter SEC(".maps");

// Define the Counting Table 
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct counting_table_entry);
	__uint(max_entries, COUNTING_TABLE_SIZE);
} counting_table SEC(".maps");


static inline __u32 jhash(__u128 flow_key,  __u32 initval) {
	
	__u32 a, b, c;
	a = b = c = JHASH_INITVAL + 13 + initval;
	
	__u32 k0 = 0;
	__u32 k4 = 0;
	__u32 k8 = 0;
	__u32 k12 = 0;

	k0 = flow_key;
	a += k0;
	flow_key = flow_key >> 32;

	k4 = flow_key;
	b += k4;
	flow_key = flow_key >> 32;

	k8 = flow_key;
	c += k8;
	flow_key = flow_key >> 32;

	k12 = flow_key;
	a += k12;
	__jhash_final(a, b, c);
	
	return c; 
}

__u128 flow_key_generator_function(struct network_flow * flow) {
	
	if (flow == NULL) {
		return -1;
	}
	
	__u32 src_ip = flow->source_ip;
	__u32 dst_ip = flow->dest_ip;
	__u16 src_port = flow->source_port;
	__u16 dst_port = flow->dest_port;
	__u8 protocol = flow->protocol;
	// Flow
	__u128 flowKey = 0;
	// Parse the Source IP;
	for (int i = 0 ; i < 4 ; ++i) {
		__u8 byte = (__u8) src_ip;
		flowKey |= byte;
		flowKey = flowKey << 8;
		src_ip = src_ip >> 8;
	}
	// Parse the Destination IP
	for (int i = 0 ; i < 4 ; ++i) {
		__u8 byte = (__u8) dst_ip;
		flowKey |= byte;
		flowKey = flowKey << 8;
		dst_ip = dst_ip >> 8;
	}
	// Parse the Source Port
	for (int i = 0 ; i < 2 ; ++i) {
		__u8 byte = (__u8) src_port;
		flowKey |= byte;
		flowKey = flowKey << 8;
		src_port = src_port >> 8;
	}
	// Parse the Destination Port
	for (int i = 0 ; i < 2 ; ++i) {
		__u8 byte = (__u8) dst_port;
		flowKey |= byte;
		flowKey = flowKey << 8;
		dst_port = dst_port >> 8;
	}	
	
	flowKey |= protocol;
	return flowKey;
}


static __always_inline
int insert_flow_to_counting_table(__u128 flowKey, bool old_flow) {
	
	int num_buckets = COUNTING_TABLE_HASH_COUNT;

	for(int  i = 0 ; i < num_buckets ; ++i) {
		
		__u32 j = i;

		struct counting_table_entry *ct = NULL;
	
		int bucket_index = jhash(j, flowKey) % COUNTING_TABLE_SIZE;
		// Hash Value % BUCKET_SIZE 7500;
	
		if(old_flow == true) {
			// Packet Comes from an existing flow
			ct = bpf_map_lookup_elem(&counting_table, &bucket_index);
			if(ct){
				struct counting_table_entry cte = *ct;
				cte.flowXOR = ct->flowXOR ^ flowKey;
				cte.packetCount = ct->packetCount + 1;
				bpf_map_update_elem(&counting_table, &bucket_index, &cte, BPF_EXIST);
			} else {
				return -1;
			}
		} else {
			// Packet Comes from a new flow
			ct = bpf_map_lookup_elem(&counting_table, &bucket_index);
			if(ct){
				struct counting_table_entry cte = *ct;
				cte.flowXOR ^= flowKey;
				cte.packetCount++;
				cte.flowCount++;
				bpf_map_update_elem(&counting_table, &bucket_index, &cte, BPF_EXIST);
			} else{
				return -1;
			}
		}
	}

	return 0;
}
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
		return XDP_PASS;
	}
	
	// bpf_printk("Flow: %-3u %-3u %-3u %-3u %-3u", source_ip, dest_ip, source_port, dest_port, protocol);
	
	// generate_flow_key();
	struct network_flow nflow = (struct network_flow){.source_ip = source_ip, .dest_ip = dest_ip, .source_port = source_port, .dest_port = dest_port, .protocol = protocol};
	// print_flow(nflow);
	// struct network_flow * nf = NULL;
	__u128 flowKey = flow_key_generator_function(&nflow);

	bool old_flow = false;

	if (bpf_map_peek_elem(&bloom_filter, &flowKey) == 0) {
		// Element In Bloom Filter;
		old_flow = true;
	} else {
		bpf_map_push_elem(&bloom_filter, &flowKey, BPF_NOEXIST);
	}
	
	insert_flow_to_counting_table(flowKey, old_flow);
	
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";