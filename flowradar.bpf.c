#include "hashutils.h"
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

// #define BLOOM_FILTER_HASH_COUNT 7
// #define COUNTING_TABLE_HASH_COUNT 4
// #define NUM_SLICES 7
// #define BITS_PER_SLICE 35000
// #define BLOOM_FILTER_SIZE 245000
// #define COUNTING_TABLE_SIZE 30000
// #define BUCKET_SIZE 7500

// Define the Bloom Filter
// struct {
//  __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
//  __type(value, __u128);
//  __uint(max_entries, BLOOM_FILTER_SIZE);
//  __uint(map_extra, BLOOM_FILTER_HASH_COUNT);
//} bloom_filter SEC(".maps");

//Stucture to decide which flowset should be used
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, bool);
  __uint(max_entries, 1);
} Flowset_ID SEC(".maps");


// Define the Counting Table 0
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct counting_table_entry);
  __uint(max_entries, COUNTING_TABLE_SIZE);
} Counting_table_0 SEC(".maps");

//Define the flow filter 0
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, bool);
  __uint(max_entries, FLOW_FILTER_SIZE);
} Flow_filter_0 SEC(".maps");


// Define the Counting Table 1
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct counting_table_entry);
  __uint(max_entries, COUNTING_TABLE_SIZE);
} Counting_table_1 SEC(".maps");

//Define the flow filter 1
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, bool);
  __uint(max_entries, FLOW_FILTER_SIZE);
} Flow_filter_1 SEC(".maps");



static __always_inline int insert_to_flow_filter(struct network_flow flow,bool flowset_id) {

  __u128 flow_key = 0;
  memcpy(&flow_key, &flow, sizeof(struct network_flow));
  // flow key generator function
  for (int i = 0; i < FLOW_FILTER_HASH_COUNT; ++i) {
    int offset = murmurhash(flow_key, i) % BITS_PER_SLICE;
    int hashIndex = i * BITS_PER_SLICE + offset;
    bool bit = true;
    if(flowset_id){
      bpf_map_update_elem(&Flow_filter_1, &hashIndex, &bit, BPF_ANY);
    }else{
      bpf_map_update_elem(&Flow_filter_0, &hashIndex, &bit, BPF_ANY);
    }
  }

  return 0;
}

static __always_inline bool query_flow_filter(struct network_flow flow,bool flowset_id) {

  __u128 flow_key = 0;
  memcpy(&flow_key, &flow, sizeof(struct network_flow));

  for (int i = 0; i < FLOW_FILTER_HASH_COUNT; ++i) {
    int offset = murmurhash(flow_key, i) % BITS_PER_SLICE;
    int hashIndex = i * BITS_PER_SLICE + offset;
    bool *set;
    if(flowset_id){
      set = bpf_map_lookup_elem(&Flow_filter_1, &hashIndex);
    }else{
      set = bpf_map_lookup_elem(&Flow_filter_0, &hashIndex);
    }
    if (set) {
      if (*set == false) {
        return false;
      }
    }
  }
  return true;
}

static __always_inline int
insert_flow_to_counting_table(struct network_flow flow, bool old_flow,bool flowset_id) {

  //int num_buckets = COUNTING_TABLE_HASH_COUNT;

  __u128 flowKey = 0;
  memcpy(&flowKey, &flow, sizeof(struct network_flow));

  for (int i = 0; i < COUNTING_TABLE_HASH_COUNT; ++i) {

    __u32 j = i;

    struct counting_table_entry *ct = NULL;
    struct counting_table_entry cte;

    int bucket_index = jhash_flow(flow, j) % COUNTING_TABLE_SIZE;
    // Hash Value % BUCKET_SIZE 7500;

    if(flowset_id){
        ct = bpf_map_lookup_elem(&Counting_table_1, &bucket_index);
    }else{
        ct = bpf_map_lookup_elem(&Counting_table_0, &bucket_index);
    }

    if(ct){
      cte=*ct;
    }else{
      return -1;
    }

    if(old_flow){
      cte.packetCount++; 
    }else{
      cte.flowXOR ^= flowKey;
      cte.packetCount++;
      cte.flowCount++;
    }

    if(flowset_id){
      bpf_map_update_elem(&Counting_table_1, &bucket_index, &cte, BPF_EXIST);
    }else{
      bpf_map_update_elem(&Counting_table_0, &bucket_index, &cte, BPF_EXIST);
    }


    // if (old_flow == true) {
    //   // Packet Comes from an existing flow
    //   // ct = bpf_map_lookup_elem(&counting_table, &bucket_index);

    //   if (ct) {
    //     struct counting_table_entry cte = *ct;
    //     // cte.flowXOR ^= flowKey;
    //     cte.packetCount++;
    //     bpf_map_update_elem(&counting_table, &bucket_index, &cte, BPF_EXIST);
    //   } else {
    //     return -1;
    //   }

    // } else {
    //   // Packet Comes from a new flow
    //   // ct = bpf_map_lookup_elem(&counting_table, &bucket_index);

    //   if (ct) {
    //     struct counting_table_entry cte = *ct;
    //     cte.flowXOR ^= flowKey;
    //     cte.packetCount++;
    //     cte.flowCount++;
    //     bpf_map_update_elem(&counting_table, &bucket_index, &cte, BPF_EXIST);
    //   } else {
    //     return -1;
    //   }
    // }
  }

  return 0;
}
// k = seed value // which slice
// hostID = host Num;
// flow sh;

SEC("xdp")
int xdp_parse_flow(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  __u16 h_proto;

  // Packet Does not Contain Ethernet Header (Even if this passes it might not contain eth header as it can
  // be a raw IP packet)
  if (data + sizeof(struct ethhdr) > data_end)
    return XDP_PASS;

  h_proto = eth->h_proto;

  // Packet is not IP Packet
  if (h_proto != htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // Data Does not Contain IP Header
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
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

  if (ip->protocol == IPPROTO_TCP) {

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct tcphdr) >
        data_end) {
      return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    source_port = tcp->source;
    dest_port = tcp->dest;

  } else if (ip->protocol == IPPROTO_UDP) {

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct udphdr) >
        data_end) {
      return XDP_PASS;
    }

    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    source_port = udp->source;
    dest_port = udp->dest;

  } else /*if (ip->protocol == IPPROTO_ICMP)*/ {

    return XDP_PASS;
  }

  // bpf_printk("Flow: %-3u %-3u %-3u %-3u %-3u", source_ip, dest_ip,
  // source_port, dest_port, protocol);

  // generate_flow_key();
  struct network_flow nflow = (struct network_flow){.source_ip = source_ip,
                                                    .dest_ip = dest_ip,
                                                    .source_port = source_port,
                                                    .dest_port = dest_port,
                                                    .protocol = protocol};
  // print_flow(nflow);
  // struct network_flow * nf = NULL;
  // bpf_printk("%x",nflow);

  bool old_flow = false;

  //Get the ID of the flowset to which the flow should be inserted
  int temp=0;
  bool *flowset_id_ptr = bpf_map_lookup_elem(&Flowset_ID, &temp);
  bool flowset_id;

  if(flowset_id_ptr){
    flowset_id=*flowset_id_ptr;
  }else{
    //if flowset_id not initialized start from 0
    flowset_id=false;
  }



  //checking whether old flow and insert if its not
  if (query_flow_filter(nflow,flowset_id)) {
    old_flow = true;
  } else {
    insert_to_flow_filter(nflow,flowset_id);
  }

  insert_flow_to_counting_table(nflow, old_flow,flowset_id);

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
