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

// Define the Counting Table
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct counting_table_entry);
  __uint(max_entries, COUNTING_TABLE_SIZE);
} counting_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, bool);
  __uint(max_entries, BLOOM_FILTER_SIZE);
} flow_filter SEC(".maps");

static __always_inline int insert_to_flow_filter(struct network_flow flow) {

  __u128 flow_key = 0;
  memcpy(&flow_key, &flow, sizeof(struct network_flow));
  // flow key generator function
  for (int i = 0; i < FLOW_FILTER_HASH_COUNT; ++i) {
    int offset = murmurhash(flow_key, i) % BITS_PER_SLICE;
    int hashIndex = i * BITS_PER_SLICE + offset;
    bool bit = true;
    bpf_map_update_elem(&flow_filter, &hashIndex, &bit, BPF_ANY);
  }

  return 0;
}

static __always_inline bool query_flow_filter(struct network_flow flow,
                                              int num_buckets) {

  __u128 flow_key = 0;
  memcpy(&flow_key, &flow, sizeof(struct network_flow));

  for (int i = 0; i < num_buckets; ++i) {
    int offset = murmurhash(flow_key, i) % BITS_PER_SLICE;
    int hashIndex = i * BITS_PER_SLICE + offset;
    bool *set = bpf_map_lookup_elem(&flow_filter, &hashIndex);
    if (set) {
      if (*set == false) {
        return false;
      }
    }
  }
  return true;
}

static __always_inline int
insert_flow_to_counting_table(struct network_flow flow, bool old_flow) {

  int num_buckets = COUNTING_TABLE_HASH_COUNT;

  __u128 flowKey = 0;
  memcpy(&flowKey, &flow, sizeof(struct network_flow));

  for (int i = 0; i < num_buckets; ++i) {

    __u32 j = i;

    struct counting_table_entry *ct = NULL;

    int bucket_index = jhash_flow(flow, j) % COUNTING_TABLE_SIZE;
    // Hash Value % BUCKET_SIZE 7500;

    if (old_flow == true) {
      // Packet Comes from an existing flow
      ct = bpf_map_lookup_elem(&counting_table, &bucket_index);

      if (ct) {
        struct counting_table_entry cte = *ct;
        // cte.flowXOR ^= flowKey;
        cte.packetCount++;
        bpf_map_update_elem(&counting_table, &bucket_index, &cte, BPF_EXIST);
      } else {
        return -1;
      }

    } else {
      // Packet Comes from a new flow
      ct = bpf_map_lookup_elem(&counting_table, &bucket_index);

      if (ct) {
        struct counting_table_entry cte = *ct;
        cte.flowXOR ^= flowKey;
        cte.packetCount++;
        cte.flowCount++;
        bpf_map_update_elem(&counting_table, &bucket_index, &cte, BPF_EXIST);
      } else {
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
int xdp_parse_flow(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  __u16 h_proto;

  // Packet Does not Contain Ethernet Header
  if (data + sizeof(struct ethhdr) >= data_end)
    return XDP_PASS;

  h_proto = eth->h_proto;

  // Packet is not IP Packet
  if (h_proto != htons(ETH_P_IP)) {
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

  if (ip->protocol == IPPROTO_TCP) {

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct tcphdr) >=
        data_end) {
      return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    source_port = tcp->source;
    dest_port = tcp->dest;

  } else if (ip->protocol == IPPROTO_UDP) {

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct tcphdr) >=
        data_end) {
      return XDP_PASS;
    }

    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    source_port = udp->source;
    dest_port = udp->dest;

  } else if (ip->protocol == IPPROTO_ICMP) {

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

  bool old_flow = false;

  if (query_flow_filter(nflow, FLOW_FILTER_HASH_COUNT)) {
    old_flow = true;
  } else {
    insert_to_flow_filter(nflow);
  }

  insert_flow_to_counting_table(nflow, old_flow);

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
