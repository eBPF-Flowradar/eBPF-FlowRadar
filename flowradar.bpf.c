#include "flowradar.h"
#include "murmur.h"
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


//Stucture to decide which flowset should be used
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct flowset_id_struct);
  __uint(max_entries, 1);
} Flowset_ID SEC(".maps");

//Define Flow Set 0
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct flowset);
  __uint(max_entries, 1);
} Flow_set_0 SEC(".maps");

//Define Flow Set 1
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct flowset);
  __uint(max_entries, 1);
} Flow_set_1 SEC(".maps");



static __always_inline int insert_to_flow_filter(__u128 flow_key,struct flowset *curr_flowset) {
  
  for (int i = 0; i < FLOW_FILTER_HASH_COUNT; ++i) {
    
    //Generate Hash
    __u32 offset;
    MurmurHash3_x86_32(&flow_key,16,i,&offset);
    offset=offset%FLOW_FILTER_BITS_PER_SLICE;
    __u32 hashIndex = i * FLOW_FILTER_BITS_PER_SLICE + offset;

    if(hashIndex>=FLOW_FILTER_SIZE){
      return -1;
    }

    //set the bit
    curr_flowset->flow_filter[hashIndex]=true;
  }

  return 0;
}

static __always_inline bool is_old_flow(__u128 flow_key,struct flowset *curr_flowset) {

  for (int i = 0; i < FLOW_FILTER_HASH_COUNT; i++) {

    //generate hash
    __u32 offset;
    MurmurHash3_x86_32(&flow_key,16,i,&offset);
    offset=offset%FLOW_FILTER_BITS_PER_SLICE;
    __u32 hashIndex = i * FLOW_FILTER_BITS_PER_SLICE + offset;


    if(hashIndex>=FLOW_FILTER_SIZE){
      return -1;
    }

    if(curr_flowset->flow_filter[hashIndex]==false){
      return false;  //new flow
    }

  }
  return true; //old flow
}

static __always_inline int
insert_flow_to_counting_table(__u128 flow_key, bool old_flow,struct flowset *curr_flowset) {


  for (int i = 0; i < COUNTING_TABLE_HASH_COUNT; ++i) {

    //generate hash
    __u32 offset;
    MurmurHash3_x86_32(&flow_key,16,i,&offset);
    offset=offset%COUNTING_TABLE_ENTRIES_PER_SLICE;
    __u32 hashIndex=i*COUNTING_TABLE_ENTRIES_PER_SLICE+offset;

    
    if(hashIndex>=COUNTING_TABLE_SIZE){
      return -1;
    }

    struct counting_table_entry cte =curr_flowset->counting_table[hashIndex];

    if(old_flow){
      cte.packetCount++;
    }else{
      cte.flowXOR ^= flow_key;
      cte.packetCount++;
      cte.flowCount++;
    }
    
    curr_flowset->counting_table[hashIndex]=cte;

  }

  return 0;
}


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

  // Packet is not IP Packet (only IPv4 currently supported)
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
  __u8 protocol = ip->protocol;


  __u16 source_port;
  __u16 dest_port;

  if (ip->protocol == IPPROTO_TCP && data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct tcphdr) <=
        data_end) {
      
      struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
      source_port = tcp->source;
      dest_port = tcp->dest;

  } else if (ip->protocol == IPPROTO_UDP && data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct udphdr) <=
        data_end) {

        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        source_port = udp->source;
        dest_port = udp->dest;

    }else{

      //in case of non TCP/UDP or fragmented IP packets
      source_port=0;
      dest_port=0;
  }


  struct network_flow nflow = (struct network_flow){.source_ip = source_ip,
                                                    .dest_ip = dest_ip,
                                                    .source_port = source_port,
                                                    .dest_port = dest_port,
                                                    .protocol = protocol};


  bool old_flow = false;

  //Get the ID of the flowset to which the flow should be inserted
  int first=0;
  struct flowset_id_struct *flowset_id_ptr = bpf_map_lookup_elem(&Flowset_ID, &first);
  struct flowset *flowset_0=bpf_map_lookup_elem(&Flow_set_0,&first);
  struct flowset *flowset_1=bpf_map_lookup_elem(&Flow_set_1,&first);
  
  //start only when flowset_id  and flowsets are initialized
  if(flowset_id_ptr && flowset_0 && flowset_1){

    bpf_spin_lock(&flowset_id_ptr->lock);

    bool flowset_id=flowset_id_ptr->id;
    struct flowset *curr_flowset=NULL;


    if(flowset_id){
      curr_flowset=flowset_1;
    }else{
      curr_flowset=flowset_0;
    }

    //expanding network flow to 128 bits (Check:Is is possible without this?)
    __u128 flow_key;
    memcpy(&flow_key, &nflow, sizeof(struct network_flow));
    
    
    //checking whether old flow and insert if its not
    if (is_old_flow(flow_key,curr_flowset)) {
      old_flow = true;
    } else {
      insert_to_flow_filter(flow_key,curr_flowset);
    }

    insert_flow_to_counting_table(flow_key, old_flow,curr_flowset);


    bpf_spin_unlock(&flowset_id_ptr->lock);

  }


  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
