#ifndef FLOW_RADAR_H

#define FLOW_RADAR_H

#include <linux/types.h>
#include <stdbool.h>
#include <linux/bpf.h>   //don't know whether its good to include it here

#define FLOW_FILTER_HASH_COUNT 7
#define COUNTING_TABLE_HASH_COUNT 4

#define FLOW_FILTER_BITS_PER_SLICE  34286  //35000
#define COUNTING_TABLE_ENTRIES_PER_SLICE 7500

#define FLOW_FILTER_SIZE  FLOW_FILTER_HASH_COUNT * FLOW_FILTER_BITS_PER_SLICE  //240002   //245000  
#define COUNTING_TABLE_SIZE  COUNTING_TABLE_HASH_COUNT * COUNTING_TABLE_ENTRIES_PER_SLICE //30000 
 
#define MAX_PURE_CELLS COUNTING_TABLE_SIZE * 2    //TODO:need to check this

#define POLL_TIME_MS  280  //in milliseconds (280)
#define POLL_TIME_US POLL_TIME_MS*1000   // in microseconds

struct pureset {
  __u128 purecells[MAX_PURE_CELLS];
  int latest_index;
};


struct counting_table_entry {
  __u128 flowXOR;
  __u32 flowCount;
  __u32 packetCount;
};

struct flowset {
  struct counting_table_entry counting_table[COUNTING_TABLE_SIZE];
  bool flow_filter[FLOW_FILTER_SIZE];
};

struct flowset_id_struct{
  struct bpf_spin_lock lock;
  bool id;
};

struct network_flow {
  __u32 source_ip;
  __u32 dest_ip;
  __u16 source_port;
  __u16 dest_port;
  __u8 protocol;
};

#endif // !FLOW_RADAR_H
