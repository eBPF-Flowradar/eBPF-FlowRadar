#ifndef FLOW_RADAR_H

#define FLOW_RADAR_H

#include <linux/types.h>
#include <stdbool.h>
#include <linux/bpf.h>   //don't know whether its good to include it here

#define FLOW_FILTER_HASH_COUNT 7
#define COUNTING_TABLE_HASH_COUNT 4

// #define FLOW_FILTER_BITS_PER_SLICE 35000
#define FLOW_FILTER_BITS_PER_SLICE 32985  
#define COUNTING_TABLE_ENTRIES_PER_SLICE 7801

#define FLOW_FILTER_SIZE  FLOW_FILTER_HASH_COUNT * FLOW_FILTER_BITS_PER_SLICE  //230895  
#define COUNTING_TABLE_SIZE  COUNTING_TABLE_HASH_COUNT * COUNTING_TABLE_ENTRIES_PER_SLICE //31204
 
#define PURE_SET_SIZE COUNTING_TABLE_SIZE    //TODO:need to check this

#define POLL_TIME_MS  280  //in milliseconds (280)
#define POLL_TIME_US POLL_TIME_MS*1000   // in microseconds


#define RING_BUFFER_SIZE 100


#define SINGLE_DECODE_LOG_FILE "sd_logs.csv"
#define COUNTER_DECODE_LOG_FILE "cd_logs.csv"
#define DETECTION_LOG_FILE "detect.csv"


struct pureset {
  __u128 purecells[PURE_SET_SIZE];
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
  int pkt_count;
  int num_flows_collide_all_indices;  //for detection mechanism
  int num_flows_all_new_cells;  //for detection mechanism
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

struct ring_buffer{
  struct flowset * const buffer;
  int head;
  int tail;
  const int maxlen;
};

struct thread_args{
  int flowset_fd_0;
  int flowset_fd_1;
  int flowset_id_fd;
};


#endif // !FLOW_RADAR_H
