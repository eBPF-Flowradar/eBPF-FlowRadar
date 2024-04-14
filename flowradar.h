#ifndef FLOW_RADAR_H

#define FLOW_RADAR_H

#include <linux/types.h>

#define FLOW_FILTER_SIZE 240000
#define COUNTING_TABLE_SIZE 30000
#define MAX_PURE_CELLS COUNTING_TABLE_SIZE * 2
// #define NUM_HASH_FUNCTIONS 5
#define FLOW_FILTER_HASH_COUNT 7
#define COUNTING_TABLE_HASH_COUNT 4
// #define NUM_SLICES 7
#define BITS_PER_SLICE 35000
// #define BUCKET_SIZE 7500
#define POLL_TIME_MS  280  //in milliseconds (280)
#define POLL_TIME_US POLL_TIME_MS*1000

struct pureset {
  __u128 purecells[MAX_PURE_CELLS];
  int latest_index;
};

// struct pureset_packet_count {
//   struct pureset set;
//   int pktCount[COUNTING_TABLE_SIZE];
// };

struct counting_table_entry {
  __u128 flowXOR;
  __u32 flowCount;
  __u32 packetCount;
};

struct flowset {
  struct counting_table_entry counting_table[COUNTING_TABLE_SIZE];
};

struct network_flow {
  __u32 source_ip;
  __u32 dest_ip;
  __u16 source_port;
  __u16 dest_port;
  __u8 protocol;
};

#endif // !FLOW_RADAR_H
