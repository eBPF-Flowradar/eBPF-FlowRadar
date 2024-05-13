#ifndef FLOW_RADAR_H

#define FLOW_RADAR_H

#include <linux/types.h>
#include <stdbool.h>
#include <linux/bpf.h>   //don't know whether its good to include it here

#define FLOW_FILTER_HASH_COUNT 7  //int(math.ceil(math.log(1 / FPR, 2)))  #here FPR is false positive rate (0.01)
#define COUNTING_TABLE_HASH_COUNT 4  //already fixed


/*
	ck[3] = 1.222
	ck[4] = 1.295
	ck[5] = 1.425
	ck[6] = 1.570
	ck[7] = 1.721
*/


#define FLOW_FILTER_BITS_PER_SLICE 33000   //int(math.ceil((EXP_NO_OF_FLOWS * abs(math.log(FPR))) /(FLOW_FILTER_HASH_COUNT * (math.log(2) ** 2))))  #EXP_NO_OF_FLOWS=24100
#define COUNTING_TABLE_ENTRIES_PER_SLICE 7804 //int(math.floor((int(EXP_NO_OF_FLOWS * ck[COUNTING_TABLE_HASH_COUNT]) + 10) / COUNTING_TABLE_HASH_COUNT)) 

#define FLOW_FILTER_SIZE  FLOW_FILTER_HASH_COUNT * FLOW_FILTER_BITS_PER_SLICE  //231000  
#define COUNTING_TABLE_SIZE  COUNTING_TABLE_HASH_COUNT * COUNTING_TABLE_ENTRIES_PER_SLICE //31216
 
#define PURE_SET_SIZE COUNTING_TABLE_SIZE    //TODO:need to check this

#define POLL_TIME_MS  280  //in milliseconds (280)
#define POLL_TIME_US POLL_TIME_MS*1000   // in microseconds

#define DETECTION_TIME_WINDOW_MS  28   //in milliseconds
#define DETECTION_TIME_WINDOW_US DETECTION_TIME_WINDOW_MS*1000  //in microseconds

#define DETECTION_WINDOWS_PER_EPOCH POLL_TIME_MS/DETECTION_TIME_WINDOW_MS   //10


#define RING_BUFFER_SIZE 100
#define RING_BUFFER_FULL_WAIT_TIME  5  //in seconds


#define SINGLE_DECODE_LOG_FILE "sd_logs.csv"
#define COUNTER_DECODE_LOG_FILE "cd_logs.csv"
#define DETECTION_LOG_FILE "detect.csv"
#define TIME_WINDOW_DETECTION_LOG_FILE "window_detect.csv"


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


enum flowset_id_enum{flowset_enum_0,flowset_enum_1,wait_enum};

struct flowset_id_struct{
  struct bpf_spin_lock lock;
  enum flowset_id_enum id;
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
  int count;
  const int maxlen;
};

struct thread_args{
  int flowset_fd_0;
  int flowset_fd_1;
  int flowset_id_fd;
};


#endif // !FLOW_RADAR_H
