#include <linux/types.h>

#ifndef FLOWRADAR_H
#define FLOWRADAR_H

#define BLOOM_FILTER_SIZE 245000
#define COUNTING_TABLE_SIZE 30000
#define MAX_PURE_CELLS COUNTING_TABLE_SIZE * 2
#define NUM_HASH_FUNCTIONS 5

struct pureset{
    __u128 purecells[MAX_PURE_CELLS];
    int latest_index;
};

struct pureset_packet_count{
	struct pureset flowset;
	int pktCount[COUNTING_TABLE_SIZE];
};

struct counting_table_entry {
	__u128 flowXOR;
	__u32 flowCount;
	__u32 packetCount;
};

struct flowset
{
    struct counting_table_entry counting_table[COUNTING_TABLE_SIZE];
};

struct network_flow{
	__u32 source_ip;
	__u32 dest_ip;
	__u16 source_port;
	__u16 dest_port;
	__u8 protocol;
};

#endif
