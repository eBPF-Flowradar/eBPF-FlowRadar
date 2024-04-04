#ifndef SINGLE_DECODE_H

#define SINGLE_DECODE_H

int add(struct pureset *flowSet, __u128 flowXOR) {

  for (int i = 0; i < flowSet->latest_index; ++i) {
    if (flowSet->purecells[i] == flowXOR) {
      return -1;
    }
  }

  flowSet->purecells[flowSet->latest_index] = flowXOR;
  flowSet->latest_index = flowSet->latest_index + 1;

  return 1;
}

struct pureset_packet_count single_decode(struct flowset A) {

  struct pureset_packet_count flowset_pktcount;
  flowset_pktcount.flowset.latest_index = 0;

  for (int c = 0; c < COUNTING_TABLE_SIZE; ++c) {

    struct counting_table_entry ct_entry = A.counting_table[c];
    flowset_pktcount.pktCount[c] = A.counting_table[c].packetCount;

    if (ct_entry.flowCount == 1) {
      
      __u128 flowXOR = ct_entry.flowXOR;
      int ispresent = add(&(flowset_pktcount.flowset), flowXOR);
      int packetCount = ct_entry.packetCount;

      for (int num_hash = 0; num_hash < COUNTING_TABLE_HASH_COUNT; ++num_hash) {
          __u32 j = num_hash;
          int hashIndex = jhash_key(flowXOR, j) % COUNTING_TABLE_SIZE;
          struct counting_table_entry *ct_poses = &A.counting_table[hashIndex];
          ct_poses->flowXOR = ct_poses->flowXOR ^ flowXOR;
          ct_poses->flowCount = ct_poses->flowCount - 1;
          ct_poses->packetCount = ct_poses->packetCount - packetCount;
      }

    }
  }
  printf("%d\n",flowset_pktcount.flowset.latest_index);
  return flowset_pktcount;
}

#endif
