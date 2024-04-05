#include "hashutils.h"

void add(struct pureset *flowSet, __u128 flowXOR) {

  //check not necessary
  // for (int i = 0; i < flowSet->latest_index; ++i) {
  //   if (flowSet->purecells[i] == flowXOR) {
  //     return -1;
  //   }
  // }

  flowSet->purecells[flowSet->latest_index] = flowXOR;
  flowSet->latest_index = flowSet->latest_index + 1;
}


//more efficient possible return the  index to prevent the first search in single decode
int check_purecells(struct flowset* A){
    
  for(int i=0;i<COUNTING_TABLE_SIZE;i++){

    if(A->counting_table[i].flowCount==1){
      return 1;
    }


  }

  return 0;

}



void single_decode(struct flowset* A,struct pureset* pure_set) {

  // struct pureset pure_set;
  // pure_set.latest_index = 0;

  for (int c = 0; c < COUNTING_TABLE_SIZE; ++c) {

    struct counting_table_entry ct_entry = A->counting_table[c];
    // flowset_pktcount.pktCount[c] = A.counting_table[c].packetCount;

    if (ct_entry.flowCount == 1) {
      __u128 flowXOR = ct_entry.flowXOR;
      //add to pureset
      add(pure_set, flowXOR);
      int packetCount = ct_entry.packetCount;

      for (int num_hash = 0; num_hash < COUNTING_TABLE_HASH_COUNT; ++num_hash) {
        __u32 j = num_hash;
        int hashIndex = jhash_key(flowXOR, j) % COUNTING_TABLE_SIZE;
        struct counting_table_entry *ct_poses =&(A->counting_table[hashIndex]);
        ct_poses->flowXOR = ct_poses->flowXOR ^ flowXOR;
        ct_poses->flowCount = ct_poses->flowCount - 1;
        ct_poses->packetCount = ct_poses->packetCount - packetCount;
      }
    }
  }

  // return pure_set;
}
