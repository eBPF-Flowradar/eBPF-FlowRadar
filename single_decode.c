#include "flowradar.h"

void add(struct pureset *flowSet, __u128 flowXOR) {

  //each element of pure set is unique no check required(verify)
  flowSet->purecells[flowSet->latest_index] = flowXOR;
  flowSet->latest_index = flowSet->latest_index + 1;
}


//TODO:more efficient possible,return the  index to prevent the first search in single decode
int check_purecells(struct flowset* A){
    
  for(int i=0;i<COUNTING_TABLE_SIZE;i++){

    if(A->counting_table[i].flowCount==1){
      return 1;
    }


  }

  return 0;

}



void single_decode(struct flowset* A,struct pureset* pure_set) {


  for (int c = 0; c < COUNTING_TABLE_SIZE; ++c) {

    struct counting_table_entry ct_entry = A->counting_table[c];
    

    if (ct_entry.flowCount == 1) {
      __u128 flowXOR = ct_entry.flowXOR;
      //add to pureset
      add(pure_set, flowXOR);
      int packetCount = ct_entry.packetCount;

      for (int num_hash = 0; num_hash < COUNTING_TABLE_HASH_COUNT; ++num_hash) {
        
        //Generate Hash
        __u32 offset;
        MurmurHash3_x86_32(&flowXOR,16,num_hash,&offset);
        offset=offset%COUNTING_TABLE_ENTRIES_PER_SLICE;
        __u32 hashIndex=num_hash*COUNTING_TABLE_ENTRIES_PER_SLICE+offset;

        struct counting_table_entry *ct_poses =&(A->counting_table[hashIndex]);
        ct_poses->flowXOR = ct_poses->flowXOR ^ flowXOR;
        ct_poses->flowCount = ct_poses->flowCount - 1;
        ct_poses->packetCount = ct_poses->packetCount - packetCount;
      }
    }
  }

}
