#include "flowradar.h"

static int add(struct pureset *pure_set, __u128 flowXOR) {

  //each element of pure set is unique no check required(verify)
  if(pure_set->latest_index>=PURE_SET_SIZE){
    fprintf(stderr,"Error : pure_set out of bounds access (Pureset size=%d , index=%d)\n",PURE_SET_SIZE,pure_set->latest_index);
    return -1;   //handle errors here (including removing the xdp program)
  }


  pure_set->purecells[pure_set->latest_index] = flowXOR;
  pure_set->latest_index = pure_set->latest_index + 1;
  return 0;
}


//finds the first index of a pure cell, if no pure cell return -1
int check_purecells(struct flowset* A){
    
  for(int i=0;i<COUNTING_TABLE_SIZE;i++){

    if(A->counting_table[i].flowCount==1){
      return i;
    }


  }

  return -1;

}



int single_decode(struct flowset* A,struct pureset* pure_set,int init_index) {


  for (int c = init_index; c < COUNTING_TABLE_SIZE; ++c) {

    struct counting_table_entry ct_entry = A->counting_table[c];
    

    if (ct_entry.flowCount == 1) {
      __u128 flowXOR = ct_entry.flowXOR;

      //add to pureset and if it overflows return -1
      if(add(pure_set, flowXOR)){
        return -1;
      }

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
  return 0;
}
