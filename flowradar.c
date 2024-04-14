#include "counter_decode.c"
#include "single_decode.c"
#include "concurrency.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <inttypes.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <xdp/libxdp.h>

static int ifindex;
struct xdp_program *prog = NULL;
int first=0; //used for accessing the only element in flowset_id



static void int_exit(int sig) {
  xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
  xdp_program__close(prog);
  exit(sig);
}


static void initialize_flow_filter(int flow_filter_file_descriptor) {

  for (int i = 0; i < BLOOM_FILTER_SIZE; ++i) {
    bool set = false;
    bpf_map_update_elem(flow_filter_file_descriptor, &i, &set, BPF_ANY);
  }
}

static void initialize_counting_table(int counting_table_file_desc) {

  for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
    struct counting_table_entry entry = {
        .flowXOR = 0, .flowCount = 0, .packetCount = 0};
    bpf_map_update_elem(counting_table_file_desc, &i, &entry, BPF_ANY);
  }
}



static void start_decode(int ct_fd_0,int ff_fd_0,int ct_fd_1,int ff_fd_1,int flowset_id_fd) {

  int loop = 0;

  while (true) {

    //Collect data at poll interval
    usleep(POLL_TIME_US);


    //variable to store whether the counting table is empty or not
    bool ct_empty=true; 

    loop++;
    printf("\nPoll No : %d\n", loop);
    printf("FlowXOR ,FlowCount ,PacketCount\n");

    struct flowset flow_set;
    __u32 pktCount[COUNTING_TABLE_SIZE];

    //Get map currently in use
    
    struct FlowSetIDWithLocks current;
    
    int counting_table_fd, flow_filter_fd;

    bpf_map_lookup_elem(flowset_id_fd, &first, &current);
    
    // if(ret<0){
    //   return ret;
    // }
    
    if(current.val){
    
      counting_table_fd=ct_fd_1;
      flow_filter_fd=ff_fd_1;
      printf("Flowset 1 in use\n");
    
    }
    else{
    
      counting_table_fd=ct_fd_0;
      flow_filter_fd=ff_fd_0;
      printf("Flowset 0 in use\n");
    
    }
  
    //invert Flowset_ID

    current.val = !current.val;

    bpf_map_update_elem(flowset_id_fd, &first, &current, BPF_EXIST);
    // if(ret<0){
    //   return ret;
    // }

    //TODO: check for more efficient ways of copying maps to userspace
    //DONE: Using two flowsets
    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
      struct counting_table_entry cte;
      int ret = bpf_map_lookup_elem(counting_table_fd, &i, &cte);
      //TODO: could this be more efficient?
      if (ret == 0) {
        flow_set.counting_table[i] = cte;
        pktCount[i]=cte.packetCount;
      }
      if (cte.flowXOR) {
        ct_empty=false;
        printf("%" PRIx64 "%016" PRIx64, (uint64_t)(cte.flowXOR >> 64),
              (uint64_t)cte.flowXOR);
        printf(" ,%d ,%d\n", cte.flowCount, cte.packetCount);
      // printf("%x ,%d ,%d\n", cte.flowXOR, cte.flowCount, cte.packetCount);
      }
    }

    //Continue the loop if counting table is empty
    if(ct_empty){
      printf("Counting table empty!!!\n");
      continue;
    }


    //reset the flowset 
    //TODO : better way to do this?
    initialize_flow_filter(flow_filter_fd);
    initialize_counting_table(counting_table_fd);


    //perform single decode and print the purecells
    struct pureset pure_set;
    pure_set.latest_index=0;
    while(check_purecells(&flow_set)){

      single_decode(&flow_set,&pure_set);

    }

    printf("\nSingle Decode Complete.....\nPureCells\n");
    for (int i = 0; i < pure_set.latest_index; i++) {
      printf("%" PRIx64 "%016" PRIx64 "\n",
             (uint64_t)(pure_set.purecells[i] >> 64),
             (uint64_t)pure_set.purecells[i]);
    }
    
    
    //perform counter decode
    counter_decode(pure_set,pktCount);
    // counter_decode(flow_set,pure_set,pktCount);


  }
}

int main(int argc, char *argv[]) {

  int prog_fd, map_fd, ret;
  struct bpf_object *bpf_obj;
  // struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

  //// IS THIS NECESSARY
  // if (setrlimit(RLIMIT_MEMLOCK, &r)) {
  //   fprintf(stderr, "ERROR:failed to set rlimit\n");
  //   return 1;
  // }

  signal(SIGINT, int_exit);
  signal(SIGTERM, int_exit);

  if (argc != 2) {
    printf("Usage: %s Interface_Name\n", argv[0]);
    return 1;
  }

  ifindex = if_nametoindex(argv[1]);
  if (!ifindex) {
    printf("Getting ifindex from interface name failed\n");
    return 1;
  }

  /* load XDP object by libxdp */
  prog = xdp_program__open_file("flowradar.o", "xdp", NULL);
  if (!prog) {
    printf("Error, load xdp prog failed\n");
    return 1;
  }

  // MAYBE CHANGE to XDP_MODE_NATIVE
  ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
  if (ret) {
    printf("Error, Set xdp fd on %d failed\n", ifindex);
    return ret;
  }

  bpf_obj = xdp_program__bpf_obj(prog);

  int Counting_table_fd_0 =
      bpf_object__find_map_fd_by_name(bpf_obj, "Counting_table_0");
  int Flow_filter_fd_0 = bpf_object__find_map_fd_by_name(bpf_obj, "Flow_filter_0");
  int Counting_table_fd_1 =
      bpf_object__find_map_fd_by_name(bpf_obj, "Counting_table_1");
  int Flow_filter_fd_1 = bpf_object__find_map_fd_by_name(bpf_obj, "Flow_filter_1");


  int Flowset_id_fd=bpf_object__find_map_fd_by_name(bpf_obj, "Flowset_ID");

  //initialize Flowset_ID
  bool set=false;
  bpf_map_update_elem(Flowset_id_fd, &first, &set, BPF_ANY);
  // if(ret<0){
  //   return ret;
  // }

  initialize_flow_filter(Flow_filter_fd_0);
  initialize_counting_table(Counting_table_fd_0);
  initialize_flow_filter(Flow_filter_fd_1);
  initialize_counting_table(Counting_table_fd_1);

  start_decode(Counting_table_fd_0,Flow_filter_fd_0,Counting_table_fd_1,Flow_filter_fd_1,Flowset_id_fd);

  int_exit(0);
  return 0;
}
