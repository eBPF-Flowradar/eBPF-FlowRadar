#include "counter_decode.c"
#include "single_decode.c"
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


//TODO:Verify this
//relying on automatic init by compiler
struct flowset empty_flowset;


static void int_exit(int sig) {
  xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
  xdp_program__close(prog);
  exit(sig);
}


static void inline initialize_flowset(int flowset_fd){

  bpf_map_update_elem(flowset_fd,&first,&empty_flowset,BPF_ANY);

}


static void start_decode(int flowset_fd_0,int flowset_fd_1,int flowset_id_fd) {

  int loop = 0;

  while (true) {

    //Collect data at poll interval
    usleep(POLL_TIME_US);


    //variable to store whether the counting table is empty or not
    bool ct_empty=true; 

    loop++;
    printf("\nPoll No : %d\n", loop);
    

    struct flowset flow_set;
    __u32 pktCount[COUNTING_TABLE_SIZE];

    //Get map currently in use
    struct flowset_id_struct current;
    int curr_flowset_fd;
    bpf_map_lookup_elem(flowset_id_fd, &first, &current);
    // if(ret<0){
    //   return ret;
    // }
    if(current.id){
      curr_flowset_fd=flowset_fd_1;
      printf("Flowset 1 in use\n");
    }else{
      curr_flowset_fd=flowset_fd_0;
      printf("Flowset 0 in use\n");
    }
  
    //invert Flowset_ID
    current.id=!(current.id);
    //wait till lock release to update
    bpf_map_update_elem(flowset_id_fd, &first, &current, BPF_F_LOCK);
    // if(ret<0){
    //   return ret;
    // }

    bpf_map_lookup_elem(curr_flowset_fd,&first,&flow_set);

    printf("FlowXOR ,FlowCount ,PacketCount\n");
    for(int i=0;i<COUNTING_TABLE_SIZE;i++){

      struct counting_table_entry cte=flow_set.counting_table[i];
      pktCount[i]=cte.packetCount;

      if(cte.flowXOR){
         ct_empty=false;
        printf("%" PRIx64 "%016" PRIx64, (uint64_t)(cte.flowXOR >> 64),
              (uint64_t)cte.flowXOR);
        printf(" ,%d ,%d\n", cte.flowCount, cte.packetCount);
      }

    }



    //Continue the loop if counting table is empty
    if(ct_empty){
      printf("Counting table empty!!!\n");
      continue;
    }


    //reset the flowset 
    initialize_flowset(curr_flowset_fd);


    //perform single decode and print the purecells
    struct pureset pure_set;
    pure_set.latest_index=0;
    //perform single decode till there are no pure cells left
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
  }
}

int main(int argc, char *argv[]) {

  int prog_fd, map_fd, ret;
  struct bpf_object *bpf_obj;

  //check if necessary (setting resource limits to infinity)
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

  // IS THIS NECESSARY
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    fprintf(stderr, "ERROR:failed to set rlimit\n");
    return 1;
  }

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

  //get fds of flowsets
  int Flowset_fd_0=bpf_object__find_map_fd_by_name(bpf_obj, "Flow_set_0");
  int Flowset_fd_1=bpf_object__find_map_fd_by_name(bpf_obj, "Flow_set_1");

  //get fd of flowset_id
  int Flowset_id_fd=bpf_object__find_map_fd_by_name(bpf_obj, "Flowset_ID");


  initialize_flowset(Flowset_fd_0);
  initialize_flowset(Flowset_fd_1);

  //initialize Flowset_ID
  bool set=false;
  bpf_map_update_elem(Flowset_id_fd, &first, &set, BPF_ANY);
  // if(ret<0){
  //   return ret;
  // }


  start_decode(Flowset_fd_0,Flowset_fd_1,Flowset_id_fd);

  int_exit(0);
  return 0;
}
