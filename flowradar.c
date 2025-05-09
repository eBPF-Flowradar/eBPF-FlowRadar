#include "counter_decode.c"
#include "single_decode.c"
#include "ring_buffer.c"
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
#include <pthread.h>


static int ifindex;
struct xdp_program *prog = NULL;
int first=0; //used for accessing the only element in flowset_id
pthread_t thread_id;


//defining ring buffer
struct flowset buffer[RING_BUFFER_SIZE];
struct ring_buffer flowset_ring_buffer ={
  .buffer=buffer,
  .head=0,
  .tail=0,
  .maxlen=RING_BUFFER_SIZE
};


//relying on automatic init by compiler
struct flowset empty_flowset;


static void int_exit(int sig) {
  pthread_cancel(thread_id);
  xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
  xdp_program__close(prog);
  exit(sig);
}


static void inline initialize_flowset(int flowset_fd){

  bpf_map_update_elem(flowset_fd,&first,&empty_flowset,BPF_ANY);

}


//copies flowset from eBPF map to ring buffer and switches flowset in kernel space
void *flowset_switcher_thread(void *arg){

  int loop=0;
  struct thread_args *args = (struct thread_args*)arg;

  int flowset_fd_0=args->flowset_fd_0;
  int flowset_fd_1=args->flowset_fd_1;
  int flowset_id_fd=args->flowset_id_fd;

  while(true){

    usleep(POLL_TIME_US);
    loop++;
    printf("\nPoll No : %d\n", loop);

    struct flowset flow_set;

    //Get map currently in use
    struct flowset_id_struct current;
    int curr_flowset_fd;
    bpf_map_lookup_elem(flowset_id_fd, &first, &current);


    if(current.id){
      curr_flowset_fd=flowset_fd_1;
      printf("Flowset 1 in use\n");
    }else{
      curr_flowset_fd=flowset_fd_0;
      printf("Flowset 0 in use\n");
    }
  
    printf("Inverting the flowset\n");
    //invert Flowset_ID
    current.id=!(current.id);
    //wait till lock release to update
    bpf_map_update_elem(flowset_id_fd, &first, &current, BPF_F_LOCK);
    // if(ret<0){
    //   return ret;
    // }

    printf("Getting the flowset from kernel space\n");
    bpf_map_lookup_elem(curr_flowset_fd,&first,&flow_set);

    if(flow_set.pkt_count==0){
      printf("Flowset empty!!!\n");
      continue;
    }

    //add the flowset to ring buffer, if full exit
    if(ring_buf_push(&flowset_ring_buffer,flow_set)){
      printf("Ring buffer full\n");
      // pthread_exit(NULL);
      int_exit(1);
    }

    //reset the flowset 
    printf("Reset the flowset in kernel space\n");
    initialize_flowset(curr_flowset_fd);


  }
}




static void start_decode() {

  
  struct flowset flow_set;

  while (true) {

    if(!ring_buf_pop(&flowset_ring_buffer,&flow_set)){


      double pktCount[COUNTING_TABLE_SIZE];  //double because to use in gsl
      int numHashCollisions=0;    //Data for detection mechanism

      // printf("FlowXOR ,FlowCount ,PacketCount\n");
      for(int i=0;i<COUNTING_TABLE_SIZE;i++){

        struct counting_table_entry cte=flow_set.counting_table[i];
        pktCount[i]=cte.packetCount;

        if(cte.flowCount>1){
          numHashCollisions+=cte.flowCount-1;
        }

        // if(cte.flowXOR){
        
          // printf("%" PRIx64 "%016" PRIx64, (uint64_t)(cte.flowXOR >> 64),
          //       (uint64_t)cte.flowXOR);
          // printf(" ,%d ,%d\n", cte.flowCount, cte.packetCount);
        // }

      }


      printf("Number of packets in flowset:%d\n",flow_set.pkt_count);

      //perform single decode and print the purecells
      struct pureset pure_set;
      pure_set.latest_index=0;
      //perform single decode till there are no pure cells left
      printf("\nStarting single decode\n");
      while(check_purecells(&flow_set)){

        single_decode(&flow_set,&pure_set);

      }

      int num_purecells=pure_set.latest_index;
      printf("Single Decode Complete.....\nNumber of PureCells:%d\n",num_purecells);

      printf("Writing to log file\n");
      FILE *fptr;
      fptr=fopen(SINGLE_DECODE_LOG_FILE,"a");

      if (fptr == NULL) {
        perror("Error opening file");
        return;  // or handle the error as needed
      }

      for (int i = 0; i < num_purecells; i++) {

        //printing the purecells
        //printf("%" PRIx64 "%016" PRIx64 "\n",
        //(uint64_t)(pure_set.purecells[i] >> 64),
        //(uint64_t)pure_set.purecells[i]);
        
        //write to log file
        // fprintf(fptr,"%lu,",(unsigned long)time(NULL));  //timestamp
        fprintf(fptr,"%" PRIx64 "%016" PRIx64"\n",
                (uint64_t)(pure_set.purecells[i] >> 64),
                (uint64_t)pure_set.purecells[i]);
      }

      fclose(fptr);
      printf("Write complete\n");

      
      //Writing to detection log file
      printf("\nWriting to Detection Log file\n");
      fptr=fopen(DETECTION_LOG_FILE,"a");
      if (fptr == NULL) {
        perror("Error opening file");
        return;  // or handle the error as needed
      }
      fprintf(fptr,"%d,%d,%d,%d\n",
              num_purecells,
              numHashCollisions,
              flow_set.num_flows_collide_all_indices,
              flow_set.num_flows_all_new_cells);
      fclose(fptr);
      printf("Write complete\n");

      
      //perform counter decode
      printf("\nStarting Counter Decode\n");
      counter_decode(&pure_set,pktCount);
        
    }

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
  signal(SIGKILL,int_exit);

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

  //remove log files if exist
  remove(SINGLE_DECODE_LOG_FILE);
  remove(COUNTER_DECODE_LOG_FILE);
  remove(DETECTION_LOG_FILE);

  //prepare arguments to the thread
  struct thread_args args;
  args.flowset_fd_0=Flowset_fd_0;
  args.flowset_fd_1=Flowset_fd_1;
  args.flowset_id_fd=Flowset_id_fd;


  //create thread for flowset switcher
  pthread_create(&thread_id,NULL,flowset_switcher_thread,(void*)&args);


  printf("\nStarting Decode function\n");
  start_decode();

  int_exit(0);
  return 0;
}
