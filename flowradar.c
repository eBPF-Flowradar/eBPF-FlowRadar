#include "counter_decode.h"
#include "single_decode.h"
#include "concurrency.h"

// #include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pthread.h>
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
// #include <linux/time.h>

static int ifindex;
struct xdp_program *prog = NULL;

__u128 flow_key_buff[COUNTING_TABLE_SIZE];
__u32 flow_count_buff[COUNTING_TABLE_SIZE];
__u32 packet_count_buff[COUNTING_TABLE_SIZE];

static void int_exit(int sig) {
  xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
  xdp_program__close(prog);
  exit(0);
}

static struct pureset_packet_count
perform_single_decode(int counting_table_file_descriptor) {

    struct flowset flow_set;

    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
    
      struct counting_table_entry cte;

      int ret = bpf_map_lookup_elem(counting_table_file_descriptor, &i, &cte);

      if (ret == 0) {  
        flow_set.counting_table[i] = cte;
      }
    }

    return single_decode(flow_set);
}

static void swap_tables(int flowsetIdMapFD){
    
    int index = 0;
    __u32 value = 0;  
    
    bpf_map_lookup_elem(flowsetIdMapFD, &index, &value);
    
    if(value == 0) {
        value = 1;
        printf("MAP UPDATE:0->1\n");
        bpf_map_update_elem(flowsetIdMapFD, &index, &value, BPF_ANY);
    }
    else if(value == 1) {
        value = 0;
        printf("MAP UPDATE:1->0\n");
        bpf_map_update_elem(flowsetIdMapFD, &index, &value, BPF_ANY);
    }

}

static void perform_counter_decode(int counting_table_file_descriptor) {
  
    struct flowset flow_set;


    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
    
        struct counting_table_entry cte;

        int ret = bpf_map_lookup_elem(counting_table_file_descriptor, &i, &cte);

        if (ret == 0) {
    
            flow_set.counting_table[i] = cte;
    
        }
        
    }

    struct pureset_packet_count pspc = perform_single_decode(counting_table_file_descriptor);
    
    CD(flow_set, pspc);

}

static void initialize_bloom_filter(int flow_filter_file_descriptor) {

      for (int i = 0; i < BLOOM_FILTER_SIZE; ++i) {
          bool set = false;

          bpf_map_update_elem(flow_filter_file_descriptor, &i, &set, BPF_ANY);
      }

}

static void initialize_counting_table(int counting_table_file_desc) {
        
      for (int i = 0; i < COUNTING_TABLE_SIZE ; ++i) {
      
          struct counting_table_entry entry = {
              .flowXOR = 0, 
              .flowCount = 0, 
              .packetCount = 0
          };

          bpf_map_update_elem(counting_table_file_desc, &i, &entry, BPF_ANY);

      }

}

static void initalize_flow_set_id(int flowset_file_descriptor) {
      int j = 0;
      __u32 val = 0;
      bpf_map_update_elem(flowset_file_descriptor, &j, &val, BPF_ANY);
}

/*
static void initialize_timestamp(int timestamp_file_descriptor) {
      
      int j = 0;
      
      __u64 nanoseconds;
      struct timespec currtime;

      clock_gettime(CLOCK_REALTIME, &currtime);
      
      nanoseconds = &currtime.tv_nsec;
      bpf_map_update_elem(timestamp_file_descriptor, &j, &nanoseconds, BPF_ANY);

}
*/

static void poll_bloom_filter(int flow_filter_file_descriptor, int poll_interval) {

    while (1) {

        FILE *fptr;
        fptr = fopen("bloom_filter_logs.csv", "a");
        
        for (int i = 0; i < BLOOM_FILTER_SIZE; ++i) {
            
            bool set_bit = false;
        
            bpf_map_lookup_elem(flow_filter_file_descriptor, &i, &set_bit);
            
            if (i == BLOOM_FILTER_SIZE - 1) {
                fprintf(fptr, "%d\n", set_bit);
            } 
            else {
                fprintf(fptr, "%d, ", set_bit);
            }
            
        }

        fclose(fptr);

        sleep(poll_interval);

    }
}

static void poll_and_perform_counter_decode(int counting_table_file_descriptor1, int counting_table_file_descriptor2, 
                                int flowset_id_file_desc, int bloom_filter_file_descriptor1, int bloom_filter_file_descriptor2) {
    
    sleep(120);
    while(true){

        int key = 0;
        __u32 flowsetId = 0;

        bpf_map_lookup_elem(flowset_id_file_desc, &key, &flowsetId);

        if(flowsetId == 0) 
        {
            perform_counter_decode(counting_table_file_descriptor1);
        } 
        else if(flowsetId == 1) 
        {
            perform_counter_decode(counting_table_file_descriptor2);
        }        

        swap_tables(flowset_id_file_desc);
        
        if(flowsetId == 1) 
        {
            initialize_counting_table(counting_table_file_descriptor1);
            initialize_bloom_filter(bloom_filter_file_descriptor1);
        }
        else if(flowsetId == 0)
        {
            initialize_counting_table(counting_table_file_descriptor2);
            initialize_bloom_filter(bloom_filter_file_descriptor2);
        }

        usleep(30000000);
        // sleep for 280ms
    }
}

static void print_entry_counting_table(int counting_table_file_descriptor, int poll_interval) {

  int loop = 0;

  while (1) {

      printf("Poll No : %d\n", loop);
      printf("FlowXOR, FlowCount, PacketCount\n");

      for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {

          struct counting_table_entry cte;

          bpf_map_lookup_elem(counting_table_file_descriptor, &i, &cte);
          
          if (cte.flowXOR) {
    
              printf("%" PRIx64 "%016" PRIx64, (uint64_t)(cte.flowXOR >> 64),
                    (uint64_t)cte.flowXOR);
            
              printf(" , %d, %d\n", cte.flowCount, cte.packetCount);
              // printf("%x ,%d ,%d\n", cte.flowXOR, cte.flowCount, cte.packetCount);
          }
      
      }

      loop++;

      printf("PureCells\n");
      struct pureset_packet_count pspc = perform_single_decode(counting_table_file_descriptor);

      for (int i = 0; i < pspc.flowset.latest_index; i++) {
        printf("%" PRIx64 "%016" PRIx64 "\n",
              (uint64_t)(pspc.flowset.purecells[i] >> 64),
              (uint64_t)pspc.flowset.purecells[i]);
      }

      sleep(poll_interval);
    
  }

}

int main(int argc, char *argv[]) {

  int prog_fd, map_fd, ret;
  struct bpf_object *bpf_obj;
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

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

  int counting_table_fd1 = bpf_object__find_map_fd_by_name(bpf_obj, "counting_table_X");
  int counting_table_fd2 = bpf_object__find_map_fd_by_name(bpf_obj, "counting_table_Y");
  int flow_filter_fd1 = bpf_object__find_map_fd_by_name(bpf_obj, "flow_filter_X");
  int flow_filter_fd2 = bpf_object__find_map_fd_by_name(bpf_obj, "flow_filter_Y");
  int flow_set_fd = bpf_object__find_map_fd_by_name(bpf_obj, "flowsetID");
  int time_stamp_fd = bpf_object__find_map_fd_by_name(bpf_obj, "program_start_time");

  initialize_bloom_filter(flow_filter_fd1);
  initialize_bloom_filter(flow_filter_fd2);
  initialize_counting_table(counting_table_fd1);
  initialize_counting_table(counting_table_fd2);
  // initialize_timestamp(time_stamp_fd);
  initalize_flow_set_id(flow_set_fd);

  // poll_counting_table(counting_table_fd, 2);
  // poll_bloom_filter(flow_filter_fd, 1);
  // print_entry_counting_table(counting_table_fd, 2);
  
  poll_and_perform_counter_decode(counting_table_fd1, counting_table_fd2, flow_set_fd, flow_filter_fd1, flow_filter_fd2);
  
  int_exit(0);
  return 0;
}
