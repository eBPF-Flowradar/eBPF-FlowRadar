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

// __u128 flow_key_buff[COUNTING_TABLE_SIZE];
// __u32 flow_count_buff[COUNTING_TABLE_SIZE];
// __u32 packet_count_buff[COUNTING_TABLE_SIZE];

static void int_exit(int sig) {
  xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
  xdp_program__close(prog);
  exit(0);
}


static void initialize_bloom_filter(int flow_filter_file_descriptor) {

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



static void start_decode(int counting_table_file_descriptor,
                                       int poll_interval) {

  int loop = 0;

  while (1) {

    loop++;
    printf("Poll No : %d\n", loop);
    printf("FlowXOR ,FlowCount ,PacketCount\n");

    struct flowset flow_set;
    __u32 pktCount[COUNTING_TABLE_SIZE];

    //TODO: check for more efficient ways of copying maps to userspace
    //TODO: Concurrency control
    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
      struct counting_table_entry cte;
      int ret = bpf_map_lookup_elem(counting_table_file_descriptor, &i, &cte);
      if (ret == 0) {
        flow_set.counting_table[i] = cte;
        pktCount[i]=cte.packetCount;
      }
      if (cte.flowXOR) {
        printf("%" PRIx64 "%016" PRIx64, (uint64_t)(cte.flowXOR >> 64),
              (uint64_t)cte.flowXOR);
        printf(" ,%d ,%d\n", cte.flowCount, cte.packetCount);
      // printf("%x ,%d ,%d\n", cte.flowXOR, cte.flowCount, cte.packetCount);
      }
    }

    //empty the the flowset?    

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


    
    sleep(poll_interval);   
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

  int counting_table_fd =
      bpf_object__find_map_fd_by_name(bpf_obj, "counting_table");
  int flow_filter_fd = bpf_object__find_map_fd_by_name(bpf_obj, "flow_filter");

  initialize_bloom_filter(flow_filter_fd);
  initialize_counting_table(counting_table_fd);

  start_decode(counting_table_fd, 2);

  int_exit(0);
  return 0;
}
