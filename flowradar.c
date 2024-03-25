#include "flowradar.h"
#include "counter_decode.h"
#include "single_decode.h"
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

static void poll_bloom_filter(int flow_filter_file_descriptor,
                              int poll_interval) {

  while (1) {

    FILE *fptr;
    fptr = fopen("bloom_filter_logs.csv", "a");

    for (int i = 0; i < BLOOM_FILTER_SIZE; ++i) {
      bool set_bit = false;
      bpf_map_lookup_elem(flow_filter_file_descriptor, &i, &set_bit);
      if (i == BLOOM_FILTER_SIZE - 1) {
        fprintf(fptr, "%d\n", set_bit);
      } else {
        fprintf(fptr, "%d, ", set_bit);
      }
    }

    fclose(fptr);

    sleep(poll_interval);
  }
}

static void poll_counting_table(int counting_table_file_descriptor,
                                int poll_interval) {

  while (1) {

    FILE *fptr;
    fptr = fopen("counting_table_logs.csv", "a");

    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
      struct counting_table_entry cte;
      bpf_map_lookup_elem(counting_table_file_descriptor, &i, &cte);
      flow_key_buff[i] = cte.flowXOR;
      flow_count_buff[i] = cte.flowCount;
      packet_count_buff[i] = cte.packetCount;
    }

    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
      if (i == COUNTING_TABLE_SIZE - 1) {
        fprintf(fptr, "%lf\n", (float)flow_key_buff[i]);
      } else if (i == 0) {
        fprintf(fptr, "FlowXOR, %lf, ", (float)flow_key_buff[i]);
      } else {
        fprintf(fptr, "%lf, ", (float)flow_key_buff[i]);
      }
    }

    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
      if (i == COUNTING_TABLE_SIZE - 1) {
        fprintf(fptr, "%d\n", flow_count_buff[i]);
      } else if (i == 0) {
        fprintf(fptr, "FlowCount, %d, ", flow_count_buff[i]);
      } else {
        fprintf(fptr, "%d, ", flow_count_buff[i]);
      }
    }

    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
      if (i == COUNTING_TABLE_SIZE - 1) {
        fprintf(fptr, "%d\n", packet_count_buff[i]);
      } else if (i == 0) {
        fprintf(fptr, "PacketCount, %d, ", packet_count_buff[i]);
      } else {
        fprintf(fptr, "%d, ", packet_count_buff[i]);
      }
    }
    fclose(fptr);
    sleep(poll_interval);
  }
}

static void print_entry_counting_table(int counting_table_file_descriptor,
                                       int poll_interval) {

  int loop = 0;

  while (1) {

    printf("Poll No : %d\n", loop);
    printf("FlowXOR ,FlowCount ,PacketCount\n");

    for (int i = 0; i < COUNTING_TABLE_SIZE; ++i) {
      struct counting_table_entry cte;
      bpf_map_lookup_elem(counting_table_file_descriptor, &i, &cte);
      if (cte.flowXOR) {
        printf("%" PRIx64 "%016" PRIx64, (uint64_t)(cte.flowXOR >> 64),
               (uint64_t)cte.flowXOR);
        printf(" ,%d ,%d\n", cte.flowCount, cte.packetCount);
        // printf("%x ,%d ,%d\n", cte.flowXOR, cte.flowCount, cte.packetCount);
      }
    }

    loop++;

    // struct pureset_packet_count pspc =
    //     perform_single_decode(counting_table_file_descriptor);
    // for (int i = 0; i < pspc.flowset.latest_index; i++) {
    //   printf("%" PRIx64 "%016" PRIx64 "\n",
    //          (uint64_t)(pspc.flowset.purecells[i] >> 64),
    //          (uint64_t)pspc.flowset.purecells[i]);
    // }
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

  int counting_table_fd =
      bpf_object__find_map_fd_by_name(bpf_obj, "counting_table");
  int flow_filter_fd = bpf_object__find_map_fd_by_name(bpf_obj, "flow_filter");

  initialize_bloom_filter(flow_filter_fd);
  initialize_counting_table(counting_table_fd);

  // poll_counting_table(counting_table_fd, 2);
  //  poll_bloom_filter(flow_filter_fd, 1);
  print_entry_counting_table(counting_table_fd, 2);

  int_exit(0);
  return 0;
}
