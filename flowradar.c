#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <sys/resource.h>
#include "flowradar.h"
#include "single_decode.h"

static int ifindex;
struct xdp_program * prog = NULL;

static void int_exit(int sig)
{
    xdp_program__close(prog);
    exit(0);
}

static void perform_single_decode(int counting_table_file_descriptor) {
    
    struct flowset flow_set;
    
    for(int i = 0 ; i < COUNTING_TABLE_SIZE ; ++i) {
        struct counting_table_entry cte;
        int ret = bpf_map_lookup_elem(&counting_table_file_descriptor, &i, &cte);
        if(ret == 0) {
            flow_set.counting_table[i] = cte;
        }
    }

    struct pureset_packet_count pspc = single_decode(flow_set);
    
}

int main(int argc, char *argv[]) {
    
    int prog_fd, map_fd, ret;
    struct bpf_object *bpf_obj;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    
	if(setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR:failed to set rlimit\n");
		return 1;
	}

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

    ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
    if (ret) {
        printf("Error, Set xdp fd on %d failed\n", ifindex);
        return ret;
    }

    bpf_obj = xdp_program__bpf_obj(prog);
    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "counting_table");
    
    if (map_fd < 0) {
        printf("Error, get map fd from bpf obj failed\n");
        return map_fd;
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    return 0;
}
