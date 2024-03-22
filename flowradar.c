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

static int ifindex;
struct xdp_program * prog = NULL;

static void int_exit(int sig)
{
    xdp_program__close(prog);
    exit(0);
}

static void poll_stats(int map_fd, int poll_interval){
	
}

int main(int argc, char *argv[])
{
    int prog_fd, map_fd, ret;
    struct bpf_object *bpf_obj;

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

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    return 0;
}
