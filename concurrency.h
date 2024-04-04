#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef CONCURRENCY_H

#define CONCURRENCY_H

#define CT_LOCK_INDEX 1
#define FF_LOCK_INDEX 0


static bool flow_filter_is_locked(int lock_table_fd) {
    
    int j = FF_LOCK_INDEX;
    __u32 value = 0;
    
    bpf_map_lookup_elem(lock_table_fd, &j, &value);

    if(value==1) {
        return true;
    }

    return false;
}

static bool counting_table_is_locked(int lock_table_fd) {
    
    int j = CT_LOCK_INDEX;
    __u32 value = 0;
    
    bpf_map_lookup_elem(lock_table_fd, &j, &value);

    if(value) {
        return true;
    }

    return false;
}

#endif
