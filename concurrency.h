#include <linux/bpf.h>
#include <stdbool.h>

#ifndef CONCURRENCY_H

#define CONCURRENCY_H

struct FlowSetIDWithLocks{
  struct bpf_spin_lock lock;
  bool val;
};

#endif

