CFLAGS:= -g -O2 -Wall -Wextra
GFLAGS:= -lxdp -lbpf -lgsl

all: flowradar.o flowradar

flowradar.o: flowradar.bpf.c
	clang $(CFLAGS) -target bpf -c flowradar.bpf.c -o flowradar.o

flowradar: flowradar.c
	gcc flowradar.c -o flowradar $(GFLAGS)