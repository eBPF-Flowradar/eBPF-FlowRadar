CFLAGS:= -g -O2 -Wall -Wextra
GFLAGS:= -lxdp -lbpf -lgsl

all: flowradar.o flowradar

flowradar.o: flowradar.bpf.c hashutils.h
	clang $(CFLAGS) -target bpf -c flowradar.bpf.c -o flowradar.o

flowradar: flowradar.c counter_decode.c single_decode.c hashutils.h
	gcc flowradar.c -o flowradar $(GFLAGS)