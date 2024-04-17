CFLAGS:= -g -O2 -Wall -Wextra
GFLAGS:= -lxdp -lbpf -lgsl -lm

all: flowradar.o flowradar

flowradar.o: flowradar.bpf.c murmur.h flowradar.h Makefile
	clang $(CFLAGS) -target bpf -c flowradar.bpf.c -o flowradar.o

flowradar: flowradar.c counter_decode.c single_decode.c murmur.h flowradar.h Makefile
	gcc flowradar.c -o flowradar $(GFLAGS)