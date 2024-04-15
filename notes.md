# Questions
1. How do we test it? [x]
2. We will be having this installed in every host?[x]
3. Doubt in Counter decode in figure paper.
4. XDP can only capture packets from RX (incoming side). Is that a problem ?
5. See #Notes 1
6. Ask about hashes are implemented for consistent implementation with theirs
7. Extra metadata to be stored?  (e.g., packet counters, and the flow starting and finish times).
8. When should we clear the flowset? In the simulation its done in sequential order?

# Check
1. Check all TODOs
2. Check if memory allocated is deallocated and also proper error checking
3. Check consistency of hashing (in IITH and our impl)
4. Verify lsqr solver(partially verified)
5. Standard values to be used 
6. Concurrency controls - use two flowsets [x]
7. murmur hash implementations
8. make time to 280ms[x]
9. Test with bridging[x]
10. Test the implementation
11. Some random packets are being sent on the interface
12. Match number of packets in listener and eBPF program[x]
13. Packets rounded to nearest integer after calculation (instead of simplifying the calculation)
14. Check pure set implementation
15. Proper flow for returning errors.Check return values of bpf helpers and perform required action

# Things Need to be done
1. Pureset need not be a set as the flows added will be unique always [x]
2. Change implementation of single decode to perform it until no pure cells exist [x]
3. delay before start_decode function [x]
4. Unload the XDP program on error
5. Continue the loop if counting table empty in start_decode [x]
6. Replace the bpf maps with support for locks
    - [lwn article on BPF spinlocks](https://lwn.net/Articles/779120/)
    -[example](https://lwn.net/ml/netdev/20190131234012.3712779-10-ast@kernel.org/)

# Errors
1. Errors due to empty flowsets being passed down to gsl [x]

# Important Commands
1.`sudo ip link set dev enp1s0  xdpgeneric off` : To unload XDP program from enp1s0 interface
2.`sudo ip link show dev enp1s0` : Shows if XDP program is loaded in enp1s0 interface
3.`sudo cat /sys/kernel/tracing/trace_pipe` : bpf tracepipe (bpf_printk() for printing)
4.`sudo ip link set dev <interface> up` : setting the interface up

# Notes
1. The 110k_24k_caida.pcap has raw ip packets without the ethernet header, this causes issues with our program as it expects ethernet headers, currently while testing with scapy we are adding the ethernet headers and sending to the interface.
2. Only supporting IP packets (TCP and UDP)

# Resources to setup veth
1. Run script.sh
2. Check https://linuxconfig.org/how-to-use-bridged-networking-with-libvirt-and-kvm to setup with virt-manager
3. Add interface to virt-manager and ensure the interface is up
