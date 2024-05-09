#! /bin/bash

set -e

#sudo ip link add veth1 type veth peer name veth2
sudo ip link add br0 type bridge
# sudo ip link set veth1 up
# sudo ip link set veth2 up
# sudo ip link set veth2 master br0
sudo ip address add dev br0 192.168.0.90/24
sudo ip link set dev br0 up

