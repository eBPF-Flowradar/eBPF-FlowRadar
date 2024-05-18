#!/bin/bash

set -e

# Check if the correct number of arguments are provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

PCAP_FILE=$1
DURATION=0.274220

# Verify that the pcap file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: pcap file '$PCAP_FILE' not found"
    exit 1
fi


# Count the total number of packets in the pcap file
PACKET_COUNT=$(capinfos "$PCAP_FILE" | grep "Number of packets ="| tr -d " " | cut -d "=" -f 2)

# Calculate packets per second (PPS)
# if [ "$DURATION" -eq 0 ]; then
#     echo "Error: duration must be greater than 0"
#     exit 1
# fi

PPS=$(echo "scale=2; $PACKET_COUNT / $DURATION" | bc)
# PPS=$((PACKET_COUNT / DURATION))

# Verify that PPS is greater than 0
# if [ "$PPS" -le 0 ]; then
#     echo "Error: calculated PPS is less than or equal to 0"
#     exit 1
# fi

# Use tcpreplay to send packets at the calculated PPS rate
tcpreplay --pps="$PPS" -i br0 "$PCAP_FILE"

# Print some useful information
echo "Sent $PACKET_COUNT packets from $PCAP_FILE over $DURATION seconds ($PPS packets per second)"
