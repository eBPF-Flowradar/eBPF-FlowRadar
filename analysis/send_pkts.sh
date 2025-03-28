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

PPS=$(echo "scale=5; $PACKET_COUNT / $DURATION" | bc)

# Use tcpreplay to send packets at the calculated PPS rate
sudo tcpreplay --pps="$PPS" -i br0 "$PCAP_FILE"

# Print some useful information
echo "Sent $PACKET_COUNT packets from $PCAP_FILE over $DURATION seconds ($PPS packets per second)"
