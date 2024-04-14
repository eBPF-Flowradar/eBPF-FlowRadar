#!/bin/bash

set -e

scp anonymous@192.168.122.246:/home/anonymous/eBPF-FlowRadar/cd_logs.csv ./
ssh anonymous@192.168.122.246 "rm /home/anonymous/eBPF-FlowRadar/cd_logs.csv"
python3 analyse.py > analysis.txt
cat analysis.txt

# Create a timestamp
timestamp="results/$(date +"%Y-%m-%d:%H-%M-%S")"

# Create a new directory with the timestamp
mkdir "$timestamp"

# Move the files to the new directory
mv "cd_logs.csv" "sniff.csv" "analysis.txt" "./$timestamp/"

echo -e "\nFiles moved to directory: $timestamp"

