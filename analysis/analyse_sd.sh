#!/bin/bash

set -e

LOGS_PATH="/home/anonymous/eBPF-FlowRadar/sd_logs.csv"
ANALYSIS_FILE="analysis_sd.txt"
RES_DIR="results/$(date +"%Y-%m-%d:%H-%M-%S")_sd"
PY_SCRIPT="analysis/analyse_sd.py"

scp anonymous@192.168.122.246:$LOGS_PATH ./
ssh anonymous@192.168.122.246 "rm $LOGS_PATH"
python3 $PY_SCRIPT > $ANALYSIS_FILE
cat $ANALYSIS_FILE

# add extra info
if [ $# -ne 0 ]; then
	RES_DIR+="_$*"
fi

# Create a new directory with the timestamp
mkdir "$RES_DIR"

# Move the files to the new directory
mv "sd_logs.csv" "sniff.csv" "$ANALYSIS_FILE" "./$RES_DIR/"

echo -e "\nFiles moved to directory: $RES_DIR"

