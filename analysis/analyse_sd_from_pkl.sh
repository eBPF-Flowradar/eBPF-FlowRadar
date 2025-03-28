#!/bin/bash

set -e

LOGS_PATH="/home/anonymous/eBPF-FlowRadar"
SD_LOGS="sd_logs.csv"
DETECT_LOGS="detect.csv"
DETECT_WINDOW_LOGS="window_detect.csv"
ANALYSIS_FILE="analysis_sd_pkl.txt"
RES_DIR="results/$(date +"%Y-%m-%d:%H-%M-%S")_sd_pkl"
PY_SCRIPT="analysis/analyse_sd_from_pkl.py"

scp anonymous@192.168.122.246:$LOGS_PATH/$SD_LOGS ./
ssh anonymous@192.168.122.246 "rm $LOGS_PATH/$SD_LOGS"
scp anonymous@192.168.122.246:$LOGS_PATH/$DETECT_LOGS ./
ssh anonymous@192.168.122.246 "rm $LOGS_PATH/$DETECT_LOGS"
scp anonymous@192.168.122.246:$LOGS_PATH/$DETECT_WINDOW_LOGS ./
ssh anonymous@192.168.122.246 "rm $LOGS_PATH/$DETECT_WINDOW_LOGS"
python3 $PY_SCRIPT $* > $ANALYSIS_FILE
cat $ANALYSIS_FILE

# add extra info
if [ $# -ne 0 ]; then
	RES_DIR+="_$*"
fi

# Create a new directory with the timestamp
mkdir "$RES_DIR"

# Move the files to the new directory
mv "$SD_LOGS" "$DETECT_LOGS" "$ANALYSIS_FILE" "$DETECT_WINDOW_LOGS" "./$RES_DIR/"

echo -e "\nFiles moved to directory: $RES_DIR"

