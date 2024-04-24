#!/bin/bash


REMOTE_HOME_FOLDER="/home/anonymous/eBPF-FlowRadar"
REM_INTERFACE="enp7s0"
HOST_INTERFACE="veth1"
#PCAP_FILE="analysis/pcap_files/output_with_eth.pcap"
SLEEP_SEC=10
DECODABLE_CSV_FILE="decodable.csv"
PCAP_FOLDER="/home/anonymousa/Projects/eBPF-FlowRadar/analysis/pcap_files/attack_files/cia"

#delete before analysis
sudo rm $DECODABLE_CSV_FILE

#exit on error
set -e

# Loop through each file in the folder
for file in "$PCAP_FOLDER"/*; do
    # Check if the file is a regular file (not a directory)
    if [ -f "$file" ]; then

        echo "Processing file: $file"

	#start flowradar
	echo "Start flowradar"
	ssh root@192.168.122.246 "cd $REMOTE_HOME_FOLDER;nohup ./flowradar $REM_INTERFACE > /dev/null 2>&1 </dev/null &" 

	sleep 3

	#start tcp replay
	echo "Start tcpreplay"
	sudo tcpreplay -i $HOST_INTERFACE $file 


	#sleep
	echo "Sleep for $SLEEP_SEC seconds "
	sleep $SLEEP_SEC


	#Stop flowradar
	echo "Stopping flowradar"
	ssh root@192.168.122.246 "pkill -f flowradar" #remote

	


	#Do analysis
	echo "Start analysis"
	./analysis/analyse_sd_from_pkl.sh $(basename "$file")

	echo "$file Done"

    fi
done

echo "Completed analysis"


