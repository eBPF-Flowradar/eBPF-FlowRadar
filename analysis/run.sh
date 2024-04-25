#!/bin/bash


REMOTE_HOME_FOLDER="/home/anonymous/eBPF-FlowRadar"
REM_INTERFACE="enp7s0"
HOST_INTERFACE="veth1"
SLEEP_SEC=10
DECODABLE_CSV_FILE="decodable.csv"
PARENT_FOLDER="/home/anonymousa/Projects/eBPF-FlowRadar/analysis/pcap_files"
FINAL_RESULTS_FOLDER="/home/anonymousa/Projects/eBPF-FlowRadar/final_results"
RESULTS_FOLDER="/home/anonymousa/Projects/eBPF-FlowRadar/results"

#delete before analysis
sudo rm $DECODABLE_CSV_FILE

#exit on error
set -e

find "$PARENT_FOLDER" -maxdepth 1 -mindepth 1 -type d -print0 |
while IFS= read -r -d '' PCAP_FOLDER; do
    echo "Processing folder: $folder"

    # Loop through each file in the folder
    for file in "$PCAP_FOLDER"/*; do
	# Check if the file is a regular file (not a directory)
	if [ -f "$file" ]; then

	    echo "Processing file: $file"

	    #start flowradar
	    echo "Start flowradar"
	    ssh root@192.168.122.246 "cd $REMOTE_HOME_FOLDER;nohup ./flowradar $REM_INTERFACE > /dev/null 2>&1 </dev/null &"  </dev/null

	    sleep 3

	    #start tcp replay
	    echo "Start tcpreplay"
	    sudo tcpreplay -i $HOST_INTERFACE $file 


	    #sleep
	    echo "Sleep for $SLEEP_SEC seconds "
	    sleep $SLEEP_SEC


	    #Stop flowradar
	    echo "Stopping flowradar"
	    ssh root@192.168.122.246 "pkill -f flowradar" </dev/null  #remote

	    


	    #Do analysis
	    echo "Start analysis"
	    ./analysis/analyse_sd_from_pkl.sh $(basename "$file") </dev/null

	    echo "$file Done"

	fi
    done
    
    folder_name=$(basename "$PCAP_FOLDER") 
    mkdir $FINAL_RESULTS_FOLDER/$folder_name
    mv $RESULTS_FOLDER/*  $FINAL_RESULTS_FOLDER/$folder_name
    mv $DECODABLE_CSV_FILE $FINAL_RESULTS_FOLDER/$folder_name
    echo
    echo "Completed analysis of $folder_name"
    echo
done

echo "All analysis done"
