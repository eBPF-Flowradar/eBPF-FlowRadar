#!/bin/bash

set -e

scp anonymous@192.168.122.246:/home/anonymous/eBPF-FlowRadar/cd_logs.csv ./
python3 analyse.py
