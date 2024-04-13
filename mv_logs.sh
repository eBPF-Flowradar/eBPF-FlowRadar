#!/bin/bash

set -e

# Define the files to move
file1="cd_logs.csv"
file2="sniff.csv"

# Create a timestamp
timestamp="results/$(date +%Y%m%d%H%M%S)"

# Create a new directory with the timestamp
mkdir "$timestamp"

# Move the files to the new directory
mv "$file1" "$file2" "./$timestamp/"

echo "Files moved to directory: $timestamp"

