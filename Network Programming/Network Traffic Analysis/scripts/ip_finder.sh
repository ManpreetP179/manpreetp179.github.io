#!/bin/bash

# Usage: ./find_ip.sh <folder_path> <ip_address>

# Check if the correct number of arguments were provided
if [ $# -ne 2 ]; then
  echo "Usage: ./find_ip.sh <folder_path> <ip_address>"
  exit 1
fi

# Check if the folder exists
if [ ! -d "$1" ]; then
  echo "Error: Folder does not exist"
  exit 1
fi

# Loop through all pcapng files in the folder
for file in "$1"/*.pcapng; do
  # Check if the file contains the specified IP address
  if tshark -r "$file" -Y "ip.addr == $2" -T fields -e frame.number | grep -q .; then
    echo "$file"
  fi
done

