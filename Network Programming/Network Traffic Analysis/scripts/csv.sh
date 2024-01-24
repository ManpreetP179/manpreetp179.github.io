#!/bin/bash

# the path to the output.txt file
output_file="output.txt"

# the path to the output CSV file
csv_file="output.csv"

# create the header row for the CSV file
echo "source_ip,source_port,dest_ip,dest_port,num_packets_sent,num_bytes_sent,num_packets_received,num_bytes_received,total_packets,total_bytes,duration,avg_packets_per_sec" > $csv_file

# loop through each line in the output.txt file
while read line; do
    # skip lines that don't have the conversation data
    if [[ ! $line =~ "<->" ]]; then


        continue
    fi
    # extract the relevant columns from the line
    source_ip_port=$(echo $line | awk '{print $1}')
    dest_ip_port=$(echo $line | awk '{print $3}')
    num_packets_sent=$(echo $line | awk '{print $4}')
    num_bytes_sent=$(echo $line | awk '{print $5}')
    num_packets_received=$(echo $line | awk '{print $6}')
    num_bytes_received=$(echo $line | awk '{print $7}')
    total_packets=$(echo $line | awk '{print $8}')
    total_bytes=$(echo $line | awk '{print $9}')
    duration=$(echo $line | awk '{print $10}')
    avg_packets_per_sec=$(echo $line | awk '{print $11}')
    # split the source IP address and port number
    source_ip=$(echo $source_ip_port | cut -d: -f1)
    source_port=$(echo $source_ip_port | cut -d: -f2)
    # split the destination IP address and port number
    dest_ip=$(echo $dest_ip_port | cut -d: -f1)
    dest_port=$(echo $dest_ip_port | cut -d: -f2)
    # write the extracted data to the CSV file
    echo "$source_ip,$source_port,$dest_ip,$dest_port,$num_packets_sent,$num_bytes_sent,$num_packets_received,$num_bytes_received,$total_packets,$total_bytes,$duration,$avg_packets_per_sec" >> $csv_file
done < $output_file

