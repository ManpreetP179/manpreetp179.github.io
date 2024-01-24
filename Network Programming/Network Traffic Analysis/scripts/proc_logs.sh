#!/bin/bash

# Get the folder containing the log files
log_folder="$1"

# Get the IP address to search for
ip_address="$2"

# Create an output file name based on the IP address
output_file="${ip_address//./_}.txt"

# Function to search for log files recursively
search_logs() {
    local search_dir="$1"
    
    # Loop through all files and directories in the search directory
    for item in "$search_dir"/*; do
        if [ -d "$item" ]; then
            # If the item is a directory, recursively search it for log files
            search_logs "$item"
        elif [ -f "$item" ]; then
            # If the item is a file, use grep to search for the IP address
            # and print a separator with the filename before each match
            grep_output="$(grep -h "$ip_address" "$item")"
            if [ -n "$grep_output" ]; then
                printf "\n=== %s ===\n%s\n\n" "$item" "$grep_output" >> "$output_file"
            fi
        fi
    done
}

# Call the search_logs function with the specified directory
search_logs "$log_folder"

