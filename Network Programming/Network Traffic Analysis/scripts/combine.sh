#!/bin/bash

# the path to the folder containing the pcapng files
pcapng_folder="/network2/ec2/captures/session-1508862601"

# the path to the output file
output_file="output.txt"

# get the total number of pcapng files in the folder
total=$(find "$pcapng_folder" -name "*.pcapng" | wc -l)

# set the initial counter to 0
counter=0

# print the path to the pcapng files
echo "Searching for pcapng files in: $pcapng_folder"

# loop through each pcapng file in the folder and its subdirectories
find "$pcapng_folder" -name "*.pcapng" | while read file; do
    # extract the filename without the path and extension
    filename=$(basename "$file" .pcapng)
    # add a label for the current file
    echo -e "\n\n------$filename.pcapng------\n\n" >> "$output_file"
    # run the tshark command to extract conversations
    tshark -r "$file" -qz conv,tcp >> "$output_file" 2>&1
    # check for errors
    if [ $? -ne 0 ]; then
        echo "Error processing file: $file"
    fi
    # increment the counter by 1
    counter=$((counter+1))
    # display the progress
    echo "Processed $counter out of $total files."
done

echo "Finished processing pcapng files."

