#!/bin/bash

# Set the directory containing the pcap files
PCAP_DIR="/network2/ec2/captures/session-1508862601"

# Set the Suricata configuration file
SURICATA_CONFIG="/etc/suricata/suricata.yaml"

# Loop through each pcap file in the directory
for file in $PCAP_DIR/*.pcapng
do
    # Run Suricata on the pcap file and generate alerts
    suricata -c $SURICATA_CONFIG -r $file -l "/var/log/suricata/"

    # Check if any alerts were generated
    if [ -f "/var/log/suricata/fast.log" ]
    then
        # Print the alerts to the console
        cat "/var/log/suricata/fast.log"
	echo $file
    fi
done

