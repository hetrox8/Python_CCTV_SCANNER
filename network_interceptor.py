import os
import sys
import socket
import threading
import logging
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Function to intercept and modify packets
def intercept_packet(packet):
    # Modify the packet as needed
    # For example, you can inspect and modify packet headers, payloads, etc.
    # Here, we just print the packet's summary
    print(packet.summary())

# Function to intercept and modify incoming packets
def intercept_incoming_packets():
    # Create a sniffing thread to intercept incoming packets
    sniff(filter="", prn=intercept_packet, store=0)

# Function to intercept and modify outgoing packets
def intercept_outgoing_packets():
    # Create a socket to intercept outgoing packets
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.bind(('', 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except OSError as e:
        print("Error creating raw socket:", e)
        sys.exit(1)

    # Intercept outgoing packets and call the intercept_packet function
    while True:
        packet, _ = s.recvfrom(65565)
        intercept_packet(IP(packet))

# Main function to start interception
def start_interception():
    # Start a thread to intercept incoming packets
    incoming_thread = threading.Thread(target=intercept_incoming_packets)
    incoming_thread.daemon = True
    incoming_thread.start()

    # Start intercepting outgoing packets
    intercept_outgoing_packets()

if __name__ == "__main__":
    # Ensure script is run as root
    if os.geteuid() != 0:
        print("This script must be run as root to intercept network traffic.")
        sys.exit(1)

    # Start interception
    start_interception()
