# Import Scapy
from scapy.all import sniff

def packet_handler(packet):
    # Extract relevant information from the packet
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = packet["IP"].proto
        print(f"Packet: Source IP {src_ip} -> Destination IP {dst_ip} (Protocol: {protocol})")

# Capture 10 packets from the default network interface
sniff(filter="", prn=packet_handler, count=10)
