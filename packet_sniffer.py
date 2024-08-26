from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].payload

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")

        # Identify the protocol
        if protocol == 6:
            print("Protocol: TCP")
        elif protocol == 17:
            print("Protocol: UDP")
        elif protocol == 1:
            print("Protocol: ICMP")
        else:
            print(f"Protocol: {protocol}")

        print(f"Payload: {payload}")
        print("-" * 50)

# Start sniffing
sniff(prn=packet_callback, filter="ip", store=0)
