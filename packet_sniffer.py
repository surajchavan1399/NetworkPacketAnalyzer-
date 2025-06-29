# packet_sniffer.py
"""
Task 5 - Network Packet Analyzer (Sniffer)
Author: [Your Name]
Description: Captures and analyzes network packets for educational use.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"\n[+] Packet: {src_ip} -> {dst_ip}")
        print(f"    Protocol: {proto}")

        if TCP in packet:
            print("    TCP Packet")
            print(f"    Source Port: {packet[TCP].sport}, Dest Port: {packet[TCP].dport}")
        elif UDP in packet:
            print("    UDP Packet")
            print(f"    Source Port: {packet[UDP].sport}, Dest Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("    ICMP Packet")
        else:
            print("    Other IP Protocol")

        # Payload (limited preview)
        raw = bytes(packet[IP].payload)
        print(f"    Payload (first 32 bytes): {raw[:32]}")

def main():
    print("Starting packet sniffer... Press Ctrl+C to stop.\n")
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
