# generate_pcap.py
# This script creates a sample PCAP file for testing

from scapy.all import IP, TCP, UDP, ICMP, wrpcap

packets = []

# Create sample TCP packets
for i in range(10):
    pkt = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=80)
    packets.append(pkt)

# Create sample UDP packets
for i in range(5):
    pkt = IP(src="192.168.1.3", dst="8.8.8.8") / UDP(dport=53)
    packets.append(pkt)

# Create sample ICMP packets
for i in range(3):
    pkt = IP(src="192.168.1.4", dst="1.1.1.1") / ICMP()
    packets.append(pkt)

# Save to PCAP file
wrpcap("test.pcap", packets)

print(" test.pcap file created successfully!")