"""
This module captures live network traffic and saves it to a pcap file for further analysis.
"""
from scapy.all import sniff, wrpcap
import os


def capture_packets_windows(packet_count=100):
	"""Capture packets on a specified interface and save to a pcap file (Windows version)."""
	try:
		print("Capturing packets on Windows...")
		packets = sniff(packet_count)
		wrpcap("data/raw/demo_capture.pcap", packets)
		print("Packets saved to data/raw/demo_capture.pcap")
	except Exception as e:
		print(f"Error capturing packets: {e}")


def capture_packets_linux(interface="eth0", packet_count=100, output_file="data/raw/demo_capture.pcap"):
	"""Capture packets on a specified interface and save to a pcap file (Linux version)."""
	if os.geteuid() != 0:
		print("Error: Packet capture requires root privileges. Please run the program as root or with sudo.")
		return
	try:
		print(f"Capturing {packet_count} packets on interface {interface}...")
		packets = sniff(iface=interface, count=packet_count)
		wrpcap(output_file, packets)
		print(f"Packets saved to {output_file}")
	except Exception as e:
		print(f"Error capturing packets: {e}")


def capture_packets(packets=100):
	"""Capture packets based on the operating system."""
	if os.name == 'nt':  # Windows
		capture_packets_windows(packet_count=packets)
	else:  # Linux and other Unix-like systems
		capture_packets_linux(packet_count=packets)