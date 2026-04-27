"""Capture live network traffic and optionally process it into extracted CSV data."""

from datetime import datetime
from pathlib import Path
import os

from scapy.all import sniff, wrpcap

from .pcap import process_pcap


def _default_capture_name() -> str:
    """Build a timestamped pcap filename for raw captures."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"capture_{timestamp}.pcap"


def _resolve_output_file(output_file: str | None) -> Path:
    """Resolve an output pcap path and ensure parent directory exists."""
    if output_file:
        target = Path(output_file)
    else:
        target = Path("data/raw") / _default_capture_name()

    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def capture_packets_windows(packet_count: int = 100, output_file: str | None = None) -> str | None:
    """Capture packets on Windows and save them to a pcap file.

    Parameters
    ----------
    packet_count : int
        Number of packets to capture.
    output_file : str or None
        Destination pcap path; a timestamped name under ``data/raw/`` is used
        when None.

    Returns
    -------
    str or None
        Path to the saved pcap file, or None if capture failed.
    """
    pcap_path = _resolve_output_file(output_file)
    try:
        print("Capturing packets on Windows...")
        packets = sniff(count=packet_count)
        wrpcap(str(pcap_path), packets)
        print(f"Packets saved to {pcap_path}")
        return str(pcap_path)
    except Exception as exc:
        print(f"Error capturing packets: {exc}")
        return None


def capture_packets_linux(
    interface: str = "eth0",
    packet_count: int = 100,
    output_file: str | None = None,
) -> str | None:
    """Capture packets on a Linux/Unix interface and save them to a pcap file.

    Parameters
    ----------
    interface : str
        Network interface name to listen on (e.g. ``"eth0"``).
    packet_count : int
        Number of packets to capture.
    output_file : str or None
        Destination pcap path; a timestamped name under ``data/raw/`` is used
        when None.

    Returns
    -------
    str or None
        Path to the saved pcap file, or None if capture failed or permissions
        are insufficient.
    """
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Error: Packet capture requires root privileges. Please run the program as root or with sudo.")
        return None

    pcap_path = _resolve_output_file(output_file)
    try:
        print(f"Capturing {packet_count} packets on interface {interface}...")
        packets = sniff(iface=interface, count=packet_count)
        wrpcap(str(pcap_path), packets)
        print(f"Packets saved to {pcap_path}")
        return str(pcap_path)
    except Exception as exc:
        print(f"Error capturing packets: {exc}")
        return None


def capture_packets(packets: int = 100, output_file: str | None = None, interface: str = "eth0") -> str | None:
    """Capture packets using the appropriate OS-specific method.

    Parameters
    ----------
    packets : int
        Number of packets to capture.
    output_file : str or None
        Destination pcap path; auto-generated when None.
    interface : str
        Network interface for Linux/Unix capture (ignored on Windows).

    Returns
    -------
    str or None
        Path to the saved pcap file, or None if capture failed.
    """
    if os.name == "nt":
        return capture_packets_windows(packet_count=packets, output_file=output_file)
    return capture_packets_linux(interface=interface, packet_count=packets, output_file=output_file)


def capture_and_process_packets(
    packet_count: int = 100,
    output_file: str | None = None,
    interface: str = "eth0",
) -> dict[str, str] | None:
    """Capture live traffic to a pcap file and produce a processed extracted CSV.

    Parameters
    ----------
    packet_count : int
        Number of packets to capture.
    output_file : str or None
        Destination pcap path; auto-generated when None.
    interface : str
        Network interface for Linux/Unix capture (ignored on Windows).

    Returns
    -------
    dict[str, str] or None
        Dictionary with keys ``pcap_file`` and ``processed_csv`` on success,
        or None if capture or processing failed.
    """
    captured_pcap = capture_packets(packets=packet_count, output_file=output_file, interface=interface)
    if not captured_pcap:
        return None

    pcap_name = Path(captured_pcap).name
    process_pcap(file=pcap_name, save_to_csv=True)

    processed_csv = Path("data/processed") / (Path(pcap_name).stem + "_extracted.csv")
    if not processed_csv.exists():
        return None

    return {
        "pcap_file": captured_pcap,
        "processed_csv": str(processed_csv),
    }
