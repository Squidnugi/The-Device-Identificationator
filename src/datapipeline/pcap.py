"""PCAP ingestion pipeline: raw packet files to feature-engineered DataFrames."""
import os
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import entropy
from scapy.all import rdpcap, IP, TCP, UDP, Ether, DNS, DNSQR, Raw
from tqdm import tqdm

ROLLING_WINDOW = 100  # packets to look back per device for rolling features


def _rolling_nunique(arr):
    """Return the count of unique values in *arr*."""
    if len(arr) == 0:
        return 0.0
    return float(len(np.unique(arr)))


def _rolling_entropy(arr):
    """Return the Shannon entropy of positive values in *arr* using a histogram approximation."""
    arr = arr[arr > 0]
    if len(arr) == 0:
        return 0.0
    hist, _ = np.histogram(arr, bins=min(20, len(arr)))
    if hist.sum() == 0:
        return 0.0
    nonzero_probs = hist / hist.sum()
    nonzero_probs = nonzero_probs[nonzero_probs > 0]
    return float(entropy(nonzero_probs))


def _rolling_mode(arr):
    """Return the most frequently occurring value in *arr*."""
    if len(arr) == 0:
        return 0.0
    vals, counts = np.unique(arr, return_counts=True)
    return float(vals[np.argmax(counts)])


def load_datasets(path):
    """Load a dataset from a CSV or PCAP file into a DataFrame.

    Parameters
    ----------
    path : str
        Path to a .csv, .pcap, or .pcapng file.

    Returns
    -------
    pd.DataFrame
    """
    if path.endswith(".csv"):
        return pd.read_csv(path)
    if path.endswith(".pcap") or path.endswith(".pcapng"):
        return pcap_to_dataframe(path)
    raise ValueError(f"Unsupported file format: {path}")


def _extract_packet_fields(pkt, idx):
    """Extract layer fields from a single Scapy packet into a flat dictionary.

    Parameters
    ----------
    pkt : scapy.packet.Packet
        A single captured packet.
    idx : int
        Packet index used as the Packet ID field.

    Returns
    -------
    dict
        Flat mapping of field names to extracted values.
    """
    packet_info = {
        "Packet ID": idx,
        "TIME": float(pkt.time) if hasattr(pkt, "time") else 0,
        "Size": len(pkt),
    }

    if Ether in pkt:
        eth = pkt[Ether]
        packet_info["eth.src"] = eth.src
        packet_info["eth.dst"] = eth.dst
    else:
        packet_info["eth.src"] = "N/A"
        packet_info["eth.dst"] = "N/A"

    if IP in pkt:
        ip = pkt[IP]
        packet_info["IP.src"] = ip.src
        packet_info["IP.dst"] = ip.dst
        packet_info["IP.proto"] = ip.proto
        packet_info["IP.ttl"] = ip.ttl
        packet_info["IP.len"] = ip.len

        if TCP in pkt:
            tcp = pkt[TCP]
            packet_info["port.src"] = tcp.sport
            packet_info["port.dst"] = tcp.dport
            packet_info["TCP.flags"] = tcp.flags
            packet_info["TCP.window"] = tcp.window
        elif UDP in pkt:
            udp = pkt[UDP]
            packet_info["port.src"] = udp.sport
            packet_info["port.dst"] = udp.dport
            packet_info["TCP.flags"] = 0
            packet_info["TCP.window"] = 0
        else:
            packet_info["port.src"] = 0
            packet_info["port.dst"] = 0
            packet_info["TCP.flags"] = 0
            packet_info["TCP.window"] = 0
    else:
        packet_info["IP.src"] = "N/A"
        packet_info["IP.dst"] = "N/A"
        packet_info["IP.proto"] = 0
        packet_info["IP.ttl"] = 0
        packet_info["IP.len"] = 0
        packet_info["port.src"] = 0
        packet_info["port.dst"] = 0
        packet_info["TCP.flags"] = 0
        packet_info["TCP.window"] = 0

    packet_info["Is_DNS"] = 0
    packet_info["DNS_Query"] = None
    if UDP in pkt and DNS in pkt:
        try:
            dns = pkt[DNS]
            if dns.qr == 0 and DNSQR in pkt:
                packet_info["Is_DNS"] = 1
                dnsqr = pkt[DNSQR]
                packet_info["DNS_Query"] = (
                    dnsqr.qname.decode()
                    if isinstance(dnsqr.qname, bytes)
                    else str(dnsqr.qname)
                )
        except Exception as exc:
            print(f"Error extracting DNS query: {exc}")

    return packet_info


def pcap_to_dataframe(pcap_path):
    """Convert a PCAP file to a DataFrame by extracting per-packet fields.

    Extracts Ethernet, IP, TCP/UDP, and DNS layers. Returns an empty
    DataFrame if the file cannot be read.

    Parameters
    ----------
    pcap_path : str
        Path to the .pcap or .pcapng file.

    Returns
    -------
    pd.DataFrame
        One row per packet with raw layer fields as columns.
    """
    packets_data = []

    try:
        print(f"\n{'='*70}")
        print(f"Reading PCAP file with Scapy: {pcap_path}")
        print(f"{'='*70}\n")

        packets = rdpcap(pcap_path)
        total_packets = len(packets)
        print(f"Total packets to process: {total_packets:,}\n")

        for idx, pkt in enumerate(tqdm(
            packets,
            desc="Extracting packets",
            unit=" packets",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        )):
            try:
                packets_data.append(_extract_packet_fields(pkt, idx))
            except Exception as exc:
                print(f"Error processing packet: {exc}")
                continue

    except FileNotFoundError:
        print(f"Error: PCAP file not found: {pcap_path}")
        if os.path.exists("data/raw/"):
            print("\nAvailable files in data/raw/:")
            for filename in os.listdir("data/raw/"):
                try:
                    size_mb = os.path.getsize(f"data/raw/{filename}") / (1024 * 1024)
                    print(f"  - {filename} ({size_mb:.1f} MB)")
                except Exception as exc:
                    print(f"Error getting size for {filename}: {exc}")
        return pd.DataFrame()
    except Exception as exc:
        print(f"Error reading PCAP file: {exc}")
        traceback.print_exc()
        return pd.DataFrame()

    df = pd.DataFrame(packets_data)
    if not df.empty:
        print(f"\n✓ Successfully extracted {len(df):,} packets from {pcap_path}\n")
    return df


def add_labels(data):
    """Add device-type labels based on known MAC addresses for model training.

    The MAC-to-device-type mapping is hardcoded. To train on new device types,
    add MAC addresses to the appropriate key in the ``labels`` dictionary.

    Parameters
    ----------
    data : pd.DataFrame
        Packet DataFrame containing an ``eth.src`` column.

    Returns
    -------
    pd.DataFrame
        Same DataFrame with a ``Device_Type`` column added. Rows whose source
        MAC is not in the mapping receive ``None`` and should be dropped before
        training (see ``process_pcap``).
    """
    labels = {
        "Smart Home": ["d0:52:a8:00:67:5e"],
        "Assistant": ["44:65:0d:56:cc:d3"],
        "Security Camera": [
            "70:ee:50:18:34:43", "f4:f2:6d:93:51:f1", "00:16:6c:ab:6b:88",
            "30:8c:fb:2f:e4:b2", "00:62:6e:51:27:2e", "e8:ab:fa:19:de:4f",
            "30:8c:fb:b6:e4:b5",
        ],
        "Baby Monitor": ["00:24:e4:11:18:a8"],
        "Smart Plug": ["ec:1a:59:79:f4:89", "50:c7:bf:00:56:39"],
        "Speaker": ["74:c6:3b:29:d7:1d", "18:b7:9e:02:20:44"],
        "Sensor": ["ec:1a:59:83:28:11", "70:ee:50:03:b8:ac", "00:24:e4:20:28:c6"],
        "Smoke Alarm": ["18:b4:30:25:be:e4"],
        "Scale": ["00:24:e4:1b:6f:96"],
        "Blood Pressure Monitor": ["74:6a:89:00:2e:25"],
        "Smart Bulb": ["d0:73:d5:01:83:08"],
        "Smart Frame": ["e0:76:d0:33:bb:85"],
        "Printer": ["70:5a:0f:e4:9b:c0"],
        "Phone/Tablet": [
            "08:21:ef:3b:fc:e3", "40:f3:08:ff:1e:da",
            "b4:ce:f6:a7:a3:c2", "d0:a6:37:df:a1:e1",
        ],
        "Laptop/PC": ["74:2f:68:81:69:42", "ac:bc:32:d4:6f:2f "],
        "Router": ["14:cc:20:51:33:ea"],
        "Apple": ["f4:5c:89:93:cc:85"],
    }
    data["Device_Type"] = None
    for device_type, mac_addresses in labels.items():
        for mac in mac_addresses:
            data.loc[data["eth.src"] == mac, "Device_Type"] = device_type
    return data


def calculate_packet_rate(data):
    """Calculate rolling packet rate and related per-device statistics.

    Parameters
    ----------
    data : pd.DataFrame
        Raw packet DataFrame with ``eth.src`` and ``Size`` columns.

    Returns
    -------
    pd.DataFrame
        Same DataFrame sorted by [eth.src, TIME] with new feature columns appended.
    """
    print("\nCalculating packet rate and features...")

    data = data.sort_values(["eth.src", "TIME"]).reset_index(drop=True)

    with tqdm(total=6, desc="Feature extraction", unit=" features") as pbar:
        data["Packet_Rate"] = data.groupby("eth.src").cumcount() + 1
        pbar.update(1)

        data["Packet_Rate"] = data.groupby("eth.src")["Packet_Rate"].transform(
            lambda x: x.rolling(window=10, min_periods=1).mean()
        )
        pbar.update(1)

        data["Avg_Size_Per_Device"] = data.groupby("eth.src")["Size"].transform(
            lambda x: x.rolling(window=ROLLING_WINDOW, min_periods=1).mean()
        )
        data["Avg_Size_Per_Device"] = data["Avg_Size_Per_Device"] / data["Size"].max()
        pbar.update(1)

        data["_is_tcp"] = (data["IP.proto"] == 6).astype(float)
        data["TCP_Ratio"] = data.groupby("eth.src")["_is_tcp"].transform(
            lambda x: x.rolling(window=ROLLING_WINDOW, min_periods=1).mean()
        )
        data.drop(columns=["_is_tcp"], inplace=True)
        pbar.update(1)

        data["Port_Diversity"] = data.groupby("eth.src")["port.dst"].transform(
            lambda x: x.rolling(window=ROLLING_WINDOW, min_periods=1).apply(
                _rolling_nunique, raw=True
            )
        )
        pbar.update(1)

        data["Src_Port_Variance"] = data.groupby("eth.src")["port.src"].transform(
            lambda x: x.rolling(window=ROLLING_WINDOW, min_periods=2).std().fillna(0)
        )
        pbar.update(1)

    print("[OK] Features calculated successfully\n")
    return data


def calculate_advanced_features(data):
    """Calculate advanced flow-level and statistical features per source MAC.

    Parameters
    ----------
    data : pd.DataFrame
        Packet DataFrame after ``calculate_packet_rate`` (already sorted by
        [eth.src, TIME]).

    Returns
    -------
    pd.DataFrame
        Same DataFrame with additional feature columns appended.
        ``Unique_Src_IPs`` and ``Unique_Dst_IPs`` are intentionally omitted —
        IP-based counts are network-topology-dependent and do not generalise.
    """
    print("\nCalculating advanced features...")

    with tqdm(total=5, desc="Advanced features", unit=" features") as pbar:
        data["TTL_Mode"] = data.groupby("eth.src")["IP.ttl"].transform(
            lambda x: x.rolling(window=ROLLING_WINDOW, min_periods=1).apply(
                _rolling_mode, raw=True
            )
        )
        pbar.update(1)

        data["Size_Entropy"] = data.groupby("eth.src")["Size"].transform(
            lambda x: x.rolling(window=ROLLING_WINDOW, min_periods=1).apply(
                _rolling_entropy, raw=True
            )
        )
        pbar.update(1)

        data["Size_Std_Dev"] = data.groupby("eth.src")["Size"].transform(
            lambda x: x.rolling(window=ROLLING_WINDOW, min_periods=2).std().fillna(0)
        )
        pbar.update(1)

        data["Inter_Packet_Time"] = data.groupby("eth.src")["TIME"].transform(
            lambda x: x.diff().fillna(0)
        )
        pbar.update(1)

        data["Avg_Inter_Packet_Time"] = data.groupby("eth.src")["Inter_Packet_Time"].transform(
            lambda x: x.rolling(window=ROLLING_WINDOW, min_periods=1).mean()
        )
        pbar.update(1)

    print("[OK] Advanced features calculated successfully\n")
    return data


def clean_data(df):
    """Remove malformed packets and fill remaining missing values with zero.

    Parameters
    ----------
    df : pd.DataFrame
        Feature-engineered packet DataFrame.

    Returns
    -------
    pd.DataFrame
        Cleaned DataFrame with critical-identifier rows removed and
        numeric NaNs filled with 0. The ``Device_Type`` column (if present)
        is excluded from the fill so labelled None values are not overwritten.
    """
    initial_count = len(df)
    print(f"\nInitial row count: {initial_count:,}")

    critical_cols = ["eth.src", "eth.dst", "IP.src", "IP.dst"]
    df = df[~((df[critical_cols] == "N/A").any(axis=1))]
    print(f"After removing rows with missing network identifiers (N/A): {len(df):,}")

    df = df.drop_duplicates()
    print(f"After removing duplicates: {len(df):,}")

    # Preserve Device_Type labels; only fill numeric/feature NaNs.
    label_col = "Device_Type"
    if label_col in df.columns:
        fill_cols = [col for col in df.columns if col != label_col]
        df[fill_cols] = df[fill_cols].fillna(0)
    else:
        df = df.fillna(0)

    removed_count = initial_count - len(df)
    print(f"\n✓ Cleaned data: removed {removed_count:,} rows ({100 * removed_count / initial_count:.1f}%)\n")
    return df


def save_dataframe_to_csv(df, output_path):
    """Write a DataFrame to a CSV file.

    Parameters
    ----------
    df : pd.DataFrame
        Data to save.
    output_path : str
        Destination file path.

    Returns
    -------
    None

    Raises
    ------
    OSError
        If the file cannot be written.
    """
    try:
        df.to_csv(output_path, index=False)
        print(f"DataFrame saved to {output_path}")
    except OSError as exc:
        print(f"Error saving DataFrame to CSV: {exc}")
        raise


def process_pcap(file=None, save_to_csv=True, train=False):
    """Run the full PCAP processing pipeline and optionally save to CSV.

    Parameters
    ----------
    file : str
        Filename (relative to ``data/raw/``) or absolute/relative path to a
        .pcap or .pcapng file.
    save_to_csv : bool
        When True the extracted DataFrame is saved to ``data/processed/``.
        When False the DataFrame is returned directly (required for classification).
    train : bool
        When True, device-type labels are added from the hardcoded MAC map and
        unlabelled rows are dropped before returning.

    Returns
    -------
    pd.DataFrame or None
        The processed DataFrame when ``save_to_csv=False``; None otherwise.
    """
    if not file:
        print("Error: No PCAP file specified for processing.")
        return None
    raw_path = "data/raw/"
    processed_path = "data/processed/"
    if os.path.isabs(file) or os.path.exists(file):
        pcap_path = file
    else:
        pcap_path = os.path.join(raw_path, file)

    pcap_name = os.path.basename(pcap_path)
    pcap_stem, _ = os.path.splitext(pcap_name)
    output_csv_path = os.path.join(processed_path, f"{pcap_stem}_extracted.csv")
    Path(processed_path).mkdir(parents=True, exist_ok=True)

    time_start = time.time()
    print(f"\n{'='*70}")
    print("PCAP Processing Pipeline")
    print(f"{'='*70}")
    print(f"Started: {time.ctime(time_start)}\n")

    df = pcap_to_dataframe(pcap_path)

    if df.empty:
        print("Warning: PCAP produced no usable packets.")
        return None

    df = calculate_packet_rate(df)
    df = calculate_advanced_features(df)

    if train:
        print("Adding device labels...")
        df = add_labels(df)
        # Drop packets with no matching label so the target column stays clean.
        df = df[df["Device_Type"].notna()].copy()
        print(f"✓ Labels added ({len(df):,} labelled rows retained)\n")

    df = clean_data(df)

    if save_to_csv:
        print("Saving to CSV...")
        save_dataframe_to_csv(df, output_csv_path)
        print("✓ CSV saved\n")

    time_end = time.time()
    elapsed = time_end - time_start
    print(f"{'='*70}")
    print("✓ Processing completed!")
    print(f"Total time: {elapsed:.1f} seconds ({elapsed / 60:.1f} minutes)")
    print(f"{'='*70}\n")

    if not save_to_csv:
        return df
    return None


def process_and_merge_pcaps(
    raw_dir="data/raw/train_files",
    merged_output_path="data/processed/merged_training_extracted.csv",
    include_patterns=("*.pcap", "*.pcapng"),
    save_individual_csv=True,
):
    """Process every PCAP in a directory and merge into one training dataset.

    Parameters
    ----------
    raw_dir : str
        Directory containing the raw .pcap / .pcapng training files.
    merged_output_path : str
        Destination path for the merged output CSV.
    include_patterns : tuple[str]
        Glob patterns used to discover files in *raw_dir*.
    save_individual_csv : bool
        When True, also save a per-file extracted CSV alongside the merged one.

    Returns
    -------
    tuple[None, str]
        Always (None, merged_output_path) for pipeline compatibility.
    """
    raw_path = Path(raw_dir)
    if not raw_path.exists():
        raise FileNotFoundError(f"Raw directory not found: {raw_path}")

    pcap_files = []
    for pattern in include_patterns:
        pcap_files.extend(raw_path.glob(pattern))
    pcap_files = sorted(set(pcap_files))

    if not pcap_files:
        raise FileNotFoundError(
            f"No PCAP files found in {raw_path} using patterns: {include_patterns}"
        )

    processed_dir = Path("data/processed")
    processed_dir.mkdir(parents=True, exist_ok=True)

    merged_path = Path(merged_output_path)
    merged_path.parent.mkdir(parents=True, exist_ok=True)
    if merged_path.exists():
        merged_path.unlink()

    total_rows = 0
    wrote_header = False

    print(f"Found {len(pcap_files)} PCAP file(s) to process.")
    for pcap_file in pcap_files:
        print(f"\nProcessing: {pcap_file}")
        df = process_pcap(file=str(pcap_file), save_to_csv=False, train=True)

        if df is None or df.empty:
            print(f"Skipping empty/failed dataset: {pcap_file}")
            continue

        if save_individual_csv:
            single_output = processed_dir / f"{pcap_file.stem}_extracted.csv"
            save_dataframe_to_csv(df, str(single_output))

        df.to_csv(merged_path, mode="a", index=False, header=not wrote_header)
        wrote_header = True
        total_rows += len(df)

    if total_rows == 0:
        raise ValueError("No valid processed datasets were produced from the supplied PCAP files.")

    print(f"\nMerged dataset created: {merged_path}")
    print(f"Merged rows: {total_rows:,}")

    return str(merged_path)


if __name__ == "__main__":
    process_pcap(file="fart.pcap", save_to_csv=False, train=False)
