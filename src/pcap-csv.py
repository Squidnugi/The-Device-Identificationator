import pandas as pd
import time
from scapy.all import rdpcap, IP, TCP, UDP, Ether, DNS, DNSQR, Raw
import os
from tqdm import tqdm
import numpy as np
from scipy.stats import entropy


def load_datasets(path):
    """Load dataset from CSV or PCAP file."""
    if path.endswith('.csv'):
        data = pd.read_csv(path)
    elif path.endswith('.pcap') or path.endswith('.pcapng'):
        data = pcap_to_dataframe(path)
    else:
        raise ValueError(f"Unsupported file format: {path}")
    return data

def pcap_to_dataframe(pcap_path):
    """Convert PCAP file to DataFrame using Scapy with progress bar"""
    
    packets_data = []
    
    try:
        print(f"\n{'='*70}")
        print(f"Reading PCAP file with Scapy: {pcap_path}")
        print(f"{'='*70}\n")
        
        packets = rdpcap(pcap_path)
        total_packets = len(packets)
        print(f"Total packets to process: {total_packets:,}\n")
        
        # Process packets with progress bar
        for idx, pkt in enumerate(tqdm(packets, desc="Extracting packets", unit=" packets", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')):
            try:
                packet_info = {
                    'Packet ID': idx,
                    'TIME': float(pkt.time) if hasattr(pkt, 'time') else 0,
                    'Size': len(pkt),
                }
                
                # Extract Ethernet layer (Layer 2)
                if Ether in pkt:
                    eth = pkt[Ether]
                    packet_info['eth.src'] = eth.src
                    packet_info['eth.dst'] = eth.dst
                else:
                    packet_info['eth.src'] = 'N/A'
                    packet_info['eth.dst'] = 'N/A'
                
                # Extract IP layer (Layer 3)
                if IP in pkt:
                    ip = pkt[IP]
                    packet_info['IP.src'] = ip.src
                    packet_info['IP.dst'] = ip.dst
                    packet_info['IP.proto'] = ip.proto
                    packet_info['IP.ttl'] = ip.ttl
                    packet_info['IP.len'] = ip.len
                    
                    # Extract Transport layer (Layer 4)
                    if TCP in pkt:
                        tcp = pkt[TCP]
                        packet_info['port.src'] = tcp.sport
                        packet_info['port.dst'] = tcp.dport
                        packet_info['TCP.flags'] = tcp.flags
                        packet_info['TCP.window'] = tcp.window
                    elif UDP in pkt:
                        udp = pkt[UDP]
                        packet_info['port.src'] = udp.sport
                        packet_info['port.dst'] = udp.dport
                        packet_info['TCP.flags'] = 0
                        packet_info['TCP.window'] = 0
                    else:
                        packet_info['port.src'] = 0
                        packet_info['port.dst'] = 0
                        packet_info['TCP.flags'] = 0
                        packet_info['TCP.window'] = 0
                else:
                    packet_info['IP.src'] = 'N/A'
                    packet_info['IP.dst'] = 'N/A'
                    packet_info['IP.proto'] = 0
                    packet_info['IP.ttl'] = 0
                    packet_info['IP.len'] = 0
                    packet_info['port.src'] = 0
                    packet_info['port.dst'] = 0
                    packet_info['TCP.flags'] = 0
                    packet_info['TCP.window'] = 0
                
                # Extract DNS queries
                packet_info['Is_DNS'] = 0
                packet_info['DNS_Query'] = None
                if UDP in pkt and DNS in pkt:
                    try:
                        dns = pkt[DNS]
                        if dns.qr == 0 and DNSQR in pkt:
                            packet_info['Is_DNS'] = 1
                            dnsqr = pkt[DNSQR]
                            packet_info['DNS_Query'] = dnsqr.qname.decode() if isinstance(dnsqr.qname, bytes) else str(dnsqr.qname)
                    except:
                        pass
                
                packets_data.append(packet_info)
                
            except Exception as e:
                continue
    
    except FileNotFoundError:
        print(f"Error: PCAP file not found: {pcap_path}")
        
        if os.path.exists('data/raw/'):
            print("\nAvailable files in data/raw/:")
            for f in os.listdir('data/raw/'):
                try:
                    size_mb = os.path.getsize(f'data/raw/{f}') / (1024*1024)
                    print(f"  - {f} ({size_mb:.1f} MB)")
                except:
                    pass
        return pd.DataFrame()
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame()
    
    df = pd.DataFrame(packets_data)
    if not df.empty:
        print(f"\n✓ Successfully extracted {len(df):,} packets from {pcap_path}\n")
    return df

def add_lables(data):
    """Add device type labels based on MAC addresses for model training."""
    lables = {'Smart Home':['d0:52:a8:00:67:5e'],
              'Assistant':['44:65:0d:56:cc:d3'],
              'Security Camera':['70:ee:50:18:34:43','f4:f2:6d:93:51:f1','00:16:6c:ab:6b:88','30:8c:fb:2f:e4:b2','00:62:6e:51:27:2e','e8:ab:fa:19:de:4f','30:8c:fb:b6:e4:b5'],
              'Baby Monitor':['00:24:e4:11:18:a8'],
              'Smart Plug':['ec:1a:59:79:f4:89','50:c7:bf:00:56:39'],
              'Speaker':['74:c6:3b:29:d7:1d','18:b7:9e:02:20:44'],
              'Sensor':['ec:1a:59:83:28:11','70:ee:50:03:b8:ac','00:24:e4:20:28:c6'],
              'Smoke Alarm':['18:b4:30:25:be:e4'],
              'Scale':['00:24:e4:1b:6f:96'],
              'Blood Pressure Monitor':['74:6a:89:00:2e:25'],
              'Smart Bulb':['d0:73:d5:01:83:08'],
              'Smart Frame':['e0:76:d0:33:bb:85'],
              'Printer':['70:5a:0f:e4:9b:c0'],
              'Phone/Tablet':['08:21:ef:3b:fc:e3','40:f3:08:ff:1e:da','b4:ce:f6:a7:a3:c2','d0:a6:37:df:a1:e1'],
              'Laptop/PC':['74:2f:68:81:69:42','ac:bc:32:d4:6f:2f '],
              'Router':['14:cc:20:51:33:ea'],
              'Apple':['f4:5c:89:93:cc:85']}
    data['Device_Type'] = None
    for device_type, mac_addresses in lables.items():
        for mac in mac_addresses:
            data.loc[data['eth.src'] == mac, 'Device_Type'] = device_type
    return data

def calculate_packet_rate(data):
    """Calculate packet rate and additional features with progress bar"""
    
    print("\nCalculating packet rate and features...")
    
    # Method: Count packets per source in a rolling window
    # Group by source and calculate packet count with rolling average
    with tqdm(total=6, desc="Feature extraction", unit=" features") as pbar:
        data['Packet_Rate'] = data.groupby('eth.src').cumcount() + 1
        pbar.update(1)
        
        data['Packet_Rate'] = data.groupby('eth.src')['Packet_Rate'].transform(
            lambda x: x.rolling(window=10, min_periods=1).mean()
        )
        pbar.update(1)
        
        data['Avg_Size_Per_Device'] = data.groupby('eth.src')['Size'].transform('mean')
        data['Avg_Size_Per_Device'] = data['Avg_Size_Per_Device'] / data['Size'].max()
        pbar.update(1)
        
        data['TCP_Ratio'] = data.groupby('eth.src')['IP.proto'].transform(
            lambda x: (x == 6).sum() / len(x) if len(x) > 0 else 0
        )
        pbar.update(1)
        
        data['Port_Diversity'] = data.groupby('eth.src')['port.dst'].transform('nunique')
        pbar.update(1)
        
        data['Src_Port_Variance'] = data.groupby('eth.src')['port.src'].transform('std')
        data['Src_Port_Variance'] = data['Src_Port_Variance'].fillna(0)
        pbar.update(1)

    print("✓ Features calculated successfully\n")
    return data

def calculate_advanced_features(data):
    """Calculate advanced flow-level and statistical features"""
    
    print("\nCalculating advanced features...")
    
    with tqdm(total=7, desc="Advanced features", unit=" features") as pbar:
        # Flow Level
        data['Unique_Src_IPs'] = data.groupby('eth.src')['IP.src'].transform('nunique')
        pbar.update(1)
        
        data['Unique_Dst_IPs'] = data.groupby('eth.src')['IP.dst'].transform('nunique')
        pbar.update(1)
        
        data['TTL_Mode'] = data.groupby('eth.src')['IP.ttl'].transform(
            lambda x: x.mode()[0] if len(x.mode()) > 0 else 0
        )
        pbar.update(1)
        
        # Packet Size
        def calculate_size_entropy(sizes):
            if len(sizes) == 0:
                return 0
            hist, _ = np.histogram(sizes[sizes > 0], bins=20)
            hist = hist / hist.sum()
            hist = hist[hist > 0]
            return entropy(hist) if len(hist) > 0 else 0
        
        data['Size_Entropy'] = data.groupby('eth.src')['Size'].transform(calculate_size_entropy)
        pbar.update(1)
        
        data['Size_Std_Dev'] = data.groupby('eth.src')['Size'].transform('std')
        data['Size_Std_Dev'] = data['Size_Std_Dev'].fillna(0)
        pbar.update(1)
        
        # Time-Based Patterns
        
        data['Inter_Packet_Time'] = data.groupby('eth.src')['TIME'].transform(
            lambda x: x.diff().fillna(0)
        )
        pbar.update(1)
        
        data['Avg_Inter_Packet_Time'] = data.groupby('eth.src')['Inter_Packet_Time'].transform('mean')
        pbar.update(1)
        
    print("✓ Advanced features calculated successfully\n")
    return data

def clean_data(df):
    """Clean DataFrame by removing malformed packets and useless rows."""
    initial_count = len(df)
    print(f"\nInitial row count: {initial_count:,}")
    
    # Remove rows with missing critical network identifiers
    critical_cols = ['eth.src', 'eth.dst', 'IP.src', 'IP.dst']
    df = df[~((df[critical_cols] == 'N/A').any(axis=1))]
    print(f"After removing rows with missing network identifiers (N/A): {len(df):,}")
    
    df = df.drop_duplicates()
    print(f"After removing duplicates: {len(df):,}")
    
    df = df.fillna(0)
    
    removed_count = initial_count - len(df)
    print(f"\n✓ Cleaned data: removed {removed_count:,} rows ({100*removed_count/initial_count:.1f}%)\n")
    return df

def save_dataframe_to_csv(df, output_path):
    """Save DataFrame to CSV file."""
    try:
        df.to_csv(output_path, index=False)
        print(f"DataFrame saved to {output_path}")
    except Exception as e:
        print(f"Error saving DataFrame to CSV: {e}")




if __name__ == "__main__":
    pcap_path = 'data/raw/16-09-24.pcap'
    output_csv_path = 'data/processed/16-09-24_extracted.csv'
    time_start = time.time()
    print(f"\n{'='*70}")
    print(f"PCAP Processing Pipeline")
    print(f"{'='*70}")
    print(f"Started: {time.ctime(time_start)}\n")
    
    df = pcap_to_dataframe(pcap_path)
    
    if not df.empty: 
        
        df = calculate_packet_rate(df)
        
        df = calculate_advanced_features(df)
        
        print("Adding device labels...")
        df = add_lables(df)
        print("✓ Labels added\n")
        
        df = clean_data(df)
        
        print("Saving to CSV...")
        save_dataframe_to_csv(df, output_csv_path)
        print("✓ CSV saved\n")
    
    time_end = time.time()
    elapsed = time_end - time_start
    print(f"{'='*70}")
    print(f"✓ Processing completed!")
    print(f"Total time: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    print(f"{'='*70}\n")
