import pandas as pd
from . import datapipeline as datapipeline
import os


def _resolve_report_output_path(traffic_file, report_file):
    """Build report name from traffic file and avoid collisions with (n) suffixes."""
    report_dir = os.path.dirname(report_file) or 'data/reports'
    os.makedirs(report_dir, exist_ok=True)

    report_ext = os.path.splitext(report_file)[1] or '.csv'
    traffic_stem = os.path.splitext(os.path.basename(traffic_file))[0]
    if traffic_stem.endswith('_extracted'):
        traffic_stem = traffic_stem[:-10]

    base_name = f"report_for_{traffic_stem}"
    resolved_path = os.path.join(report_dir, f"{base_name}{report_ext}")

    counter = 1
    while os.path.exists(resolved_path):
        resolved_path = os.path.join(report_dir, f"{base_name}({counter}){report_ext}")
        counter += 1

    return resolved_path

def generate_report(traffic_file, report_file, network=None):
    """Generate a report summarizing the network data."""
    try:
        if traffic_file.endswith('.csv'):
            df = pd.read_csv(traffic_file)
        elif traffic_file.endswith('.pcap'):
            df = datapipeline.process_pcap(traffic_file, save_to_csv=False)
        else:
            print("Unsupported file type. Please provide a .csv or .pcap file.")
            return
        report_rows = []
        devices = datapipeline.get_devices_by_network(network) if network else []

        for device in devices:
            mac_address = (getattr(device, 'mac_address', '') or '').lower()
            if {'eth.src', 'eth.dst'}.issubset(df.columns):
                total_packets = int(
                    ((df['eth.src'].astype(str).str.lower() == mac_address) |
                     (df['eth.dst'].astype(str).str.lower() == mac_address)).sum()
                )
            elif 'eth.src' in df.columns:
                total_packets = int((df['eth.src'].astype(str).str.lower() == mac_address).sum())
            else:
                total_packets = 0

            report_rows.append({
                'device_name': getattr(device, 'device_name', 'Unknown') or 'Unknown',
                'device_type': getattr(device, 'device_type', 'Unknown') or 'Unknown',
                'mac_address': getattr(device, 'mac_address', '') or '',
                'total_packets': total_packets,
            })

        report_df = pd.DataFrame(report_rows, columns=['device_name', 'device_type', 'mac_address', 'total_packets'])
        resolved_report_file = _resolve_report_output_path(traffic_file, report_file)
        report_df.to_csv(resolved_report_file, index=False)
        report_df.attrs['report_file'] = resolved_report_file
        print(f"Report generated and saved to {resolved_report_file}")
        return report_df
    except Exception as e:
        print(f"Error generating report: {e}")