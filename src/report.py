"""Report generation module for summarizing network data and device information."""
import pandas as pd
from . import datapipeline as datapipeline
import os
import ipaddress


def _resolve_report_output_path(traffic_file, report_file):
    """Build report name from traffic file and avoid collisions with (n) suffixes."""
    report_dir = os.path.dirname(report_file) or 'data/reports'
    os.makedirs(report_dir, exist_ok=True)

    report_ext = '.txt'
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


def _is_local_device_ip(ip_text):
    """Return True for source IPs that likely represent local device addresses."""
    try:
        ip_obj = ipaddress.ip_address(ip_text)
        if ip_text == '0.0.0.0':
            return False
        return ip_obj.is_private or ip_obj.is_link_local
    except ValueError:
        return False


def generate_report(traffic_file, report_file, network=None):
    """
    Generate a report comparing traffic data against known devices in the database.

    For each MAC address observed in the traffic file:
      - If the MAC is registered in the database for this network, its stored
        classification and confidence are used.
      - If the MAC has no database entry, it is treated as a foreign/unknown
        device and automatically flagged regardless of confidence.
    """
    try:
        if traffic_file.endswith('.csv'):
            df = pd.read_csv(traffic_file)
        elif traffic_file.endswith('.pcap'):
            df = datapipeline.process_pcap(traffic_file, save_to_csv=False)
        else:
            print("Unsupported file type. Please provide a .csv or .pcap file.")
            return

        def _resolve_column(candidates):
            for candidate in candidates:
                if candidate in df.columns:
                    return candidate
            by_lower = {str(col).lower(): col for col in df.columns}
            for candidate in candidates:
                match = by_lower.get(candidate.lower())
                if match is not None:
                    return match
            return None

        # --- Build a lookup of known devices from the database ---
        db_devices = datapipeline.get_devices_by_network(network) if network else []
        known_devices = {
            (getattr(d, 'mac_address', '') or '').lower(): d
            for d in db_devices
        }

        # --- Collect all unique source MACs seen in the traffic file ---
        src_mac_col = _resolve_column(['eth.src'])
        dst_mac_col = _resolve_column(['eth.dst'])
        src_ip_col = _resolve_column(['IP.src', 'ip.src'])

        if src_mac_col is None:
            print("Traffic file does not contain an 'eth.src' column.")
            return

        traffic_macs = df[src_mac_col].astype(str).str.lower().unique()

        report_rows = []
        for mac in traffic_macs:
            if mac in ('n/a', 'nan', '', 'none'):
                continue

            src_mask = df[src_mac_col].astype(str).str.lower() == mac

            # Packet counts: any packet where this MAC is source or destination
            if dst_mac_col is not None:
                total_packets = int(
                    (src_mask |
                     (df[dst_mac_col].astype(str).str.lower() == mac)).sum()
                )
            else:
                total_packets = int(
                    src_mask.sum()
                )

            if src_ip_col is not None:
                ip_values = [
                    ip.strip() for ip in df.loc[src_mask, src_ip_col].astype(str).tolist()
                    if ip and ip.strip() and ip.strip().lower() not in ('n/a', 'nan', 'none')
                ]
                local_ip_values = sorted({ip for ip in ip_values if _is_local_device_ip(ip)})
                source_ips = ', '.join(local_ip_values) if local_ip_values else 'N/A'
            else:
                source_ips = 'N/A'

            if mac in known_devices:
                # MAC is registered — use stored classification
                device = known_devices[mac]
                device_name = getattr(device, 'device_name', 'Unknown') or 'Unknown'
                device_type = getattr(device, 'device_type', 'Unknown') or 'Unknown'
                confidence = round(float(getattr(device, 'confidence', 0.0) or 0.0), 4)
                # Still flag if confidence is low even for known devices
                flagged = confidence < 0.6 or device_type.lower() == 'unknown'
                foreign = False
            else:
                # MAC not in database — foreign/unknown device
                device_name = 'Unknown'
                device_type = 'Unknown'
                confidence = 0.0
                flagged = True
                foreign = True

            report_rows.append({
                'device_name': device_name,
                'device_type': device_type,
                'mac_address': mac,
                'confidence': confidence,
                'total_packets': total_packets,
                'flagged': flagged,
                'foreign': foreign,
                'source_ips': source_ips,
            })

        report_df = pd.DataFrame(
            report_rows,
            columns=['device_name', 'device_type', 'mac_address', 'confidence',
                     'total_packets', 'flagged', 'foreign', 'source_ips']
        )
        resolved_report_file = _resolve_report_output_path(traffic_file, report_file)

        # --- Summary statistics ---
        total_devices = len(report_df)
        known_count = int((~report_df['flagged']).sum())
        flagged_count = int(report_df['flagged'].sum())
        foreign_count = int(report_df['foreign'].sum())
        total_packets_sum = int(report_df['total_packets'].sum())
        classified = report_df[~report_df['foreign']]
        avg_confidence = round(float(classified['confidence'].mean()), 4) if not classified.empty else 0.0

        lines = [
            "Device Identification Report",
            f"Generated at: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Network: {network or 'N/A'}",
            f"Source file: {traffic_file}",
            "",
            "--- Summary ---",
            f"Total devices:      {total_devices}",
            f"Known devices:      {known_count}",
            f"Flagged/Unknown:    {flagged_count}",
            f"Foreign (new MAC):  {foreign_count}",
            f"Total packets:      {total_packets_sum}",
            f"Avg confidence:     {avg_confidence}",
            "",
        ]

        if report_df.empty:
            lines.append("No MAC addresses found in traffic file.")
        else:
            display_cols = ['device_name', 'device_type', 'mac_address', 'confidence', 'total_packets', 'source_ips']
            fixed_cols = ['device_name', 'device_type', 'mac_address', 'confidence', 'total_packets']
            widths = {
                col: max(len(col), report_df[col].astype(str).map(len).max())
                for col in fixed_cols
            }
            widths['source_ips'] = len('source_ips')

            def _format_row(row, marker=""):
                left = "  ".join(f"{str(row[col]):<{widths[col]}}" for col in fixed_cols)
                return f"{left}  {row['source_ips']}{marker}"

            lines.append("--- All Devices ---")
            lines.append("  ".join(f"{col:<{widths[col]}}" for col in display_cols))
            lines.append("  ".join("-" * widths[col] for col in display_cols))
            for _, row in report_df.sort_values('flagged').iterrows():
                if row['foreign']:
                    marker = " [FOREIGN]"
                elif row['flagged']:
                    marker = " [FLAGGED]"
                else:
                    marker = ""
                lines.append(_format_row(row, marker))

            flagged_df = report_df[report_df['flagged']]
            if not flagged_df.empty:
                lines.append("")
                lines.append("--- Flagged Devices ---")
                lines.append("  ".join(f"{col:<{widths[col]}}" for col in display_cols))
                lines.append("  ".join("-" * widths[col] for col in display_cols))
                for _, row in flagged_df.iterrows():
                    marker = " [FOREIGN]" if row['foreign'] else ""
                    lines.append(_format_row(row, marker))

        with open(resolved_report_file, 'w', encoding='utf-8') as report_handle:
            report_handle.write("\n".join(lines))

        report_df.attrs['report_file'] = resolved_report_file
        return report_df

    except Exception as e:
        print(f"Error generating report: {e}")