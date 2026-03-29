from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, Static


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------

@dataclass
class DeviceRow:
    """Represents a single device row from the report."""
    device_name: str
    device_type: str
    mac_address: str
    confidence: str
    total_packets: str
    source_ips: str = "N/A"
    flagged: bool = False
    foreign: bool = False


@dataclass
class ParsedReport:
    """Represents a parsed report."""
    generated_at: str = "N/A"
    network: str = "N/A"
    source_file: str = "N/A"
    total_devices: int = 0
    known_devices: int = 0
    flagged_count: int = 0
    foreign_count: int = 0
    total_packets: int = 0
    avg_confidence: float = 0.0
    devices: List[DeviceRow] = field(default_factory=list)
    flagged: List[DeviceRow] = field(default_factory=list)
    raw_path: str = ""


def _parse_summary_line(line: str, key: str) -> Optional[str]:
    """Parse a summary line of the form 'Key: Value' and return the value if the key matches."""
    match = re.match(rf"^{re.escape(key)}\s*:\s*(.+)$", line.strip())
    return match.group(1).strip() if match else None


def _parse_table_rows(lines: List[str], start_idx: int) -> List[DeviceRow]:
    """Parse table rows starting from the given index. Expects a header line, a separator line, then data rows."""
    rows = []
    if start_idx + 1 >= len(lines):
        return rows

    header_line = lines[start_idx]
    sep_line = lines[start_idx + 1]

    if not sep_line.strip() or not all(c in "-  " for c in sep_line):
        return rows

    col_spans = []
    in_col = False
    start = 0
    for i, ch in enumerate(sep_line):
        if ch == "-" and not in_col:
            in_col = True
            start = i
        elif ch != "-" and in_col:
            col_spans.append((start, i))
            in_col = False
    if in_col:
        col_spans.append((start, len(sep_line)))

    headers = [header_line[s:e].strip() for s, e in col_spans]

    for row_line in lines[start_idx + 2:]:
        stripped = row_line.rstrip()
        if not stripped or stripped.startswith("---"):
            break
        foreign = stripped.endswith("[FOREIGN]")
        flagged = stripped.endswith("[FLAGGED]") or foreign
        clean = re.sub(r"\s*\[(FLAGGED|FOREIGN)\]$", "", stripped)
        d = {}
        for idx, (s, e) in enumerate(col_spans):
            header = headers[idx]
            if header == "source_ips":
                d[header] = clean[s:].strip()
            else:
                d[header] = clean[s:e].strip() if e <= len(clean) else clean[s:].strip()
        rows.append(DeviceRow(
            device_name=d.get("device_name", ""),
            device_type=d.get("device_type", ""),
            mac_address=d.get("mac_address", ""),
            confidence=d.get("confidence", "0.0"),
            total_packets=d.get("total_packets", "0"),
            source_ips=d.get("source_ips", "N/A"),
            flagged=flagged,
            foreign=foreign,
        ))

    return rows


def _parse_source_ip_rows(lines: List[str], start_idx: int) -> dict[str, str]:
    """Parse source IP rows of the form 'MAC: ... | Device: ... | Source IPs: ...'."""
    source_ip_by_mac: dict[str, str] = {}
    row_re = re.compile(
        r"^MAC:\s*(.+?)\s*\|\s*Device:\s*(.*?)\s*\|\s*Source IPs:\s*(.*)$"
    )

    for row_line in lines[start_idx:]:
        stripped = row_line.strip()
        if not stripped or stripped.startswith("---"):
            break
        match = row_re.match(stripped)
        if not match:
            continue
        mac = match.group(1).strip().lower()
        source_ips = match.group(3).strip() or "N/A"
        source_ip_by_mac[mac] = source_ips

    return source_ip_by_mac


def parse_report(path: str) -> ParsedReport:
    """Parse a report file and return a ParsedReport object."""
    report = ParsedReport(raw_path=path)
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except Exception:
        return report

    source_ip_by_mac: dict[str, str] = {}

    for i, line in enumerate(lines):
        for label, attr in [
            ("Generated at", "generated_at"),
            ("Network", "network"),
            ("Source file", "source_file"),
        ]:
            val = _parse_summary_line(line, label)
            if val is not None:
                setattr(report, attr, val)

        for label, attr, cast in [
            ("Total devices",     "total_devices",  int),
            ("Known devices",     "known_devices",   int),
            ("Flagged/Unknown",   "flagged_count",   int),
            ("Foreign (new MAC)", "foreign_count",   int),
            ("Total packets",     "total_packets",   int),
            ("Avg confidence",    "avg_confidence",  float),
        ]:
            val = _parse_summary_line(line, label)
            if val is not None:
                try:
                    setattr(report, attr, cast(val))
                except ValueError:
                    pass

        if line.strip() == "--- All Devices ---":
            report.devices = _parse_table_rows(lines, i + 1)
        if line.strip() == "--- Flagged Devices ---":
            report.flagged = _parse_table_rows(lines, i + 1)
        if line.strip() in {"--- All Device Source IPs ---", "--- Flagged Device Source IPs ---"}:
            source_ip_by_mac.update(_parse_source_ip_rows(lines, i + 1))

    if source_ip_by_mac:
        for dev in report.devices:
            dev.source_ips = source_ip_by_mac.get(dev.mac_address.lower(), "N/A")
        for dev in report.flagged:
            dev.source_ips = source_ip_by_mac.get(dev.mac_address.lower(), "N/A")

    return report


def load_all_reports(reports_dir: str = "data/reports") -> List[ParsedReport]:
    """Load and parse all report files from the given directory, sorted by creation time (newest first)."""
    data_path = Path(reports_dir)
    if not data_path.exists():
        return []
    files = sorted(data_path.glob("*.txt"), key=os.path.getctime, reverse=True)
    return [parse_report(str(f)) for f in files]


# ---------------------------------------------------------------------------
# Device detail screen
# ---------------------------------------------------------------------------

class DeviceDetailScreen(Screen):
    """Full-screen detail view for a single device."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, device: DeviceRow) -> None:
        super().__init__()
        self.device = device

    def compose(self) -> ComposeResult:
        """Compose the layout for the device detail screen."""
        yield Header(show_clock=True)
        yield Static(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        """Render the device details when the screen is mounted."""
        d = self.device
        t = Text()
        t.append("Device Detail\n\n", style="bold")

        def row(label: str, value: str, style: str = "") -> None:
            t.append(f"  {label:<22}", style="dim")
            t.append(value + "\n", style=style)

        row("Name:",          d.device_name)
        row("Type:",          d.device_type)
        row("MAC Address:",   d.mac_address)

        try:
            conf_f = float(d.confidence)
            conf_style = "bold green" if conf_f >= 0.6 else "bold yellow"
            conf_str = f"{conf_f:.4f}"
        except ValueError:
            conf_style = ""
            conf_str = d.confidence

        row("Confidence:",    conf_str, conf_style)
        row("Total Packets:", d.total_packets)
        row("Source IPs:",    d.source_ips)

        if d.foreign:
            row("Status:", "FOREIGN — MAC not registered on this network", "bold red")
        elif d.flagged:
            row("Status:", "FLAGGED — low classification confidence", "yellow")
        else:
            row("Status:", "OK — classified with sufficient confidence", "bold green")

        self.query_one("#detail", Static).update(
            Panel(t, title=f"Device: {d.mac_address}", border_style="dim")
        )


# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------

_DASHBOARD_NAV_BINDINGS = [
    ("n", "next_report",   "Next report"),
    ("p", "prev_report",   "Prev report"),
    ("right", "next_report", "Next report"),
    ("left", "prev_report",  "Prev report"),
    ("j", "cursor_down",   "Device down"),
    ("k", "cursor_up",     "Device up"),
    ("down", "cursor_down", "Device down"),
    ("up", "cursor_up",     "Device up"),
    ("d", "device_detail", "Detail"),
    ("r", "refresh",       "Refresh"),
]


class DashboardMixin:
    """Shared dashboard behavior used by both standalone App and embedded Screen."""

    def _init_dashboard_state(self) -> None:
        self.all_reports: List[ParsedReport] = []
        self.active_idx: int = 0
        self.selected_device_idx: int = 0
        self.status_message: str = "Ready"

    def _on_dashboard_mount(self) -> None:
        """Load reports and start auto-refresh timer."""
        # Render immediately once mounted.
        self._reload()
        self.set_interval(30, self._auto_refresh)

    # --- Data ---------------------------------------------------------------

    def _reload(self) -> None:
        """Reload all reports from disk and reset state."""
        self.all_reports = load_all_reports()
        self.active_idx = 0
        self.selected_device_idx = 0
        self.status_message = (
            f"Loaded {len(self.all_reports)} report(s)"
            if self.all_reports
            else "No reports found in data/reports/"
        )
        self._refresh_dashboard()

    def _auto_refresh(self) -> None:
        """Auto-refresh reports from disk without changing the current selection."""
        self.all_reports = load_all_reports()
        self.status_message = f"Auto-refreshed at {datetime.now().strftime('%H:%M:%S')}"
        self._refresh_dashboard()

    def _active_report(self) -> Optional[ParsedReport]:
        """Get the currently active report, or None if no reports are loaded."""
        if not self.all_reports:
            return None
        return self.all_reports[self.active_idx]

    # --- Rendering ----------------------------------------------------------

    def _refresh_dashboard(self) -> None:
        """Re-render the entire dashboard based on the current state."""
        try:
            self.query_one("#dashboard", Static).update(self._build_renderable())
        except Exception as exc:
            fallback = Text()
            fallback.append("Dashboard render error\n", style="bold red")
            fallback.append(str(exc), style="yellow")
            self.query_one("#dashboard", Static).update(Panel(fallback, title="Dashboard", border_style="red"))

    def _build_renderable(self) -> Group:
        """Build the main renderable Group containing all dashboard components."""
        header = self._build_header() or Panel("Header unavailable", border_style="red")
        middle = self._build_mid() or Panel("Body unavailable", border_style="red")
        status = self._build_status() or Panel("Status unavailable", border_style="red")
        return Group(
            header,
            middle,
            status,
        )

    def _build_header(self) -> Panel:
        """Build the header panel showing the current report and network."""
        t = Text()
        t.append("Device Identificationator", style="bold")
        t.append("  ")
        r = self._active_report()
        if r:
            t.append("Network: ", style="dim")
            t.append(r.network, style="bold")
            t.append(f"  |  {Path(r.raw_path).name}", style="dim")
            t.append(f"  |  Generated: {r.generated_at}", style="dim")
        else:
            t.append("No report loaded", style="dim")
        return Panel(t, title="Overview", border_style="dim")

    def _build_mid(self) -> Group:
        """Build the middle section with devices and flagged panels on the right."""
        left = self._build_left() or Panel("Left unavailable", border_style="red")
        centre = self._build_centre() or Panel("Center unavailable", border_style="red")
        activity = self._build_activity() or Panel("Activity unavailable", border_style="red")
        flagged = self._build_flagged_panel() or Panel("Flagged unavailable", border_style="red")

        # Keep controls and activity on the left.
        left_column = Group(left, activity)

        # Put device table on the right, with flagged directly beneath it.
        right_column = Group(centre, flagged)

        layout_table = Table.grid(expand=True, padding=1)
        layout_table.add_column(ratio=1)
        layout_table.add_column(ratio=2)
        layout_table.add_row(left_column, right_column)

        return Group(layout_table)

    # --- Left column --------------------------------------------------------

    def _build_left(self) -> Group:
        """Build the left column containing the menu and summary panels."""
        return Group(self._build_menu(), self._build_summary())

    def _build_menu(self) -> Panel:
        """Build the menu panel showing key bindings and available reports."""
        t = Text()
        t.append("Keys\n", style="bold")
        t.append("  n / p    Next / prev report\n")
        t.append("  ← / →    Next / prev report\n")
        t.append("  j / k    Move device cursor\n")
        t.append("  ↑ / ↓    Move device cursor\n")
        t.append("  d        Device detail\n")
        t.append("  r        Refresh\n")
        t.append("  q        Quit\n\n")
        t.append("Reports\n", style="bold")
        for idx, rep in enumerate(self.all_reports):
            marker = "▶ " if idx == self.active_idx else "  "
            style = "bold" if idx == self.active_idx else "dim"
            t.append(f"{marker}{Path(rep.raw_path).name}\n", style=style)
        if not self.all_reports:
            t.append("  (none)\n", style="dim")
        return Panel(t, title="Menu", border_style="dim")

    def _build_summary(self) -> Panel:
        """Build the summary panel showing key statistics about the current report."""
        t = Text()
        r = self._active_report()
        if not r:
            t.append("No data available", style="dim")
            return Panel(t, title="Summary", border_style="dim")

        def stat(label: str, value: str, style: str = "bold") -> None:
            """Helper to add a summary statistic line."""
            t.append(f"  {label:<22}")
            t.append(value + "\n", style=style)

        stat("Total devices:",     str(r.total_devices))
        stat("Known devices:",     str(r.known_devices),  "bold green")
        stat(
            "Flagged/Unknown:",
            str(r.flagged_count),
            "bold red" if r.flagged_count > 0 else "bold green",
        )
        stat(
            "Foreign (new MAC):",
            str(r.foreign_count),
            "bold red" if r.foreign_count > 0 else "bold green",
        )
        stat("Total packets:",     str(r.total_packets))
        stat(
            "Avg confidence:",
            f"{r.avg_confidence:.4f}",
            "bold green" if r.avg_confidence >= 0.6 else "bold yellow",
        )
        t.append("\n  Auto-refresh: every 30s", style="dim")
        return Panel(t, title="Summary", border_style="dim")

    # --- Centre column ------------------------------------------------------

    def _build_centre(self) -> Group:
        """Build the centre column containing the main device table."""
        return Group(self._build_device_table())

    def _build_device_table(self) -> Panel:
        """Build the main device table panel showing all devices in the current report."""
        r = self._active_report()
        table = Table(show_header=True, header_style="bold")
        table.add_column(" ",      width=2)
        table.add_column("Name",   style="cyan")
        table.add_column("Type")
        table.add_column("MAC",    style="dim")
        table.add_column("Conf",   justify="right")
        table.add_column("Pkts",   justify="right")
        table.add_column("Status", justify="center")

        if not r or not r.devices:
            table.add_row("", "—", "—", "—", "—", "—", "—", style="dim")
            return Panel(table, title="All Devices (0)", border_style="dim")

        for idx, dev in enumerate(r.devices):
            try:
                conf_str = f"{float(dev.confidence):.2f}"
            except ValueError:
                conf_str = dev.confidence

            if dev.foreign:
                status, base_style = "FOREIGN", "bold red"
            elif dev.flagged:
                status, base_style = "FLAGGED", "yellow"
            else:
                status, base_style = "OK",      "green"

            is_selected = idx == self.selected_device_idx
            cursor = ">" if is_selected else " "
            row_style = f"{base_style} reverse" if is_selected else base_style
            table.add_row(
                cursor,
                dev.device_name,
                dev.device_type,
                dev.mac_address,
                conf_str,
                dev.total_packets,
                status,
                style=row_style,
            )

        return Panel(
            table,
            title=f"All Devices ({len(r.devices)})  —  j/k to move  d for detail",
            border_style="dim",
        )

    # --- Right column -------------------------------------------------------

    def _build_right(self) -> Group:
        """Build the right column containing the flagged devices panel and activity log."""
        return Group(self._build_flagged_panel(), self._build_activity())

    def _build_flagged_panel(self) -> Panel:
        """Build the flagged devices panel showing any devices that are flagged or foreign."""
        r = self._active_report()
        if not r or not r.flagged:
            t = Text()
            t.append(
                "✓ No flagged devices" if r else "No data",
                style="green" if r else "dim",
            )
            return Panel(t, title="Flagged Devices", border_style="dim")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("MAC",    style="dim")
        table.add_column("Conf",   justify="right")
        table.add_column("Reason")

        for dev in r.flagged:
            if dev.foreign:
                reason, row_style = "Foreign MAC",    "bold red"
            else:
                reason, row_style = "Low confidence", "yellow"
            try:
                conf_str = f"{float(dev.confidence):.2f}"
            except ValueError:
                conf_str = dev.confidence

            table.add_row(
                dev.device_name,
                dev.mac_address,
                conf_str,
                reason,
                style=row_style,
            )

        return Panel(table, title=f"⚠ Flagged ({len(r.flagged)})", border_style="dim")

    def _build_activity(self) -> Panel:
        """Build the activity panel showing recent actions and status messages."""
        t = Text()
        t.append("[OK] Dashboard initialised\n")
        t.append(f"[OK] {len(self.all_reports)} report(s) found\n")
        r = self._active_report()
        if r:
            t.append(f"[OK] Viewing: {Path(r.raw_path).name}\n")
            t.append(f"[OK] Network: {r.network}\n")
        t.append(f"[  ] {self.status_message}\n")
        return Panel(t, title="Activity", border_style="dim")

    # --- Status bar ---------------------------------------------------------

    def _build_status(self) -> Panel:
        """Build the status bar showing current status and timestamp."""
        r = self._active_report()
        t = Text()
        t.append(f"Status: {self.status_message}  |  ")
        if r:
            t.append(
                f"Report {self.active_idx + 1}/{len(self.all_reports)}  |  "
                f"Device {self.selected_device_idx + 1}/{len(r.devices) or 1}  |  "
            )
        t.append(datetime.now().strftime("%H:%M:%S"), style="dim")
        return Panel(t, title="Status", border_style="dim")

    # --- Actions ------------------------------------------------------------

    def action_next_report(self) -> None:
        """Switch to the next report in the list."""
        if self.all_reports:
            self.active_idx = (self.active_idx + 1) % len(self.all_reports)
            self.selected_device_idx = 0
            self.status_message = f"Viewing: {Path(self.all_reports[self.active_idx].raw_path).name}"
        self._refresh_dashboard()

    def action_prev_report(self) -> None:
        """Switch to the previous report in the list."""
        if self.all_reports:
            self.active_idx = (self.active_idx - 1) % len(self.all_reports)
            self.selected_device_idx = 0
            self.status_message = f"Viewing: {Path(self.all_reports[self.active_idx].raw_path).name}"
        self._refresh_dashboard()

    def action_cursor_down(self) -> None:
        """Move the device selection cursor down in the current report's device list."""
        r = self._active_report()
        if r and r.devices:
            self.selected_device_idx = min(
                self.selected_device_idx + 1, len(r.devices) - 1
            )
            self.status_message = f"Device {self.selected_device_idx + 1}/{len(r.devices)}"
            self._refresh_dashboard()

    def action_cursor_up(self) -> None:
        """Move the device selection cursor up in the current report's device list."""
        r = self._active_report()
        if r and r.devices:
            self.selected_device_idx = max(self.selected_device_idx - 1, 0)
            self.status_message = f"Device {self.selected_device_idx + 1}/{len(r.devices)}"
            self._refresh_dashboard()

    def action_device_detail(self) -> None:
        """Open the device detail screen for the currently selected device."""
        r = self._active_report()
        if r and r.devices:
            self.app.push_screen(DeviceDetailScreen(r.devices[self.selected_device_idx]))
        else:
            self.status_message = "No device selected"
            self._refresh_dashboard()

    def action_refresh(self) -> None:
        """Manually refresh the reports from disk."""
        self._reload()


class DashboardScreen(DashboardMixin, Screen):
    """Embeddable dashboard screen for the main TUI app."""

    BINDINGS = _DASHBOARD_NAV_BINDINGS + [
        ("escape", "app.pop_screen", "Back"),
        ("q", "app.pop_screen", "Back"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._init_dashboard_state()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="dashboard", expand=True)
        yield Footer()

    def on_mount(self) -> None:
        self._on_dashboard_mount()


class DashboardApp(DashboardMixin, App):
    """Standalone dashboard app used by the CLI dashboard command."""

    BINDINGS = _DASHBOARD_NAV_BINDINGS + [("q", "quit", "Quit")]

    def __init__(self) -> None:
        super().__init__()
        self._init_dashboard_state()

    def compose(self) -> ComposeResult:
        """Compose the main dashboard layout."""
        yield Header(show_clock=True)
        yield Static(id="dashboard", expand=True)
        yield Footer()

    def on_mount(self) -> None:
        self._on_dashboard_mount()


if __name__ == "__main__":
    DashboardApp().run()