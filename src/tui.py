"""
TUI dashboard for Device Identificationator.
Parses report .txt files produced by report.py and renders them
as a live Textual dashboard, styled after the demo in tests/tui.py.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, Static


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------

@dataclass
class ParsedReport:
    generated_at: str = "N/A"
    network: str = "N/A"
    source_file: str = "N/A"
    total_devices: int = 0
    known_devices: int = 0
    flagged_count: int = 0
    foreign_count: int = 0
    total_packets: int = 0
    avg_confidence: float = 0.0
    devices: List[dict] = field(default_factory=list)   # all devices
    flagged: List[dict] = field(default_factory=list)   # flagged subset
    raw_path: str = ""


def _parse_summary_line(line: str, key: str) -> Optional[str]:
    pattern = rf"^{re.escape(key)}\s*:\s*(.+)$"
    match = re.match(pattern, line.strip())
    return match.group(1).strip() if match else None


def _parse_table_rows(lines: List[str], start_idx: int) -> List[dict]:
    """
    Parse a fixed-width table.
    Derives column boundaries from the separator (dash) line.
    Recognises [FLAGGED] and [FOREIGN] row markers.
    """
    rows = []
    if start_idx >= len(lines):
        return rows

    header_line = lines[start_idx] if start_idx < len(lines) else ""
    sep_line = lines[start_idx + 1] if start_idx + 1 < len(lines) else ""

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
        values = [clean[s:e].strip() if e <= len(clean) else clean[s:].strip() for s, e in col_spans]
        row = dict(zip(headers, values))
        row["_flagged"] = flagged
        row["_foreign"] = foreign
        rows.append(row)

    return rows


def parse_report(path: str) -> ParsedReport:
    report = ParsedReport(raw_path=path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw_lines = fh.read().splitlines()
    except Exception:
        return report

    lines = raw_lines
    i = 0
    while i < len(lines):
        line = lines[i]

        for label, attr in [
            ("Generated at", "generated_at"),
            ("Network", "network"),
            ("Source file", "source_file"),
        ]:
            val = _parse_summary_line(line, label)
            if val is not None:
                setattr(report, attr, val)

        for label, attr, cast in [
            ("Total devices", "total_devices", int),
            ("Known devices", "known_devices", int),
            ("Flagged/Unknown", "flagged_count", int),
            ("Foreign (new MAC)", "foreign_count", int),
            ("Total packets", "total_packets", int),
            ("Avg confidence", "avg_confidence", float),
        ]:
            val = _parse_summary_line(line, label)
            if val is not None:
                try:
                    setattr(report, attr, cast(val))
                except ValueError:
                    pass

        if line.strip() == "--- All Devices ---" and i + 1 < len(lines):
            report.devices = _parse_table_rows(lines, i + 1)

        if line.strip() == "--- Flagged Devices ---" and i + 1 < len(lines):
            report.flagged = _parse_table_rows(lines, i + 1)

        i += 1

    return report


def load_all_reports(reports_dir: str = "data/reports") -> List[ParsedReport]:
    data_path = Path(reports_dir)
    if not data_path.exists():
        return []
    reports = sorted(data_path.glob("*.txt"), key=os.path.getctime, reverse=True)
    return [parse_report(str(p)) for p in reports]


# ---------------------------------------------------------------------------
# TUI widgets
# ---------------------------------------------------------------------------

def _fmt_conf(raw: str) -> str:
    try:
        return f"{float(raw):.2f}"
    except ValueError:
        return raw


class DashboardWidget(Static):

    def __init__(self, reports_dir: str = "data/reports", **kwargs) -> None:
        super().__init__(**kwargs)
        self.reports_dir = reports_dir
        self.all_reports: List[ParsedReport] = []
        self.active_idx: int = 0
        self.status_message: str = "Ready"

    def on_mount(self) -> None:
        self._reload()

    def _reload(self) -> None:
        self.all_reports = load_all_reports(self.reports_dir)
        self.active_idx = 0
        self.status_message = (
            f"Loaded {len(self.all_reports)} report(s)"
            if self.all_reports
            else "No reports found in data/reports/"
        )
        self._render_view()

    def _render_view(self) -> None:
        self.update(self._build())

    # --- Layout -------------------------------------------------------------

    def _build(self) -> Group:
        return Group(self._build_header(), self._build_mid(), self._build_status())

    def _build_header(self) -> Panel:
        t = Text()
        t.append("Device Identificationator", style="bold")
        t.append("  ")
        t.append("Network Dashboard", style="dim")
        t.append("\n")
        if self.all_reports:
            r = self.all_reports[self.active_idx]
            t.append("Network: ", style="dim")
            t.append(r.network, style="bold cyan")
            t.append(f"   File: {Path(r.raw_path).name}", style="dim")
        else:
            t.append("No report loaded", style="dim red")
        return Panel(t, title="Overview", border_style="dim")

    def _build_mid(self) -> Columns:
        return Columns(
            [self._build_left(), self._build_centre(), self._build_right()],
            equal=True,
            expand=True,
        )

    # --- Left column --------------------------------------------------------

    def _build_left(self) -> Group:
        return Group(self._build_menu(), self._build_summary())

    def _build_menu(self) -> Panel:
        t = Text()
        t.append("Keys\n", style="bold")
        t.append("  n  Next report\n")
        t.append("  p  Previous report\n")
        t.append("  r  Refresh\n")
        t.append("  q  Quit\n\n")
        t.append("Reports\n", style="bold")
        for idx, rep in enumerate(self.all_reports):
            marker = "▶ " if idx == self.active_idx else "  "
            name = Path(rep.raw_path).name
            style = "bold cyan" if idx == self.active_idx else "dim"
            t.append(f"{marker}{name}\n", style=style)
        return Panel(t, title="Menu", border_style="dim")

    def _build_summary(self) -> Panel:
        t = Text()
        if not self.all_reports:
            t.append("No data available", style="dim")
            return Panel(t, title="Summary", border_style="dim")

        r = self.all_reports[self.active_idx]

        def stat(label: str, value: str, style: str = "bold") -> None:
            t.append(f"{label:<20}")
            t.append(value + "\n", style=style)

        stat("Total devices:", str(r.total_devices))
        stat("Known devices:", str(r.known_devices), "bold green")
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
        stat("Total packets:", str(r.total_packets))
        stat(
            "Avg confidence:",
            f"{r.avg_confidence:.4f}",
            "bold green" if r.avg_confidence >= 0.6 else "bold yellow",
        )
        t.append("\nGenerated at:\n  ", style="dim")
        t.append(r.generated_at, style="dim")
        return Panel(t, title="Summary", border_style="dim")

    # --- Centre column ------------------------------------------------------

    def _build_centre(self) -> Group:
        return Group(self._build_device_table())

    def _build_device_table(self) -> Panel:
        if not self.all_reports:
            return Panel(
                Text("No report loaded", style="dim"),
                title="All Devices",
                border_style="dim",
            )

        r = self.all_reports[self.active_idx]
        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Type")
        table.add_column("MAC", style="dim")
        table.add_column("Conf", justify="right")
        table.add_column("Pkts", justify="right")

        for dev in r.devices:
            if dev.get("_foreign"):
                row_style = "bold red"        # foreign — never-seen MAC
            elif dev.get("_flagged"):
                row_style = "yellow"          # known but low-confidence
            else:
                row_style = "green"           # classified and confident

            table.add_row(
                dev.get("device_name", ""),
                dev.get("device_type", ""),
                dev.get("mac_address", ""),
                _fmt_conf(dev.get("confidence", "0")),
                dev.get("total_packets", ""),
                style=row_style,
            )

        if not r.devices:
            table.add_row("—", "—", "—", "—", "—", style="dim")

        return Panel(
            table,
            title=f"All Devices ({len(r.devices)})",
            border_style="dim",
        )

    # --- Right column -------------------------------------------------------

    def _build_right(self) -> Group:
        return Group(self._build_flagged_panel(), self._build_activity())

    def _build_flagged_panel(self) -> Panel:
        if not self.all_reports:
            return Panel(Text("No data", style="dim"), title="Flagged Devices", border_style="dim")

        r = self.all_reports[self.active_idx]

        if not r.flagged:
            t = Text()
            t.append("✓ No flagged devices", style="green")
            return Panel(t, title="Flagged Devices", border_style="dim")

        table = Table(show_header=True, header_style="bold red", expand=True)
        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Conf", justify="right")
        table.add_column("Reason")

        for dev in r.flagged:
            if dev.get("_foreign"):
                reason = "Foreign MAC"
                row_style = "bold red"
            else:
                reason = "Low confidence"
                row_style = "yellow"

            table.add_row(
                dev.get("device_name", ""),
                dev.get("device_type", ""),
                _fmt_conf(dev.get("confidence", "0")),
                reason,
                style=row_style,
            )

        return Panel(
            table,
            title=f"⚠ Flagged ({len(r.flagged)})",
            border_style="red",
        )

    def _build_activity(self) -> Panel:
        t = Text()
        t.append("[OK] Dashboard initialised\n")
        t.append(f"[OK] {len(self.all_reports)} report(s) loaded\n")
        if self.all_reports:
            r = self.all_reports[self.active_idx]
            t.append(f"[OK] Active: {Path(r.raw_path).name}\n")
        t.append(f"[  ] {self.status_message}\n")
        return Panel(t, title="Activity", border_style="dim")

    # --- Status bar ---------------------------------------------------------

    def _build_status(self) -> Panel:
        t = Text()
        t.append(f"Status: {self.status_message}  |  ")
        if self.all_reports:
            r = self.all_reports[self.active_idx]
            t.append(f"Report {self.active_idx + 1}/{len(self.all_reports)}: ")
            t.append(f"{r.network}  ", style="cyan")
        t.append(datetime.now().strftime("%H:%M:%S"), style="dim")
        return Panel(t, title="Status", border_style="dim")

    # --- Actions ------------------------------------------------------------

    def next_report(self) -> None:
        if self.all_reports:
            self.active_idx = (self.active_idx + 1) % len(self.all_reports)
            self.status_message = f"Viewing: {Path(self.all_reports[self.active_idx].raw_path).name}"
        self._render_view()

    def prev_report(self) -> None:
        if self.all_reports:
            self.active_idx = (self.active_idx - 1) % len(self.all_reports)
            self.status_message = f"Viewing: {Path(self.all_reports[self.active_idx].raw_path).name}"
        self._render_view()

    def refresh_reports(self) -> None:
        self._reload()
        self.status_message = "Refreshed"
        self._render_view()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

class DashboardApp(App):
    BINDINGS = [
        ("n", "next_report", "Next report"),
        ("p", "prev_report", "Prev report"),
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield DashboardWidget(id="dashboard")
        yield Footer()

    def action_next_report(self) -> None:
        self.query_one("#dashboard", DashboardWidget).next_report()

    def action_prev_report(self) -> None:
        self.query_one("#dashboard", DashboardWidget).prev_report()

    def action_refresh(self) -> None:
        self.query_one("#dashboard", DashboardWidget).refresh_reports()


if __name__ == "__main__":
    DashboardApp().run()