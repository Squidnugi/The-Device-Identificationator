from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List

from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, Static


@dataclass
class ResultRow:
    file: str
    status: str
    devices: str
    anomalies: str


MOCK_RESULTS: List[ResultRow] = [
    ResultRow("16-09-23.csv", "Processed", "12", "3"),
    ResultRow("16-09-24.csv", "Processed", "15", "2"),
    ResultRow("16-09-25.csv", "Processing", "8", "1"),
]


class DeviceIDApp(App):
    """Text-oriented TUI for Device Identificationator (DEMO)."""

    BINDINGS = [
        ("n", "new_analysis", "New analysis"),
        ("l", "load_results", "Load results"),
        ("e", "export", "Export"),
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.status_message = "Ready"
        self.files_loaded = len(MOCK_RESULTS)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="dashboard")
        yield Footer()

    def on_mount(self) -> None:
        self._render_dashboard()

    def _render_dashboard(self) -> None:
        dashboard = self.query_one("#dashboard", Static)
        dashboard.update(self._build_renderable())

    def _build_renderable(self) -> Group:
        header_text = Text()
        header_text.append("Device Identificationator", style="bold")
        header_text.append("  ")
        header_text.append("[DEMO]", style="dim")
        header_text.append("\n")
        header_text.append("A text-oriented dashboard (ratatui-style)", style="dim")

        header_panel = Panel(header_text, title="Overview", border_style="dim")

        menu_text = Text()
        menu_text.append("Keys\n", style="bold")
        menu_text.append("  n  New analysis\n")
        menu_text.append("  l  Load results\n")
        menu_text.append("  e  Export\n")
        menu_text.append("  r  Refresh\n")
        menu_text.append("  q  Quit\n\n")
        menu_text.append("Notes\n", style="bold")
        menu_text.append("  • All data is mock\n")
        menu_text.append("  • No files are touched\n")

        menu_panel = Panel(menu_text, title="Menu", border_style="dim")

        stats_text = Text()
        stats_text.append("Files loaded: ")
        stats_text.append(str(self.files_loaded), style="bold")
        stats_text.append("\n")
        stats_text.append("Models: random_forest, isolation_forest\n")
        stats_text.append("Last run: demo\n")
        stats_text.append("Errors: 0\n")
        stats_panel = Panel(stats_text, title="Stats", border_style="dim")

        activity_text = Text()
        activity_text.append("[OK] Initialized dashboard\n")
        activity_text.append("[OK] Mock data loaded\n")
        activity_text.append(f"[OK] Status: {self.status_message}\n")
        activity_panel = Panel(activity_text, title="Activity", border_style="dim")

        table = Table(show_header=True, header_style="bold")
        table.add_column("File", style="cyan")
        table.add_column("Status")
        table.add_column("Devices", justify="right")
        table.add_column("Anomalies", justify="right")

        for row in MOCK_RESULTS:
            table.add_row(row.file, row.status, row.devices, row.anomalies)

        results_panel = Panel(table, title="Results", border_style="dim")

        left_column = Group(menu_panel, stats_panel)
        middle_column = Group(results_panel)
        right_column = Group(activity_panel)

        mid = Columns([left_column, middle_column, right_column], equal=True, expand=True)

        status_text = Text()
        status_text.append(f"Status: {self.status_message} | ")
        status_text.append(f"Files loaded: {self.files_loaded}")
        status_text.append(f" | {datetime.now().strftime('%H:%M:%S')}")

        status_panel = Panel(status_text, title="Status", border_style="dim")

        return Group(header_panel, mid, status_panel)

    def action_new_analysis(self) -> None:
        self.status_message = "New analysis (demo)"
        self._render_dashboard()

    def action_load_results(self) -> None:
        self.status_message = "Loaded demo results"
        self._render_dashboard()

    def action_export(self) -> None:
        self.status_message = "Exported to outputs/ (demo)"
        self._render_dashboard()

    def action_refresh(self) -> None:
        self.status_message = "Refreshed"
        self._render_dashboard()


if __name__ == "__main__":
    DeviceIDApp().run()