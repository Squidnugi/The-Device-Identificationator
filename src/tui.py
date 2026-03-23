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
import os
from pathlib import Path




class Dashboard(Static):
    def render(self) -> str:
        
        data_path = Path("data/reports")
        if not data_path.exists():
            return "No reports folder found"
        
        reports = list(data_path.glob("*.txt"))
        if not reports:
            return "No reports available"
        
        latest_report = max(reports, key=os.path.getctime)
        with open(latest_report, 'r') as f:
            content = f.read()
        
        return content[:500] + "..." if len(content) > 500 else content


class DashboardApp(App):
    BINDINGS = [("q", "quit", "Quit")]
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Dashboard()
        yield Footer()


if __name__ == "__main__":
    app = DashboardApp()
    app.run()