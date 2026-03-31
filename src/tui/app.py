from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path
from typing import Callable, List

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from textual.app import App as TextualApp, ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Footer, Header, Input, Static

if __package__ in (None, ""):
    REPO_ROOT = Path(__file__).resolve().parents[2]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from src.datapipeline import add_device, add_to_network, all_networks, capture_and_process_packets, create_all_tables, get_devices_by_network, process_pcap
    from src.models import use_model
    from src.report import generate_report
    from src.security import is_password_set, set_password, verify_password
    from src.tui.dashboard import DashboardScreen
else:
    from ..datapipeline import add_device, add_to_network, all_networks, capture_and_process_packets, create_all_tables, get_devices_by_network, process_pcap
    from ..models import use_model
    from ..report import generate_report
    from ..security import is_password_set, set_password, verify_password
    from .dashboard import DashboardScreen


NETWORK_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "network.txt"
CREATE_NETWORK_OPTION = "+ Create new network..."
DEFAULT_CLASSIFICATION_FILE = "data/processed/16-09-24_extracted.csv"
DEFAULT_REPORT_INPUT = "data/processed/16-09-24_extracted.csv"
DEFAULT_REPORT_OUTPUT = "data/reports/report.txt"
STATUS_STEP_DELAY_SECONDS = 0.15
DEFAULT_CAPTURE_PACKET_COUNT = 100
DATA_DIRECTORIES = ("data/processed", "data/raw", "data/reports")


class PasswordPromptScreen(ModalScreen[tuple[str, str] | None]):
    """Prompt for creating or changing a password (placeholder-only for now)."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, title: str, prompt_text: str) -> None:
        super().__init__()
        self._title = title
        self._prompt_text = prompt_text

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._prompt_text, id="password-label")
        yield Input(placeholder="Password", password=True, id="password-input")
        yield Input(placeholder="Confirm password", password=True, id="password-confirm-input")
        yield Static("Enter in confirm field to submit, Esc to cancel", id="password-help")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#password-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "password-input":
            self.query_one("#password-confirm-input", Input).focus()
            return

        if event.input.id != "password-confirm-input":
            return

        password = self.query_one("#password-input", Input).value
        confirm = self.query_one("#password-confirm-input", Input).value
        self.dismiss((password, confirm))

    def action_cancel(self) -> None:
        self.dismiss(None)


class PasswordEntryScreen(ModalScreen[str | None]):
    """Prompt for a single password entry before protected actions."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, prompt_text: str) -> None:
        super().__init__()
        self._prompt_text = prompt_text

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._prompt_text, id="password-entry-label")
        yield Input(placeholder="Password", password=True, id="password-entry-input")
        yield Static("Press Enter to submit, Esc to cancel", id="password-entry-help")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#password-entry-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "password-entry-input":
            return
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class CreateNetworkScreen(ModalScreen[str | None]):
    """Prompt for creating a new network from the selector."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Enter a new network name and press Enter:", id="new-network-label")
        yield Input(placeholder="Network name", id="new-network-input")
        yield Static("Esc to cancel", id="new-network-help")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#new-network-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "new-network-input":
            return
        self.dismiss(event.value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class CaptureSettingsScreen(ModalScreen[tuple[str, str] | None]):
    """Prompt for live capture settings before starting sniffing."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, packet_count_default: int, interface_default: str) -> None:
        super().__init__()
        self._packet_count_default = packet_count_default
        self._interface_default = interface_default

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Configure traffic capture settings:", id="capture-settings-label")
        yield Input(value=str(self._packet_count_default), placeholder="Packet count", id="capture-packet-count-input")
        yield Input(value=self._interface_default, placeholder="Interface (Linux only)", id="capture-interface-input")
        yield Static("Enter in interface field to submit, Esc to cancel", id="capture-settings-help")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#capture-packet-count-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "capture-packet-count-input":
            self.query_one("#capture-interface-input", Input).focus()
            return

        if event.input.id != "capture-interface-input":
            return

        packet_count = self.query_one("#capture-packet-count-input", Input).value.strip()
        interface = self.query_one("#capture-interface-input", Input).value.strip()
        self.dismiss((packet_count, interface))

    def action_cancel(self) -> None:
        self.dismiss(None)


class FilePathPromptScreen(ModalScreen[str | None]):
    """Prompt for a file path used by report/classification actions."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, label: str, default_path: str, input_id: str = "file-path-input") -> None:
        super().__init__()
        self._label = label
        self._default_path = default_path
        self._input_id = input_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._label, id="file-path-label")
        yield Input(value=self._default_path, placeholder="Path to CSV or PCAP file", id=self._input_id)
        yield Static("Press Enter to submit, Esc to cancel", id="file-path-help")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(f"#{self._input_id}", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != self._input_id:
            return
        self.dismiss(event.value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class App(TextualApp):
    """Main application class for the TUI."""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "start_classification", "Start Classification"),
        ("s", "start_capture", "Capture Traffic"),
        ("r", "generate_report", "Generate Report"),
        ("x", "clear_data", "Clear Data"),
        ("d", "dashboard", "View Dashboard"),
        ("p", "change_password", "Change Password"),
        ("[", "network_prev", "Prev Network"),
        ("]", "network_next", "Next Network"),
        ("enter", "network_apply", "Apply Network"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.network_options: List[str] = []
        self.network_cursor_idx: int = 0
        self.current_network: str = "Not set"
        self.status_message: str = "Ready"
        self.current_devices: List = []
        self.operation_steps: List[str] = []
        self.initial_setup_in_progress: bool = False
        self.capture_packet_count: int = DEFAULT_CAPTURE_PACKET_COUNT
        self.capture_interface: str = "eth0"
        self.last_capture_pcap: str | None = None
        self.last_capture_csv: str | None = None
        self.selected_classification_file: str | None = None
        self.selected_report_file: str | None = None

    def _add_operation_step(self, message: str) -> None:
        """Record operation progress messages and keep only recent entries."""
        self.operation_steps.append(message)
        self.operation_steps = self.operation_steps[-10:]

    async def _set_operation_status(self, status: str, step: str | None = None) -> None:
        """Update status UI and yield to the event loop so changes render immediately."""
        if step:
            self._add_operation_step(step)
        self.status_message = status
        self._render_welcome()
        await asyncio.sleep(STATUS_STEP_DELAY_SECONDS)

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()
        yield Static(id="welcome")

    def on_mount(self) -> None:
        self._ensure_database_ready()
        self.current_network = self._load_current_network()
        self._load_network_options()
        self._load_devices_for_network()
        self._render_welcome()
        self._run_initial_setup_flow()

    def _ensure_database_ready(self) -> None:
        """Create required database tables before app workflows run."""
        try:
            create_all_tables()
        except Exception as exc:
            self.status_message = f"Database initialization failed: {exc}"
            self._add_operation_step(f"Startup warning: database initialization failed ({exc})")

    def _is_password_configured(self) -> bool:
        """Return True when a command password is configured."""
        return is_password_set()

    def _run_initial_setup_flow(self) -> None:
        """Run first-time setup prompts in order: password first, then network."""
        if not self._is_password_configured():
            self.initial_setup_in_progress = True
            self.push_screen(
                PasswordPromptScreen(
                    "Create Password",
                    "No password found. Create a password to continue setup:",
                ),
                self._handle_initial_password_result,
            )
            return

        self._maybe_prompt_initial_network()

    def _maybe_prompt_initial_network(self) -> None:
        """Prompt for initial network creation when no network is configured."""
        if self.current_network != "Not set":
            self.initial_setup_in_progress = False
            return

        self.initial_setup_in_progress = True
        self.push_screen(CreateNetworkScreen(), self._handle_initial_network_result)

    def _handle_initial_password_result(self, result: tuple[str, str] | None) -> None:
        """Handle first-time password prompt result and persist password."""
        if result is None:
            self.status_message = "Password setup canceled"
            self.initial_setup_in_progress = False
            self._render_welcome()
            return

        if not self._save_password_from_prompt(result, "Password created"):
            self.initial_setup_in_progress = False
            self._render_welcome()
            return

        self._render_welcome()
        self._maybe_prompt_initial_network()

    def _save_password_from_prompt(self, result: tuple[str, str], success_message: str) -> bool:
        """Validate and persist password entered via prompt."""
        password, confirm = result
        if not password:
            self.status_message = "Password cannot be empty"
            return False

        if password != confirm:
            self.status_message = "Password confirmation does not match"
            return False

        try:
            set_password(password)
        except Exception as exc:
            self.status_message = f"Failed to save password: {exc}"
            return False

        self.status_message = success_message
        return True

    def _require_password_then(self, action_name: str, on_success: Callable[[], None]) -> None:
        """Require an existing password (or create one) and then continue an action."""
        if not self._is_password_configured():
            self.push_screen(
                PasswordPromptScreen(
                    "Create Password",
                    f"No password found. Create one before {action_name}:",
                ),
                lambda result: self._handle_missing_password_for_action(result, action_name, on_success),
            )
            return

        self.push_screen(
            PasswordEntryScreen(f"Enter password to {action_name}:"),
            lambda result: self._handle_password_verification(result, action_name, on_success),
        )

    def _handle_missing_password_for_action(
        self,
        result: tuple[str, str] | None,
        action_name: str,
        on_success: Callable[[], None],
    ) -> None:
        """Handle create-password flow when a protected action has no password set."""
        if result is None:
            self.status_message = f"{action_name.capitalize()} canceled"
            self._render_welcome()
            return

        if not self._save_password_from_prompt(result, "Password created"):
            self._render_welcome()
            return

        self._render_welcome()
        on_success()

    def _handle_password_verification(
        self,
        result: str | None,
        action_name: str,
        on_success: Callable[[], None],
    ) -> None:
        """Verify entered password before continuing a protected action."""
        if result is None:
            self.status_message = f"{action_name.capitalize()} canceled"
            self._render_welcome()
            return

        if not result.strip():
            self.status_message = "Password cannot be empty"
            self._render_welcome()
            return

        try:
            if not verify_password(result):
                self.status_message = "Authentication failed"
                self._render_welcome()
                return
        except Exception as exc:
            self.status_message = f"Password verification failed: {exc}"
            self._render_welcome()
            return

        on_success()

    def _require_network_then(self, action_name: str, on_success: Callable[[], None]) -> None:
        """Require an active network (or create one) before continuing an action."""
        if self.current_network != "Not set":
            on_success()
            return

        self.push_screen(
            CreateNetworkScreen(),
            lambda result: self._handle_missing_network_for_action(result, action_name, on_success),
        )

    def _handle_missing_network_for_action(
        self,
        result: str | None,
        action_name: str,
        on_success: Callable[[], None],
    ) -> None:
        """Handle create-network flow when a protected action has no network configured."""
        if result is None:
            self.status_message = f"{action_name.capitalize()} canceled: no network configured"
            self._render_welcome()
            return

        new_name = result.strip()
        if not new_name:
            self.status_message = "Network name cannot be empty"
            self._render_welcome()
            return

        if new_name == CREATE_NETWORK_OPTION:
            self.status_message = "Choose a different network name"
            self._render_welcome()
            return

        if not self._create_and_select_network(new_name):
            self._render_welcome()
            return

        self.status_message = f"Created network: {new_name}"
        self._render_welcome()
        on_success()

    def _handle_initial_network_result(self, result: str | None) -> None:
        """Handle first-time network prompt result after password stage."""
        self.initial_setup_in_progress = False
        self._handle_create_network_result(result)

    def _load_current_network(self) -> str:
        """Load the currently configured network from config/network.txt."""
        try:
            value = NETWORK_CONFIG_PATH.read_text(encoding="utf-8").strip()
            return value or "Not set"
        except FileNotFoundError:
            return "Not set"

    def _save_current_network(self, network_name: str) -> None:
        """Persist the selected network to config/network.txt."""
        NETWORK_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        NETWORK_CONFIG_PATH.write_text(network_name, encoding="utf-8")

    def _load_network_options(self) -> None:
        """Load all known network names and align the cursor to the current network."""
        names: List[str] = []
        try:
            names = [n.network_name for n in all_networks() if getattr(n, "network_name", None)]
        except Exception:
            names = []

        if self.current_network != "Not set" and self.current_network not in names:
            names.append(self.current_network)

        self.network_options = sorted({name for name in names if name != CREATE_NETWORK_OPTION}, key=str.lower)
        if not self.network_options:
            self.network_options = ["Not set"]

        self.network_options.append(CREATE_NETWORK_OPTION)

        if self.current_network in self.network_options:
            self.network_cursor_idx = self.network_options.index(self.current_network)
        else:
            self.network_cursor_idx = 0

    def _selected_network(self) -> str:
        """Return the currently highlighted network option."""
        if not self.network_options:
            return "Not set"
        return self.network_options[self.network_cursor_idx]

    def _load_devices_for_network(self) -> None:
        """Load all devices for the current network."""
        self.current_devices = []
        if self.current_network and self.current_network != "Not set":
            try:
                self.current_devices = get_devices_by_network(self.current_network)
            except Exception:
                self.current_devices = []

    def _resolve_classification_file(self) -> str | None:
        """Pick dataset for classification, preferring most recent captured CSV."""
        if self.last_capture_csv and Path(self.last_capture_csv).exists():
            return self.last_capture_csv

        processed_dir = Path("data/processed")
        if processed_dir.exists():
            csv_candidates = [
                path for path in processed_dir.glob("*_extracted.csv") if path.is_file()
            ]
            if csv_candidates:
                latest = max(csv_candidates, key=lambda path: path.stat().st_mtime)
                return str(latest)

        if Path(DEFAULT_CLASSIFICATION_FILE).exists():
            return DEFAULT_CLASSIFICATION_FILE
        return None

    @staticmethod
    def _supported_traffic_extension(file_path: str) -> bool:
        """Return True when file is a supported traffic input format."""
        suffix = Path(file_path).suffix.lower()
        return suffix in {".csv", ".pcap", ".pcapng"}

    def _build_devices_panel(self) -> Panel:
        """Build a panel showing all devices in the current network."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Device Name", style="cyan")
        table.add_column("MAC Address", style="dim")
        table.add_column("IP Address", style="dim")
        table.add_column("Confidence")

        if not self.current_devices:
            table.add_row("—", "—", "—", "—", style="dim")
        else:
            for device in self.current_devices:
                confidence_value = None
                try:
                    confidence_value = float(device.confidence) if device.confidence is not None else None
                    conf_str = f"{confidence_value:.2f}" if confidence_value is not None else "N/A"
                except (ValueError, TypeError):
                    conf_str = str(device.confidence)

                row_style = "red" if confidence_value is not None and confidence_value < 0.6 else ""

                table.add_row(
                    device.device_name or "—",
                    device.mac_address or "—",
                    device.ip_address or "—",
                    conf_str,
                    style=row_style,
                )

        return Panel(
            table,
            title=f"Devices ({len(self.current_devices)})",
            border_style="blue",
        )

    def _build_flagged_devices_panel(self) -> Panel:
        """Build a panel showing flagged devices using the CLI threshold."""
        table = Table(show_header=True, header_style="bold red")
        table.add_column("Device Name", style="red")
        table.add_column("MAC Address", style="dim")
        table.add_column("Confidence", style="red")

        flagged_devices = []
        for device in self.current_devices:
            try:
                confidence = float(device.confidence or 0)
            except (TypeError, ValueError):
                confidence = 0.0
            if confidence < 0.6:
                flagged_devices.append((device, confidence))

        if not flagged_devices:
            table.add_row("-", "-", "-", style="dim")
        else:
            for device, confidence in flagged_devices:
                table.add_row(
                    device.device_name or "Unknown",
                    device.mac_address or "N/A",
                    f"{confidence:.2f}",
                )

        return Panel(
            table,
            title=f"Flagged Devices ({len(flagged_devices)})",
            border_style="red",
        )

    def _render_welcome(self) -> None:
        """Render the app home screen with network selector state."""
        network_text = Text()
        network_text.append("Current network: ", style="dim")
        network_text.append(f"{self.current_network}\n", style="bold")
        network_text.append("Selected network: ", style="dim")
        network_text.append(f"{self._selected_network()}\n\n", style="bold")
        network_text.append("Available networks:\n", style="dim")
        for idx, name in enumerate(self.network_options):
            marker = ">" if idx == self.network_cursor_idx else " "
            suffix = " (current)" if name == self.current_network else ""
            if name == CREATE_NETWORK_OPTION:
                suffix = ""
                style = "bold green" if idx == self.network_cursor_idx else "green"
            else:
                style = "bold" if idx == self.network_cursor_idx else ""
            network_text.append(f" {marker} {name}{suffix}\n", style=style)

        controls_text = Text(
            "[      Select previous network\n"
            "]      Select next network\n"
            "Enter  Apply selected network\n"
            "       (or create one from bottom option)\n"
            "p      Change password\n"
            "s      Capture traffic (pcap + processed csv)\n"
            "c      Start classification\n"
            "d      Open dashboard\n"
            "r      Generate report\n"
            "x      Clear data folders\n"
            "q      Quit"
        )

        status_text = Text()
        status_text.append("Current: ", style="dim")
        status_text.append(self.status_message + "\n", style="bold")
        status_text.append("Recent operation steps:\n", style="dim")
        if self.operation_steps:
            for step in self.operation_steps:
                status_text.append(f"  - {step}\n")
        else:
            status_text.append("  - No report/classification action run yet\n", style="dim")

        left_column = Group(
            Panel(
                network_text,
                title="Network",
                border_style="cyan",
                subtitle="Use [ / ] and Enter",
            ),
            Panel(
                controls_text,
                title="Controls",
                border_style="green",
            ),
        )

        right_column = Group(
            self._build_devices_panel(),
            self._build_flagged_devices_panel(),
        )

        layout_table = Table.grid(padding=1)
        layout_table.add_row(left_column, right_column)

        renderable = Group(
            layout_table,
            Panel(
                status_text,
                title="App Status",
                border_style="magenta",
            ),
        )
        self.query_one("#welcome", Static).update(renderable)

    async def action_generate_report(self) -> None:
        """Require password before generating a report."""
        if self.initial_setup_in_progress:
            self.status_message = "Finish setup prompts before generating a report"
            self._render_welcome()
            return

        self._require_password_then(
            "running report",
            lambda: self._require_network_then("running report", self._prompt_report_source_file),
        )

    def _prompt_report_source_file(self) -> None:
        """Prompt user to choose which CSV file to use for report generation."""
        default_source = self.selected_report_file or self._resolve_classification_file() or DEFAULT_REPORT_INPUT
        self.push_screen(
            FilePathPromptScreen("Enter source file (.csv or .pcap) for report generation:", default_source, "report-file-input"),
            self._handle_report_source_file_result,
        )

    def _handle_report_source_file_result(self, result: str | None) -> None:
        """Validate selected report source file then start report worker."""
        if result is None:
            self.status_message = "Report canceled"
            self._render_welcome()
            return

        source_file = result.strip()
        if not source_file:
            self.status_message = "Report source file cannot be empty"
            self._render_welcome()
            return

        if not Path(source_file).exists():
            self.status_message = f"Report source file not found: {source_file}"
            self._render_welcome()
            return

        if not self._supported_traffic_extension(source_file):
            self.status_message = "Unsupported report file type. Use .csv or .pcap"
            self._render_welcome()
            return

        self.selected_report_file = source_file
        self._start_report_worker(source_file)

    def _start_report_worker(self, source_file: str) -> None:
        """Start report worker once password requirement passes."""
        self.status_message = "Authentication successful"
        self._render_welcome()
        self.run_worker(self._run_generate_report(source_file))

    async def _run_generate_report(self, source_file: str) -> None:
        """Generate a report from traffic data with visible step-by-step progress."""
        self.operation_steps = []
        await self._set_operation_status(
            "Report in progress (1/5): validating configured network",
            "Report 1/5: Validating configured network",
        )

        if self.current_network == "Not set":
            await self._set_operation_status(
                "Select a network before generating a report",
                "Stopped: no network selected",
            )
            return

        await self._set_operation_status(
            "Report in progress (2/5): checking source file",
            f"Report 2/5: Checking source file ({source_file})",
        )

        if not Path(source_file).exists():
            await self._set_operation_status(
                f"Report source file not found: {source_file}",
                "Stopped: source file not found",
            )
            return

        try:
            await self._set_operation_status(
                "Report in progress (3/5): generating report",
                "Report 3/5: Running report pipeline",
            )

            report_df = await asyncio.to_thread(
                generate_report,
                source_file,
                DEFAULT_REPORT_OUTPUT,
                self.current_network,
            )
            if report_df is None:
                await self._set_operation_status(
                    "Report generation returned no output",
                    "Stopped: report pipeline returned no output",
                )
                return

            await self._set_operation_status(
                "Report in progress (4/5): resolving saved file",
                "Report 4/5: Resolving saved report file",
            )

            saved_report = str(report_df.attrs.get("report_file", DEFAULT_REPORT_OUTPUT))

            await self._set_operation_status(
                f"Report generated: {Path(saved_report).name}",
                "Report 5/5: Finalizing",
            )
            self._add_operation_step(f"Complete: report saved to {saved_report}")
        except Exception as exc:
            await self._set_operation_status(
                f"Report generation failed: {exc}",
                f"Failed: {exc}",
            )

        self._render_welcome()

    async def action_start_classification(self) -> None:
        """Require password before running classification."""
        if self.initial_setup_in_progress:
            self.status_message = "Finish setup prompts before starting classification"
            self._render_welcome()
            return

        self._require_password_then(
            "running classification",
            lambda: self._require_network_then("running classification", self._prompt_classification_file),
        )

    async def action_clear_data(self) -> None:
        """Require password before clearing generated data folders."""
        if self.initial_setup_in_progress:
            self.status_message = "Finish setup prompts before clearing data"
            self._render_welcome()
            return

        self._require_password_then("clearing data", self._start_clear_data_worker)

    def _start_clear_data_worker(self) -> None:
        """Start clear-data worker once password requirement passes."""
        self.status_message = "Authentication successful"
        self._render_welcome()
        self.run_worker(self._run_clear_data())

    async def _run_clear_data(self) -> None:
        """Clear generated data directories and recreate them."""
        self.operation_steps = []
        await self._set_operation_status(
            "Clear in progress (1/3): removing data folders",
            "Clear 1/3: Removing data/processed, data/raw, data/reports",
        )

        try:
            for directory in DATA_DIRECTORIES:
                await asyncio.to_thread(shutil.rmtree, directory, True)

            await self._set_operation_status(
                "Clear in progress (2/3): recreating data folders",
                "Clear 2/3: Recreating data folders",
            )

            for directory in DATA_DIRECTORIES:
                await asyncio.to_thread(Path(directory).mkdir, parents=True, exist_ok=True)

            self.selected_classification_file = None
            self.selected_report_file = None
            self.last_capture_pcap = None
            self.last_capture_csv = None

            await self._set_operation_status(
                "All data cleared",
                "Clear 3/3: Complete",
            )
            self._add_operation_step("Reset: capture and selected source file history cleared")
        except Exception as exc:
            await self._set_operation_status(
                f"Clear failed: {exc}",
                f"Failed: {exc}",
            )

        self._render_welcome()

    def _prompt_classification_file(self) -> None:
        """Prompt user to choose which source file to use for classification."""
        default_source = self.selected_classification_file or self._resolve_classification_file() or DEFAULT_CLASSIFICATION_FILE
        self.push_screen(
            FilePathPromptScreen("Enter source file (.csv or .pcap) for classification:", default_source, "classification-file-input"),
            self._handle_classification_file_result,
        )

    def _handle_classification_file_result(self, result: str | None) -> None:
        """Validate selected classification file then start worker."""
        if result is None:
            self.status_message = "Classification canceled"
            self._render_welcome()
            return

        classification_file = result.strip()
        if not classification_file:
            self.status_message = "Classification file cannot be empty"
            self._render_welcome()
            return

        if not Path(classification_file).exists():
            self.status_message = f"Classification file not found: {classification_file}"
            self._render_welcome()
            return

        if not self._supported_traffic_extension(classification_file):
            self.status_message = "Unsupported classification file type. Use .csv or .pcap"
            self._render_welcome()
            return

        self.selected_classification_file = classification_file
        self._start_classification_worker(classification_file)

    async def action_start_capture(self) -> None:
        """Require password before capturing traffic and generating processed CSV."""
        if self.initial_setup_in_progress:
            self.status_message = "Finish setup prompts before capturing traffic"
            self._render_welcome()
            return

        self._require_password_then("capturing traffic", self._prompt_capture_settings)

    def _prompt_capture_settings(self) -> None:
        """Open capture settings prompt before starting live capture."""
        self.push_screen(
            CaptureSettingsScreen(self.capture_packet_count, self.capture_interface),
            self._handle_capture_settings_result,
        )

    def _handle_capture_settings_result(self, result: tuple[str, str] | None) -> None:
        """Validate capture settings from prompt and start capture worker."""
        if result is None:
            self.status_message = "Capture canceled"
            self._render_welcome()
            return

        packet_count_raw, interface_raw = result
        if not packet_count_raw:
            self.status_message = "Packet count is required"
            self._render_welcome()
            return

        try:
            packet_count = int(packet_count_raw)
        except ValueError:
            self.status_message = "Packet count must be a valid integer"
            self._render_welcome()
            return

        if packet_count <= 0:
            self.status_message = "Packet count must be greater than 0"
            self._render_welcome()
            return

        self.capture_packet_count = packet_count
        self.capture_interface = interface_raw or "eth0"
        self._start_capture_worker()

    def _start_capture_worker(self) -> None:
        """Start live-capture worker once password requirement passes."""
        self.status_message = "Authentication successful"
        self._render_welcome()
        self.run_worker(self._run_capture_traffic())

    async def _run_capture_traffic(self) -> None:
        """Capture live traffic and generate both pcap and extracted CSV outputs."""
        self.operation_steps = []
        await self._set_operation_status(
            "Capture in progress (1/4): preparing output paths",
            "Capture 1/4: Preparing output paths",
        )

        try:
            await self._set_operation_status(
                f"Capture in progress (2/4): sniffing {self.capture_packet_count} packets",
                "Capture 2/4: Capturing live packets",
            )

            capture_result = await asyncio.to_thread(
                capture_and_process_packets,
                packet_count=self.capture_packet_count,
                interface=self.capture_interface,
            )
            if not capture_result:
                await self._set_operation_status(
                    "Capture failed or produced no output files",
                    "Stopped: no capture output",
                )
                return

            await self._set_operation_status(
                "Capture in progress (3/4): verifying generated files",
                "Capture 3/4: Verifying generated files",
            )

            pcap_path = capture_result["pcap_file"]
            csv_path = capture_result["processed_csv"]
            if not Path(pcap_path).exists() or not Path(csv_path).exists():
                await self._set_operation_status(
                    "Capture outputs are missing after processing",
                    "Stopped: output validation failed",
                )
                return

            await self._set_operation_status(
                f"Capture complete: {Path(csv_path).name}",
                "Capture 4/4: Finalizing",
            )
            self.last_capture_pcap = pcap_path
            self.last_capture_csv = csv_path
            self._add_operation_step(f"PCAP saved to {pcap_path}")
            self._add_operation_step(f"CSV saved to {csv_path}")
        except Exception as exc:
            await self._set_operation_status(
                f"Capture failed: {exc}",
                f"Failed: {exc}",
            )

        self._render_welcome()

    def _start_classification_worker(self, classification_file: str) -> None:
        """Start classification worker once password requirement passes."""
        self.status_message = "Authentication successful"
        self._render_welcome()
        self.run_worker(self._run_start_classification(classification_file))

    async def _run_start_classification(self, classification_file: str) -> None:
        """Run classification and save predictions with visible step-by-step progress."""
        self.operation_steps = []
        await self._set_operation_status(
            "Classification in progress (1/6): validating selected network",
            "Classification 1/6: Validating selected network",
        )

        if self.current_network == "Not set":
            await self._set_operation_status(
                "Select a network before starting classification",
                "Stopped: no network selected",
            )
            return

        await self._set_operation_status(
            "Classification in progress (2/6): checking dataset file",
            (
                f"Classification 2/6: Checking dataset file ({classification_file})"
                if classification_file
                else "Classification 2/6: Checking dataset file"
            ),
        )

        if not classification_file or not Path(classification_file).exists():
            await self._set_operation_status(
                "Dataset not found: no processed CSV is available",
                "Stopped: dataset file not found",
            )
            return

        try:
            await self._set_operation_status(
                "Classification in progress (3/6): ensuring network exists",
                "Classification 3/6: Ensuring network exists in database",
            )
            await asyncio.to_thread(add_to_network, self.current_network)

            await self._set_operation_status(
                "Classification in progress (4/6): running model inference",
                "Classification 4/6: Running model inference",
            )

            if Path(classification_file).suffix.lower() in {".pcap", ".pcapng"}:
                dataset = await asyncio.to_thread(process_pcap, File=classification_file, save_to_csv=False)
                if dataset is None or dataset.empty:
                    await self._set_operation_status(
                        "Classification failed: no data extracted from selected pcap",
                        "Stopped: empty pcap extraction result",
                    )
                    return
                results = await asyncio.to_thread(use_model, file_path=classification_file, dataset=dataset)
            else:
                results = await asyncio.to_thread(use_model, file_path=classification_file)

            await self._set_operation_status(
                "Classification in progress (5/6): writing predictions",
                "Classification 5/6: Writing predictions to database",
            )

            save_stats = await asyncio.to_thread(add_device, results, self.current_network)

            await self._set_operation_status(
                "Classification in progress (6/6): refreshing device view",
                "Classification 6/6: Refreshing device list",
            )

            await asyncio.to_thread(self._load_devices_for_network)
            self.status_message = (
                f"Classification complete: {len(results)} predictions processed for {self.current_network}"
            )
            self._add_operation_step(
                "Complete: "
                f"inserted={save_stats.get('inserted', 0)}, "
                f"updated={save_stats.get('updated', 0)}, "
                f"skipped={save_stats.get('skipped', 0)}"
            )
        except Exception as exc:
            await self._set_operation_status(
                f"Classification failed: {exc}",
                f"Failed: {exc}",
            )

        self._render_welcome()

    def action_dashboard(self) -> None:
        self.push_screen(DashboardScreen())

    def action_change_password(self) -> None:
        """Open password change flow with verification and persistence."""
        if self.initial_setup_in_progress:
            self.status_message = "Finish setup prompts before changing password"
            self._render_welcome()
            return

        if not self._is_password_configured():
            self.push_screen(
                PasswordPromptScreen(
                    "Create Password",
                    "No password found. Create a password:",
                ),
                self._handle_create_password_from_change_action,
            )
            return

        self.push_screen(
            PasswordEntryScreen("Enter current password to continue:"),
            self._handle_change_password_auth_result,
        )

    def _handle_create_password_from_change_action(self, result: tuple[str, str] | None) -> None:
        """Create password when change-password is requested without existing auth."""
        if result is None:
            self.status_message = "Password creation canceled"
            self._render_welcome()
            return

        if not self._save_password_from_prompt(result, "Password created"):
            self._render_welcome()
            return

        self._render_welcome()

    def _handle_change_password_auth_result(self, result: str | None) -> None:
        """Handle pre-check password prompt before changing password."""
        if result is None:
            self.status_message = "Password change canceled"
            self._render_welcome()
            return

        if not result.strip():
            self.status_message = "Password cannot be empty"
            self._render_welcome()
            return

        try:
            if not verify_password(result):
                self.status_message = "Authentication failed"
                self._render_welcome()
                return
        except Exception as exc:
            self.status_message = f"Password verification failed: {exc}"
            self._render_welcome()
            return

        self.push_screen(
            PasswordPromptScreen(
                "Change Password",
                "Enter a new password:",
            ),
            self._handle_change_password_result,
        )

    def _handle_change_password_result(self, result: tuple[str, str] | None) -> None:
        """Handle password change result and persist new password."""
        if result is None:
            self.status_message = "Password change canceled"
            self._render_welcome()
            return

        if not self._save_password_from_prompt(result, "Password changed"):
            self._render_welcome()
            return
        self._render_welcome()

    def action_network_next(self) -> None:
        """Move network selector to the next available network."""
        if not self.network_options:
            self.status_message = "No network options available"
            self._render_welcome()
            return
        self.network_cursor_idx = (self.network_cursor_idx + 1) % len(self.network_options)
        self.status_message = f"Selected network: {self._selected_network()}"
        self._render_welcome()

    def action_network_prev(self) -> None:
        """Move network selector to the previous available network."""
        if not self.network_options:
            self.status_message = "No network options available"
            self._render_welcome()
            return
        self.network_cursor_idx = (self.network_cursor_idx - 1) % len(self.network_options)
        self.status_message = f"Selected network: {self._selected_network()}"
        self._render_welcome()

    def action_network_apply(self) -> None:
        """Apply selected network as the current configured network."""
        selected = self._selected_network()
        if selected == CREATE_NETWORK_OPTION:
            self.push_screen(CreateNetworkScreen(), self._handle_create_network_result)
            return

        if selected == "Not set":
            self.status_message = "Pick a valid network before applying"
            self._render_welcome()
            return

        try:
            add_to_network(selected)
            self._save_current_network(selected)
            self.current_network = selected
            self._load_network_options()
            self._load_devices_for_network()
            self.status_message = f"Current network changed to: {selected}"
        except Exception as exc:
            self.status_message = f"Failed to change network: {exc}"
        self._render_welcome()

    def _handle_create_network_result(self, result: str | None) -> None:
        """Handle the value returned from the create-network prompt."""
        if result is None:
            self.status_message = "Create network canceled"
            self._render_welcome()
            return

        new_name = result.strip()
        if not new_name:
            self.status_message = "Network name cannot be empty"
            self._render_welcome()
            return

        if new_name == CREATE_NETWORK_OPTION:
            self.status_message = "Choose a different network name"
            self._render_welcome()
            return

        if self._create_and_select_network(new_name):
            self.status_message = f"Created and switched to network: {new_name}"
        self._render_welcome()

    def _create_and_select_network(self, network_name: str) -> bool:
        """Create/select a network and refresh related UI state."""
        try:
            add_to_network(network_name)
            self._save_current_network(network_name)
            self.current_network = network_name
            self._load_network_options()
            self._load_devices_for_network()
            return True
        except Exception as exc:
            self.status_message = f"Failed to create network: {exc}"
            return False

def run_app():
    """Run the TUI application."""
    App().run()


if __name__ == "__main__":
    run_app()