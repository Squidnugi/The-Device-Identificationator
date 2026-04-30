"""Command-line entry point for The Device Identificationator.

Provides commands for device identification, live capture, report generation,
network management, and application launch. All state-mutating commands
require the configured command password.
"""
import shutil
import os
from pathlib import Path
from functools import wraps

import click
import src
from src.config import NETWORK_CONFIG_PATH, DATA_DIRECTORIES, DEFAULT_CONFIDENCE_THRESHOLD, DEFAULT_MARGIN_THRESHOLD


DEFAULT_NETWORK_NAME = "Default_Network"
SUPPORTED_TRAFFIC_EXTENSIONS = {".csv", ".pcap", ".pcapng"}

ASCII_BANNER = r"""

██████╗ ███████╗██╗   ██╗██╗ ██████╗███████╗                                                                                         
██╔══██╗██╔════╝██║   ██║██║██╔════╝██╔════╝                                                                                         
██║  ██║█████╗  ██║   ██║██║██║     █████╗                                                                                           
██║  ██║██╔══╝  ╚██╗ ██╔╝██║██║     ██╔══╝                                                                                           
██████╔╝███████╗ ╚████╔╝ ██║╚██████╗███████╗                                                                                         
╚═════╝ ╚══════╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝                                                                                         
                                                                                                                                     
██╗██████╗ ███████╗███╗   ██╗████████╗██╗███████╗██╗ ██████╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝██║██╔════╝██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██║██║  ██║█████╗  ██╔██╗ ██║   ██║   ██║█████╗  ██║██║     ███████║   ██║   ██║██║   ██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
██║██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██║██╔══╝  ██║██║     ██╔══██║   ██║   ██║██║   ██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
██║██████╔╝███████╗██║ ╚████║   ██║   ██║██║     ██║╚██████╗██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                                                                                     """.lstrip("\n")

COMMANDS = [
    ("intro",       "Show this introduction screen"),
    ("setup",       "Create network, password, and initialise the database"),
    ("identifier",  "Run device identification analysis on a traffic file"),
    ("scanner",     "Capture and identify live network traffic"),
    ("report",      "Generate or read a device classification report"),
    ("network",     "View or manage networks"),
    ("device",      "View or analyse a specific device"),
    ("flagged",     "View low-confidence flagged devices"),
    ("clear",       "Clear all data and reset the application"),
    ("dashboard",   "Open the dashboard TUI"),
    ("app",         "Run the full Textual TUI application"),
]


def _read_current_network() -> str | None:
    """Return configured network name from config/network.txt, if present."""
    try:
        content = NETWORK_CONFIG_PATH.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return content or None


def _write_current_network(network_name: str) -> None:
    """Persist current network to config/network.txt."""
    NETWORK_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    NETWORK_CONFIG_PATH.write_text(str(network_name).strip(), encoding="utf-8")


def _require_command_password() -> bool:
    """Prompt for the command password and validate it.

    Returns
    -------
    bool
        True when authentication succeeds, False otherwise.
    """
    if not src.is_password_set():
        click.echo(click.style("No command password is configured yet.", fg="yellow", bold=True))
        click.echo(click.style("Run: python main.py setup", fg="yellow"))
        return False

    password = click.prompt("Command password", hide_input=True)
    if not src.verify_password(password):
        click.echo(click.style("Authentication failed.", fg="red", bold=True))
        return False
    return True


def _require_command_authentication() -> callable:
    """Decorator that enforces command-password authentication."""
    def decorator(func):
        @wraps(func)
        @click.pass_context
        def wrapper(ctx, *args, **kwargs):
            if not _require_command_password():
                return
            return func(*args, **kwargs)
        return wrapper
    return decorator


def _require_network_configured() -> callable:
    """Decorator that aborts the command when no network is configured."""
    def decorator(func):
        @wraps(func)
        @click.pass_context
        def wrapper(ctx, *args, **kwargs):
            if not _read_current_network():
                click.echo(click.style(
                    "No network configured. Run: python main.py network --change <network_name>",
                    fg="yellow",
                ))
                return
            return func(*args, **kwargs)
        return wrapper
    return decorator


def grab_network() -> str | None:
    """Return the currently configured network name, or None if unset."""
    return _read_current_network()


def _echo_colored_report(report_text) -> None:
    """Render text report output with unknown device rows highlighted in red."""
    if not report_text or not str(report_text).strip():
        click.echo(click.style("No devices found for this network in the report.", fg="yellow", bold=True))
        return

    lines = str(report_text).splitlines()
    in_table = False

    for line in lines:
        stripped = line.strip()

        if not stripped:
            click.echo("")
            continue

        if stripped.startswith("device_name") and "device_type" in stripped and "mac_address" in stripped:
            in_table = True
            click.echo(click.style(line, fg="cyan", bold=True))
            continue

        if in_table and set(stripped) <= {"-", " "}:
            click.echo(click.style(line, fg="cyan", bold=True))
            continue

        if in_table:
            parts = [part.strip() for part in line.split("  ") if part.strip()]
            is_unknown = len(parts) >= 2 and (
                parts[0].lower() == "unknown" or parts[1].lower() == "unknown"
            )
            row_color = "red" if is_unknown else "green"
            click.echo(click.style(line, fg=row_color, bold=True))
            continue

        click.echo(click.style(line, fg="green", bold=True))


@click.group()
def cli():
    """Device Identificationator - Wizard"""
    pass


@cli.command()
@click.option("--change", is_flag=True, help="Change command password")
def setup(change):
    """Create Network, password, and initialise database"""
    if change:
        if not _require_command_password():
            return
        click.echo(click.style("Changing command password...", fg="green", bold=True))
        password = click.prompt("New command password", hide_input=True, confirmation_prompt=True)
        src.set_password(password)
        click.echo(click.style("Command password changed!", fg="green", bold=True))
        return

    dirs = [
        "config",
        "data",
        "data/raw",
        "data/processed",
        "data/reports",
    ]
    for d in dirs:
        path = Path(d)
        if not path.exists():
            path.mkdir(parents=True)
            click.echo(click.style(f"Created directory: {d}", fg="cyan"))

    src.create_all_tables()
    if src.is_password_set():
        click.echo(click.style(
            'A command password is already set. Use "python main.py setup --change" to change it.',
            fg="yellow",
            bold=True,
        ))
        return
    password = click.prompt("Set command password", hide_input=True, confirmation_prompt=True)
    src.set_password(password)
    click.echo(click.style("Password saved.", fg="green", bold=True))
    src.add_to_network(DEFAULT_NETWORK_NAME)
    if not _read_current_network():
        _write_current_network(DEFAULT_NETWORK_NAME)
    click.echo(click.style("Default network created.", fg="green", bold=True))


@cli.command()
@click.option("--file", required=True, help="Path to the dataset file (.csv, .pcap, or .pcapng)")
@click.option(
    "--confidence-threshold", default=DEFAULT_CONFIDENCE_THRESHOLD, show_default=True,
    type=click.FloatRange(0.0, 1.0),
    help="Minimum confidence required before classifying a device.",
)
@click.option(
    "--margin-threshold", default=DEFAULT_MARGIN_THRESHOLD, show_default=True,
    type=click.FloatRange(0.0, 1.0),
    help="Minimum top-1 vs top-2 probability margin required before classifying a device.",
)
@_require_command_authentication()
@_require_network_configured()
def identifier(file, confidence_threshold, margin_threshold):
    """Run device identification analysis"""
    source_path = Path(file)
    if not source_path.exists():
        click.echo(click.style(f"Dataset file not found: {file}", fg="red", bold=True))
        return

    if source_path.suffix.lower() not in SUPPORTED_TRAFFIC_EXTENSIONS:
        click.echo(click.style(
            "Unsupported file type. Please provide a .csv, .pcap, or .pcapng file.",
            fg="red", bold=True,
        ))
        return

    click.echo(click.style("Running device identification analysis...", fg="green", bold=True))
    data = None
    if source_path.suffix.lower() == ".csv":
        click.echo(click.style("Processing CSV file...", fg="green", bold=True))
    elif source_path.suffix.lower() in {".pcap", ".pcapng"}:
        click.echo(click.style("Processing pcap file...", fg="green", bold=True))
        data = src.process_pcap(file, save_to_csv=False)

    try:
        results = src.use_model(
            file_path=file,
            dataset=data,
            confidence_threshold=confidence_threshold,
            margin_threshold=margin_threshold,
        )
    except FileNotFoundError as exc:
        click.echo(click.style(str(exc), fg="red", bold=True))
        return
    except Exception as exc:
        click.echo(click.style(f"Identification failed: {exc}", fg="red", bold=True))
        return

    click.echo(click.style("Analysis complete!", fg="green", bold=True))
    click.echo(click.style(results.to_string(), fg="green", bold=True))
    network = grab_network()
    src.add_device(results, network)


@cli.command()
@click.option(
    "--packets", default=100, show_default=True, type=click.IntRange(1),
    help="Number of packets to capture",
)
@click.option("--interface", default="eth0", show_default=True, help="Network interface to capture on (Linux/Unix)")
@_require_command_authentication()
def scanner(packets, interface):
    """Run a network scan"""
    click.echo(click.style("Running device scanning...", fg="green", bold=True))
    capture_result = src.capture_and_process_packets(packet_count=packets, interface=interface)
    if capture_result is None:
        click.echo(click.style("Scanning failed. Could not capture/process traffic.", fg="red", bold=True))
        return

    click.echo(click.style(f"PCAP saved to: {capture_result['pcap_file']}", fg="cyan", bold=True))
    click.echo(click.style(f"Processed CSV saved to: {capture_result['processed_csv']}", fg="cyan", bold=True))
    click.echo(click.style("Scanning complete!", fg="green", bold=True))


@cli.command()
@click.option("--report-file", default="data/reports/report.txt", help="Path to save the generated report")
@click.option("--file", default=None, help="Path to the dataset file (.csv, .pcap, or .pcapng)")
@click.option("--read", default=None, help="Read and display an existing report")
@_require_network_configured()
def report(report_file, file, read):
    """Generate a report"""
    network = grab_network()
    if read:
        try:
            with open(read, "r", encoding="utf-8") as report_handle:
                _echo_colored_report(report_handle.read())
        except FileNotFoundError:
            click.echo(click.style("Report not found.", fg="red", bold=True))
    else:
        if not _require_command_password():
            return
        if file is None:
            click.echo(click.style(
                "No input file provided. Use --file to specify a .csv, .pcap, or .pcapng file.",
                fg="red", bold=True,
            ))
            return
        if not Path(file).exists():
            click.echo(click.style(f"Report source file not found: {file}", fg="red", bold=True))
            return
        if Path(file).suffix.lower() not in SUPPORTED_TRAFFIC_EXTENSIONS:
            click.echo(click.style(
                "Unsupported file type. Please provide a .csv, .pcap, or .pcapng file.",
                fg="red", bold=True,
            ))
            return

        try:
            generated = src.generate_report(file, report_file, network)
        except Exception as exc:
            click.echo(click.style(f"Failed to generate report: {exc}", fg="red", bold=True))
            return

        saved_report_file = generated.attrs.get("report_file") if generated is not None else report_file
        saved_report_file_display = str(saved_report_file).replace("\\", "/")
        click.echo(click.style(f"Report generated and saved to: {saved_report_file_display}", fg="cyan", bold=True))
        try:
            with open(saved_report_file, "r", encoding="utf-8") as report_handle:
                _echo_colored_report(report_handle.read())
        except FileNotFoundError:
            click.echo(click.style("Report not found.", fg="red", bold=True))


@cli.command()
@click.option("--change", default=None, help="Change Network")
@click.option("--view", is_flag=True, help="View all Networks")
@click.option("--create", is_flag=True, help="Create a new Network")
def network(change, view, create):
    """View or change the current network"""
    if sum([bool(change), view, create]) > 1:
        click.echo(click.style("Please choose only one option: --change, --view, or --create", fg="red", bold=True))
        return
    if change:
        click.echo(click.style("Changing network...", fg="green", bold=True))
        requested_network = str(change)
        try:
            existing_networks = src.all_networks()
        except Exception as exc:
            click.echo(click.style(f"Failed to load networks: {exc}", fg="red", bold=True))
            return

        if not any(net.network_name == requested_network for net in existing_networks):
            click.echo(click.style(
                f"Network '{requested_network}' does not exist. Use --create to add it first.",
                fg="red",
                bold=True,
            ))
            return

        _write_current_network(requested_network)
        click.echo(click.style("Network changed!", fg="green", bold=True))
    elif view:
        click.echo(click.style("Viewing all networks...", fg="green", bold=True))
        networks = src.all_networks()
        for net in networks:
            click.echo(click.style(f"- {net.network_name}", fg="green", bold=True))
        click.echo(click.style("All networks displayed!", fg="green", bold=True))
    elif create:
        click.echo(click.style("Creating new network...", fg="green", bold=True))
        if not _require_command_password():
            return
        new_network = click.prompt("Enter new network name", default=None, show_default=False)

        try:
            existing_networks = src.all_networks()
        except Exception as exc:
            click.echo(click.style(f"Failed to load networks: {exc}", fg="red", bold=True))
            return

        if any(net.network_name == new_network for net in existing_networks):
            click.echo(click.style(f"Network '{new_network}' already exists.", fg="yellow", bold=True))
            return

        try:
            src.add_to_network(new_network)
        except Exception as exc:
            click.echo(click.style(f"Failed to create network: {exc}", fg="red", bold=True))
            return
        click.echo(click.style("New network created!", fg="green", bold=True))
    else:
        click.echo(click.style("Current network: ", fg="green", bold=True))
        current_network = _read_current_network()
        if current_network:
            click.echo(click.style(current_network, fg="green", bold=True))
        else:
            click.echo(click.style("No network set.", fg="yellow", bold=True))


@cli.command()
@click.option("--device", default=None, help="Look at a specific device")
@_require_network_configured()
def device(device):
    """View or analyze a specific device"""
    if device:
        click.echo(click.style(f"Analyzing device {device}...", fg="green", bold=True))
        devices = src.get_devices_by_network(grab_network())
        device_info = next((d for d in devices if d.mac_address == device), None)
        if device_info:
            click.echo(click.style(f"Device Name: {device_info.device_name}", fg="green", bold=True))
            click.echo(click.style(f"Device Type: {device_info.device_type}", fg="green", bold=True))
            click.echo(click.style(f"MAC Address: {device_info.mac_address}", fg="green", bold=True))
            click.echo(click.style(f"IP Address: {device_info.ip_address}", fg="green", bold=True))
            click.echo(click.style(f"Confidence: {device_info.confidence}", fg="green", bold=True))
        click.echo(click.style("Device analysis complete!", fg="green", bold=True))
    else:
        click.echo(click.style("All devices.", fg="green", bold=True))
        devices = src.get_devices_by_network(grab_network())
        for dev in devices:
            click.echo(click.style(f"- {dev.device_name} ({dev.mac_address})", fg="green", bold=True))


@cli.command()
@_require_command_authentication()
def clear():
    """Clear all data and reset the application"""
    click.echo(click.style("WARNING: This will delete all data and reset the application!", fg="red", bold=True))
    if not click.confirm(click.style("Are you sure you want to continue?", fg="yellow", bold=True)):
        click.echo(click.style("Operation cancelled.", fg="green", bold=True))
        return
    click.echo(click.style("Clearing all data...", fg="green", bold=True))
    for directory in DATA_DIRECTORIES:
        shutil.rmtree(directory, ignore_errors=True)
    for directory in DATA_DIRECTORIES:
        os.makedirs(directory, exist_ok=True)
    click.echo(click.style("All data cleared!", fg="green", bold=True))


@cli.command()
@_require_network_configured()
def flagged():
    """View flagged devices"""
    click.echo(click.style("Viewing flagged devices...", fg="green", bold=True))
    devices = src.get_devices_by_network(grab_network())
    for dev in devices:
        if dev.confidence < DEFAULT_CONFIDENCE_THRESHOLD:
            click.echo(click.style(f"- {dev.device_name} ({dev.mac_address})", fg="red", bold=True))
    click.echo(click.style("Flagged devices displayed!", fg="green", bold=True))


@cli.command()
def dashboard():
    """View the dashboard"""
    click.echo(click.style("Opening dashboard...", fg="green", bold=True))
    src.DashboardApp().run()
    click.echo(click.style("Dashboard displayed!", fg="green", bold=True))


@cli.command(name="app")
def application():
    """Run the application"""
    click.echo(click.style("Running the application...", fg="green", bold=True))
    src.run_app()
    click.echo(click.style("Application is running!", fg="green", bold=True))


@cli.command()
def intro():
    """Show the introduction screen with ASCII art and command reference."""
    click.echo()
    click.echo(click.style(ASCII_BANNER, fg="magenta", bold=True))
    click.echo()
    click.echo(click.style(
        "  The Device Identificationator -- Network Device Classification Tool",
        fg="white",
    ))
    click.echo()
    col_width = max(len(cmd) for cmd, _ in COMMANDS) + 2
    click.echo(click.style(f"  {'Command':<{col_width}}Description", fg="cyan", bold=True))
    click.echo(click.style(f"  {'-' * col_width}{'-' * 40}", fg="cyan"))
    for cmd, desc in COMMANDS:
        click.echo(
            click.style(f"  {cmd:<{col_width}}", fg="cyan", bold=True)
            + click.style(desc, fg="white")
        )
    click.echo()
    click.echo(click.style(
        "  Run: python main.py <command> --help  for details",
        fg="white", dim=True,
    ))


def main():
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
