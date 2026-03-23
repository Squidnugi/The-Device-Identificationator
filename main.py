import click
import src
import shutil
import os
from functools import wraps
import tests.tui as tui

def _require_command_password():
    """Prompt for the command password and validate it."""
    if not src.is_password_set():
        click.echo(click.style('No command password is configured yet.', fg='yellow', bold=True))
        click.echo(click.style('Run: python main.py setup-password', fg='yellow'))
        return False

    password = click.prompt('Command password', hide_input=True)
    if not src.verify_password(password):
        click.echo(click.style('Authentication failed.', fg='red', bold=True))
        return False
    return True

def _require_network_configured():      
    """Decorator that checks if a network is configured in network.txt"""
    def decorator(func):
        @wraps(func)
        @click.pass_context
        def wrapper(ctx, *args, **kwargs):
            try:
                with open('config/network.txt', 'r') as f:
                    content = f.read().strip()
                    if not content:
                        click.echo(click.style('No network configured. Run: python main.py network --change <network_name>', fg='yellow'))
                        return
            except FileNotFoundError:
                click.echo(click.style('No network configured. Run: python main.py network --change <network_name>', fg='yellow'))
                return
                
            return func(*args, **kwargs)
        return wrapper
    return decorator

def grab_network():
    """Helper function to grab the current network from network.txt"""
    try:
        with open('config/network.txt', 'r') as f:
            content = f.read().strip()
            return content
    except FileNotFoundError:
        return None


def _echo_colored_report(report_text):
    """Render text report output with unknown device rows highlighted in red."""
    if not report_text or not str(report_text).strip():
        click.echo(click.style('No devices found for this network in the report.', fg='yellow', bold=True))
        return

    lines = str(report_text).splitlines()
    in_table = False

    for line in lines:
        stripped = line.strip()

        if not stripped:
            click.echo('')
            continue

        if stripped.startswith('device_name') and 'device_type' in stripped and 'mac_address' in stripped:
            in_table = True
            click.echo(click.style(line, fg='cyan', bold=True))
            continue

        if in_table and set(stripped) <= {'-', ' '}:
            click.echo(click.style(line, fg='cyan', bold=True))
            continue

        if in_table:
            parts = [part.strip() for part in line.split('  ') if part.strip()]
            is_unknown = len(parts) >= 2 and (
                parts[0].lower() == 'unknown' or parts[1].lower() == 'unknown'
            )
            row_color = 'red' if is_unknown else 'green'
            click.echo(click.style(line, fg=row_color, bold=True))
            continue

        click.echo(click.style(line, fg='green', bold=True))


@click.group()
def cli():
    """Device Identificationator - Wizard (DEMO)"""
    pass


@cli.command()
@click.option('--change', is_flag=True, help='Change command password')
def setup(change):
    """Create Network, password, and initialise database (DEMO)"""
    if change:
        if not _require_command_password():
            return

        click.echo(click.style('Changing command password...', fg='green', bold=True))
        password = click.prompt('New command password', hide_input=True, confirmation_prompt=True)
        src.set_password(password)
        click.echo(click.style('Command password changed! (DEMO)', fg='green', bold=True))
        return
    else:
        src.create_all_tables()
        if src.is_password_set():
            click.echo(click.style('A command password is already set. Use "python main.py setup --change" to change it.', fg='yellow', bold=True))
            return
        password = click.prompt('Set command password', hide_input=True, confirmation_prompt=True)
        src.set_password(password)
        click.echo(click.style('Password saved.', fg='green', bold=True))
        with open('config/network.txt', 'r') as f:
            content = f.read().strip()
            src.add_to_network('Default_Network')
            if not content:
                with open('config/network.txt', 'w') as f:
                    f.write('Default_Network')
        click.echo(click.style('Default network created.', fg='green', bold=True))


@cli.command()
@click.option('--file', default='data/processed/16-09-24_extracted.csv', help='Path to the dataset file')
@_require_network_configured()
def identifier(file):
    """Run device identification analysis (DEMO)"""
    click.echo(click.style('Running device identification analysis...', fg='green', bold=True))
    data = None
    if file.endswith('.csv'):
        click.echo(click.style('Processing CSV file...', fg='green', bold=True))
    elif file.endswith('.pcap'):
        click.echo(click.style('Processing pcap file...', fg='green', bold=True))
        data = src.process_pcap(file, save_to_csv=False)
    else:
        click.echo(click.style('Unsupported file type. Please provide a .csv or .pcap file.', fg='red', bold=True))
        return
    results = src.use_model(file_path=file, dataset=data)
    click.echo(click.style('Analysis complete! (DEMO)', fg='green', bold=True))
    click.echo(click.style(results.to_string(), fg='green', bold=True))
    network = grab_network()
    src.add_device(results, network)

#creates pcap file for demo purposes
#files generate in data/raw/ with name format: 16-09-24.csv
@cli.command()
def scanner():
    """Run a network scan (DEMO)"""
    click.echo(click.style('Running device scanning...', fg='green', bold=True))
    src.capture_packets()
    click.echo(click.style('Scanning complete! (DEMO)', fg='green', bold=True))

#creates a report for demo purposes
#report could include summary statistics, identified devices, and network insights
@cli.command()
@click.option('--report-file', default='data/reports/report.txt', help='Path to save the generated report')
@click.option('--file', default='data/processed/16-09-24_extracted.csv', help='Path to the dataset file')
@click.option('--read', default=None, help='Read and display an existing report')
@_require_network_configured()
def report(report_file, file, read):
    """Generate a report (DEMO)"""
    network = grab_network()
    if read:
        try:
            with open(read, 'r', encoding='utf-8') as report_handle:
                _echo_colored_report(report_handle.read())
        except FileNotFoundError:
            click.echo(click.style('Report not found.', fg='red', bold=True))
    else:
        report = src.generate_report(file, report_file, network)
        saved_report_file = report.attrs.get('report_file') if report is not None else report_file
        saved_report_file_display = str(saved_report_file).replace('\\', '/')
        click.echo(click.style(f'Report generated and saved to: {saved_report_file_display}', fg='cyan', bold=True))
        try:
            with open(saved_report_file, 'r', encoding='utf-8') as report_handle:
                _echo_colored_report(report_handle.read())
        except FileNotFoundError:
            click.echo(click.style('Report not found.', fg='red', bold=True))


@cli.command()
@click.option('--change', default=None, help='Change Network')
@click.option('--view', is_flag=True, help='View all Networks')
@click.option('--create', is_flag=True, help='Create a new Network')
def network(change, view, create):
    """View or change the current network (DEMO)"""
    if sum([bool(change), view, create]) > 1:
        click.echo(click.style('Please choose only one option: --change, --view, or --create', fg='red', bold=True))
        return
    if change:
        if not _require_command_password():
            return

        click.echo(click.style('Changing network...', fg='green', bold=True))
        try:
            with open('config/network.txt', 'r+') as f:
                content = f.read()
                f.seek(0)
                f.truncate()
                f.write(str(change))
        except FileNotFoundError:
            with open('config/network.txt', 'w') as f:
                f.write(str(change))
        click.echo(click.style('Network changed! (DEMO)', fg='green', bold=True))
    elif view:
        click.echo(click.style('Viewing all networks... (DEMO)', fg='green', bold=True))
        networks = src.all_networks()
        for network in networks:
            click.echo(click.style(f"- {network.network_name}", fg='green', bold=True))
        click.echo(click.style('All networks displayed! (DEMO)', fg='green', bold=True))
    elif create:
        if not _require_command_password():
            return

        click.echo(click.style('Creating new network...', fg='green', bold=True))
        new_network = click.prompt('Enter new network name', default='New_Network')
        src.add_to_network(new_network)
        click.echo(click.style('New network created! (DEMO)', fg='green', bold=True))
    else:
        click.echo(click.style('Current network: (DEMO)', fg='green', bold=True))
        try:
            with open('config/network.txt', 'r') as f:
                content = f.read()
                click.echo(click.style(content, fg='green', bold=True))
        except FileNotFoundError:
            click.echo(click.style('No network set. (DEMO)', fg='yellow', bold=True))

@cli.command()
@click.option('--device', default=None, help='Look at a specific device')
@_require_network_configured()
def device(device):    
    """View or analyze a specific device (DEMO)"""
    if device:
        click.echo(click.style(f'Analyzing device {device}...', fg='green', bold=True))
        devices = src.get_devices_by_network(grab_network())
        device_info = next((d for d in devices if d.mac_address == device), None)
        if device_info:
            click.echo(click.style(f"Device Name: {device_info.device_name}", fg='green', bold=True))
            click.echo(click.style(f"Device Type: {device_info.device_type}", fg='green', bold=True))
            click.echo(click.style(f"MAC Address: {device_info.mac_address}", fg='green', bold=True))
            click.echo(click.style(f"IP Address: {device_info.ip_address}", fg='green', bold=True))
            click.echo(click.style(f"Confidence: {device_info.confidence}", fg='green', bold=True))
        click.echo(click.style('Device analysis complete! (DEMO)', fg='green', bold=True))
    else:
        click.echo(click.style('All devices. (DEMO)', fg='green', bold=True))
        devices = src.get_devices_by_network(grab_network())
        for device in devices:
            click.echo(click.style(f"- {device.device_name} ({device.mac_address})", fg='green', bold=True))

@cli.command()
def clear():
    """Clear all data and reset the application (DEMO)"""
    if not _require_command_password():
        return

    click.echo(click.style('Clearing all data...', fg='green', bold=True))
    shutil.rmtree('data/processed', ignore_errors=True)
    shutil.rmtree('data/raw', ignore_errors=True)
    shutil.rmtree('data/reports', ignore_errors=True)
    os.makedirs('data/processed', exist_ok=True)
    os.makedirs('data/raw', exist_ok=True)
    os.makedirs('data/reports', exist_ok=True)
    click.echo(click.style('All data cleared! (DEMO)', fg='green', bold=True))

@cli.command()
@_require_network_configured()
def flagged():
    """View flagged devices (DEMO)"""
    click.echo(click.style('Viewing flagged devices...', fg='green', bold=True))
    devices = src.get_devices_by_network(grab_network())
    for device in devices:
        if device.confidence < 0.6:  # Example threshold
            click.echo(click.style(f"- {device.device_name} ({device.mac_address})", fg='red', bold=True))

    click.echo(click.style('Flagged devices displayed! (DEMO)', fg='green', bold=True))

@cli.command()
def dashboard():
    """View the dashboard (DEMO)"""
    click.echo(click.style('Opening dashboard...', fg='green', bold=True))
    tui.DeviceIDApp().run()
    click.echo(click.style('Dashboard displayed! (DEMO)', fg='green', bold=True))

def main():
    #click.echo(click.style('Welcome to the Device Identificationator - Wizard (DEMO)', fg='cyan', bold=True))
    cli()

if __name__ == "__main__":
    main()