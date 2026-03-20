import click
import src

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


@click.group()
def cli():
    """Device Identificationator - Wizard (DEMO)"""
    pass


@cli.command(name='setup')
def setup():
    """Create Network, password, and initialise database (DEMO)"""
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


@cli.command(name='identify')
@click.option('--file', default='data/processed/16-09-24_extracted.csv', help='Path to the dataset file')
@_require_network_configured()
def identifier(file):
    """Run device identification analysis (DEMO)"""
    click.echo(click.style('Running device identification analysis...', fg='green', bold=True))
    results = src.use_model(file_path=file)
    click.echo(click.style('Analysis complete! (DEMO)', fg='green', bold=True))
    click.echo(click.style(results.to_string(), fg='green', bold=True))
    #click.echo(click.style(results.dtypes.to_string(), fg='cyan'))
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
def report():
    """Generate a report (DEMO)"""
    if not _require_command_password():
        return

    click.echo(click.style('Generating report...', fg='green', bold=True))
    # Here you would implement the actual report generation logic
    click.echo(click.style('Report generated! (DEMO)', fg='green', bold=True))


@cli.command()
@click.option('--change', default=None, help='Change Network')
@click.option('--view', is_flag=True, help='View all Networks')
@click.option('--create', is_flag=True, help='Create a new Network')
def network(change, view, create):
    """View or change the current network (DEMO)"""
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
        # Here you would implement the actual logic to view all networks
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
def device(device):    
    """View or analyze a specific device (DEMO)"""
    if device:
        click.echo(click.style(f'Analyzing device {device}...', fg='green', bold=True))
        # Here you would implement the actual device analysis logic
        click.echo(click.style('Device analysis complete! (DEMO)', fg='green', bold=True))
    else:
        click.echo(click.style('All devices. (DEMO)', fg='green', bold=True))

cli.add_command(identifier)
cli.add_command(scanner)
cli.add_command(report)
cli.add_command(network)
cli.add_command(device)
cli.add_command(setup)

def main():
    cli()

if __name__ == "__main__":
    main()