from .models import train_model, use_model
from .datapipeline import create_all_tables, drop_all_tables, capture_packets, capture_and_process_packets, add_to_network, add_device, get_devices_by_network, process_pcap, all_networks
from .security import set_password, verify_password, is_password_set
from .report import generate_report
from .tui import DashboardApp, run_app

__version__ = "0.1.0"
__author__ = "Your Name"

# Import main classes/functions for easier access
# from .module_name import ClassName, function_name

__all__ = [
    "train_model",
    "use_model",
    "set_password",
    "is_password_set",
    "verify_password",
    "create_all_tables",
    "drop_all_tables",
    "capture_packets",
    "capture_and_process_packets",
    "add_to_network",
    "add_device",
    "get_devices_by_network",
    "process_pcap",
    "generate_report",
    "all_networks",
    "DashboardApp",
    "run_app"
]