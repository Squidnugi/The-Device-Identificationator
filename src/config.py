"""Shared application-level configuration constants for The Device Identificationator."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

NETWORK_CONFIG_PATH = REPO_ROOT / "config" / "network.txt"

DATA_DIRECTORIES = ("data/processed", "data/raw", "data/reports")

DEFAULT_CONFIDENCE_THRESHOLD = 0.70
DEFAULT_MARGIN_THRESHOLD = 0.12
