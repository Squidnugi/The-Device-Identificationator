# The Device Identificationator

> A network device classification tool that captures or ingests network traffic, analyses packet behaviour, and identifies device types by MAC address using a trained Random Forest model.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [First-Time Setup](#first-time-setup)
- [Running the Application](#running-the-application)
  - [TUI Application](#tui-application)
  - [Dashboard](#dashboard)
- [Commands](#commands)
  - [identifier](#identifier)
  - [scanner](#scanner)
  - [report](#report)
  - [network](#network)
  - [device](#device)
  - [flagged](#flagged)
  - [clear](#clear)
  - [setup](#setup)
  - [intro](#intro)
- [Model Training](#model-training)
- [Project Structure](#project-structure)
- [Notes](#notes)

---

## Overview

The Device Identificationator processes network traffic (live capture or PCAP/CSV files) and classifies devices on your network by their MAC address. Results are stored in a local SQLite database and can be viewed through either the interactive TUI or the command line. These results can be used to generate reports, view an overview of classified devices, and identify any unknown or foreign devices.

**Key features:**
- Classify devices from PCAP or pre-processed CSV files
- Live packet capture and real-time classification
- Per-device confidence scoring with flagging for uncertain results
- Multi-network support
- Interactive Textual TUI with a live dashboard
- Password-protected state-mutating commands

---

## Requirements

- Python 3.10+
- A network interface accessible to Scapy (live capture requires appropriate permissions)
- See `requirements.txt` for full Python dependencies

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Squidnugi/The-Device-Identificationator
cd The-Device-Identificationator

# Install dependencies
pip install -r requirements.txt
```

---

## First-Time Setup

Run the setup command once before using any other commands. This creates the database tables, sets your command password, and creates a default network.

```bash
python main.py setup
```

You will be prompted to create a command password. This password is required for all state-changing operations.

To change your password later:

```bash
python main.py setup --change
```

---

## Running the Application

### TUI Application

The full interactive interface — includes network management, device classification, live capture, report generation, and the dashboard.

```bash
python main.py app
```

**TUI key bindings:**

| Key | Action |
|-----|--------|
| `c` | Start classification |
| `s` | Capture live traffic |
| `r` | Generate report |
| `x` | Clear data folders |
| `d` | Open dashboard |
| `p` | Change password |
| `[` | Select previous network |
| `]` | Select next network |
| `Enter` | Apply selected network |
| `q` | Quit |

### Dashboard

Opens the dashboard screen on its own without the full TUI.

```bash
python main.py dashboard
```

---

## Commands

All commands that modify data require the command password set during setup.

---

### `identifier`

Runs device identification analysis on a traffic file. Classifies devices by MAC address and saves results to the database.

```bash
python main.py identifier --file <path>
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--file` | *(required)* | Path to a `.csv`, `.pcap`, or `.pcapng` file |
| `--confidence-threshold` | `0.60` | Minimum confidence score to accept a classification |
| `--margin-threshold` | `0.10` | Minimum gap between top-1 and top-2 probabilities |

**Example:**

```bash
python main.py identifier --file data/processed/capture_extracted.csv
python main.py identifier --file data/raw/capture.pcap --confidence-threshold 0.75
```

> Requires command password. Requires a network to be configured.

---

### `scanner`

Captures live packets from a network interface, processes them, and saves both the PCAP and extracted CSV to disk.

```bash
python main.py scanner --packets <n> --interface <iface>
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--packets` | `100` | Number of packets to capture |
| `--interface` | `eth0` | Network interface to capture on (Linux/Unix) |

**Example:**

```bash
python main.py scanner --packets 500 --interface wlan0
```

> Requires command password. On Windows, Scapy may require running as Administrator.

---

### `report`

Generates a classification report comparing traffic MACs against the database, or reads an existing saved report.

```bash
# Generate a new report
python main.py report --file <path>

# Read an existing report
python main.py report --read <path>
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--file` | — | Source traffic file (`.csv`, `.pcap`, or `.pcapng`) |
| `--report-file` | `data/reports/report.txt` | Output path for the generated report |
| `--read` | — | Path to an existing report file to display |

**Example:**

```bash
python main.py report --file data/processed/capture_extracted.csv
python main.py report --read data/reports/report.txt
```

> Generating a report requires command password. Reading an existing report does not.

---

### `network`

View all networks, switch to an existing network, or create a new one.

```bash
python main.py network [--view | --change <name> | --create]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--view` | List all saved networks |
| `--change <name>` | Switch to an existing network by name |
| `--create` | Create a new network (prompted for name) |

**Example:**

```bash
python main.py network --view
python main.py network --change HomeNetwork
python main.py network --create
```

> `--create` requires command password. `--view` and `--change` do not.

---

### `device`

View all devices on the current network, or inspect a specific device by MAC address.

```bash
# List all devices
python main.py device

# Inspect a specific device
python main.py device --device <mac-address>
```

**Options:**

| Option | Description |
|--------|-------------|
| `--device` | MAC address of the device to inspect |

**Example:**

```bash
python main.py device
python main.py device --device aa:bb:cc:dd:ee:ff
```

> Requires a network to be configured. No password required.

---

### `flagged`

Lists all devices on the current network whose confidence score falls below the classification threshold. These are devices the model is uncertain about.

```bash
python main.py flagged
```

> Requires a network to be configured. No password required.

---

### `clear`

Deletes all files in the data directories (`data/raw/`, `data/processed/`, `data/reports/`) and recreates them empty. Does **not** affect the database or trained models.

```bash
python main.py clear
```

You will be asked to confirm before anything is deleted.

> Requires command password.

---

### `setup`

Initialises the database, creates the default network, and sets the command password. Only needs to be run once.

```bash
python main.py setup
```

To change the password on an existing installation:

```bash
python main.py setup --change
```

---

### `intro`

Displays the ASCII banner and a summary of all available commands.

```bash
python main.py intro
```

---

## Model Training

The classifier is a calibrated Random Forest trained on per-packet features extracted from labelled PCAP files. The data used to train the model was sourced from [UNSW Sydney](https://iotanalytics.unsw.edu.au/iottraces.html). The labelling is hardcoded, so if different data is to be used, the device labels in the `add_labels()` function need to be updated to reflect the new dataset.

**Train the model:**

Edit the `if __name__ == "__main__":` block at the bottom of `src/models/random_forest.py` to set your dataset path and model output path, then run:

```bash
python src/models/random_forest.py
```

**Full pipeline — process all PCAPs in a directory, merge, and train:**

Edit the constants at the top of `train_from_pcaps.py` (`RAW_DIR`, `MERGED_OUTPUT`, `MODEL_PATH`) to match your paths, then run:

```bash
python train_from_pcaps.py
```

**Process a PCAP file:**

Edit the `if __name__ == "__main__":` block at the bottom of `src/datapipeline/pcap.py` to set the target file and options (`save_to_csv`, `train`), then run:

```bash
python src/datapipeline/pcap.py
```

> Training labels are defined as a hardcoded MAC-to-device-type dictionary in `src/datapipeline/pcap.py`. Add new MAC addresses there before training on new device types.

---

## Project Structure

```
The-Device-Identificationator/
├── main.py                        # CLI entry point
├── train_from_pcaps.py            # Batch PCAP processing and training script
├── requirements.txt
│
├── src/
│   ├── datapipeline/
│   │   ├── pcap.py                # PCAP → DataFrame, feature engineering
│   │   ├── live_data.py           # Live packet capture via Scapy
│   │   └── database.py            # SQLAlchemy models and CRUD operations
│   ├── models/
│   │   └── random_forest.py       # Train, save, load, and run the classifier
│   ├── config.py                  # Shared constants (paths, confidence thresholds)
│   ├── report.py                  # Report generation
│   ├── security/
│   │   └── password_auth.py       # bcrypt password management
│   └── tui/
│       ├── app.py                 # Full Textual TUI application
│       └── dashboard.py           # Dashboard screen
│
├── models/                        # Saved model .pkl artifacts
├── data/
│   ├── raw/                       # Original PCAP files
│   ├── processed/                 # Extracted feature CSVs
│   └── reports/                   # Generated text reports
└── config/                        # auth.json (password), network.txt (active network)
```

---

## Notes

- **Confidence threshold:** A device is classified as `Unknown` if its confidence is below `0.70` or the margin between the top two predictions is below `0.12`. Both thresholds can be overridden with `--confidence-threshold` and `--margin-threshold` on the `identifier` command.
- **Device upsert:** When running classification more than once, a stored device record is only overwritten if the new run produces a strictly higher confidence score.
- **Model artifacts:** Two files are required — `models/random_forest_model.pkl` (the classifier) and `models/random_forest_model_encoder.pkl` (the label encoders). If these are missing, run training before using `identifier` or `scanner`.
