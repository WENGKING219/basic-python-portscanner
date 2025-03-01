# Network Port Scanner

A powerful and user-friendly port scanning tool built in Python that allows you to check for open ports on a network, helping identify potential vulnerabilities.

## Features

- **Multiple Scanning Modes**:
  - Quick Scan: Checks common ports only
  - Full Scan: Scans all ports (1-65535)
  - Custom Scan: Specify port range and thread count

- **Multithreaded Scanning**: Significantly speeds up the scanning process

- **Service Detection**: Identifies services running on open ports

- **Results Management**:
  - Save scan results to text files
  - Organized reports with timestamps

## Installation

1. Clone or download this repository
2. Install the required dependencies: `pip install -r requirements.txt`

## Usage

1. Run the script: `python port_scanner.py`
2. Choose a scanning mode:
   - Quick Scan
   - Full Scan
   - Custom Scan
3. Enter the target IP address or hostname
4. View the scan results
