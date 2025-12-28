# Network Scanner

## Overview
The Network Scanner is a cybersecurity tool designed to scan a local network and identify live hosts and open ports. Its primary purpose is to teach the concepts of reconnaissance in both offensive and defensive cybersecurity contexts.

## Purpose
- **Education**: To demonstrate how network reconnaissance works.
- **Utility**: To quickly identify devices and services running on a local network.

## Features
- **Host Discovery**: Identify live hosts on the local network using ICMP/ARP requests.
- **Port Scanning**: Scan identified hosts for open ports (e.g., 22, 80, 443).
- **Service Identification**: Attempt to identify services running on open ports (banner grabbing).
- **User-Friendly Output**: Display results in a clear, readable format.

## Technical Requirements
- **Language**: Python 3.x
- **Libraries**: `socket`, `scapy` (optional but recommended for robust scanning), `argparse`.
- **OS Support**: Cross-platform (Linux, macOS, Windows). *Note: Raw socket operations often require root/admin privileges.*

## Usage
The tool will be a command-line interface (CLI) script.

```bash
# Example usage
sudo python scanner.py --target 192.168.1.0/24 --ports 1-1024
```

## Deliverables
1. Python script (`scanner.py`)
2. `README.md` with documentation and screenshots.
3. `product.md` (this file).

