# Network Scanner

A simple Python-based tool for network reconnaissance. It discovers active hosts on a local network and scans them for open ports.

## Features
- **Host Discovery**: Uses ARP requests to find live devices on the local subnet.
- **Port Scanning**: Connects to specified ports to check if they are open.
- **Service Identification**: (Basic) Identifies open TCP ports.

## Prerequisites
- **Python 3.x**
- **Scapy**: `pip install scapy`
- **Root/Admin Privileges**: Required for constructing raw packets (ARP).

## Installation

1. Clone the repository or download the files.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script with `sudo` (Linux/macOS) or as Administrator (Windows).

### Basic Host Discovery
Scan a subnet to find active devices.
```bash
sudo python scanner.py --target 192.168.1.1/24
```

### Host Discovery + Port Scan
Scan a subnet and check for specific open ports on discovered hosts.
```bash
sudo python scanner.py --target 192.168.1.1/24 --ports 22,80,443,3000
```

### Scan a Range of Ports
```bash
sudo python scanner.py --target 192.168.1.15 --ports 1-100
```

## Example Output

```text
[+] Scanning 192.168.1.1/24 for active hosts...

[+] Discovered Hosts:
IP			MAC Address
-----------------------------------------
192.168.1.1		aa:bb:cc:dd:ee:ff
192.168.1.15		11:22:33:44:55:66

[+] Starting Port Scan...

[+] Scanning ports on 192.168.1.1...
    [+] Port 53 is OPEN
    [+] Port 80 is OPEN

[+] Scanning ports on 192.168.1.15...
    [+] Port 22 is OPEN
```

## Troubleshooting
- **Permission Denied**: Ensure you run the script with `sudo`.
- **No Hosts Found**: Check if the target subnet is correct and matches your network configuration.
- **Scapy Warnings**: You may see warnings from Scapy; these are usually harmless and can be ignored.
