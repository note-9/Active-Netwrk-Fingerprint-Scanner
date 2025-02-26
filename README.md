# Network and Fingerprint Scanner

## Overview
This Python script scans a network to find active devices and fingerprints them by retrieving their MAC address vendor and checking for open ports. It utilizes ARP requests to detect devices, queries an online MAC vendor API, and performs a basic port scan.

## Features
- Scans a local network using ARP requests
- Identifies active devices with their IP and MAC addresses
- Retrieves MAC address vendor information
- Scans common ports (22, 80, 443, 3389) for open connections

## Requirements
Ensure you have the following dependencies installed:
```sh
pip install scapy requests
```

## Usage
Run the script with Python:
```sh
python scanner.py
```

By default, the script scans the `192.168.1.0/24` network range. Modify this range in the script as needed.

## Example Output
```
Scanning network: 192.168.1.0/24

IP: 192.168.1.2, MAC: 00:1A:2B:3C:4D:5E, Vendor: Apple Inc.
  Open ports: 22, 80

IP: 192.168.1.3, MAC: 00:1F:7D:8E:9C:AB, Vendor: TP-Link Technologies
  No common ports open.
```

## How It Works
1. Uses ARP to find active devices on the local network.
2. Fetches MAC vendor details from an online API.
3. Scans for open ports on detected devices.
4. Displays results in a user-friendly format.

## Disclaimer
This script is for educational and security auditing purposes only. Do not use it on networks you do not own or have explicit permission to scan.

