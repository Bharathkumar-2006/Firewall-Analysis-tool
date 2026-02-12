# Firewall Evasion Packet Tester

## Overview
The Firewall Evasion Packet Tester is a CLI-based security analysis tool built using Python and Scapy. It evaluates firewall configurations by sending multiple crafted packet types to a specified target IP address. The tool determines which packets are permitted, identifies open ports, and generates a detailed summary report in a separate output file.

## Features
- Sends multiple packet types (TCP, UDP, ICMP, SYN, ACK, etc.)
- Identifies firewall-allowed packets
- Detects open and responsive ports
- Generates structured output report
- Command-line based execution
- Lightweight and customizable

## Tech Stack
- **Programming Language:** Python
- **Networking Library:** Scapy


## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/firewall-evasion-packet-tester.git

# Navigate into the project directory
cd firewall-evasion-packet-tester

# Install required dependency
pip install scapy

# Run this tool
python main.py <target_ip>
```
