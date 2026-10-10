# NetScope

> A lightweight real-time network packet analyzer built with Python, PyShark, TShark, and PySide6.

NetScope is a desktop network monitoring and packet analysis application designed to capture, inspect, filter, and analyze network traffic in real time.

The project provides a graphical interface for viewing network packets without requiring users to work directly with command-line packet analysis tools.

---

## Features

### Live Packet Capture

NetScope can capture network packets from an available network interface in real time.

Supported packet information includes:

- Ethernet
- IPv4
- IPv6
- TCP
- UDP
- ICMP
- ARP
- DNS
- HTTP
- HTTPS / TLS
- SSH
- DHCP
- Source and destination addresses
- Source and destination ports
- Packet length
- Packet information

### Network Interface Selection

NetScope allows the user to select the network interface that should be monitored.

Example interfaces:

```text
wlo1
lo
any
```

The available interfaces depend on the operating system and network configuration.

### Start / Stop Capture

NetScope provides controls for managing packet capture:

- Start Capture
- Stop Capture
- Clear

The capture process is separated from the graphical interface so that the application remains responsive while packets are being captured.

### Packet Table

Captured packets are displayed in a structured table.

| Column | Description |
|---|---|
| # | Packet number |
| Time | Packet capture time |
| Source | Source IP/address |
| Destination | Destination IP/address |
| Protocol | Detected network protocol |
| Length | Packet size |
| Source Port | Source port when available |
| Destination Port | Destination port when available |
| Info | Additional packet information |

### Packet Details

Selecting a packet displays additional information about the selected packet.

This allows individual packets to be inspected directly from the graphical interface.

---

# Advanced Packet Filtering

NetScope provides packet filtering through the search/filter interface.

Filters can be used to locate specific types of traffic, network addresses, or ports.

## Protocol Filters

```text
tcp
udp
dns
http
tls
icmp
arp
```

## IP Filter

```text
ip:192.168.1.1
```

Matches packets involving the specified IP address.

## Source Filter

```text
src:192.168.1.1
```

Matches packets originating from the specified source address.

## Destination Filter

```text
dst:8.8.8.8
```

Matches packets sent to the specified destination address.

## Port Filter

```text
port:443
```

Matches packets where either the source or destination port is the specified port.

## Source Port Filter

```text
srcport:443
```

Matches packets with the specified source port.

## Destination Port Filter

```text
dstport:53
```

Matches packets with the specified destination port.

## Combined Filters

Multiple conditions can be combined.

Examples:

```text
tcp && port:443
```

```text
udp && port:53
```

```text
tcp && ip:192.168.1.10
```

```text
tcp || udp
```

Negation can also be used:

```text
!arp
```

Filtering changes the packets displayed in the interface while the captured packet collection remains available to the application.

---

# Statistics

NetScope maintains statistics about captured network traffic.

The application tracks:

- Total packets
- Total bytes
- Packets per second
- Bytes per second
- Protocol distribution
- Top source IP addresses
- Top destination IP addresses
- Source port activity
- Destination port activity

Important statistics are displayed through dedicated summary cards in the GUI.

---

# Architecture

NetScope follows a modular architecture separating packet capture, analysis, storage, statistics, and the graphical interface.

```text
                    ┌─────────────────────┐
                    │       NetScope      │
                    │      PySide6 GUI    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Capture Worker   │
                    │   Process Manager   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      PyShark         │
                    │      TShark          │
                    │      Dumpcap         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │     Packet Data     │
                    │   Parsing / Store   │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
           ┌─────────────────┐   ┌─────────────────┐
           │ Packet Filtering│   │   Statistics    │
           └─────────────────┘   └─────────────────┘
```

## Main Components

### Capture

Responsible for receiving packets from the selected network interface.

### Analyzer

Responsible for packet filtering and traffic statistics.

### Packet Store

Maintains captured packet information during the current application session.

### UI

Responsible for displaying packets, statistics, controls, filters, and packet details.

---

# Project Structure

```text
Network monitor/
│
├── analyzer/
│   ├── filters.py
│   ├── packet_store.py
│   └── statistics.py
│
├── capture/
│   ├── worker.py
│   └── ...
│
├── ui/
│   ├── main_window.py
│   └── ...
│
├── data/
│
├── main.py
├── requirements.txt
└── README.md
```

The exact file structure may evolve as the project is extended.

---

# Technologies Used

## Python

Python is the primary programming language used to build NetScope.

It is used for:

- Application logic
- Packet processing
- Filtering
- Statistics
- Process management
- GUI integration

## PySide6

PySide6 is used to build the desktop graphical user interface.

It provides:

- Windows
- Buttons
- Tables
- Input fields
- Layouts
- Signals and slots
- Application events
- GUI event handling

## PyShark

PyShark provides Python access to packet capture and packet dissection functionality through TShark.

It is responsible for interacting with captured network traffic.

## TShark

TShark is the command-line version of Wireshark's packet analysis engine.

NetScope uses TShark as the underlying packet analysis and dissection engine.

## Dumpcap

Dumpcap is used underneath the packet capture stack to obtain network traffic from the selected network interface.

---

# Requirements

Before running NetScope, install:

- Python 3.13
- TShark
- Dumpcap
- PyShark
- PySide6

Python dependencies are listed in:

```text
requirements.txt
```

---

# Python Environment

NetScope currently uses Python 3.13.

A virtual environment is recommended.

If using `uv`:

```bash
uv python install 3.13
```

Create the virtual environment:

```bash
uv venv --python 3.13
```

Activate it:

```bash
source .venv/bin/activate
```

Install the dependencies:

```bash
uv pip install -r requirements.txt
```

Verify Python:

```bash
python --version
```

Expected version:

```text
Python 3.13.x
```

---

# Installing TShark

On Ubuntu/Debian-based systems:

```bash
sudo apt update
sudo apt install tshark
```

Verify the installation:

```bash
tshark --version
```

Check available interfaces:

```bash
sudo tshark -D
```

Example:

```text
1. wlo1
2. any
3. lo
4. bluetooth0
```

---

# Running NetScope

Navigate to the project directory:

```bash
cd ~/Network\ monitor
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Run the application:

```bash
python main.py
```

The NetScope graphical interface should open.

---

# Using NetScope

## 1. Select a Network Interface

Select the network interface from the interface dropdown.

For example:

```text
wlo1
```

For a Wi-Fi connection, the interface name may be different depending on the system.

## 2. Start Capture

Click:

```text
Start Capture
```

NetScope will begin capturing packets from the selected interface.

Captured packets will appear in the packet table.

## 3. Inspect Packets

Click any packet in the table.

The packet details section will display additional information about the selected packet.

## 4. Filter Packets

Enter a filter into the filter/search field.

For example:

```text
dns
```

or:

```text
tcp && port:443
```

The packet table will update according to the selected filter.

## 5. Stop Capture

Click:

```text
Stop Capture
```

The capture process will be stopped and the application will return to the ready state.

## 6. Clear Packets

Click:

```text
Clear
```

to remove the currently stored packets and reset the displayed statistics.

---

# Capture Architecture

NetScope separates packet capture from the main graphical interface.

The capture architecture is:

```text
PySide6 GUI
     │
     ▼
Capture Worker
     │
     ▼
Separate Capture Process
     │
     ├── PyShark
     │
     ├── TShark
     │
     └── Dumpcap
```

This architecture prevents the graphical interface from becoming blocked by packet capture operations.

This is particularly important when stopping a live capture because packet capture libraries can perform blocking operations while communicating with TShark.

By running the capture component separately, NetScope can terminate the capture process without freezing the main GUI.

---

# Why PyShark + TShark?

NetScope does not implement network packet dissection from scratch.

Instead, it uses established packet analysis components:

```text
PyShark
   │
   ▼
TShark
   │
   ▼
Dumpcap
   │
   ▼
Network Interface
```

PyShark provides Python integration, while TShark and Dumpcap handle the underlying packet capture and packet dissection.

This allows NetScope to focus on providing a graphical packet analysis experience.

---

# Permissions

Packet capture normally requires appropriate network-capture permissions.

Depending on the Linux distribution and system configuration, running:

```bash
tshark -D
```

may result in a permission error.

For testing, interfaces can be inspected with:

```bash
sudo tshark -D
```

A direct capture test can be performed with:

```bash
sudo tshark -i wlo1
```

Replace `wlo1` with the appropriate network interface.

The entire NetScope GUI should not be routinely run as root.

A better long-term configuration is to grant the required packet-capture permissions to the appropriate capture components.

---

# Security and Ethical Use

NetScope is intended for:

- Learning computer networking
- Understanding network protocols
- Debugging network problems
- Monitoring your own systems
- Analyzing traffic on networks you are authorized to inspect
- Studying packet structures
- Learning network monitoring techniques

Only capture network traffic when you have permission to do so.

NetScope is designed around passive packet analysis.

It does not provide offensive functionality such as:

- Packet injection
- Deauthentication attacks
- Credential interception
- Exploit automation
- Unauthorized traffic manipulation

---

# Current Capabilities

The current version of NetScope provides:

```text
✓ Live packet capture
✓ Network interface selection
✓ Ethernet packet information
✓ IPv4 analysis
✓ IPv6 analysis
✓ TCP analysis
✓ UDP analysis
✓ ICMP detection
✓ ARP detection
✓ DNS detection
✓ HTTP detection
✓ TLS / HTTPS detection
✓ SSH detection
✓ DHCP detection
✓ Packet table
✓ Packet details
✓ Packet filtering
✓ Protocol filtering
✓ IP filtering
✓ Source filtering
✓ Destination filtering
✓ Port filtering
✓ Source port filtering
✓ Destination port filtering
✓ Combined filtering
✓ Packet statistics
✓ Traffic counters
✓ Top source IP statistics
✓ Top destination IP statistics
✓ Top port statistics
✓ PySide6 graphical interface
✓ Separate capture process
✓ Start / Stop capture management
✓ Dark interface
```

---

# Design Philosophy

NetScope is built around three main principles.

## 1. Understand Network Traffic

The application should make network traffic easier to understand than raw command-line packet output.

## 2. Keep the Interface Responsive

Packet capture should not freeze or block the graphical interface.

## 3. Keep the Project Modular

Packet capture, packet analysis, storage, statistics, and UI responsibilities should remain separated.

This makes the application easier to understand, maintain, debug, and extend.

---

# Future Improvements

Possible future improvements include:

- Packet hex viewer
- PCAP export
- PCAP import
- CSV export
- JSON export
- Live traffic graphs
- Network topology visualization
- Device discovery
- DNS analysis
- TLS/SNI analysis
- Connection and conversation tracking
- Passive anomaly detection
- Network overview dashboard
- Keyboard shortcuts
- Additional UI customization

These features are not part of the current version.

---

# Troubleshooting

## TShark Cannot Access the Interface

Check the available interfaces:

```bash
sudo tshark -D
```

If interfaces are listed with `sudo` but not without it, the system's packet-capture permissions need to be configured.

## No Packets Appear

Check that:

1. A valid network interface is selected.
2. The interface is active.
3. TShark is installed correctly.
4. TShark can access the interface.
5. The system has the required packet-capture permissions.

You can test TShark directly:

```bash
sudo tshark -i wlo1
```

Replace `wlo1` with your actual interface.

## Python / PyShark Problems

Check the Python version:

```bash
python --version
```

NetScope currently uses:

```text
Python 3.13
```

Make sure the virtual environment is activated before running the application.

---

# Learning Goals

NetScope is also a practical project for learning:

- Computer networking
- TCP/IP
- Ethernet
- IPv4 and IPv6
- TCP
- UDP
- ICMP
- ARP
- DNS
- HTTP
- HTTPS / TLS
- SSH
- DHCP
- Network monitoring
- Packet analysis
- Python
- PySide6
- PyShark
- TShark
- Process management
- GUI programming
- Event-driven programming
- Software architecture

---

# Project Status

**Status: Active Development**

The core packet capture, packet analysis, filtering, statistics, and graphical interface functionality is currently implemented.

Additional analysis and visualization features may be added in future versions.

---

# License

This project is currently intended as a personal learning and experimentation project.

If NetScope is published as an open-source project, an appropriate open-source license can be added here.

---

# Author

**Satyajeet Mohanty**

NetScope was developed as a hands-on project for learning network packet analysis, Python application development, and computer networking.