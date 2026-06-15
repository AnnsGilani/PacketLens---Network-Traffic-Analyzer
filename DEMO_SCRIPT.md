# PacketLens Demo Script

## 1. Introduction

PacketLens is a Python network traffic analyzer built with Scapy. It supports live packet capture and offline PCAP analysis.

## 2. Show the project structure

Explain:

- `main.py` controls menus and program flow.
- `packet_analyzer.py` processes packets and calculates statistics.
- `detection.py` contains rule-based alert logic.
- `exporters.py` saves CSV and PCAP files.
- `config.py` contains ports and detection thresholds.

## 3. Run live capture

```powershell
py main.py
```

Choose:

```text
1. Live packet capture
1. Fixed number of packets
20
1. All IPv4 packets
```

Explain the output fields:

- Source and destination IP
- Protocol
- Ports
- Service
- Packet size
- Alerts

## 4. Show the summary

Point out:

- Protocol counts
- Total bytes
- Average packet size
- Largest and smallest packets
- Most active IPs
- Most common service
- Alert severity counts

## 5. Show generated files

Open:

- The CSV report in Excel
- The PCAP file in Wireshark

Explain that CSV stores extracted fields while PCAP stores the original packets.

## 6. Show PCAP analysis mode

Run PacketLens again and choose:

```text
2. Analyze an existing PCAP file
```

Paste the path of a saved PCAP.

## 7. Explain detection carefully

Say:

> PacketLens uses heuristic rules. An alert means the traffic deserves investigation; it does not automatically prove an attack.

Mention:

- Unusual ports
- High packet rates
- Sensitive-service traffic
- Multi-port scans
- TCP SYN scans

## 8. Finish

Say:

> This project improved my understanding of TCP/IP, ports, Scapy, packet analysis, PCAP files, rule-based detection, and false positives.
