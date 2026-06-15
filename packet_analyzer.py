from scapy.all import IP, TCP, UDP, ICMP
from datetime import datetime
from collections import Counter

from config import SERVICES
from detection import detect_suspicious_activity
import detection


# Packet counters
total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0
other_packets = 0


# Packet-size statistics
total_bytes = 0
largest_packet = 0
smallest_packet = None


# Extracted packet information for CSV
packet_records = []


# Actual packets for PCAP saving
captured_packets = []


# Traffic statistics
source_ip_counts = Counter()
destination_ip_counts = Counter()
service_counts = Counter()


def get_service_name(port):
    return SERVICES.get(port, "Unknown")


def get_packet_time(packet):
    try:
        return float(packet.time)

    except (AttributeError, TypeError, ValueError):
        return datetime.now().timestamp()


def format_packet_time(packet_time):
    return datetime.fromtimestamp(packet_time).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def process_packet(packet, save_raw_packet=True):
    global total_packets, tcp_packets, udp_packets
    global icmp_packets, other_packets
    global total_bytes, largest_packet, smallest_packet

    # PacketLens currently analyzes IPv4 packets only
    if not packet.haslayer(IP):
        return

    if save_raw_packet:
        captured_packets.append(packet)

    packet_time = get_packet_time(packet)
    timestamp = format_packet_time(packet_time)

    total_packets += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "Other"
    source_port = "N/A"
    destination_port = "N/A"

    if packet.haslayer(TCP):
        tcp_packets += 1
        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        udp_packets += 1
        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        icmp_packets += 1
        protocol = "ICMP"

    else:
        other_packets += 1

    service = get_service_name(destination_port)

    if service == "Unknown":
        service = get_service_name(source_port)

    packet_size = len(packet)

    total_bytes += packet_size

    if packet_size > largest_packet:
        largest_packet = packet_size

    if smallest_packet is None or packet_size < smallest_packet:
        smallest_packet = packet_size

    source_ip_counts[source_ip] += 1
    destination_ip_counts[destination_ip] += 1
    service_counts[service] += 1

    alerts = detect_suspicious_activity(
        packet=packet,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        packet_time=packet_time
    )

    if alerts:
        alert_text = " | ".join(alerts)
    else:
        alert_text = "None"

    packet_record = {
        "Timestamp": timestamp,
        "Source IP": source_ip,
        "Destination IP": destination_ip,
        "Protocol": protocol,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Service": service,
        "Packet Size": packet_size,
        "Alerts": alert_text
    }

    packet_records.append(packet_record)

    print()
    print("Timestamp:", timestamp)
    print("Source IP:", source_ip)
    print("Destination IP:", destination_ip)
    print("Protocol:", protocol)
    print("Source Port:", source_port)
    print("Destination Port:", destination_port)
    print("Service:", service)
    print("Packet Size:", packet_size, "bytes")

    for alert in alerts:
        print(alert)

    print("----------------------------")


def print_summary(title):
    if total_packets > 0:
        average_packet_size = total_bytes / total_packets
    else:
        average_packet_size = 0

    if source_ip_counts:
        top_source_ip, top_source_count = (
            source_ip_counts.most_common(1)[0]
        )
    else:
        top_source_ip = "N/A"
        top_source_count = 0

    if destination_ip_counts:
        top_destination_ip, top_destination_count = (
            destination_ip_counts.most_common(1)[0]
        )
    else:
        top_destination_ip = "N/A"
        top_destination_count = 0

    if service_counts:
        top_service, top_service_count = (
            service_counts.most_common(1)[0]
        )
    else:
        top_service = "N/A"
        top_service_count = 0

    print()
    print(f"===== {title} =====")
    print("Total Packets:", total_packets)
    print("TCP Packets:", tcp_packets)
    print("UDP Packets:", udp_packets)
    print("ICMP Packets:", icmp_packets)
    print("Other Packets:", other_packets)

    print("Total Alerts:", detection.total_alerts)
    print(
        "INFO Alerts:",
        detection.alert_level_counts["INFO"]
    )
    print(
        "MEDIUM Alerts:",
        detection.alert_level_counts["MEDIUM"]
    )
    print(
        "HIGH Alerts:",
        detection.alert_level_counts["HIGH"]
    )

    print("Total Bytes:", total_bytes, "bytes")
    print(
        "Average Packet Size:",
        round(average_packet_size, 2),
        "bytes"
    )

    print("Largest Packet:", largest_packet, "bytes")

    if smallest_packet is None:
        print("Smallest Packet: N/A")
    else:
        print("Smallest Packet:", smallest_packet, "bytes")

    print(
        "Most Active Source IP:",
        top_source_ip,
        f"({top_source_count} packets)"
    )

    print(
        "Most Contacted Destination IP:",
        top_destination_ip,
        f"({top_destination_count} packets)"
    )

    print(
        "Most Common Service:",
        top_service,
        f"({top_service_count} packets)"
    )

    print("=" * (len(title) + 12))