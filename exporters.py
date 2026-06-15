from datetime import datetime
from scapy.all import wrpcap
import csv
import os


def save_to_csv(records):
    if not records:
        print("No packet records to save.")
        return

    os.makedirs("reports", exist_ok=True)

    filename = datetime.now().strftime(
        "reports/capture_%Y-%m-%d_%H-%M-%S.csv"
    )

    fieldnames = [
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Service",
        "Packet Size",
        "Alerts"
    ]

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(records)

    print("CSV report saved to:", filename)


def save_to_pcap(packets):
    if not packets:
        print("No packets to save in PCAP format.")
        return

    os.makedirs("captures", exist_ok=True)

    filename = datetime.now().strftime(
        "captures/capture_%Y-%m-%d_%H-%M-%S.pcap"
    )

    wrpcap(filename, packets)

    print("PCAP saved to:", filename)