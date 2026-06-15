from scapy.all import sniff, rdpcap

from packet_analyzer import (
    process_packet,
    print_summary,
    packet_records,
    captured_packets
)

from exporters import (
    save_to_csv,
    save_to_pcap
)


def get_main_mode():
    print("\nChoose PacketLens Mode:")
    print("1. Live packet capture")
    print("2. Analyze an existing PCAP file")

    while True:
        choice = input("\nEnter your choice (1 or 2): ")

        if choice in ["1", "2"]:
            return choice

        print("Invalid choice. Please enter 1 or 2.")


def get_capture_mode():
    print("\nChoose Capture Mode:")
    print("1. Fixed number of packets")
    print("2. Continuous capture")

    while True:
        choice = input("\nEnter your choice (1 or 2): ")

        if choice in ["1", "2"]:
            return choice

        print("Invalid choice. Please enter 1 or 2.")


def get_packet_count():
    while True:
        try:
            packet_count = int(
                input(
                    "How many IPv4 packets "
                    "do you want to capture? "
                )
            )

            if packet_count > 0:
                return packet_count

            print("Please enter a number greater than 0.")

        except ValueError:
            print("Please enter a valid whole number.")


def get_protocol_filter():
    print("\nChoose a protocol filter:")
    print("1. All IPv4 packets")
    print("2. TCP packets only")
    print("3. UDP packets only")
    print("4. ICMP packets only")

    while True:
        choice = input("\nEnter your choice (1-4): ")

        if choice == "1":
            return "ip", "All IPv4"

        if choice == "2":
            return "ip and tcp", "TCP"

        if choice == "3":
            return "ip and udp", "UDP"

        if choice == "4":
            return "icmp", "ICMP"

        print(
            "Invalid choice. "
            "Please enter a number from 1 to 4."
        )


def run_live_capture():
    capture_mode = get_capture_mode()

    if capture_mode == "1":
        packet_count = get_packet_count()
    else:
        packet_count = 0

    capture_filter, filter_name = get_protocol_filter()

    if capture_mode == "1":
        print(
            f"\nPacketLens is capturing "
            f"{packet_count} {filter_name} packets...\n"
        )

    else:
        print(
            f"\nPacketLens is continuously capturing "
            f"{filter_name} packets..."
        )
        print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            filter=capture_filter,
            count=packet_count,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    print("\nCapture Completed.")

    print_summary("Capture Summary")

    save_to_csv(packet_records)
    save_to_pcap(captured_packets)


def run_pcap_analysis():
    file_path = input(
        "\nEnter the full path of the PCAP file: "
    ).strip().strip('"')

    try:
        packets = rdpcap(file_path)

        print(
            f"\nLoaded {len(packets)} packets "
            f"from the PCAP file.\n"
        )

        for packet in packets:
            process_packet(
                packet,
                save_raw_packet=False
            )

    except FileNotFoundError:
        print("\nPCAP file was not found.")
        return

    except Exception as error:
        print("\nCould not analyze the PCAP file.")
        print("Error:", error)
        return

    print("\nPCAP Analysis Completed.")

    print_summary("PCAP Analysis Summary")

    save_to_csv(packet_records)


def main():
    main_mode = get_main_mode()

    if main_mode == "1":
        run_live_capture()

    else:
        run_pcap_analysis()


if __name__ == "__main__":
    main()