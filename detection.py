from collections import Counter, defaultdict, deque

from config import (
    UNUSUAL_PORTS,
    SENSITIVE_PORTS,
    PACKET_RATE_WINDOW,
    PACKET_RATE_THRESHOLD,
    PORT_SCAN_WINDOW,
    PORT_SCAN_THRESHOLD,
    SYN_SCAN_WINDOW,
    SYN_SCAN_THRESHOLD,
    SENSITIVE_PORT_WINDOW,
    SENSITIVE_PORT_THRESHOLD,
    ALERT_COOLDOWN
)


# Alert statistics
total_alerts = 0

alert_level_counts = Counter({
    "INFO": 0,
    "MEDIUM": 0,
    "HIGH": 0
})


# Detection trackers
packet_rate_tracker = defaultdict(deque)
port_scan_tracker = defaultdict(deque)
syn_scan_tracker = defaultdict(deque)
sensitive_port_tracker = defaultdict(deque)

# Stores the last time each alert was shown
last_alert_times = {}


def remove_old_timestamps(timestamp_queue, current_time, window):
    while (
        timestamp_queue
        and current_time - timestamp_queue[0] > window
    ):
        timestamp_queue.popleft()


def remove_old_port_entries(entry_queue, current_time, window):
    while (
        entry_queue
        and current_time - entry_queue[0][0] > window
    ):
        entry_queue.popleft()


def create_alert(level, message, alert_key, current_time):
    global total_alerts

    previous_alert_time = last_alert_times.get(alert_key)

    if previous_alert_time is not None:
        time_since_last_alert = current_time - previous_alert_time

        if time_since_last_alert < ALERT_COOLDOWN:
            return None

    last_alert_times[alert_key] = current_time

    total_alerts += 1
    alert_level_counts[level] += 1

    return f"[{level}] {message}"


def detect_suspicious_activity(
    packet,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    packet_time
):
    alerts = []

    # ICMP and some other packets do not have ports
    if not isinstance(destination_port, int):
        return alerts

    # Rule 1: Unusual destination port
    if destination_port in UNUSUAL_PORTS:
        reason = UNUSUAL_PORTS[destination_port]

        alert = create_alert(
            level="INFO",
            message=(
                f"Unusual destination port {destination_port} "
                f"observed from {source_ip} to {destination_ip}. "
                f"{reason}."
            ),
            alert_key=(
                "unusual_destination_port",
                source_ip,
                destination_ip,
                destination_port
            ),
            current_time=packet_time
        )

        if alert:
            alerts.append(alert)

    # Rule 2: High packet rate to one port
    packet_rate_key = (
        source_ip,
        destination_ip,
        destination_port
    )

    packet_rate_tracker[packet_rate_key].append(packet_time)

    remove_old_timestamps(
        packet_rate_tracker[packet_rate_key],
        packet_time,
        PACKET_RATE_WINDOW
    )

    packet_rate_count = len(
        packet_rate_tracker[packet_rate_key]
    )

    if packet_rate_count >= PACKET_RATE_THRESHOLD:
        alert = create_alert(
            level="MEDIUM",
            message=(
                f"High packet rate detected: {packet_rate_count} "
                f"packets from {source_ip} to "
                f"{destination_ip}:{destination_port} within "
                f"{PACKET_RATE_WINDOW} seconds."
            ),
            alert_key=(
                "high_packet_rate",
                source_ip,
                destination_ip,
                destination_port
            ),
            current_time=packet_time
        )

        if alert:
            alerts.append(alert)

    # Rule 3: Repeated sensitive-service traffic
    if destination_port in SENSITIVE_PORTS:
        service_name = SENSITIVE_PORTS[destination_port]

        sensitive_key = (
            source_ip,
            destination_ip,
            destination_port
        )

        sensitive_port_tracker[sensitive_key].append(
            packet_time
        )

        remove_old_timestamps(
            sensitive_port_tracker[sensitive_key],
            packet_time,
            SENSITIVE_PORT_WINDOW
        )

        sensitive_count = len(
            sensitive_port_tracker[sensitive_key]
        )

        if sensitive_count >= SENSITIVE_PORT_THRESHOLD:
            alert = create_alert(
                level="MEDIUM",
                message=(
                    f"Repeated traffic to sensitive service "
                    f"{service_name} on port {destination_port}: "
                    f"{sensitive_count} packets from {source_ip} "
                    f"within {SENSITIVE_PORT_WINDOW} seconds."
                ),
                alert_key=(
                    "sensitive_service_activity",
                    source_ip,
                    destination_ip,
                    destination_port
                ),
                current_time=packet_time
            )

            if alert:
                alerts.append(alert)

    # Rule 4: One source contacting many ports
    scan_key = (
        source_ip,
        destination_ip
    )

    port_scan_tracker[scan_key].append(
        (packet_time, destination_port)
    )

    remove_old_port_entries(
        port_scan_tracker[scan_key],
        packet_time,
        PORT_SCAN_WINDOW
    )

    unique_destination_ports = {
        entry[1]
        for entry in port_scan_tracker[scan_key]
    }

    if len(unique_destination_ports) >= PORT_SCAN_THRESHOLD:
        alert = create_alert(
            level="HIGH",
            message=(
                f"Possible port scan: {source_ip} contacted "
                f"{len(unique_destination_ports)} different ports "
                f"on {destination_ip} within "
                f"{PORT_SCAN_WINDOW} seconds. "
                f"Ports: {sorted(unique_destination_ports)}"
            ),
            alert_key=(
                "possible_port_scan",
                source_ip,
                destination_ip
            ),
            current_time=packet_time
        )

        if alert:
            alerts.append(alert)

    # Rule 5: TCP SYN scan
    if packet.haslayer("TCP"):
        tcp_flags = int(packet["TCP"].flags)

        syn_flag_set = bool(tcp_flags & 0x02)
        ack_flag_set = bool(tcp_flags & 0x10)

        if syn_flag_set and not ack_flag_set:
            syn_key = (
                source_ip,
                destination_ip
            )

            syn_scan_tracker[syn_key].append(
                (packet_time, destination_port)
            )

            remove_old_port_entries(
                syn_scan_tracker[syn_key],
                packet_time,
                SYN_SCAN_WINDOW
            )

            unique_syn_ports = {
                entry[1]
                for entry in syn_scan_tracker[syn_key]
            }

            if len(unique_syn_ports) >= SYN_SCAN_THRESHOLD:
                alert = create_alert(
                    level="HIGH",
                    message=(
                        f"Possible TCP SYN scan: {source_ip} sent "
                        f"SYN packets to {len(unique_syn_ports)} "
                        f"different ports on {destination_ip} "
                        f"within {SYN_SCAN_WINDOW} seconds. "
                        f"Ports: {sorted(unique_syn_ports)}"
                    ),
                    alert_key=(
                        "possible_syn_scan",
                        source_ip,
                        destination_ip
                    ),
                    current_time=packet_time
                )

                if alert:
                    alerts.append(alert)

    return alerts