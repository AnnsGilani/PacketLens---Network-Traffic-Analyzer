# Ports used for normal service identification
SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}


# Ports that may deserve investigation
# These ports are not automatically malicious
UNUSUAL_PORTS = {
    4444: "Often used by testing tools and some reverse shells",
    5555: "Often used by Android Debug Bridge",
    6667: "Traditionally used by IRC",
    31337: "Historically associated with backdoor software"
}


# Remote-access and sensitive services
SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP"
}


# High packet-rate rule
PACKET_RATE_WINDOW = 5
PACKET_RATE_THRESHOLD = 100


# General port-scan rule
PORT_SCAN_WINDOW = 10
PORT_SCAN_THRESHOLD = 10


# TCP SYN-scan rule
SYN_SCAN_WINDOW = 10
SYN_SCAN_THRESHOLD = 8


# Repeated sensitive-service traffic rule
SENSITIVE_PORT_WINDOW = 10
SENSITIVE_PORT_THRESHOLD = 20


# Prevents the same alert from appearing repeatedly
ALERT_COOLDOWN = 10