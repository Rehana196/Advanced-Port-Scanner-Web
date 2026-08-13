# config.py
"""
Configuration settings for the Advanced Port Scanner.
Contains design styles, default port lists, and scanning settings.
"""

import os

# Project Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
HISTORY_FILE = os.path.join(LOG_DIR, "scan_history.json")

# Ensure logs directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Theme Configuration: "Dark Hacker" Neon Cyberpunk
THEME = {
    "bg_main": "#0a0c10",          # Deep obsidian black
    "bg_card": "#12161f",          # Sleek card background
    "bg_input": "#1a1f2c",         # Input background
    "fg_normal": "#e1e4ea",        # Soft light gray for general text
    "fg_muted": "#626875",         # Muted gray for secondary info
    "accent_green": "#00ff66",     # Neon green (success / open ports)
    "accent_cyan": "#00d2ff",      # Neon cyan (scans, information)
    "accent_red": "#ff3366",       # Neon red (errors, closed/filtered, alerts)
    "accent_amber": "#ffaa00",     # Neon orange (warnings, filtered ports)
    "border_color": "#1f2937",     # Dark border line
    "font_title": ("Consolas", 16, "bold"),
    "font_header": ("Consolas", 12, "bold"),
    "font_body": ("Consolas", 10),
    "font_console": ("Consolas", 9),
}

# Scan Configuration Defaults
DEFAULT_TIMEOUT = 0.5
DEFAULT_THREADS = 100
MAX_THREADS = 500

# Common Ports List (TCP)
COMMON_TCP_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCBind
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # Microsoft-DS (SMB)
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1521,  # Oracle DB
    1723,  # PPTP
    2049,  # NFS
    3306,  # MySQL
    3389,  # RDP
    5060,  # SIP
    5432,  # PostgreSQL
    5900,  # VNC
    8080,  # HTTP-Proxy
    8443,  # HTTPS-Proxy
]

# Common Ports List (UDP)
COMMON_UDP_PORTS = [
    53,    # DNS
    67,    # DHCP Server
    68,    # DHCP Client
    69,    # TFTP
    123,   # NTP
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram Service
    161,   # SNMP
    162,   # SNMP Trap
    500,   # ISAKMP (IPsec)
    514,   # Syslog
]
