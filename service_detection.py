# service_detection.py
"""
Service and version detection engine.
Uses port correlations and regular expressions to parse banners and extract versions.
"""

import re

# Simple database of port-to-service mapping (Common fallback when banner grabbing fails or matches default)
WELL_KNOWN_SERVICES = {
    # TCP
    (21, "tcp"): "FTP",
    (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet",
    (25, "tcp"): "SMTP",
    (53, "tcp"): "DNS",
    (80, "tcp"): "HTTP",
    (110, "tcp"): "POP3",
    (111, "tcp"): "RPCBind",
    (135, "tcp"): "MSRPC",
    (139, "tcp"): "NetBIOS",
    (143, "tcp"): "IMAP",
    (443, "tcp"): "HTTPS",
    (445, "tcp"): "Microsoft-DS (SMB)",
    (993, "tcp"): "IMAPS",
    (995, "tcp"): "POP3S",
    (1433, "tcp"): "MSSQL",
    (1521, "tcp"): "Oracle DB",
    (1723, "tcp"): "PPTP",
    (2049, "tcp"): "NFS",
    (3306, "tcp"): "MySQL",
    (3389, "tcp"): "RDP",
    (5060, "tcp"): "SIP",
    (5432, "tcp"): "PostgreSQL",
    (5900, "tcp"): "VNC",
    (8080, "tcp"): "HTTP-Proxy",
    (8443, "tcp"): "HTTPS-Proxy",
    # UDP
    (53, "udp"): "DNS",
    (67, "udp"): "DHCP Server",
    (68, "udp"): "DHCP Client",
    (69, "udp"): "TFTP",
    (123, "udp"): "NTP",
    (137, "udp"): "NetBIOS NS",
    (138, "udp"): "NetBIOS DS",
    (161, "udp"): "SNMP",
    (162, "udp"): "SNMP Trap",
    (500, "udp"): "ISAKMP",
    (514, "udp"): "Syslog",
}

# Regex database for parsing version strings from banners
VERSION_PATTERNS = [
    # SSH Banners (e.g. SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5)
    (re.compile(r"OpenSSH_([0-9a-zA-Z\.\-]+)", re.I), "OpenSSH", r"\1"),
    (re.compile(r"Dropbear_([0-9\.]+)", re.I), "Dropbear SSH", r"\1"),
    # HTTP Server Headers (e.g. Server: Apache/2.4.41 (Ubuntu))
    (re.compile(r"Server:\s+Apache/([0-9a-zA-Z\.\-]+)", re.I), "Apache HTTPD", r"\1"),
    (re.compile(r"Server:\s+nginx/([0-9a-zA-Z\.\-]+)", re.I), "nginx", r"\1"),
    (re.compile(r"Server:\s+Microsoft-IIS/([0-9\.]+)", re.I), "Microsoft IIS", r"\1"),
    (re.compile(r"Server:\s+lighttpd/([0-9a-zA-Z\.\-]+)", re.I), "lighttpd", r"\1"),
    (re.compile(r"Server:\s+Gunicorn/([0-9\.]+)", re.I), "Gunicorn", r"\1"),
    (re.compile(r"Server:\s+Werkzeug/([0-9\.]+)", re.I), "Werkzeug WSGI", r"\1"),
    # FTP Banners (e.g. 220 vsFTPd 3.0.3)
    (re.compile(r"vsFTPd\s+([0-9\.]+)", re.I), "vsftpd", r"\1"),
    (re.compile(r"220[- ]FileZilla Server ([0-9\.]+)", re.I), "FileZilla FTP Server", r"\1"),
    (re.compile(r"220[- ]Pure-FTPd", re.I), "Pure-FTPd", "Unknown Version"),
    (re.compile(r"ProFTPD\s+([0-9a-zA-Z\.\-]+)", re.I), "ProFTPD", r"\1"),
    # SMTP Banners (e.g. 220 mail.example.com ESMTP Postfix)
    (re.compile(r"Postfix", re.I), "Postfix SMTP", "Unknown Version"),
    (re.compile(r"Exim\s+([0-9\.]+)", re.I), "Exim SMTP", r"\1"),
    # MySQL
    (re.compile(r"([0-9\.]+)-MariaDB", re.I), "MariaDB", r"\1"),
    (re.compile(r"([58]\.[0-9\.]+)[a-zA-Z0-9\-]*\s*mysql", re.I), "MySQL", r"\1"),
]

def identify_service(port, protocol="tcp", banner=None):
    """
    Identifies the service name and application version of an open port.
    Returns a tuple of (service_name, version_string).
    """
    protocol = protocol.lower()
    service_name = WELL_KNOWN_SERVICES.get((port, protocol), "Unknown")
    version_string = "Unknown"
    
    if not banner:
        return service_name, version_string
        
    # Attempt to parse banner with regular expressions
    for pattern, name, version_expr in VERSION_PATTERNS:
        match = pattern.search(banner)
        if match:
            service_name = name
            if "\\" in version_expr:
                try:
                    version_string = match.expand(version_expr)
                except Exception:
                    version_string = "Detected"
            else:
                version_string = version_expr
            break
            
    # Fallback to general parsing if matching regex was not hit but banner exists
    if service_name == "Unknown" and banner:
        # e.g., print first line of banner (truncated) as service info
        first_line = banner.split("\n")[0].strip()
        if len(first_line) > 30:
            first_line = first_line[:27] + "..."
        service_name = "Banner Reply"
        version_string = first_line

    return service_name, version_string
