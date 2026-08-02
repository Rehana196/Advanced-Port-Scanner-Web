# banner.py
"""
Banner grabbing module for Advanced Port Scanner.
Attempts to read banners sent by open ports.
If no banner is returned initially, it sends protocol-specific probes.
"""

import socket

def grab_banner(ip, port, protocol="tcp", timeout=1.5):
    """
    Connects to the specified target port and grabs the banner.
    Returns the decoded banner string or None.
    """
    if protocol.lower() == "udp":
        return grab_udp_banner(ip, port, timeout)
    
    return grab_tcp_banner(ip, port, timeout)

def grab_tcp_banner(ip, port, timeout):
    """
    TCP Banner grabber.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # 1. Try reading initial greeting (e.g. SSH, FTP, SMTP send banners instantly)
        try:
            banner = s.recv(1024)
            if banner:
                s.close()
                return clean_banner_data(banner)
        except socket.timeout:
            pass # No initial banner, we'll try sending probes
            
        # 2. Try HTTP probe if port is standard HTTP/HTTPS/alternative web port
        if port in [80, 443, 8080, 8443, 8000]:
            try:
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                banner = s.recv(2048)
                if banner:
                    s.close()
                    return clean_banner_data(banner)
            except Exception:
                pass
                
        # 3. Try standard connection message (sending basic empty newline to trigger response)
        try:
            s.sendall(b"\r\n\r\n")
            banner = s.recv(1024)
            if banner:
                s.close()
                return clean_banner_data(banner)
        except Exception:
            pass
            
        s.close()
    except Exception:
        pass
    return None

def grab_udp_banner(ip, port, timeout):
    """
    UDP banner grabbing. Sends basic protocol probes.
    """
    # UDP is connectionless. We need to send a probe to get a response.
    probes = {
        53: b"\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01", # DNS Query
        123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # NTP client message
        161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x1a\x30\x61\x08\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", # SNMP GetRequest
    }
    
    probe = probes.get(port, b"\r\n")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(probe, (ip, port))
        data, _ = s.recvfrom(1024)
        s.close()
        return clean_banner_data(data)
    except Exception:
        pass
    return None

def clean_banner_data(data):
    """
    Cleans raw binary banner data into a printable ASCII/UTF-8 string.
    """
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = data.decode("latin-1", errors="ignore")
    
    # Filter non-printable ASCII except basic separators
    cleaned = "".join([c if (32 <= ord(c) < 127 or c in "\r\n\t") else "" for c in text])
    return cleaned.strip()
