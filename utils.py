# utils.py
"""
Utility module for the Advanced Port Scanner.
Includes domain resolution, local IP address detection, and network input validators.
"""

import socket
import re

def is_valid_ip(ip_str):
    """
    Checks if a string is a valid IPv4 address.
    """
    pattern = re.compile(r"^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$")
    return bool(pattern.match(ip_str))

def resolve_target(target):
    """
    Resolves a hostname/domain or validates an IP address.
    Returns a tuple of (ip, hostname, error_message).
    """
    target = target.strip()
    if not target:
        return None, None, "Target is empty"
    
    # If it looks like an IP, validate it
    if re.match(r"^[0-9\.]+$", target):
        if is_valid_ip(target):
            try:
                # Try to get hostname (reverse lookup)
                hostname, _, _ = socket.gethostbyaddr(target)
                return target, hostname, None
            except socket.error:
                return target, target, None
        else:
            return None, None, "Invalid IPv4 address format"
    
    # Otherwise treat as hostname and resolve
    try:
        ip = socket.gethostbyname(target)
        return ip, target, None
    except socket.gaierror:
        return None, None, f"Could not resolve host: {target}"
    except Exception as e:
        return None, None, str(e)

def get_local_ip():
    """
    Attempts to detect the active local IP address.
    """
    try:
        # Create a dummy socket to connect to an external server (does not send packets)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        # Fallback to localhost if no network interface is active
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def parse_port_range(port_str):
    """
    Parses complex port range strings (e.g. "80,443,8000-8085,22").
    Returns a sorted list of unique integers.
    """
    ports = set()
    parts = port_str.replace(" ", "").split(",")
    for part in parts:
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-")
                start, end = int(start), int(end)
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.update(range(start, end + 1))
                else:
                    raise ValueError
            except ValueError:
                raise ValueError(f"Invalid range: {part}")
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    raise ValueError
            except ValueError:
                raise ValueError(f"Invalid port: {part}")
    
    return sorted(list(ports))
