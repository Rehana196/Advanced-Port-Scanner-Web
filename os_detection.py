# os_detection.py
"""
OS detection engine.
Analyzes service banners and network characteristics (like TCP TTL patterns)
to infer the target operating system.
"""

import re

def detect_os(banner=None, ttl=None, port_services=None):
    """
    Heuristic OS detection.
    Analyzes:
    - Banners containing OS footprints (e.g. "Ubuntu", "Debian", "Windows")
    - TTL values (64 -> Linux/Unix, 128 -> Windows, 255 -> Network devices)
    - Specific port fingerprints
    
    Returns a string of the estimated OS.
    """
    heuristics = []
    
    # 1. Check TTL patterns if available
    if ttl is not None:
        if ttl <= 64:
            heuristics.append(("Linux/Unix", 0.6))
        elif ttl <= 128:
            heuristics.append(("Windows", 0.6))
        elif ttl <= 255:
            heuristics.append(("Network Device (Cisco/FreeBSD)", 0.5))
            
    # 2. Analyze Banners for OS keywords
    if banner:
        banner_lower = banner.lower()
        
        # Windows indicators
        if "microsoft-iis" in banner_lower or "ms-wbt-server" in banner_lower:
            heuristics.append(("Windows", 0.9))
        elif "windows" in banner_lower:
            heuristics.append(("Windows", 0.8))
            
        # Linux distribution indicators
        elif "ubuntu" in banner_lower:
            heuristics.append(("Linux (Ubuntu)", 0.95))
        elif "debian" in banner_lower:
            heuristics.append(("Linux (Debian)", 0.95))
        elif "redhat" in banner_lower or "red hat" in banner_lower:
            heuristics.append(("Linux (RedHat)", 0.9))
        elif "centos" in banner_lower:
            heuristics.append(("Linux (CentOS)", 0.9))
        elif "gentoo" in banner_lower:
            heuristics.append(("Linux (Gentoo)", 0.95))
        elif "linux" in banner_lower:
            heuristics.append(("Linux", 0.7))
            
        # FreeBSD/NetBSD/OpenBSD/Unix
        elif "freebsd" in banner_lower:
            heuristics.append(("FreeBSD", 0.9))
        elif "openbsd" in banner_lower:
            heuristics.append(("OpenBSD", 0.9))
        elif "netbsd" in banner_lower:
            heuristics.append(("NetBSD", 0.9))
            
        # macOS / Apple
        elif "darwin" in banner_lower:
            heuristics.append(("macOS/Darwin", 0.8))

    # 3. Port services heuristics
    if port_services:
        for port, service in port_services.items():
            # Standard Microsoft services
            if port == 445 or port == 135:
                heuristics.append(("Windows", 0.4))
            # Standard Linux/Unix R-services or NFS
            if port == 2049:
                heuristics.append(("Linux/Unix", 0.3))

    # Resolve heuristics by returning the item with the highest confidence
    if not heuristics:
        return "Unknown"
        
    # Aggregate scores for each OS candidate
    scores = {}
    for os_candidate, weight in heuristics:
        scores[os_candidate] = scores.get(os_candidate, 0.0) + weight
        
    best_os = max(scores, key=scores.get)
    return best_os
