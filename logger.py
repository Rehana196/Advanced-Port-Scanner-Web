# logger.py
"""
Logging and scan history manager for Advanced Port Scanner.
Reads and writes scan history to config-configured files.
"""

import json
import os
import datetime
from threading import Lock
from config import HISTORY_FILE

history_lock = Lock()

def load_history():
    """
    Loads historical scans from the JSON history file.
    """
    with history_lock:
        if not os.path.exists(HISTORY_FILE):
            return []
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

def save_scan_to_history(target_ip, target_host, scan_duration, protocol_scanned, open_ports):
    """
    Appends a completed scan result to the scan history.
    `open_ports` is expected to be a list of dictionaries with keys:
    'port', 'protocol', 'state', 'service', 'version', 'banner', 'os'
    """
    with history_lock:
        history = []
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                history = []
        
        # Keep only the last 50 scans to prevent the history file from growing indefinitely
        if len(history) >= 50:
            history.pop(0)

        scan_record = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target_ip": target_ip,
            "target_host": target_host,
            "duration_seconds": round(scan_duration, 2),
            "protocol": protocol_scanned,
            "open_ports_count": len(open_ports),
            "results": open_ports
        }
        
        history.append(scan_record)
        
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=4)
        except Exception as e:
            print(f"Error saving history: {e}")

def clear_history():
    """
    Deletes all historical scan records.
    """
    with history_lock:
        if os.path.exists(HISTORY_FILE):
            try:
                os.remove(HISTORY_FILE)
            except Exception as e:
                print(f"Error deleting history file: {e}")
