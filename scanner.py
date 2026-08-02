# scanner.py
"""
Multi-threaded scanning engine for TCP and UDP port scans.
Integrates banner grabbing, service detection, and OS heuristic analysis.
"""

import socket
import threading
import time
from queue import Queue
from banner import grab_banner
from service_detection import identify_service
from os_detection import detect_os

class PortScanner:
    """
    Main port scanning engine.
    Supports TCP connect scan and UDP probing.
    Uses a thread pool to scan ports concurrently.
    """
    def __init__(self, target_ip, ports, scan_type="tcp", thread_count=100, timeout=1.0, callback=None):
        self.target_ip = target_ip
        self.ports = ports
        self.scan_type = scan_type.lower() # "tcp", "udp", or "both"
        self.thread_count = min(thread_count, len(ports)) if ports else thread_count
        self.timeout = timeout
        self.callback = callback # Callback function for GUI updates: callback(port, protocol, state, service, version, banner, os_heuristic)
        
        self.results = []
        self.is_running = False
        self.queue = Queue()
        self.lock = threading.Lock()
        
        # Statistics
        self.ports_scanned = 0
        self.total_ports = len(ports)
        self.start_time = None
        self.end_time = None

    def scan_tcp_port(self, port):
        """
        Attempts a TCP connect handshake on the specified port.
        """
        try:
            # Setup TCP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            
            # Connect
            start = time.time()
            result_code = s.connect_ex((self.target_ip, port))
            duration = time.time() - start
            
            if result_code == 0:
                # Port is open. Gather info.
                banner = grab_banner(self.target_ip, port, "tcp", timeout=self.timeout)
                service, version = identify_service(port, "tcp", banner)
                
                # Attempt to get socket options to infer OS (TTL)
                ttl = None
                try:
                    # IP_TTL option gets TTL of incoming packets on some platforms.
                    # As a simple backup/standard option, standard connect doesn't expose TTL easily
                    # without raw sockets, so we rely more on banners and general heuristics.
                    pass
                except Exception:
                    pass
                
                os_heuristic = detect_os(banner=banner, ttl=ttl, port_services={port: service})
                
                result = {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service,
                    "version": version,
                    "banner": banner if banner else "",
                    "os": os_heuristic
                }
                
                with self.lock:
                    self.results.append(result)
                
                if self.callback:
                    self.callback(result)
            s.close()
        except Exception:
            pass

    def scan_udp_port(self, port):
        """
        Attempts a UDP probe. UDP is connectionless and tricky:
        - If we get a response -> Open
        - If we get ICMP unreachable (requires raw socket/admin) -> Closed
        - If we get nothing (timeout) -> Open|Filtered (labeled here as Filtered/Open)
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            
            # Send standard packet payload (or protocol specific if DNS/NTP etc.)
            # If standard, send empty byte
            from banner import grab_udp_banner
            banner = grab_banner(self.target_ip, port, "udp", timeout=self.timeout)
            
            if banner:
                # Got banner, port is definitely open!
                service, version = identify_service(port, "udp", banner)
                os_heuristic = detect_os(banner=banner, port_services={port: service})
                
                result = {
                    "port": port,
                    "protocol": "udp",
                    "state": "open",
                    "service": service,
                    "version": version,
                    "banner": banner,
                    "os": os_heuristic
                }
                with self.lock:
                    self.results.append(result)
                if self.callback:
                    self.callback(result)
            else:
                # Without raw sockets to catch ICMP port unreachable, UDP scanning usually yields
                # "filtered" status for non-responding ports. If common port, we can ping
                # but we'll only label it open if it responds. To avoid flooding GUI with thousands of 
                # 'filtered' ports, we only report UDP ports if they responded or are highly suspicious.
                # Here we report it if the port is common and we want to show it.
                pass
            s.close()
        except Exception:
            pass

    def _worker(self):
        """
        Worker thread executing port scans from the queue.
        """
        while self.is_running:
            try:
                task = self.queue.get_nowait()
            except Exception:
                break # Queue is empty
                
            port, proto = task
            if proto == "tcp":
                self.scan_tcp_port(port)
            elif proto == "udp":
                self.scan_udp_port(port)
                
            with self.lock:
                self.ports_scanned += 1
                
            self.queue.task_done()

    def start_scan(self):
        """
        Populates tasks and spawns worker threads to start the scan.
        Blocks until completion.
        """
        self.is_running = True
        self.start_time = time.time()
        self.ports_scanned = 0
        self.results = []
        
        # Enqueue scan tasks
        for port in self.ports:
            if self.scan_type in ["tcp", "both"]:
                self.queue.put((port, "tcp"))
            if self.scan_type in ["udp", "both"]:
                self.queue.put((port, "udp"))
                
        # Total items in queue
        self.total_tasks = self.queue.qsize()
        
        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self._worker, daemon=True)
            threads.append(t)
            t.start()
            
        # Wait for all tasks to be finished
        while not self.queue.empty() and self.is_running:
            time.sleep(0.1)
            
        self.queue.join()
        self.is_running = False
        self.end_time = time.time()
        
        # Sort results by port number
        self.results.sort(key=lambda x: x["port"])
        return self.results

    def stop_scan(self):
        """
        Aborts the active scan by clearing the queue and setting status flag.
        """
        self.is_running = False
        with self.queue.mutex:
            self.queue.queue.clear()
        self.queue.all_tasks_done.acquire()
        self.queue.all_tasks_done.notify_all()
        self.queue.all_tasks_done.release()
