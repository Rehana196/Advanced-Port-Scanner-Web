# web_server.py
"""
Web Server for Advanced Port Scanner.
Provides REST API endpoints for scanning, status tracking, scan history, and report exports,
while serving the neon-cyberpunk web dashboard frontend.
"""

import http.server
import socketserver
import json
import urllib.parse
import os
import sys
import threading
import time
import datetime
import webbrowser

from config import THEME, DEFAULT_TIMEOUT, DEFAULT_THREADS, MAX_THREADS, COMMON_TCP_PORTS, COMMON_UDP_PORTS
from utils import resolve_target, get_local_ip, parse_port_range
from scanner import PortScanner
from logger import load_history, save_scan_to_history, clear_history
from export import export_to_json, export_to_csv, export_to_txt

# Global active scan state management
current_scan_job = {
    "scanner": None,
    "thread": None,
    "job_id": None,
    "target": "",
    "target_ip": "",
    "target_host": "",
    "protocol": "TCP",
    "is_running": False,
    "start_time": 0,
    "end_time": 0,
    "results": [],
    "total_tasks": 0,
    "scanned_tasks": 0,
    "error": None
}
scan_lock = threading.Lock()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

class ScannerHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP Request Handler serving static web files and handling API requests.
    """
    def log_message(self, format, *args):
        # Clean custom logging output
        sys.stdout.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {format % args}\n")

    def _send_json(self, data, status_code=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, file_path, mime_type):
        if not os.path.exists(file_path):
            self.send_error(404, "File Not Found")
            return
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, str(e))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Static assets routing
        if path == "/" or path == "/index.html":
            self._send_file(os.path.join(WEB_DIR, "index.html"), "text/html; charset=utf-8")
            return
        elif path == "/style.css":
            self._send_file(os.path.join(WEB_DIR, "style.css"), "text/css; charset=utf-8")
            return
        elif path == "/app.js":
            self._send_file(os.path.join(WEB_DIR, "app.js"), "application/javascript; charset=utf-8")
            return
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        # API Endpoints
        if path == "/api/local-ip":
            local_ip = get_local_ip()
            self._send_json({"status": "success", "local_ip": local_ip})
            return

        elif path == "/api/scan/status":
            with scan_lock:
                scanner = current_scan_job["scanner"]
                is_running = current_scan_job["is_running"]
                scanned = scanner.ports_scanned if scanner else current_scan_job["scanned_tasks"]
                total = current_scan_job["total_tasks"]
                percentage = int((scanned / total) * 100) if total > 0 else 0
                
                duration = 0
                if current_scan_job["start_time"] > 0:
                    end = current_scan_job["end_time"] if current_scan_job["end_time"] > 0 else time.time()
                    duration = round(end - current_scan_job["start_time"], 2)

                data = {
                    "is_running": is_running,
                    "target": current_scan_job["target"],
                    "target_ip": current_scan_job["target_ip"],
                    "target_host": current_scan_job["target_host"],
                    "protocol": current_scan_job["protocol"],
                    "percentage": percentage,
                    "scanned_count": scanned,
                    "total_tasks": total,
                    "duration": duration,
                    "open_ports_count": len(current_scan_job["results"]),
                    "results": current_scan_job["results"],
                    "error": current_scan_job["error"]
                }
            self._send_json(data)
            return

        elif path == "/api/history":
            records = load_history()
            self._send_json({"status": "success", "history": records})
            return

        self.send_error(404, "Endpoint Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            body = {}

        if path == "/api/scan/start":
            target_raw = body.get("target", "").strip()
            ports_raw = body.get("ports", "1-1024").strip()
            proto_raw = body.get("protocol", "TCP").strip()
            threads_val = int(body.get("threads", DEFAULT_THREADS))
            timeout_val = float(body.get("timeout", DEFAULT_TIMEOUT))

            if not target_raw:
                self._send_json({"status": "error", "message": "Target IP or Hostname is required."}, status_code=400)
                return

            if not (1 <= threads_val <= MAX_THREADS):
                self._send_json({"status": "error", "message": f"Threads must be between 1 and {MAX_THREADS}."}, status_code=400)
                return

            if timeout_val <= 0:
                self._send_json({"status": "error", "message": "Timeout must be greater than 0."}, status_code=400)
                return

            # Resolve ports
            try:
                if ports_raw.lower() == "common":
                    ports = COMMON_TCP_PORTS if proto_raw.lower() == "tcp" else COMMON_UDP_PORTS
                else:
                    ports = parse_port_range(ports_raw)
            except Exception as e:
                self._send_json({"status": "error", "message": f"Invalid port range: {str(e)}"}, status_code=400)
                return

            if not ports:
                self._send_json({"status": "error", "message": "No valid ports specified."}, status_code=400)
                return

            # Resolve target domain / IP
            ip, hostname, err = resolve_target(target_raw)
            if err:
                self._send_json({"status": "error", "message": f"Target Resolution Error: {err}"}, status_code=400)
                return

            with scan_lock:
                if current_scan_job["is_running"]:
                    self._send_json({"status": "error", "message": "A scan is already in progress. Abort it first."}, status_code=400)
                    return

                # Reset scan job state
                job_id = f"scan_{int(time.time())}"
                current_scan_job["job_id"] = job_id
                current_scan_job["target"] = target_raw
                current_scan_job["target_ip"] = ip
                current_scan_job["target_host"] = hostname if hostname else ip
                current_scan_job["protocol"] = proto_raw
                current_scan_job["results"] = []
                current_scan_job["is_running"] = True
                current_scan_job["start_time"] = time.time()
                current_scan_job["end_time"] = 0
                current_scan_job["error"] = None

                scan_type_str = "tcp"
                if "udp" in proto_raw.lower():
                    scan_type_str = "udp"
                elif "both" in proto_raw.lower():
                    scan_type_str = "both"

                def on_port_discovered(result):
                    with scan_lock:
                        current_scan_job["results"].append(result)

                scanner_obj = PortScanner(
                    target_ip=ip,
                    ports=ports,
                    scan_type=scan_type_str,
                    thread_count=threads_val,
                    timeout=timeout_val,
                    callback=on_port_discovered
                )
                current_scan_job["scanner"] = scanner_obj

                def run_background_scan():
                    try:
                        results = scanner_obj.start_scan()
                        duration = scanner_obj.end_time - scanner_obj.start_time
                        with scan_lock:
                            current_scan_job["end_time"] = scanner_obj.end_time
                            current_scan_job["is_running"] = False
                            current_scan_job["scanned_tasks"] = scanner_obj.total_tasks
                            current_scan_job["total_tasks"] = scanner_obj.total_tasks
                            
                        # Save to history
                        save_scan_to_history(
                            target_ip=ip,
                            target_host=hostname if hostname else ip,
                            scan_duration=duration,
                            protocol_scanned=proto_raw,
                            open_ports=results
                        )
                    except Exception as ex:
                        with scan_lock:
                            current_scan_job["is_running"] = False
                            current_scan_job["error"] = str(ex)

                t = threading.Thread(target=run_background_scan, daemon=True)
                current_scan_job["thread"] = t
                t.start()

                # Calculate total tasks count
                multiplier = 2 if scan_type_str == "both" else 1
                current_scan_job["total_tasks"] = len(ports) * multiplier
                current_scan_job["scanned_tasks"] = 0

            self._send_json({
                "status": "success",
                "message": f"Scan initiated for {ip}",
                "job_id": job_id,
                "target_ip": ip,
                "target_host": hostname if hostname else ip,
                "total_ports": len(ports)
            })
            return

        elif path == "/api/scan/stop":
            with scan_lock:
                if current_scan_job["scanner"] and current_scan_job["is_running"]:
                    current_scan_job["scanner"].stop_scan()
                    current_scan_job["is_running"] = False
                    current_scan_job["end_time"] = time.time()
                    self._send_json({"status": "success", "message": "Scan aborted successfully."})
                else:
                    self._send_json({"status": "info", "message": "No active scan was running."})
            return

        elif path == "/api/export":
            format_type = body.get("format", "json").lower()
            results = body.get("results", [])
            target_info = body.get("target_info", {})

            if format_type == "json":
                export_data = json.dumps({"target": target_info, "results": results}, indent=4)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition", f'attachment; filename="scan_report.json"')
                self.end_headers()
                self.wfile.write(export_data.encode("utf-8"))
            elif format_type == "csv":
                import io, csv
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["Target IP", target_info.get("ip", "")])
                writer.writerow(["Target Host", target_info.get("host", "")])
                writer.writerow(["Scan Time", target_info.get("timestamp", "")])
                writer.writerow([])
                writer.writerow(["Port", "Protocol", "State", "Service", "Version", "OS Heuristic", "Banner"])
                for r in results:
                    writer.writerow([
                        r.get("port", ""),
                        r.get("protocol", ""),
                        r.get("state", ""),
                        r.get("service", ""),
                        r.get("version", ""),
                        r.get("os", ""),
                        r.get("banner", "").replace("\n", " ").replace("\r", "")
                    ])
                csv_bytes = output.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", f'attachment; filename="scan_report.csv"')
                self.end_headers()
                self.wfile.write(csv_bytes)
            elif format_type == "txt":
                lines = []
                lines.append("="*60)
                lines.append("             ADVANCED PORT SCANNER REPORT")
                lines.append("="*60)
                lines.append(f"Target IP:   {target_info.get('ip', '')}")
                lines.append(f"Target Host: {target_info.get('host', '')}")
                lines.append(f"Scan Date:   {target_info.get('timestamp', '')}")
                lines.append(f"Duration:    {target_info.get('duration', '')} seconds")
                lines.append(f"Protocol:    {target_info.get('protocol', '')}")
                lines.append("="*60 + "\n")
                lines.append(f"{'PORT':<8} {'PROTO':<6} {'STATE':<8} {'SERVICE':<15} {'VERSION':<20} {'OS':<15}")
                lines.append("-" * 75)
                for r in results:
                    lines.append(
                        f"{r.get('port', ''):<8} "
                        f"{r.get('protocol', '').upper():<6} "
                        f"{r.get('state', ''):<8} "
                        f"{r.get('service', ''):<15} "
                        f"{r.get('version', ''):<20} "
                        f"{r.get('os', ''):<15}"
                    )
                    if r.get('banner'):
                        clean_b = r.get('banner').strip().replace('\n', '\n      | ')
                        lines.append(f"   └─ Banner: {clean_b}")
                lines.append("\n" + "="*60)
                lines.append("Report generated by Advanced Port Scanner.")
                lines.append("="*60)
                txt_bytes = "\n".join(lines).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Disposition", f'attachment; filename="scan_report.txt"')
                self.end_headers()
                self.wfile.write(txt_bytes)
            else:
                self._send_json({"status": "error", "message": "Invalid export format"}, status_code=400)
            return

        self.send_error(404, "Endpoint Not Found")

    def do_DELETE(self):
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == "/api/history":
            clear_history()
            self._send_json({"status": "success", "message": "History cleared successfully."})
            return
        self.send_error(404, "Endpoint Not Found")


def run_server(port=5000, open_browser=True):
    """
    Starts the HTTP Server on the specified port.
    """
    server_address = ("", port)
    # Enable socket address reuse
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(server_address, ScannerHTTPRequestHandler)
    
    url = f"http://localhost:{port}"
    print("\n" + "="*65)
    print("  [+] ADVANCED PORT SCANNER // WEB APPLICATION ENGINE")
    print(f"  [+] Server running at: {url}")
    print("  [+] Press Ctrl+C in terminal to stop server")
    print("="*65 + "\n")

    if open_browser:
        def launch_browser():
            time.sleep(1.0)
            webbrowser.open(url)
        threading.Thread(target=launch_browser, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Web Server...")
        httpd.shutdown()
        httpd.server_close()

if __name__ == "__main__":
    port_arg = int(os.environ.get("PORT", 5000))
    open_browser_flag = True if "PORT" not in os.environ and "RENDER" not in os.environ else False
    if len(sys.argv) > 1:
        try:
            port_arg = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port=port_arg, open_browser=open_browser_flag)
