# gui.py
"""
Graphical User Interface for Advanced Port Scanner.
Styled with a custom 'Dark Hacker' theme using standard Tkinter libraries.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import os
import datetime

from config import THEME, DEFAULT_TIMEOUT, DEFAULT_THREADS, MAX_THREADS, COMMON_TCP_PORTS, COMMON_UDP_PORTS
from utils import resolve_target, get_local_ip, parse_port_range
from scanner import PortScanner
from logger import load_history, save_scan_to_history, clear_history
from export import export_to_json, export_to_csv, export_to_txt

class ScannerGUI:
    """
    Main Tkinter application class.
    Implements a responsive neon-cyberpunk layout.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("ADVANCED PORT SCANNER")
        self.root.geometry("1000x700")
        self.root.minsize(850, 600)
        
        # Configure overall window colors
        self.root.configure(bg=THEME["bg_main"])
        
        # Set window icon / styling parameters
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._configure_styles()
        
        # Scanner references
        self.scanner = None
        self.scan_thread = None
        self.active_results = []
        self.target_ip = ""
        self.target_host = ""
        
        # Build UI layout
        self.build_ui()
        
        # Initialize default values
        self.detect_local_environment()
        self.update_history_display()

    def _configure_styles(self):
        """
        Overwrites Tkinter TTK element styles to enforce the Dark Hacker theme.
        """
        # Global Scrollbar styling
        self.style.configure("Vertical.TScrollbar", 
                             gripcount=0,
                             background=THEME["bg_card"], 
                             troughcolor=THEME["bg_main"], 
                             bordercolor=THEME["border_color"], 
                             arrowcolor=THEME["accent_green"])
        
        # Notebook (tabs) styling
        self.style.configure("TNotebook", background=THEME["bg_main"], borderwidth=0)
        self.style.configure("TNotebook.Tab", 
                             background=THEME["bg_card"], 
                             foreground=THEME["fg_muted"], 
                             padding=[15, 5], 
                             font=THEME["font_header"],
                             borderwidth=1, 
                             bordercolor=THEME["border_color"])
        self.style.map("TNotebook.Tab", 
                       background=[("selected", THEME["bg_main"])], 
                       foreground=[("selected", THEME["accent_green"])],
                       focuscolor=[("selected", THEME["bg_main"])])

        # Treeview (table) styling
        self.style.configure("Treeview", 
                             background=THEME["bg_card"], 
                             foreground=THEME["fg_normal"], 
                             fieldbackground=THEME["bg_card"], 
                             rowheight=25,
                             font=THEME["font_body"],
                             borderwidth=1, 
                             bordercolor=THEME["border_color"])
        self.style.configure("Treeview.Heading", 
                             background=THEME["bg_input"], 
                             foreground=THEME["accent_cyan"], 
                             font=THEME["font_header"],
                             borderwidth=1, 
                             bordercolor=THEME["border_color"])
        self.style.map("Treeview", 
                       background=[("selected", THEME["bg_input"])], 
                       foreground=[("selected", THEME["accent_green"])])
        
        # Progressbar styling
        self.style.configure("Green.Horizontal.TProgressbar", 
                             troughcolor=THEME["bg_input"], 
                             background=THEME["accent_green"], 
                             thickness=15)

    def build_ui(self):
        """
        Builds the modular layout.
        """
        # Header banner
        header_frame = tk.Frame(self.root, bg=THEME["bg_main"], height=60)
        header_frame.pack(fill="x", padx=15, pady=10)
        
        title_label = tk.Label(header_frame, 
                               text="ADVANCED PORT SCANNER v1.0", 
                               font=THEME["font_title"], 
                               fg=THEME["accent_green"], 
                               bg=THEME["bg_main"])
        title_label.pack(side="left")
        
        self.local_ip_label = tk.Label(header_frame, 
                                       text="LOCAL IP: DETECTING...", 
                                       font=THEME["font_header"], 
                                       fg=THEME["accent_cyan"], 
                                       bg=THEME["bg_main"])
        self.local_ip_label.pack(side="right")
        
        # Divider Line
        divider = tk.Frame(self.root, bg=THEME["accent_green"], height=2)
        divider.pack(fill="x", padx=15)

        # Tabbed view container
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Tabs
        self.scan_tab = tk.Frame(self.notebook, bg=THEME["bg_main"])
        self.history_tab = tk.Frame(self.notebook, bg=THEME["bg_main"])
        
        self.notebook.add(self.scan_tab, text="[ SCANNER ENGINE ]")
        self.notebook.add(self.history_tab, text="[ SCAN LOGS & HISTORY ]")
        
        self.build_scan_tab()
        self.build_history_tab()

    def build_scan_tab(self):
        """
        Builds the scanning configurations and real-time outputs panel.
        """
        # Split scan tab into left (Inputs) and right (Live Terminal Console/Progress)
        top_settings = tk.LabelFrame(self.scan_tab, 
                                     text=" SCAN PARAMETERS ", 
                                     font=THEME["font_header"], 
                                     fg=THEME["accent_cyan"], 
                                     bg=THEME["bg_card"], 
                                     bd=1, 
                                     relief="solid", 
                                     labelanchor="nw")
        top_settings.pack(fill="x", padx=5, pady=5, ipadx=10, ipady=10)
        
        # Grid layout for inputs
        for i in range(4):
            top_settings.columnconfigure(i, weight=1)

        # Target entry
        tk.Label(top_settings, text="Target IP / Host:", font=THEME["font_body"], fg=THEME["fg_normal"], bg=THEME["bg_card"]).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.target_entry = tk.Entry(top_settings, font=THEME["font_body"], fg=THEME["accent_green"], bg=THEME["bg_input"], insertbackground=THEME["accent_green"], bd=1, relief="solid")
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

        # Port range entry
        tk.Label(top_settings, text="Ports (e.g. 21-80,443):", font=THEME["font_body"], fg=THEME["fg_normal"], bg=THEME["bg_card"]).grid(row=0, column=2, sticky="w", padx=10, pady=5)
        self.ports_entry = tk.Entry(top_settings, font=THEME["font_body"], fg=THEME["accent_green"], bg=THEME["bg_input"], insertbackground=THEME["accent_green"], bd=1, relief="solid")
        self.ports_entry.insert(0, "1-1024")
        self.ports_entry.grid(row=0, column=3, sticky="ew", padx=10, pady=5)

        # Scan Type / Protocol
        tk.Label(top_settings, text="Scan Protocol:", font=THEME["font_body"], fg=THEME["fg_normal"], bg=THEME["bg_card"]).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.proto_var = tk.StringVar(value="TCP")
        self.proto_combo = ttk.Combobox(top_settings, textvariable=self.proto_var, values=["TCP", "UDP", "Both (TCP+UDP)"], state="readonly", font=THEME["font_body"])
        self.proto_combo.grid(row=1, column=1, sticky="ew", padx=10, pady=5)

        # Threads entry
        tk.Label(top_settings, text="Speed (Threads):", font=THEME["font_body"], fg=THEME["fg_normal"], bg=THEME["bg_card"]).grid(row=1, column=2, sticky="w", padx=10, pady=5)
        self.threads_entry = tk.Entry(top_settings, font=THEME["font_body"], fg=THEME["accent_green"], bg=THEME["bg_input"], insertbackground=THEME["accent_green"], bd=1, relief="solid")
        self.threads_entry.insert(0, str(DEFAULT_THREADS))
        self.threads_entry.grid(row=1, column=3, sticky="ew", padx=10, pady=5)

        # Timeout entry
        tk.Label(top_settings, text="Timeout (seconds):", font=THEME["font_body"], fg=THEME["fg_normal"], bg=THEME["bg_card"]).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.timeout_entry = tk.Entry(top_settings, font=THEME["font_body"], fg=THEME["accent_green"], bg=THEME["bg_input"], insertbackground=THEME["accent_green"], bd=1, relief="solid")
        self.timeout_entry.insert(0, str(DEFAULT_TIMEOUT))
        self.timeout_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=5)

        # Control Buttons Frame
        btn_frame = tk.Frame(top_settings, bg=THEME["bg_card"])
        btn_frame.grid(row=2, column=2, columnspan=2, sticky="ew", padx=10, pady=5)
        
        self.start_btn = tk.Button(btn_frame, text="INITIATE SCAN", font=THEME["font_header"], fg=THEME["bg_main"], bg=THEME["accent_green"], activebackground=THEME["accent_cyan"], activeforeground=THEME["bg_main"], bd=0, cursor="hand2", command=self.start_scan_action)
        self.start_btn.pack(side="left", fill="x", expand=True, padx=2)

        self.stop_btn = tk.Button(btn_frame, text="ABORT SCAN", font=THEME["font_header"], fg=THEME["fg_normal"], bg=THEME["accent_red"], activebackground=THEME["accent_amber"], activeforeground=THEME["fg_normal"], bd=0, cursor="hand2", state="disabled", command=self.stop_scan_action)
        self.stop_btn.pack(side="right", fill="x", expand=True, padx=2)

        # Main table to show results
        table_frame = tk.Frame(self.scan_tab, bg=THEME["bg_main"])
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Scrollbar for Table
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side="right", fill="y")

        columns = ("port", "protocol", "state", "service", "version", "os", "banner")
        self.results_table = ttk.Treeview(table_frame, columns=columns, show="headings", yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.results_table.yview)

        # Treeview Headings definitions
        self.results_table.heading("port", text="PORT")
        self.results_table.heading("protocol", text="PROTOCOL")
        self.results_table.heading("state", text="STATE")
        self.results_table.heading("service", text="SERVICE")
        self.results_table.heading("version", text="VERSION")
        self.results_table.heading("os", text="ESTIMATED OS")
        self.results_table.heading("banner", text="BANNER GRABBED")

        # Column widths
        self.results_table.column("port", width=80, anchor="center")
        self.results_table.column("protocol", width=90, anchor="center")
        self.results_table.column("state", width=80, anchor="center")
        self.results_table.column("service", width=120, anchor="w")
        self.results_table.column("version", width=180, anchor="w")
        self.results_table.column("os", width=150, anchor="w")
        self.results_table.column("banner", width=250, anchor="w")

        self.results_table.pack(fill="both", expand=True)

        # Real-time console / logs and Progressbar at bottom
        bottom_panel = tk.Frame(self.scan_tab, bg=THEME["bg_main"])
        bottom_panel.pack(fill="x", padx=5, pady=5)

        # Progress bar
        self.progress_bar = ttk.Progressbar(bottom_panel, orient="horizontal", mode="determinate", style="Green.Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x", pady=5)

        # Status text/stats row
        self.status_label = tk.Label(bottom_panel, text="READY TO SCAN // TARGET REQUIRED", font=THEME["font_console"], fg=THEME["fg_muted"], bg=THEME["bg_main"])
        self.status_label.pack(side="left")

        # Export options dropdown / buttons
        export_frame = tk.Frame(bottom_panel, bg=THEME["bg_main"])
        export_frame.pack(side="right")
        
        tk.Label(export_frame, text="Export:", font=THEME["font_body"], fg=THEME["fg_normal"], bg=THEME["bg_main"]).pack(side="left", padx=5)
        
        self.export_json_btn = tk.Button(export_frame, text="JSON", font=THEME["font_console"], fg=THEME["accent_cyan"], bg=THEME["bg_card"], activebackground=THEME["bg_input"], activeforeground=THEME["accent_cyan"], bd=1, relief="solid", command=lambda: self.export_action("json"))
        self.export_json_btn.pack(side="left", padx=2)
        
        self.export_csv_btn = tk.Button(export_frame, text="CSV", font=THEME["font_console"], fg=THEME["accent_cyan"], bg=THEME["bg_card"], activebackground=THEME["bg_input"], activeforeground=THEME["accent_cyan"], bd=1, relief="solid", command=lambda: self.export_action("csv"))
        self.export_csv_btn.pack(side="left", padx=2)
        
        self.export_txt_btn = tk.Button(export_frame, text="TXT", font=THEME["font_console"], fg=THEME["accent_cyan"], bg=THEME["bg_card"], activebackground=THEME["bg_input"], activeforeground=THEME["accent_cyan"], bd=1, relief="solid", command=lambda: self.export_action("txt"))
        self.export_txt_btn.pack(side="left", padx=2)

    def build_history_tab(self):
        """
        Builds the Scan history viewing tab.
        """
        # Outer layout
        top_bar = tk.Frame(self.history_tab, bg=THEME["bg_main"])
        top_bar.pack(fill="x", padx=10, pady=10)

        history_title = tk.Label(top_bar, text="PREVIOUS SCAN RECORDS", font=THEME["font_header"], fg=THEME["accent_green"], bg=THEME["bg_main"])
        history_title.pack(side="left")

        clear_btn = tk.Button(top_bar, text="CLEAR SCAN HISTORY", font=THEME["font_console"], fg=THEME["accent_red"], bg=THEME["bg_card"], activebackground=THEME["bg_input"], activeforeground=THEME["accent_red"], bd=1, relief="solid", cursor="hand2", command=self.clear_history_action)
        clear_btn.pack(side="right")

        # PanedWindow to show historical scans list (left) and results details (right)
        paned = tk.PanedWindow(self.history_tab, orient="horizontal", bg=THEME["bg_main"], sashwidth=4, sashrelief="solid")
        paned.pack(fill="both", expand=True, padx=10, pady=5)

        # Left list of scans
        left_frame = tk.Frame(paned, bg=THEME["bg_main"])
        
        history_scroll = ttk.Scrollbar(left_frame)
        history_scroll.pack(side="right", fill="y")
        
        self.history_list = tk.Listbox(left_frame, font=THEME["font_body"], fg=THEME["fg_normal"], bg=THEME["bg_card"], selectbackground=THEME["bg_input"], selectforeground=THEME["accent_green"], bd=1, relief="solid", yscrollcommand=history_scroll.set)
        self.history_list.pack(fill="both", expand=True)
        history_scroll.config(command=self.history_list.yview)
        
        self.history_list.bind("<<ListboxSelect>>", self.on_history_select)
        
        # Right details viewer
        right_frame = tk.Frame(paned, bg=THEME["bg_main"])
        
        details_scroll = ttk.Scrollbar(right_frame)
        details_scroll.pack(side="right", fill="y")
        
        self.history_details = tk.Text(right_frame, font=THEME["font_console"], fg=THEME["fg_normal"], bg=THEME["bg_card"], insertbackground=THEME["accent_green"], bd=1, relief="solid", yscrollcommand=details_scroll.set, wrap="word", state="disabled")
        self.history_details.pack(fill="both", expand=True)
        details_scroll.config(command=self.history_details.yview)

        paned.add(left_frame, minsize=350)
        paned.add(right_frame, minsize=400)

    def detect_local_environment(self):
        """
        Retrieves local IP and populates target.
        """
        def run_detect():
            local_ip = get_local_ip()
            self.root.after(0, lambda: self.local_ip_label.config(text=f"LOCAL IP: {local_ip}"))
        
        threading.Thread(target=run_detect, daemon=True).start()

    def update_history_display(self):
        """
        Reloads history list.
        """
        self.history_list.delete(0, tk.END)
        self.history_records = load_history()
        for idx, scan in enumerate(reversed(self.history_records)):
            label = f"{scan['timestamp']} - {scan['target_ip']} ({scan['open_ports_count']} ports open)"
            self.history_list.insert(tk.END, label)

    def on_history_select(self, event):
        """
        Event listener to render selected history item.
        """
        selection = self.history_list.curselection()
        if not selection:
            return
            
        index = selection[0]
        # Since list is reversed in UI, calculate correct database index
        real_idx = len(self.history_records) - 1 - index
        record = self.history_records[real_idx]
        
        # Format display text
        self.history_details.config(state="normal")
        self.history_details.delete("1.0", tk.END)
        
        report = []
        report.append("="*60)
        report.append(f"SCAN RECORD: {record['timestamp']}")
        report.append("="*60)
        report.append(f"Target IP:      {record['target_ip']}")
        report.append(f"Target Host:    {record['target_host']}")
        report.append(f"Duration:       {record['duration_seconds']}s")
        report.append(f"Protocol:       {record.get('protocol', 'TCP')}")
        report.append(f"Open Ports:     {record['open_ports_count']}")
        report.append("="*60)
        report.append("")
        
        report.append(f"{'PORT':<8} {'PROTO':<6} {'SERVICE':<15} {'VERSION':<20} {'OS':<15}")
        report.append("-" * 70)
        for r in record["results"]:
            report.append(
                f"{r.get('port', ''):<8} "
                f"{r.get('protocol', '').upper():<6} "
                f"{r.get('service', ''):<15} "
                f"{r.get('version', ''):<20} "
                f"{r.get('os', ''):<15}"
            )
            if r.get("banner"):
                clean_b = r.get("banner").replace("\n", " ").replace("\r", "")
                if len(clean_b) > 50:
                    clean_b = clean_b[:47] + "..."
                report.append(f"   └─ Banner: {clean_b}")
                
        self.history_details.insert(tk.END, "\n".join(report))
        self.history_details.config(state="disabled")

    def clear_history_action(self):
        """
        Deletes all local history.
        """
        if messagebox.askyesno("CONFIRMATION REQUIRED", "Are you sure you want to clear all scan history?"):
            clear_history()
            self.update_history_display()
            self.history_details.config(state="normal")
            self.history_details.delete("1.0", tk.END)
            self.history_details.config(state="disabled")

    def start_scan_action(self):
        """
        Action triggered when "INITIATE SCAN" is pressed.
        Validates target parameters and spawns port scanning engine thread.
        """
        target = self.target_entry.get().strip()
        port_raw = self.ports_entry.get().strip()
        proto = self.proto_var.get()
        
        # Validations
        if not target:
            messagebox.showerror("ERROR", "Please specify a Target IP or Hostname.")
            return
            
        try:
            threads = int(self.threads_entry.get().strip())
            if not (1 <= threads <= MAX_THREADS):
                raise ValueError
        except ValueError:
            messagebox.showerror("ERROR", f"Thread count must be an integer between 1 and {MAX_THREADS}.")
            return

        try:
            timeout = float(self.timeout_entry.get().strip())
            if timeout <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("ERROR", "Timeout must be a positive decimal/integer value.")
            return

        # Resolve ports
        try:
            if port_raw.lower() == "common":
                ports = COMMON_TCP_PORTS if proto.lower() == "tcp" else COMMON_UDP_PORTS
            else:
                ports = parse_port_range(port_raw)
        except Exception as e:
            messagebox.showerror("ERROR", f"Could not parse ports: {str(e)}")
            return

        if not ports:
            messagebox.showerror("ERROR", "No valid ports specified.")
            return

        # Disable fields during scan
        self.toggle_ui_state(scanning=True)
        self.progress_bar["value"] = 0
        
        # Clear table
        for item in self.results_table.get_children():
            self.results_table.delete(item)
            
        self.status_label.config(text="RESOLVING TARGET DOMAIN...", fg=THEME["accent_cyan"])
        self.active_results = []
        
        # Spawn thread
        self.scan_thread = threading.Thread(target=self.scan_runner, args=(target, ports, proto, threads, timeout), daemon=True)
        self.scan_thread.start()

    def toggle_ui_state(self, scanning):
        """
        Enables/Disables parameters depending on whether scanner is running.
        """
        state = "disabled" if scanning else "normal"
        self.target_entry.config(state=state)
        self.ports_entry.config(state=state)
        self.proto_combo.config(state="disabled" if scanning else "readonly")
        self.threads_entry.config(state=state)
        self.timeout_entry.config(state=state)
        
        if scanning:
            self.start_btn.config(state="disabled", bg=THEME["bg_card"], fg=THEME["fg_muted"])
            self.stop_btn.config(state="normal")
        else:
            self.start_btn.config(state="normal", bg=THEME["accent_green"], fg=THEME["bg_main"])
            self.stop_btn.config(state="disabled")

    def scan_runner(self, target, ports, proto, threads, timeout):
        """
        Background scanner thread runner.
        Resolves domain and monitors scanner progress.
        """
        # Resolve target
        ip, hostname, error = resolve_target(target)
        if error:
            self.root.after(0, lambda: messagebox.showerror("RESOLUTION ERROR", error))
            self.root.after(0, lambda: self.toggle_ui_state(scanning=False))
            self.root.after(0, lambda: self.status_label.config(text="READY TO SCAN // TARGET FAILED", fg=THEME["accent_red"]))
            return
            
        self.target_ip = ip
        self.target_host = hostname if hostname else ip
        
        # Start Scanner
        self.root.after(0, lambda: self.status_label.config(text=f"SCANNING {self.target_ip} ({self.target_host})...", fg=THEME["accent_cyan"]))
        
        scan_type_str = "tcp"
        if "udp" in proto.lower():
            scan_type_str = "udp"
        elif "both" in proto.lower():
            scan_type_str = "both"

        self.scanner = PortScanner(
            target_ip=ip, 
            ports=ports, 
            scan_type=scan_type_str, 
            thread_count=threads, 
            timeout=timeout,
            callback=self.on_port_discovered
        )
        
        # Monitor thread
        def monitor_progress():
            while self.scanner and self.scanner.is_running:
                scanned = self.scanner.ports_scanned
                total = self.scanner.total_tasks
                percentage = int((scanned / total) * 100) if total else 0
                
                self.root.after(0, lambda p=percentage: self.update_progress(p))
                time.sleep(0.1)
                
        # Run progress tracker
        tracker = threading.Thread(target=monitor_progress, daemon=True)
        tracker.start()
        
        # Run scan blocking block
        results = self.scanner.start_scan()
        duration = self.scanner.end_time - self.scanner.start_time
        
        # Scan complete processing
        self.root.after(0, lambda: self.progress_bar.config(value=100))
        self.root.after(0, lambda: self.status_label.config(text=f"SCAN COMPLETE IN {duration:.2f}s // FOUND {len(results)} OPEN PORTS", fg=THEME["accent_green"]))
        
        # Save to database file
        if self.scanner.is_running or results:
            save_scan_to_history(
                target_ip=self.target_ip,
                target_host=self.target_host,
                scan_duration=duration,
                protocol_scanned=proto,
                open_ports=results
            )
            self.root.after(0, self.update_history_display)
            
        self.root.after(0, lambda: self.toggle_ui_state(scanning=False))

    def on_port_discovered(self, result):
        """
        Scanner callback triggers this when a port returns open.
        """
        self.active_results.append(result)
        # Safely insert into Tkinter Treeview from background thread
        self.root.after(0, lambda: self.results_table.insert("", "end", values=(
            result["port"],
            result["protocol"].upper(),
            result["state"].upper(),
            result["service"],
            result["version"],
            result["os"],
            result["banner"].replace("\n", " ").replace("\r", "")
        )))

    def update_progress(self, percentage):
        """
        Updates GUI progress metrics.
        """
        self.progress_bar["value"] = percentage
        self.status_label.config(text=f"SCANNING {self.target_ip}... {percentage}% COMPLETED", fg=THEME["accent_cyan"])

    def stop_scan_action(self):
        """
        Stops the execution run immediately.
        """
        if self.scanner:
            self.scanner.stop_scan()
            self.status_label.config(text="SCAN ABORTED BY OPERATOR", fg=THEME["accent_red"])
            self.toggle_ui_state(scanning=False)

    def export_action(self, format_type):
        """
        Prompts dialog to save current result table.
        """
        if not self.active_results:
            messagebox.showwarning("NO RESULTS", "There are no active scan results to export. Run a scan first.")
            return
            
        # File selector dialog
        file_types = {
            "json": [("JSON file", "*.json")],
            "csv": [("CSV file", "*.csv")],
            "txt": [("Text file", "*.txt")]
        }
        
        default_name = f"scan_report_{self.target_ip.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d')}"
        
        filepath = filedialog.asksaveasfilename(
            initialfile=default_name,
            defaultextension=f".{format_type}",
            filetypes=file_types[format_type],
            title="SAVE SCAN RESULTS"
        )
        
        if not filepath:
            return # Cancelled
            
        target_info = {
            "ip": self.target_ip,
            "host": self.target_host,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": round(self.scanner.end_time - self.scanner.start_time, 2) if (self.scanner and self.scanner.end_time) else 0,
            "protocol": self.proto_var.get()
        }
        
        success = False
        message = ""
        
        if format_type == "json":
            success, message = export_to_json(filepath, target_info, self.active_results)
        elif format_type == "csv":
            success, message = export_to_csv(filepath, target_info, self.active_results)
        elif format_type == "txt":
            success, message = export_to_txt(filepath, target_info, self.active_results)
            
        if success:
            messagebox.showinfo("EXPORT COMPLETED", message)
        else:
            messagebox.showerror("EXPORT ERROR", f"Could not write file: {message}")
