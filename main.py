# main.py
"""
Universal Entry point for the Advanced Port Scanner application.
Supports Web Application mode (default) and Desktop Tkinter GUI mode.
"""

import sys
import argparse

def launch_web(port=5000):
    from web_server import run_server
    run_server(port=port, open_browser=True)

def launch_gui():
    import tkinter as tk
    from gui import ScannerGUI
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner (Web & Desktop Edition)")
    parser.add_argument("--gui", action="store_true", help="Launch desktop Tkinter GUI interface")
    parser.add_argument("--web", action="store_true", help="Launch web application server (Default)")
    parser.add_argument("--port", type=int, default=5000, help="Web server port (Default: 5000)")
    
    args = parser.parse_args()

    try:
        if args.gui:
            print("[+] Launching Desktop Tkinter GUI...")
            launch_gui()
        else:
            print(f"[+] Launching Web Application Server on http://localhost:{args.port}...")
            launch_web(port=args.port)
    except KeyboardInterrupt:
        print("\n[!] Application shutting down.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Critical application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
