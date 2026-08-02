# main.py
"""
Entry point for the Advanced Port Scanner application.
Initializes the main Tkinter window and starts the event loop.
"""

import tkinter as tk
import sys
from gui import ScannerGUI

def main():
    try:
        root = tk.Tk()
        app = ScannerGUI(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\n[!] Scanner shutting down.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Critical application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
