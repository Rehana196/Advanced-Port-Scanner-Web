# Advanced Port Scanner

A professional, modular, multi-threaded port scanner written in Python with a premium "Dark Hacker" neon-cyberpunk GUI. It features advanced banner grabbing, service detection, OS heuristics, and report exporting capabilities.

## Architecture & Project Structure
The project is built modularly following standard software engineering patterns:

```
Advanced-Port-Scanner/
│
├── main.py                # Application entry point
├── gui.py                 # Tkinter application UI (Dark Hacker Theme)
├── scanner.py             # Multi-threaded TCP/UDP scanning engines
├── banner.py              # Custom network banner grabber
├── service_detection.py   # Banner regex matching and service discovery
├── os_detection.py        # TTL and banner OS heuristic classifier
├── export.py              # Export module (JSON, CSV, TXT)
├── logger.py              # Scan history management (JSON logs)
├── utils.py               # Hostname resolvers, IP validators, configuration tools
├── config.py              # Styling parameters and common network configurations
└── requirements.txt       # Project dependencies
```

## Features
- **Interactive Cyberpunk UI**: Sleek neon elements using standard `tkinter.ttk` (no external styling engines needed).
- **Multi-threaded Scan Pipeline**: Supports scanning hundreds of ports concurrently.
- **Service Versioning**: Connects and analyzes service banners (e.g. Apache, SSH, nginx version extraction).
- **Heuristic OS Analysis**: Detects target operating systems by parsing signature matches in banners and analyzing networking TTL parameters.
- **Scan History Logs**: Remembers previous scans so you can review them inside the log dashboard.
- **Universal Exporter**: Quick-click generation of JSON, CSV, or human-readable TXT security reports.

## Getting Started

### Prerequisites
- Python 3.8 or higher.
- Standard libraries are used (`tkinter`, `socket`, `threading`, etc.). If you are on Linux, you may need to install the Tkinter package (e.g., `sudo apt-get install python3-tk`).

### Running the App
Execute the app using:
```bash
python main.py
```

### Usage
1. Enter your Target IP or Hostname (e.g. `127.0.0.1` or `scanme.nmap.org`).
2. Provide a port list or range (e.g. `21-80,443`). Alternatively, type `common` to query the list of popular TCP/UDP services configured in `config.py`.
3. Choose your protocol (TCP, UDP, or Both) and specify how many threads to allocate.
4. Press **INITIATE SCAN**.
5. Once complete, select your preferred format in the bottom right corner to export a report, or look in the **[ SCAN LOGS & HISTORY ]** tab to view your past logs.
