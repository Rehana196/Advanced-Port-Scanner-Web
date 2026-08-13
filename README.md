# Advanced Port Scanner (Web & Desktop Edition)

A professional, modular, multi-threaded port scanner written in Python featuring a modern **Neon Cyberpunk Web Application Dashboard** and desktop Tkinter GUI. It provides advanced banner grabbing, service detection, OS heuristics, live port grid matrix mapping, and report exporting capabilities.

## Architecture & Project Structure
The project is built modularly following clean software engineering patterns:

```
Advanced-Port-Scanner/
│
├── main.py                # Universal application entry point (Web & GUI mode)
├── web_server.py          # Python REST API server & static asset bridge
├── web/                   # Cyberpunk Web Dashboard UI
│   ├── index.html         # Responsive HTML5 layout
│   ├── style.css          # Dark Hacker / Neon Cyberpunk Design System
│   └── app.js             # Real-time WebSocket/polling UI controller & charts
├── gui.py                 # Desktop Tkinter application UI
├── scanner.py             # Multi-threaded TCP/UDP scanning engine
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
- **Neon Cyberpunk Web Dashboard**: Interactive browser UI with live progress tracking, responsive glassmorphism design, and custom theme tokens.
- **Interactive Port Matrix**: Visual grid map of open ports with real-time glowing indicators.
- **Service & OS Analytics**: Breakdown charts of detected services and heuristic operating system distributions.
- **Multi-threaded Scan Pipeline**: Supports concurrent scanning across hundreds of ports with custom speed/thread sliders.
- **Service Versioning**: Connects and analyzes service banners (e.g. Apache, SSH, nginx version extraction).
- **Heuristic OS Analysis**: Detects target operating systems by parsing signature matches in banners and analyzing TTL parameters.
- **Scan History Logs**: Persists previous scan records for review in the dashboard log explorer.
- **Universal Exporter**: Quick-click generation of JSON, CSV, or formatted TXT security reports.

## Getting Started

### Prerequisites
- Python 3.8 or higher.
- Standard libraries are used (`socket`, `http.server`, `threading`, `json`). Zero third-party web dependencies required!

### Running the Application

#### Option 1: Web Application Mode (Default)
Run the web application server and automatically open the dashboard in your default browser:
```bash
python main.py
```
Or specify a custom port:
```bash
python main.py --port 8080
```
Then navigate to `http://localhost:5000` (or your custom port) in any web browser.

#### Option 2: Desktop GUI Mode
To launch the traditional desktop Tkinter window:
```bash
python main.py --gui
```

## Usage
1. Enter your **Target IP or Hostname** (e.g. `127.0.0.1` or `scanme.nmap.org`).
2. Provide a **Port list or range** (e.g. `21-80,443` or click quick preset buttons like `Common Ports` or `Web Ports`).
3. Choose your protocol (`TCP`, `UDP`, or `Both`) and set your thread count slider.
4. Click **[ INITIATE SCAN ]**.
5. Watch the live progress bar, port matrix, and real-time open port table populate.
6. Export reports in **JSON**, **CSV**, or **TXT** format with one click, or review past telemetry in the **[ SCAN LOGS & HISTORY ]** tab.
