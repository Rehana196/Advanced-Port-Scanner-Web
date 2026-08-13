// app.js - Full-Stack Cyberpunk Web Scanner Controller

let pollInterval = null;
let currentResults = [];
let currentTargetInfo = {};
let selectedHistoryRecord = null;
let currentHistoryRecords = [];

document.addEventListener("DOMContentLoaded", () => {
  initNavigationTabs();
  initLocalIP();
  initClock();
  loadScanHistory();
});

// Tab Navigation
function initNavigationTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      tab.classList.add("active");
      const targetPane = document.getElementById(tab.getAttribute("data-tab"));
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

// Clock
function initClock() {
  const clockEl = document.getElementById("clock-display");
  function update() {
    const now = new Date();
    if (clockEl) clockEl.innerText = now.toTimeString().split(" ")[0];
  }
  update();
  setInterval(update, 1000);
}

// Local IP Fetcher
async function initLocalIP() {
  try {
    const res = await fetch("/api/local-ip");
    const data = await res.json();
    if (data.status === "success" && data.local_ip) {
      document.getElementById("local-ip-text").innerText = `LOCAL IP: ${data.local_ip}`;
    }
  } catch (e) {
    document.getElementById("local-ip-text").innerText = `LOCAL IP: 127.0.0.1`;
  }
}

// Presets
function setTargetPreset(val) {
  document.getElementById("target-input").value = val;
}

function setPortPreset(val) {
  document.getElementById("ports-input").value = val;
}

// Scanner Actions
async function startScan() {
  const target = document.getElementById("target-input").value.trim();
  const ports = document.getElementById("ports-input").value.trim();
  const protocol = document.getElementById("proto-select").value;
  const threads = parseInt(document.getElementById("threads-input").value);
  const timeout = parseFloat(document.getElementById("timeout-input").value);

  if (!target) {
    alert("Please enter a Target IP or Hostname.");
    return;
  }

  // Disable UI
  toggleInputs(true);
  updateEngineStatus(true, "SCANNING ACTIVE...");
  resetResultsDisplay();

  try {
    const res = await fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, ports, protocol, threads, timeout })
    });
    const data = await res.json();

    if (data.status === "error") {
      alert("Scan Error: " + data.message);
      toggleInputs(false);
      updateEngineStatus(false, "SYSTEM READY");
      return;
    }

    currentTargetInfo = {
      ip: data.target_ip,
      host: data.target_host,
      timestamp: new Date().toLocaleString(),
      protocol: protocol
    };

    // Start polling status
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(pollScanStatus, 250);
  } catch (e) {
    alert("Failed to connect to scan engine server.");
    toggleInputs(false);
    updateEngineStatus(false, "SERVER ERROR");
  }
}

async function stopScan() {
  try {
    await fetch("/api/scan/stop", { method: "POST" });
    document.getElementById("scan-status-text").innerText = "SCAN ABORTED BY OPERATOR";
    document.getElementById("scan-status-text").style.color = "var(--accent-red)";
  } catch (e) {
    console.error("Stop scan error:", e);
  }
}

async function pollScanStatus() {
  try {
    const res = await fetch("/api/scan/status");
    const data = await res.json();

    const percentage = data.percentage || 0;
    const isRunning = data.is_running;
    const duration = data.duration || 0;

    // Update Progress UI
    const fillEl = document.getElementById("cyber-progress-bar");
    const percentEl = document.getElementById("progress-percentage-text");
    fillEl.style.width = `${percentage}%`;
    percentEl.innerText = `${percentage}%`;

    const statusTxt = isRunning 
      ? `SCANNING ${data.target_ip} (${data.target_host})... ${percentage}% COMPLETED`
      : `SCAN COMPLETE IN ${duration}s // FOUND ${data.open_ports_count} OPEN PORTS`;

    document.getElementById("scan-status-text").innerText = statusTxt;
    document.getElementById("scan-status-text").style.color = isRunning ? "var(--accent-cyan)" : "var(--accent-green)";
    document.getElementById("scan-stats-text").innerText = `SCANNED: ${data.scanned_count} / ${data.total_tasks} | TIME: ${duration}s`;

    // Render results
    currentResults = data.results || [];
    renderResultsTable(currentResults);
    renderPortMatrix(currentResults);
    renderAnalytics(currentResults);

    if (!isRunning) {
      clearInterval(pollInterval);
      pollInterval = null;
      toggleInputs(false);
      updateEngineStatus(false, "SYSTEM READY");
      loadScanHistory(); // Refresh history
    }
  } catch (e) {
    console.error("Polling status error:", e);
  }
}

function toggleInputs(scanning) {
  document.getElementById("target-input").disabled = scanning;
  document.getElementById("ports-input").disabled = scanning;
  document.getElementById("proto-select").disabled = scanning;
  document.getElementById("threads-slider").disabled = scanning;
  document.getElementById("threads-input").disabled = scanning;
  document.getElementById("timeout-input").disabled = scanning;

  document.getElementById("start-scan-btn").disabled = scanning;
  document.getElementById("stop-scan-btn").disabled = !scanning;
}

function updateEngineStatus(busy, text) {
  const indicator = document.getElementById("engine-status-indicator");
  indicator.className = busy ? "status-indicator busy" : "status-indicator ready";
  document.getElementById("engine-status-text").innerText = text;
}

function resetResultsDisplay() {
  currentResults = [];
  document.getElementById("open-ports-count").innerText = "0";
  document.getElementById("results-table-body").innerHTML = `
    <tr class="empty-row">
      <td colspan="7">Scanning target network... waiting for responses.</td>
    </tr>`;
  document.getElementById("port-matrix-container").innerHTML = `<div class="empty-matrix-msg">Scanning network... mapping ports grid.</div>`;
}

// Render Results Table
function renderResultsTable(results) {
  const tbody = document.getElementById("results-table-body");
  document.getElementById("open-ports-count").innerText = results.length;

  if (results.length === 0) {
    return;
  }

  const query = document.getElementById("results-search").value.toLowerCase();
  const filtered = results.filter(r => {
    if (!query) return true;
    return (
      r.port.toString().includes(query) ||
      r.protocol.toLowerCase().includes(query) ||
      r.service.toLowerCase().includes(query) ||
      r.version.toLowerCase().includes(query) ||
      r.os.toLowerCase().includes(query) ||
      r.banner.toLowerCase().includes(query)
    );
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No open ports matching query "${query}".</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(r => {
    const cleanBanner = r.banner ? r.banner.replace(/[\r\n]+/g, " ") : "N/A";
    return `
      <tr>
        <td class="port-badge">${r.port}</td>
        <td class="proto-badge">${r.protocol.toUpperCase()}</td>
        <td><span class="state-badge open">OPEN</span></td>
        <td><strong>${escapeHtml(r.service)}</strong></td>
        <td>${escapeHtml(r.version)}</td>
        <td>${escapeHtml(r.os)}</td>
        <td><div class="banner-preview" title="${escapeHtml(cleanBanner)}">${escapeHtml(cleanBanner)}</div></td>
      </tr>`;
  }).join("");
}

function filterResultsTable() {
  renderResultsTable(currentResults);
}

// Interactive Port Matrix Grid
function renderPortMatrix(results) {
  const container = document.getElementById("port-matrix-container");
  if (!results || results.length === 0) {
    container.innerHTML = `<div class="empty-matrix-msg">Execute a scan to generate the real-time port grid map.</div>`;
    return;
  }

  container.innerHTML = results.map(r => `
    <div class="matrix-cell open" title="Port ${r.port} (${r.protocol.toUpperCase()}) - ${r.service}">
      <div style="font-weight:bold;">:${r.port}</div>
      <div style="font-size:9px; opacity:0.8;">${r.service.substring(0, 8)}</div>
    </div>
  `).join("");
}

// Render Analytics Bar Charts
function renderAnalytics(results) {
  const serviceContainer = document.getElementById("service-chart-container");
  const osContainer = document.getElementById("os-chart-container");

  if (!results || results.length === 0) {
    serviceContainer.innerHTML = `<div class="empty-matrix-msg">Waiting for open port services...</div>`;
    osContainer.innerHTML = `<div class="empty-matrix-msg">Waiting for OS fingerprinting data...</div>`;
    return;
  }

  // Count services
  const services = {};
  const osMap = {};
  results.forEach(r => {
    services[r.service] = (services[r.service] || 0) + 1;
    osMap[r.os] = (osMap[r.os] || 0) + 1;
  });

  const total = results.length;

  serviceContainer.innerHTML = Object.entries(services).map(([svc, count]) => {
    const pct = Math.round((count / total) * 100);
    return `
      <div class="bar-chart-row" style="width:100%;">
        <span class="chart-label" title="${escapeHtml(svc)}">${escapeHtml(svc)}</span>
        <div class="chart-track">
          <div class="chart-fill" style="width: ${pct}%;"></div>
        </div>
        <span class="chart-count">${count}</span>
      </div>`;
  }).join("");

  osContainer.innerHTML = Object.entries(osMap).map(([osName, count]) => {
    const pct = Math.round((count / total) * 100);
    return `
      <div class="bar-chart-row" style="width:100%;">
        <span class="chart-label" title="${escapeHtml(osName)}">${escapeHtml(osName)}</span>
        <div class="chart-track">
          <div class="chart-fill" style="width: ${pct}%; background: var(--accent-cyan);"></div>
        </div>
        <span class="chart-count">${count}</span>
      </div>`;
  }).join("");
}

// Table Sorting
let sortDirection = 1;
function sortTable(columnIndex) {
  sortDirection = -sortDirection;
  currentResults.sort((a, b) => {
    const keys = ["port", "protocol", "state", "service", "version", "os"];
    const key = keys[columnIndex];
    let valA = a[key];
    let valB = b[key];
    if (typeof valA === "number") {
      return (valA - valB) * sortDirection;
    }
    return valA.toString().localeCompare(valB.toString()) * sortDirection;
  });
  renderResultsTable(currentResults);
}

// Export Results
async function exportResults(format) {
  if (currentResults.length === 0) {
    alert("No active scan results to export. Run a scan first.");
    return;
  }

  const payload = {
    format: format,
    target_info: currentTargetInfo,
    results: currentResults
  };

  try {
    const response = await fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan_report_${currentTargetInfo.ip || "target"}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } catch (e) {
    alert("Export failed: " + e.message);
  }
}

// Scan History Explorer
async function loadScanHistory() {
  try {
    const res = await fetch("/api/history");
    const data = await res.json();
    if (data.status === "success") {
      currentHistoryRecords = data.history || [];
      renderHistoryList(currentHistoryRecords);
    }
  } catch (e) {
    console.error("Failed to load history:", e);
  }
}

function renderHistoryList(records) {
  const ul = document.getElementById("history-list");
  if (records.length === 0) {
    ul.innerHTML = `<li class="empty-list-msg">No scan history recorded.</li>`;
    return;
  }

  ul.innerHTML = records.slice().reverse().map((rec, index) => {
    const realIdx = records.length - 1 - index;
    return `
      <li class="history-item" onclick="selectHistoryRecord(${realIdx}, this)">
        <div class="history-item-target">${escapeHtml(rec.target_ip)} (${escapeHtml(rec.target_host)})</div>
        <div class="history-item-date">${rec.timestamp} | ${rec.open_ports_count} open ports</div>
      </li>`;
  }).join("");
}

function selectHistoryRecord(idx, el) {
  document.querySelectorAll(".history-item").forEach(item => item.classList.remove("selected"));
  if (el) el.classList.add("selected");

  selectedHistoryRecord = currentHistoryRecords[idx];
  if (!selectedHistoryRecord) return;

  document.getElementById("history-export-btn").style.display = "inline-block";

  const rec = selectedHistoryRecord;
  const lines = [];
  lines.push("============================================================");
  lines.push(`SCAN RECORD TELEMETRY: ${rec.timestamp}`);
  lines.push("============================================================");
  lines.push(`Target IP:      ${rec.target_ip}`);
  lines.push(`Target Host:    ${rec.target_host}`);
  lines.push(`Duration:       ${rec.duration_seconds} seconds`);
  lines.push(`Protocol:       ${rec.protocol}`);
  lines.push(`Open Ports:     ${rec.open_ports_count}`);
  lines.push("============================================================\n");
  lines.push(`${'PORT'.padEnd(8)} ${'PROTO'.padEnd(6)} ${'SERVICE'.padEnd(15)} ${'VERSION'.padEnd(20)} ${'OS'.padEnd(15)}`);
  lines.push("-".repeat(70));

  rec.results.forEach(r => {
    lines.push(
      `${r.port.toString().padEnd(8)} ` +
      `${r.protocol.toUpperCase().padEnd(6)} ` +
      `${r.service.padEnd(15)} ` +
      `${r.version.padEnd(20)} ` +
      `${r.os.padEnd(15)}`
    );
    if (r.banner) {
      const cleanB = r.banner.replace(/[\r\n]+/g, " ");
      lines.push(`   └─ Banner: ${cleanB}`);
    }
  });

  document.getElementById("history-details-content").innerText = lines.join("\n");
}

async function exportSelectedHistoryRecord() {
  if (!selectedHistoryRecord) return;
  currentResults = selectedHistoryRecord.results;
  currentTargetInfo = {
    ip: selectedHistoryRecord.target_ip,
    host: selectedHistoryRecord.target_host,
    timestamp: selectedHistoryRecord.timestamp,
    protocol: selectedHistoryRecord.protocol
  };
  await exportResults("txt");
}

async function clearHistoryRecords() {
  if (!confirm("Are you sure you want to clear all historical scan records?")) return;

  try {
    await fetch("/api/history", { method: "DELETE" });
    document.getElementById("history-details-content").innerText = "Select a scan record from the left list to view detailed telemetry output.";
    document.getElementById("history-export-btn").style.display = "none";
    selectedHistoryRecord = null;
    loadScanHistory();
  } catch (e) {
    alert("Could not clear history: " + e.message);
  }
}

// Helper: Escape HTML
function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>"']/g, m => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}
