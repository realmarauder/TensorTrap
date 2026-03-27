/* TensorTrap Web UI - SPA Application */

const app = document.getElementById("app");

// --- Persistent Scan State ---
// Survives tab switches so progress is never lost
const scanState = {
    active: false,
    scanId: null,
    ws: null,
    path: "",
    statusText: "Preparing scan...",
    fileName: "Waiting...",
    current: 0,
    total: 0,
    percent: 0,
    complete: false,
    completeSummary: null,
    error: null,
};

// --- Router ---

function router() {
    const hash = window.location.hash || "#/dashboard";
    const parts = hash.slice(2).split("/");
    const page = parts[0] || "dashboard";
    const param = parts[1] || null;

    // Update active nav
    document.querySelectorAll(".nav-links a").forEach((a) => {
        const p = a.getAttribute("data-page");
        a.classList.toggle("active", p === page || (p === "reports" && page === "report"));
    });

    switch (page) {
        case "dashboard":
            renderDashboard();
            break;
        case "reports":
            renderReports();
            break;
        case "report":
            renderReportDetail(param);
            break;
        case "scan":
            renderScan();
            break;
        case "config":
            renderConfig();
            break;
        default:
            renderDashboard();
    }
}

window.addEventListener("hashchange", router);

// --- API Helpers ---

async function api(path, options = {}) {
    const res = await fetch(`/api${path}`, {
        headers: { "Content-Type": "application/json" },
        ...options,
        body: options.body ? JSON.stringify(options.body) : undefined,
    });
    return res.json();
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function formatSize(bytes) {
    const units = ["B", "KB", "MB", "GB"];
    let size = bytes;
    for (const unit of units) {
        if (size < 1024) return `${size.toFixed(1)} ${unit}`;
        size /= 1024;
    }
    return `${size.toFixed(1)} TB`;
}

function showToast(message, type = "success") {
    let toast = document.querySelector(".toast");
    if (!toast) {
        toast = document.createElement("div");
        toast.className = "toast";
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    setTimeout(() => toast.classList.remove("show"), 2500);
}

function severityBadge(severity) {
    return `<span class="badge ${severity}">${severity}</span>`;
}

// --- Dashboard Page ---

async function renderDashboard() {
    app.innerHTML = `<div class="loading">Loading dashboard...</div>`;

    const [status, reports] = await Promise.all([api("/status"), api("/reports")]);

    document.getElementById("version-text").textContent = `TensorTrap v${status.version}`;

    if (!reports.length) {
        app.innerHTML = `
            <div class="page-header">
                <h2>Dashboard</h2>
                <p>Welcome to TensorTrap</p>
            </div>
            ${scanState.active ? scanBannerHtml() : ""}
            <div class="empty-state">
                <h3>No scans yet</h3>
                <p>Run your first scan to see results here.</p>
                <a href="#/scan" class="btn btn-primary">Start a Scan</a>
            </div>
        `;
        return;
    }

    const latest = reports[0];
    const summary = latest.summary || {};
    const totalFiles = summary.total_files || 0;
    const safeFiles = summary.safe_files || 0;
    const unsafeFiles = summary.unsafe_files || totalFiles - safeFiles;
    const severity = summary.findings_by_severity || {};

    app.innerHTML = `
        <div class="page-header">
            <h2>Dashboard</h2>
            <p>Latest scan: ${escapeHtml(latest.date_display)}</p>
        </div>
        ${scanState.active ? scanBannerHtml() : ""}
        <div class="stats-grid">
            <div class="stat-card safe">
                <div class="stat-value">${safeFiles}</div>
                <div class="stat-label">Safe Files</div>
            </div>
            <div class="stat-card ${unsafeFiles > 0 ? "critical" : "safe"}">
                <div class="stat-value">${unsafeFiles}</div>
                <div class="stat-label">Files with Issues</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">${severity.critical || 0}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">${severity.high || 0}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">${severity.medium || 0}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">${severity.low || 0}</div>
                <div class="stat-label">Low / Info</div>
            </div>
        </div>
        <div class="card">
            <div class="card-header">
                <h3>Latest Report</h3>
                <a href="#/report/${latest.timestamp}" class="btn btn-secondary btn-sm">View Full Report</a>
            </div>
            <div class="card-body">
                <p>Scanned <strong>${totalFiles}</strong> files.
                ${unsafeFiles > 0
                    ? `Found <strong style="color:var(--critical)">${unsafeFiles} file(s) with issues</strong>.`
                    : `<strong style="color:var(--safe)">All files are safe.</strong>`
                }</p>
                <p style="margin-top:10px;color:var(--text-secondary)">
                    Formats: ${latest.formats.map((f) => f.toUpperCase()).join(", ")}
                </p>
            </div>
        </div>
        <div class="card">
            <div class="card-header">
                <h3>Recent Reports</h3>
                <a href="#/reports" class="btn btn-secondary btn-sm">View All</a>
            </div>
            <div class="card-body" style="padding:0">
                <ul class="report-list">
                    ${reports
                        .slice(0, 5)
                        .map((r) => reportListItem(r))
                        .join("")}
                </ul>
            </div>
        </div>
    `;
}

// --- Scan Banner (shown on other pages while scan is running) ---

function scanBannerHtml() {
    return `
        <div class="card" style="border-color:var(--safe);margin-bottom:20px;cursor:pointer"
             onclick="window.location.hash='#/scan'">
            <div class="card-body" style="padding:12px 20px;display:flex;align-items:center;gap:15px">
                <div class="scan-spinner"></div>
                <div style="flex:1">
                    <strong>Scan in progress</strong>
                    <span style="color:var(--text-secondary);margin-left:10px">
                        ${scanState.current} / ${scanState.total} files (${scanState.percent}%)
                    </span>
                </div>
                <span class="badge safe">View</span>
            </div>
        </div>
    `;
}

// --- Reports Page ---

function reportListItem(r) {
    const summary = r.summary || {};
    const total = summary.total_files || 0;
    const unsafe = summary.unsafe_files || 0;

    return `
        <li class="report-item" onclick="window.location.hash='#/report/${r.timestamp}'">
            <div>
                <div class="report-date">${escapeHtml(r.date_display)}</div>
                <div class="report-meta">${total} files scanned</div>
            </div>
            <div class="report-badges">
                ${unsafe > 0
                    ? `<span class="badge critical">${unsafe} issue${unsafe !== 1 ? "s" : ""}</span>`
                    : `<span class="badge safe">Clean</span>`
                }
            </div>
        </li>
    `;
}

async function renderReports() {
    app.innerHTML = `<div class="loading">Loading reports...</div>`;

    const reports = await api("/reports");

    if (!reports.length) {
        app.innerHTML = `
            <div class="page-header">
                <h2>Reports</h2>
                <p>Scan history</p>
            </div>
            <div class="empty-state">
                <h3>No reports found</h3>
                <p>Reports will appear here after your first scan.</p>
                <a href="#/scan" class="btn btn-primary">Start a Scan</a>
            </div>
        `;
        return;
    }

    app.innerHTML = `
        <div class="page-header">
            <h2>Reports</h2>
            <p>${reports.length} report${reports.length !== 1 ? "s" : ""} available</p>
        </div>
        <div class="card">
            <div class="card-body" style="padding:0">
                <ul class="report-list">
                    ${reports.map((r) => reportListItem(r)).join("")}
                </ul>
            </div>
        </div>
    `;
}

// --- Report Detail Page ---

async function renderReportDetail(timestamp) {
    app.innerHTML = `<div class="loading">Loading report...</div>`;

    const data = await api(`/reports/${timestamp}`);

    if (data.error) {
        app.innerHTML = `
            <div class="page-header">
                <a href="#/reports" class="back-link">&larr; Back to Reports</a>
            </div>
            <div class="empty-state">
                <h3>Report not found</h3>
                <p>${escapeHtml(data.error)}</p>
            </div>
        `;
        return;
    }

    const results = data.results || [];
    const summary = data.summary || {};
    const unsafe = results.filter((r) => !r.is_safe);
    const safe = results.filter((r) => r.is_safe);

    app.innerHTML = `
        <div class="page-header">
            <a href="#/reports" class="back-link">&larr; Back to Reports</a>
            <h2>Scan Report</h2>
            <p>${escapeHtml(data.scan_date || "")} &mdash; ${escapeHtml(data.scan_target || "")}</p>
        </div>
        <div class="stats-grid">
            <div class="stat-card safe">
                <div class="stat-value">${safe.length}</div>
                <div class="stat-label">Safe Files</div>
            </div>
            <div class="stat-card ${unsafe.length > 0 ? "critical" : "safe"}">
                <div class="stat-value">${unsafe.length}</div>
                <div class="stat-label">Issues Found</div>
            </div>
        </div>
        ${unsafe.length > 0 ? `
            <h3 class="section-title">Threats</h3>
            ${unsafe.map((r) => renderResultCard(r)).join("")}
        ` : ""}
        ${safe.length > 0 ? `
            <h3 class="section-title">Safe Files (${safe.length})</h3>
            <div class="card">
                <div class="card-body">
                    ${safe.map((r) => `
                        <div style="padding:4px 0;font-family:'Consolas',monospace;font-size:0.85em;color:var(--safe)">
                            ${escapeHtml(r.filepath || r.file_path || "")}
                        </div>
                    `).join("")}
                </div>
            </div>
        ` : ""}
    `;

    // Bind card toggle
    document.querySelectorAll(".result-card-header").forEach((header) => {
        header.addEventListener("click", () => {
            const body = header.nextElementSibling;
            body.classList.toggle("collapsed");
        });
    });
}

function renderResultCard(result) {
    const filepath = result.filepath || result.file_path || "";
    const findings = result.findings || [];
    const maxSeverity = result.max_severity || "info";

    return `
        <div class="result-card">
            <div class="result-card-header">
                <div>
                    <span class="filepath">${escapeHtml(filepath)}</span>
                </div>
                <div class="report-badges">
                    ${severityBadge(maxSeverity)}
                    <span class="badge info">${result.format || "unknown"}</span>
                </div>
            </div>
            <div class="result-card-body collapsed">
                <div class="result-meta">
                    <div><dt>Format</dt><dd>${escapeHtml(result.format || "")}</dd></div>
                    <div><dt>Size</dt><dd>${formatSize(result.file_size || 0)}</dd></div>
                    <div><dt>Scan Time</dt><dd>${(result.scan_time_ms || 0).toFixed(1)}ms</dd></div>
                </div>
                ${findings.map((f) => `
                    <div class="finding ${f.severity || "info"}">
                        <div class="finding-header">
                            ${severityBadge(f.severity || "info")}
                            <span class="finding-message">${escapeHtml(f.message || "")}</span>
                        </div>
                        ${f.recommendation ? `
                            <div class="finding-meta">
                                <strong>Action:</strong> ${escapeHtml(f.recommendation)}
                            </div>
                        ` : ""}
                        ${f.details && f.details.context_analysis ? `
                            <div class="finding-meta">
                                <strong>Confidence:</strong> ${f.details.context_analysis.confidence_percent || "N/A"}
                                (${f.details.context_analysis.confidence_level || "N/A"})
                            </div>
                        ` : ""}
                    </div>
                `).join("")}
            </div>
        </div>
    `;
}

// --- Scan Page ---

async function renderScan() {
    // If a scan is active or just completed, restore that view
    if (scanState.active || scanState.complete) {
        renderScanWithState();
        return;
    }

    const config = await api("/config");
    const schedulePaths = (config.schedule && config.schedule.scan_paths) || [];
    const defaultPath = schedulePaths.length > 0 ? schedulePaths[0] : "";

    app.innerHTML = `
        <div class="page-header">
            <h2>Scan</h2>
            <p>Scan a directory for malicious model files</p>
        </div>
        <div class="card">
            <div class="card-body">
                <div class="scan-input-group">
                    <input type="text" id="scan-path" placeholder="/path/to/models"
                           value="${escapeHtml(defaultPath)}">
                    <button class="btn btn-secondary" onclick="openFolderBrowser()">
                        Browse
                    </button>
                    <button class="btn btn-primary" id="scan-btn" onclick="startScan()">
                        Start Scan
                    </button>
                </div>
                <div class="scan-options">
                    <label class="checkbox-label">
                        <input type="checkbox" id="scan-recursive" checked>
                        Recursive scan
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="scan-context" checked>
                        Context analysis
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="scan-external">
                        External validation
                    </label>
                </div>
                <div class="form-group" style="max-width:300px">
                    <label for="scan-confidence">Confidence threshold</label>
                    <input type="number" id="scan-confidence" value="0.5" min="0" max="1" step="0.1">
                </div>
            </div>
        </div>
    `;
}

function renderScanWithState() {
    const isRunning = scanState.active && !scanState.complete;
    const isComplete = scanState.complete;

    app.innerHTML = `
        <div class="page-header">
            <h2>Scan</h2>
            <p>${isRunning ? "Scan in progress..." : "Scan a directory for malicious model files"}</p>
        </div>
        <div class="card">
            <div class="card-body">
                <div class="scan-input-group">
                    <input type="text" id="scan-path" placeholder="/path/to/models"
                           value="${escapeHtml(scanState.path)}" ${isRunning ? "disabled" : ""}>
                    <button class="btn btn-primary" id="scan-btn"
                            onclick="${isComplete ? "resetScan()" : "startScan()"}"
                            ${isRunning ? "disabled" : ""}>
                        ${isRunning ? "Scanning..." : isComplete ? "New Scan" : "Start Scan"}
                    </button>
                </div>
            </div>
        </div>
        <div id="scan-progress" ${!isRunning && !isComplete ? 'style="display:none"' : ""}>
            <div class="card">
                <div class="card-header">
                    <h3 id="scan-status-text">${escapeHtml(scanState.statusText)}</h3>
                </div>
                <div class="card-body">
                    <div class="progress-container">
                        <div class="progress-bar-wrapper">
                            <div class="progress-bar" id="scan-progress-bar"
                                 style="width:${scanState.percent}%"></div>
                        </div>
                        <div class="progress-text">
                            <span id="scan-file-name">${escapeHtml(scanState.fileName)}</span>
                            <span id="scan-counter">${scanState.current} / ${scanState.total} (${scanState.percent}%)</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div id="scan-results">
            ${isComplete && scanState.completeSummary ? renderScanResults(scanState.completeSummary) : ""}
        </div>
    `;
}

function renderScanResults(summary) {
    const severity = summary.findings_by_severity || {};
    return `
        <div class="stats-grid" style="margin-top:20px">
            <div class="stat-card safe">
                <div class="stat-value">${summary.safe_files}</div>
                <div class="stat-label">Safe Files</div>
            </div>
            <div class="stat-card ${summary.unsafe_files > 0 ? "critical" : "safe"}">
                <div class="stat-value">${summary.unsafe_files}</div>
                <div class="stat-label">Issues Found</div>
            </div>
            <div class="stat-card info">
                <div class="stat-value">${(summary.scan_time_ms / 1000).toFixed(1)}s</div>
                <div class="stat-label">Scan Time</div>
            </div>
        </div>
        ${summary.report_timestamp ? `
            <div style="text-align:center;margin-top:20px">
                <a href="#/report/${summary.report_timestamp}" class="btn btn-primary">
                    View Full Report
                </a>
            </div>
        ` : ""}
    `;
}

function resetScan() {
    scanState.active = false;
    scanState.complete = false;
    scanState.completeSummary = null;
    scanState.error = null;
    scanState.scanId = null;
    scanState.current = 0;
    scanState.total = 0;
    scanState.percent = 0;
    scanState.statusText = "Preparing scan...";
    scanState.fileName = "Waiting...";
    renderScan();
}

// Updates the DOM only if the scan page is currently visible
function updateScanUI() {
    const onScanPage = (window.location.hash || "").startsWith("#/scan");

    if (onScanPage) {
        const bar = document.getElementById("scan-progress-bar");
        const status = document.getElementById("scan-status-text");
        const fileName = document.getElementById("scan-file-name");
        const counter = document.getElementById("scan-counter");
        const progressDiv = document.getElementById("scan-progress");

        if (bar) bar.style.width = `${scanState.percent}%`;
        if (status) status.textContent = scanState.statusText;
        if (fileName) fileName.textContent = scanState.fileName;
        if (counter) counter.textContent = `${scanState.current} / ${scanState.total} (${scanState.percent}%)`;
        if (progressDiv) progressDiv.style.display = "block";
    }
}

async function startScan() {
    const pathInput = document.getElementById("scan-path");
    const path = pathInput ? pathInput.value.trim() : "";
    if (!path) {
        showToast("Please enter a path to scan", "error");
        return;
    }

    // Initialize scan state
    scanState.active = true;
    scanState.complete = false;
    scanState.completeSummary = null;
    scanState.error = null;
    scanState.path = path;
    scanState.statusText = "Preparing scan...";
    scanState.fileName = "Waiting...";
    scanState.current = 0;
    scanState.total = 0;
    scanState.percent = 0;

    // Re-render to show progress UI
    renderScanWithState();

    // Start scan via API
    const { scan_id } = await api("/scan", {
        method: "POST",
        body: {
            path: path,
            recursive: document.getElementById("scan-recursive")
                ? document.getElementById("scan-recursive").checked
                : true,
            context_analysis: document.getElementById("scan-context")
                ? document.getElementById("scan-context").checked
                : true,
            external_validation: document.getElementById("scan-external")
                ? document.getElementById("scan-external").checked
                : false,
            confidence_threshold: document.getElementById("scan-confidence")
                ? parseFloat(document.getElementById("scan-confidence").value)
                : 0.5,
        },
    });

    scanState.scanId = scan_id;

    // Connect WebSocket
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/scan/${scan_id}`);
    scanState.ws = ws;

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);

        switch (msg.type) {
            case "collecting":
                scanState.statusText = "Discovering files...";
                scanState.fileName = msg.message;
                break;

            case "files_found":
                scanState.statusText = `Scanning ${msg.total} files...`;
                scanState.total = msg.total;
                break;

            case "progress":
                scanState.current = msg.current;
                scanState.total = msg.total;
                scanState.percent = msg.percent;
                scanState.fileName = msg.file;
                scanState.statusText = `Scanning ${msg.total} files...`;
                break;

            case "complete":
                scanState.complete = true;
                scanState.active = false;
                scanState.percent = 100;
                scanState.statusText = "Scan complete!";
                scanState.fileName = "Done";
                scanState.completeSummary = msg.summary;

                // If on scan page, re-render to show results
                if ((window.location.hash || "").startsWith("#/scan")) {
                    renderScanWithState();
                }
                return;

            case "error":
                scanState.error = msg.message;
                scanState.active = false;
                scanState.statusText = "Error";
                showToast(msg.message, "error");
                break;
        }

        updateScanUI();
    };

    ws.onerror = () => {
        scanState.active = false;
        scanState.error = "Connection error";
        showToast("Connection error", "error");
        updateScanUI();
    };

    ws.onclose = () => {
        scanState.ws = null;
    };
}

// --- Folder Browser Modal ---

let folderBrowserShowHidden = false;

let folderBrowserTargetId = "scan-path";

async function openFolderBrowser() {
    folderBrowserTargetId = "scan-path";
    const pathInput = document.getElementById("scan-path");
    const startPath = pathInput ? pathInput.value.trim() || "~" : "~";
    await renderFolderBrowser(startPath);
}

async function openFolderBrowserFor(inputId) {
    folderBrowserTargetId = inputId;
    const pathInput = document.getElementById(inputId);
    const startPath = pathInput ? pathInput.value.trim() || "~" : "~";
    await renderFolderBrowser(startPath);
}

async function renderFolderBrowser(path) {
    const data = await api(`/browse?path=${encodeURIComponent(path)}&show_hidden=${folderBrowserShowHidden}`);

    if (data.error) {
        showToast(data.error, "error");
        return;
    }

    // Remove existing modal if any
    const existing = document.querySelector(".modal-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <h3>Select Folder</h3>
                <button class="modal-close" onclick="closeFolderBrowser()">&times;</button>
            </div>
            <div class="modal-body">
                ${data.parent ? `
                    <div class="folder-item parent-dir" onclick="navigateFolder('${escapeAttr(data.parent)}')">
                        <span class="folder-icon">&#x1F519;</span>
                        <span>.. (parent directory)</span>
                    </div>
                ` : ""}
                ${data.directories.length > 0 ? `
                    <ul class="folder-list">
                        ${data.directories.map((dir) => `
                            <li class="folder-item" onclick="navigateFolder('${escapeAttr(data.current + "/" + dir)}')">
                                <span class="folder-icon">&#x1F4C1;</span>
                                <span>${escapeHtml(dir)}</span>
                            </li>
                        `).join("")}
                    </ul>
                ` : `
                    <div class="folder-empty">No subdirectories found</div>
                `}
            </div>
            <div class="modal-footer">
                <span class="current-path" title="${escapeAttr(data.current)}">${escapeHtml(data.current)}</span>
                <button class="btn btn-primary btn-sm" onclick="selectFolder('${escapeAttr(data.current)}')">
                    Select This Folder
                </button>
            </div>
        </div>
    `;

    // Close on overlay click (not modal body)
    overlay.addEventListener("click", (e) => {
        if (e.target === overlay) closeFolderBrowser();
    });

    document.body.appendChild(overlay);
}

function escapeAttr(text) {
    return text.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

async function navigateFolder(path) {
    await renderFolderBrowser(path);
}

function selectFolder(path) {
    const pathInput = document.getElementById(folderBrowserTargetId);
    if (pathInput) pathInput.value = path;
    closeFolderBrowser();
}

function closeFolderBrowser() {
    const overlay = document.querySelector(".modal-overlay");
    if (overlay) overlay.remove();
}

// --- Config Page ---

async function renderConfig() {
    app.innerHTML = `<div class="loading">Loading configuration...</div>`;

    const config = await api("/config");

    const reports = config.reports || {};
    const web = config.web || {};
    const schedule = config.schedule || {};

    app.innerHTML = `
        <div class="page-header">
            <h2>Configuration</h2>
            <p>Manage TensorTrap settings</p>
        </div>

        <div class="card">
            <div class="card-header"><h3>Reports</h3></div>
            <div class="card-body">
                <div class="form-group">
                    <label for="cfg-report-dir">Report Directory</label>
                    <div class="scan-input-group" style="margin-bottom:0">
                        <input type="text" id="cfg-report-dir"
                               value="${escapeHtml(reports.directory || "")}">
                        <button class="btn btn-secondary btn-sm"
                                onclick="openFolderBrowserFor('cfg-report-dir')">
                            Browse
                        </button>
                    </div>
                </div>
                <div class="form-group">
                    <label for="cfg-retain-days">Retention (days)</label>
                    <input type="number" id="cfg-retain-days"
                           value="${reports.retain_days || 30}" min="0">
                    <div class="form-hint">0 = keep forever</div>
                </div>
                <div class="form-group">
                    <label>Report Formats</label>
                    <div class="checkbox-group">
                        ${["html", "txt", "json", "csv"]
                            .map((f) => `
                                <label class="checkbox-label">
                                    <input type="checkbox" class="cfg-format" value="${f}"
                                           ${(reports.formats || []).includes(f) ? "checked" : ""}>
                                    ${f.toUpperCase()}
                                </label>
                            `)
                            .join("")}
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Web UI</h3></div>
            <div class="card-body">
                <div class="form-group">
                    <label for="cfg-port">Port</label>
                    <input type="number" id="cfg-port"
                           value="${web.port || 7780}" min="1024" max="65535">
                </div>
                <div class="form-group">
                    <label class="toggle-label">
                        <span class="toggle-switch">
                            <input type="checkbox" id="cfg-auto-open"
                                   ${web.auto_open_browser !== false ? "checked" : ""}>
                            <span class="toggle-slider"></span>
                        </span>
                        Auto-open browser on start
                    </label>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Scheduled Scans</h3></div>
            <div class="card-body">
                <div class="form-group">
                    <label class="toggle-label">
                        <span class="toggle-switch">
                            <input type="checkbox" id="cfg-schedule-enabled"
                                   ${schedule.enabled ? "checked" : ""}>
                            <span class="toggle-slider"></span>
                        </span>
                        Enable daily scan
                    </label>
                </div>
                <div class="form-group">
                    <label for="cfg-scan-time">Scan Time</label>
                    <input type="time" id="cfg-scan-time"
                           value="${schedule.scan_time || "03:00"}">
                </div>
                <div class="form-group">
                    <label for="cfg-scan-paths">Scan Paths (one per line)</label>
                    <textarea id="cfg-scan-paths">${escapeHtml(
                        (schedule.scan_paths || []).join("\n")
                    )}</textarea>
                </div>
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="cfg-scan-recursive"
                               ${schedule.recursive !== false ? "checked" : ""}>
                        Recursive scan
                    </label>
                </div>
                <div class="form-group">
                    <label for="cfg-scan-confidence">Confidence Threshold</label>
                    <input type="number" id="cfg-scan-confidence"
                           value="${schedule.confidence_threshold || 0.5}"
                           min="0" max="1" step="0.1">
                </div>
            </div>
        </div>

        <div style="display:flex;gap:10px;margin-top:10px">
            <button class="btn btn-primary" onclick="saveConfig()">Save Configuration</button>
            <button class="btn btn-secondary" onclick="renderConfig()">Discard Changes</button>
            <button class="btn btn-danger" onclick="resetConfigDefaults()">Reset to Defaults</button>
        </div>
    `;
}

async function resetConfigDefaults() {
    await api("/config/reset", { method: "POST" });
    showToast("Configuration reset to defaults!");
    renderConfig();
}

async function saveConfig() {
    const formats = Array.from(document.querySelectorAll(".cfg-format:checked")).map(
        (cb) => cb.value
    );
    const scanPaths = document
        .getElementById("cfg-scan-paths")
        .value.split("\n")
        .map((p) => p.trim())
        .filter(Boolean);

    const updates = {
        "reports.directory": document.getElementById("cfg-report-dir").value,
        "reports.retain_days": document.getElementById("cfg-retain-days").value,
        "reports.formats": formats.join(","),
        "web.port": document.getElementById("cfg-port").value,
        "web.auto_open_browser": document.getElementById("cfg-auto-open").checked
            ? "true"
            : "false",
        "schedule.enabled": document.getElementById("cfg-schedule-enabled").checked
            ? "true"
            : "false",
        "schedule.scan_time": document.getElementById("cfg-scan-time").value,
        "schedule.scan_paths": scanPaths.join(","),
        "schedule.recursive": document.getElementById("cfg-scan-recursive").checked
            ? "true"
            : "false",
        "schedule.confidence_threshold":
            document.getElementById("cfg-scan-confidence").value,
    };

    const result = await api("/config", { method: "PUT", body: updates });

    if (result.errors) {
        showToast("Error saving config", "error");
    } else {
        showToast("Configuration saved!");
    }
}

// --- Init ---

async function init() {
    try {
        const status = await api("/status");
        document.getElementById("version-text").textContent =
            `TensorTrap v${status.version}`;
        document.getElementById("status-dot").classList.remove("offline");
    } catch {
        document.getElementById("status-dot").classList.add("offline");
    }

    router();
}

init();
