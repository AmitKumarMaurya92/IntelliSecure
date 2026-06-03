// =============================================
// REAL-TIME MONITOR — Frontend Logic
// =============================================
// Handles scanning, live feed, timeline chart,
// detector status, and auto-refresh.

(function () {
    "use strict";

    // ── Auth Headers ──────────────────────────────
    const rtmHeaders = { "Content-Type": "application/json" };
    const token = localStorage.getItem("access_token");
    if (token) {
        rtmHeaders["Authorization"] = `Bearer ${token}`;
    }

    // ── State ─────────────────────────────────────
    let isScanning = false;
    let autoRefreshTimer = null;
    let rtmInitialized = false;

    // ── DOM Elements ──────────────────────────────
    const getEl = (id) => document.getElementById(id);

    // =============================================
    // SCAN
    // =============================================
    window.runRealtimeScan = async function () {
        if (isScanning) return;
        isScanning = true;

        // Update UI to scanning state
        const scanBtn = getEl("rtmScanBtn");
        const scanIcon = getEl("rtmScanIcon");
        const statusIndicator = getEl("rtmStatusIndicator");
        const statusText = getEl("rtmStatusText");

        if (scanBtn) {
            scanBtn.classList.add("scanning");
            scanBtn.querySelector("span").textContent = "Scanning...";
        }
        if (scanIcon) scanIcon.className = "fa-solid fa-spinner";
        if (statusIndicator) statusIndicator.className = "rtm-status-indicator scanning";
        if (statusText) statusText.textContent = "Scanning";

        try {
            const response = await fetch("/api/realtime/scan", {
                method: "POST",
                headers: rtmHeaders,
            });

            if (!response.ok) throw new Error(`Scan failed: ${response.status}`);
            const data = await response.json();

            // Update KPI cards
            updateKPICards(data);

            // Update live feed
            updateLiveFeed(data.events || []);

            // Update summary bar
            updateSummaryBar(data);

            // Update last scan time
            updateLastScanTime(data.scan_timestamp);

            // Refresh timeline chart
            loadScanHistory();

            // Set status to ready with threat info
            if (statusIndicator) {
                if (data.total_threats > 0) {
                    statusIndicator.className = "rtm-status-indicator warning";
                    if (statusText) statusText.textContent = `${data.total_threats} Threat${data.total_threats !== 1 ? "s" : ""}`;
                } else {
                    statusIndicator.className = "rtm-status-indicator";
                    if (statusText) statusText.textContent = "Secure";
                }
            }
        } catch (err) {
            console.error("Real-time scan failed:", err);
            if (statusIndicator) statusIndicator.className = "rtm-status-indicator warning";
            if (statusText) statusText.textContent = "Error";

            const summaryText = getEl("rtmSummaryText");
            const summaryBar = getEl("rtmSummaryBar");
            if (summaryText) summaryText.textContent = "Scan failed. Check your connection or try again.";
            if (summaryBar) {
                summaryBar.classList.remove("clear", "has-threats");
                summaryBar.classList.add("has-threats");
            }
        } finally {
            isScanning = false;
            if (scanBtn) {
                scanBtn.classList.remove("scanning");
                scanBtn.querySelector("span").textContent = "Run Scan Now";
            }
            if (scanIcon) scanIcon.className = "fa-solid fa-crosshairs";
        }
    };

    // =============================================
    // KPI CARDS
    // =============================================
    function updateKPICards(data) {
        const updates = [
            { id: "rtmBruteCount", value: data.brute_force_count },
            { id: "rtmPortCount", value: data.port_scan_count },
            { id: "rtmUnauthCount", value: data.unauthorized_count },
            { id: "rtmMLCount", value: data.ml_anomaly_count },
        ];

        updates.forEach(({ id, value }) => {
            const el = getEl(id);
            if (el) {
                el.textContent = value;
                if (value > 0) {
                    el.classList.add("has-threats");
                } else {
                    el.classList.remove("has-threats");
                }

                // Quick pop animation
                el.style.transform = "scale(1.2)";
                setTimeout(() => {
                    el.style.transition = "transform 0.3s ease";
                    el.style.transform = "scale(1)";
                }, 100);
            }
        });
    }

    // =============================================
    // LIVE THREAT FEED
    // =============================================
    function updateLiveFeed(events) {
        const feedList = getEl("rtmFeedList");
        const eventCount = getEl("rtmEventCount");

        if (!feedList) return;

        if (eventCount) {
            eventCount.textContent = `${events.length} event${events.length !== 1 ? "s" : ""}`;
        }

        if (events.length === 0) {
            feedList.innerHTML = `
                <div class="rtm-feed-clear">
                    <i class="fa-solid fa-shield-halved"></i>
                    <p>All Clear — No threats detected</p>
                    <span>System is operating normally</span>
                </div>
            `;
            return;
        }

        feedList.innerHTML = "";

        // Color map for event icons
        const iconBgMap = {
            "Brute Force": { bg: "var(--light-red)", color: "#ef4444" },
            "Port Scan": { bg: "var(--light-yellow)", color: "#f59e0b" },
            "Unauthorized File Access": { bg: "var(--light-blue)", color: "#2563eb" },
            "Blocked USB Device": { bg: "rgba(6, 182, 212, 0.15)", color: "#06b6d4" },
            "ML Anomaly": { bg: "var(--light-green)", color: "#10b981" },
        };

        events.forEach((event, index) => {
            const colors = iconBgMap[event.type] || { bg: "var(--bg-color)", color: "var(--text-muted)" };
            const iconClass = event.icon || "fa-triangle-exclamation";
            const now = new Date();
            const timeStr = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

            const item = document.createElement("div");
            item.className = "rtm-feed-item";
            item.style.animationDelay = `${index * 0.08}s`;

            item.innerHTML = `
                <div class="rtm-feed-icon" style="background: ${colors.bg}; color: ${colors.color}">
                    <i class="fa-solid ${iconClass}"></i>
                </div>
                <div class="rtm-feed-body">
                    <div class="rtm-feed-title">${escapeHtml(event.type)} — ${escapeHtml(event.source)}</div>
                    <div class="rtm-feed-desc">${escapeHtml(event.description)}</div>
                </div>
                <div class="rtm-feed-meta">
                    <span class="rtm-severity-badge ${event.severity}">${event.severity}</span>
                    <span class="rtm-feed-time">${timeStr}</span>
                </div>
            `;

            feedList.appendChild(item);
        });
    }

    // =============================================
    // SUMMARY BAR
    // =============================================
    function updateSummaryBar(data) {
        const summaryText = getEl("rtmSummaryText");
        const summaryBar = getEl("rtmSummaryBar");

        if (!summaryText || !summaryBar) return;

        summaryText.textContent = data.summary || "Scan complete.";

        summaryBar.classList.remove("has-threats", "clear");
        if (data.total_threats > 0) {
            summaryBar.classList.add("has-threats");
        } else {
            summaryBar.classList.add("clear");
        }
    }

    // =============================================
    // LAST SCAN TIME
    // =============================================
    function updateLastScanTime(timestamp) {
        const lastScan = getEl("rtmLastScan");
        if (!lastScan || !timestamp) return;

        const date = new Date(timestamp);
        const timeStr = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        const dateStr = date.toLocaleDateString([], { month: "short", day: "numeric" });

        lastScan.innerHTML = `<i class="fa-regular fa-clock"></i> <span>Last scan: ${dateStr}, ${timeStr}</span>`;
    }

    // =============================================
    // SCAN HISTORY / TIMELINE CHART
    // =============================================
    async function loadScanHistory() {
        try {
            const response = await fetch("/api/realtime/history?limit=20", {
                headers: rtmHeaders,
            });
            if (!response.ok) throw new Error("Failed to load history");
            const data = await response.json();

            renderTimelineChart(data.history || []);

            const chartInfo = getEl("rtmChartInfo");
            if (chartInfo) {
                chartInfo.textContent = `${data.count || 0} scan${data.count !== 1 ? "s" : ""}`;
            }
        } catch (err) {
            console.error("Failed to load scan history:", err);
            renderEmptyChart();
        }
    }

    function renderTimelineChart(history) {
        const chartEl = getEl("rtmTimelineChart");
        if (!chartEl) return;

        if (history.length === 0) {
            renderEmptyChart();
            return;
        }

        const isDark = document.body.classList.contains("dark-theme");
        const gridColor = isDark ? "#334155" : "#f1f5f9";
        const fontColor = isDark ? "#94a3b8" : "#64748b";

        const xLabels = history.map((h, i) => {
            const ts = new Date(h.timestamp);
            return ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        });

        const traces = [
            {
                x: xLabels,
                y: history.map((h) => h.brute_force_count),
                name: "Brute Force",
                type: "scatter",
                mode: "lines",
                fill: "tonexty",
                line: { color: "#ef4444", width: 2, shape: "spline" },
                fillcolor: "rgba(239, 68, 68, 0.08)",
                stackgroup: "one",
            },
            {
                x: xLabels,
                y: history.map((h) => h.port_scan_count),
                name: "Port Scans",
                type: "scatter",
                mode: "lines",
                fill: "tonexty",
                line: { color: "#f59e0b", width: 2, shape: "spline" },
                fillcolor: "rgba(245, 158, 11, 0.08)",
                stackgroup: "one",
            },
            {
                x: xLabels,
                y: history.map((h) => h.unauthorized_count),
                name: "Unauthorized",
                type: "scatter",
                mode: "lines",
                fill: "tonexty",
                line: { color: "#2563eb", width: 2, shape: "spline" },
                fillcolor: "rgba(37, 99, 235, 0.08)",
                stackgroup: "one",
            },
            {
                x: xLabels,
                y: history.map((h) => h.ml_anomaly_count),
                name: "ML Anomalies",
                type: "scatter",
                mode: "lines",
                fill: "tonexty",
                line: { color: "#10b981", width: 2, shape: "spline" },
                fillcolor: "rgba(16, 185, 129, 0.08)",
                stackgroup: "one",
            },
        ];

        Plotly.newPlot(
            chartEl,
            traces,
            {
                margin: { t: 10, l: 30, r: 10, b: 30 },
                paper_bgcolor: "transparent",
                plot_bgcolor: "transparent",
                xaxis: {
                    showgrid: false,
                    zeroline: false,
                    tickfont: { color: fontColor, size: 10 },
                },
                yaxis: {
                    showgrid: true,
                    gridcolor: gridColor,
                    zeroline: false,
                    tickfont: { color: fontColor, size: 10 },
                },
                legend: {
                    orientation: "h",
                    y: -0.2,
                    x: 0.5,
                    xanchor: "center",
                    font: { size: 10, color: fontColor },
                },
                hovermode: "x unified",
            },
            { displayModeBar: false, responsive: true }
        );
    }

    function renderEmptyChart() {
        const chartEl = getEl("rtmTimelineChart");
        if (!chartEl) return;

        const isDark = document.body.classList.contains("dark-theme");
        const gridColor = isDark ? "#334155" : "#f1f5f9";
        const fontColor = isDark ? "#94a3b8" : "#64748b";

        Plotly.newPlot(
            chartEl,
            [
                {
                    x: ["—"],
                    y: [0],
                    type: "scatter",
                    mode: "lines",
                    line: { color: "#cbd5e1", width: 1 },
                },
            ],
            {
                margin: { t: 10, l: 30, r: 10, b: 30 },
                paper_bgcolor: "transparent",
                plot_bgcolor: "transparent",
                xaxis: {
                    showgrid: false,
                    zeroline: false,
                    tickfont: { color: fontColor, size: 10 },
                },
                yaxis: {
                    showgrid: true,
                    gridcolor: gridColor,
                    zeroline: false,
                    tickfont: { color: fontColor, size: 10 },
                    range: [0, 5],
                },
                annotations: [
                    {
                        text: "No scan data yet",
                        xref: "paper",
                        yref: "paper",
                        x: 0.5,
                        y: 0.5,
                        showarrow: false,
                        font: { size: 13, color: fontColor },
                    },
                ],
            },
            { displayModeBar: false, responsive: true }
        );
    }

    // =============================================
    // DETECTOR STATUS
    // =============================================
    async function loadDetectorStatus() {
        try {
            const response = await fetch("/api/realtime/status", {
                headers: rtmHeaders,
            });
            if (!response.ok) throw new Error("Failed to load status");
            const data = await response.json();

            renderDetectors(data.detectors || []);

            // Update last scan info if available
            if (data.last_scan) {
                updateLastScanTime(data.last_scan.timestamp);
            }
        } catch (err) {
            console.error("Failed to load detector status:", err);
        }
    }

    function renderDetectors(detectors) {
        const grid = getEl("rtmDetectorGrid");
        if (!grid) return;

        grid.innerHTML = "";

        detectors.forEach((det) => {
            const statusLabel = det.status.charAt(0).toUpperCase() + det.status.slice(1);

            const item = document.createElement("div");
            item.className = "rtm-detector-item";
            item.innerHTML = `
                <div class="rtm-detector-icon">
                    <i class="fa-solid ${det.icon}"></i>
                </div>
                <div class="rtm-detector-info">
                    <div class="rtm-detector-name">${escapeHtml(det.name)}</div>
                    <div class="rtm-detector-desc">${escapeHtml(det.description)}</div>
                </div>
                <span class="rtm-detector-status ${det.status}">${statusLabel}</span>
            `;

            grid.appendChild(item);
        });
    }

    // =============================================
    // AUTO-REFRESH
    // =============================================
    function setupAutoRefresh() {
        const autoCheck = getEl("rtmAutoCheck");
        const intervalSelect = getEl("rtmIntervalSelect");

        if (autoCheck) {
            autoCheck.addEventListener("change", () => {
                if (autoCheck.checked) {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
            });
        }

        if (intervalSelect) {
            intervalSelect.addEventListener("change", () => {
                if (autoCheck && autoCheck.checked) {
                    stopAutoRefresh();
                    startAutoRefresh();
                }
            });
        }
    }

    function startAutoRefresh() {
        stopAutoRefresh();
        const intervalSelect = getEl("rtmIntervalSelect");
        const seconds = intervalSelect ? parseInt(intervalSelect.value) : 30;
        autoRefreshTimer = setInterval(() => {
            window.runRealtimeScan();
        }, seconds * 1000);
    }

    function stopAutoRefresh() {
        if (autoRefreshTimer) {
            clearInterval(autoRefreshTimer);
            autoRefreshTimer = null;
        }
    }

    // =============================================
    // INITIALIZATION
    // =============================================
    function initRealtimeMonitor() {
        if (rtmInitialized) return;
        rtmInitialized = true;

        loadDetectorStatus();
        loadScanHistory();
        setupAutoRefresh();
    }

    // Hook into SPA navigation — initialize when view becomes active
    window.initRealtimeMonitorView = initRealtimeMonitor;

    // Check if the view is already active (direct load)
    document.addEventListener("DOMContentLoaded", () => {
        const rtmView = getEl("view-real-time");
        if (rtmView && rtmView.classList.contains("active")) {
            initRealtimeMonitor();
        }
    });

    // =============================================
    // UTILITIES
    // =============================================
    function escapeHtml(text) {
        if (!text) return "";
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }
})();
