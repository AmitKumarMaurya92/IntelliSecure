// =============================
// FETCH DATA FROM BACKEND API
// =============================

async function loadDashboardStats() {
    try {
        const response = await fetch('/api/dashboard/stats');
        const data = await response.json();

        document.getElementById("totalLogs").innerText = data.total_logs.toLocaleString();
        document.getElementById("activeThreats").innerText = data.active_threats;
        document.getElementById("criticalAlerts").innerText = data.critical_alerts;
        document.getElementById("securityScore").innerText = data.security_score;
    } catch (err) {
        console.error("Failed to load dashboard stats:", err);
        // Fallback placeholder data if API fails
        document.getElementById("totalLogs").innerText = (24532).toLocaleString();
        document.getElementById("activeThreats").innerText = "28";
        document.getElementById("criticalAlerts").innerText = "7";
        document.getElementById("securityScore").innerText = "87";
    }
}

async function loadAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const alerts = await response.json();
        renderAlerts(alerts);
    } catch (err) {
        console.error("Failed to load alerts:", err);
        // Mock data
        const mockAlerts = [
            { threat: "Brute Force Attack Detected", ip: "192.168.1.105", severity: "High", time: "2 min ago", icon: "fa-shield-virus" },
            { threat: "Multiple Failed Login Attempts", ip: "192.168.1.200", severity: "Medium", time: "10 min ago", icon: "fa-triangle-exclamation" },
            { threat: "Port Scan Detected", ip: "192.168.1.150", severity: "Medium", time: "30 min ago", icon: "fa-satellite-dish" },
            { threat: "Unusual File Access", ip: "192.168.1.33", severity: "Low", time: "1 hour ago", icon: "fa-circle-info" },
            { threat: "Malware Detected", ip: "192.168.1.77", severity: "High", time: "2 hours ago", icon: "fa-bug" }
        ];
        renderAlerts(mockAlerts);
    }
}

function renderAlerts(alerts) {
    const alertsList = document.getElementById("alertsList");
    alertsList.innerHTML = ""; 

    alerts.forEach(alert => {
        let severityClass = "";
        let iconClass = alert.icon || "fa-triangle-exclamation";
        if (alert.severity === "High" || alert.severity === "Critical") severityClass = "High";
        else if (alert.severity === "Medium") severityClass = "Medium";
        else severityClass = "Low";

        let timeStr = alert.time || new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        let ipStr = alert.ip || "Unknown IP";

        alertsList.innerHTML += `
            <div class="alert-item">
                <div class="alert-left">
                    <div class="alert-icon ${severityClass}"><i class="fa-solid ${iconClass}"></i></div>
                    <div class="alert-info">
                        <h5>${alert.threat}</h5>
                        <p>${ipStr}</p>
                    </div>
                </div>
                <div class="alert-right">
                    <span class="alert-badge ${severityClass}">${alert.severity}</span>
                    <span class="alert-time">${timeStr}</span>
                </div>
            </div>
        `;
    });
}

// =============================
// TOP ATTACK SOURCES
// =============================
function loadAttackSources() {
    const sources = [
        { ip: "192.168.1.105", count: 12, color: "#ef4444" },
        { ip: "192.168.1.200", count: 8, color: "#f59e0b" },
        { ip: "192.168.1.150", count: 5, color: "#8b5cf6" },
        { ip: "192.168.1.33", count: 3, color: "#2563eb" },
        { ip: "192.168.1.77", count: 2, color: "#06b6d4" }
    ];
    
    const maxCount = 15; // used for bar width ratio
    const listEl = document.getElementById("attackSourcesList");
    listEl.innerHTML = "";
    
    sources.forEach(src => {
        let widthPct = (src.count / maxCount) * 100;
        listEl.innerHTML += `
            <div class="source-item">
                <div class="source-ip">${src.ip}</div>
                <div class="source-bar-container">
                    <div class="source-bar" style="width: ${widthPct}%; background: ${src.color}"></div>
                </div>
                <div class="source-count">${src.count}</div>
            </div>
        `;
    });
}

// =============================
// THREAT TREND CHART (Area Chart)
// =============================
Plotly.newPlot("threatTrendChart", [{
    x: ["May 13", "May 14", "May 15", "May 16", "May 17", "May 18", "May 19"],
    y: [10, 16, 17, 34, 21, 14, 18],
    type: "scatter",
    mode: "lines+markers",
    fill: "tozeroy",
    line: { color: "#2563eb", width: 3, shape: "spline" },
    marker: { size: 6, color: "#2563eb" },
    fillcolor: "rgba(37, 99, 235, 0.15)"
}], {
    margin: { t: 20, l: 30, r: 10, b: 30 },
    paper_bgcolor: "transparent",
    plot_bgcolor: "transparent",
    xaxis: { showgrid: false, zeroline: false },
    yaxis: { showgrid: true, gridcolor: "#f1f5f9", zeroline: false }
}, {displayModeBar: false});

// =============================
// THREAT DISTRIBUTION (Donut)
// =============================
const threatValues = [35, 25, 20, 10, 10];
const threatLabels = ["Brute Force", "Port Scanning", "Malware", "Unauthorized Access", "Other"];
const threatColors = ["#ef4444", "#f59e0b", "#8b5cf6", "#2563eb", "#94a3b8"];

Plotly.newPlot("threatDistributionChart", [{
    values: threatValues,
    labels: threatLabels,
    type: "pie",
    hole: .65,
    marker: {
        colors: threatColors,
        line: { color: "#ffffff", width: 2 }
    },
    textinfo: "none",
    hoverinfo: "label+percent"
}], {
    margin: { t: 0, b: 0, l: 0, r: 0 },
    showlegend: false,
    paper_bgcolor: "transparent",
    plot_bgcolor: "transparent",
    annotations: [{
        font: { size: 20, weight: 700, color: "#1e293b" },
        showarrow: false,
        text: "28<br><span style='font-size:11px;color:#64748b;font-weight:500'>Total</span>",
        x: 0.5,
        y: 0.5
    }]
}, {displayModeBar: false, responsive: true});

const legendContainer = document.getElementById("threatLegend");
if(legendContainer) {
    legendContainer.innerHTML = "";
    threatLabels.forEach((label, i) => {
        legendContainer.innerHTML += `
            <div class="legend-item">
                <div class="legend-left">
                    <span class="legend-dot" style="background: ${threatColors[i]}"></span>
                    <span>${label}</span>
                </div>
                <span class="legend-pct">${threatValues[i]}%</span>
            </div>
        `;
    });
}

// =============================
// SECURITY SCORE TREND
// =============================
Plotly.newPlot("scoreTrendChart", [{
    x: ["May 13", "May 14", "May 15", "May 16", "May 17", "May 18", "May 19"],
    y: [50, 62, 54, 70, 70, 85, 87],
    type: "scatter",
    mode: "lines+markers",
    line: { color: "#10b981", width: 2 },
    marker: { size: 6, color: "#10b981" }
}], {
    margin: { t: 20, l: 30, r: 10, b: 30 },
    xaxis: { showgrid: false, zeroline: false },
    yaxis: { showgrid: true, gridcolor: "#f1f5f9", zeroline: false, range: [0, 100] }
}, {displayModeBar: false});

// =============================
// INITIALIZE
// =============================
loadDashboardStats();
loadAlerts();
loadAttackSources();

// =============================
// REAL-TIME CLOCK
// =============================
setInterval(() => {
    // Optionally auto-refresh stats
    // loadDashboardStats();
    // loadAlerts();
}, 10000);

// =============================
// SPA NAVIGATION LOGIC
// =============================
document.addEventListener("DOMContentLoaded", () => {
    const menuItems = document.querySelectorAll(".sidebar .menu li");
    const viewSections = document.querySelectorAll(".view-section");

    menuItems.forEach(item => {
        item.addEventListener("click", () => {
            const targetId = item.getAttribute("data-target");
            if (!targetId) return;

            // Remove active class from all menu items
            menuItems.forEach(li => li.classList.remove("active"));
            
            // Add active class to clicked item
            item.classList.add("active");

            // Hide all views
            viewSections.forEach(section => section.classList.remove("active"));
            
            // Show target view
            const targetView = document.getElementById(targetId);
            if (targetView) {
                targetView.classList.add("active");
            }
        });
    });
});

// =============================
// THEME TOGGLE LOGIC
// =============================
const themeToggle = document.getElementById("theme-toggle");
if (themeToggle) {
    themeToggle.addEventListener("click", () => {
        document.body.classList.toggle("dark-theme");
        const isDark = document.body.classList.contains("dark-theme");
        
        // Update icon
        const themeIcon = document.getElementById("theme-icon");
        if (themeIcon) {
            themeIcon.className = isDark ? "fa-regular fa-moon" : "fa-regular fa-sun";
        }
        
        // Update Plotly charts layout colors
        const gridColor = isDark ? "#334155" : "#f1f5f9";
        const fontColor = isDark ? "#94a3b8" : "#64748b";
    
        const updateLayout = {
            'yaxis.gridcolor': gridColor,
            'xaxis.tickfont.color': fontColor,
            'yaxis.tickfont.color': fontColor,
            'legend.font.color': fontColor,
            'annotations[0].font.color': isDark ? "#f8fafc" : "#1e293b"
        };
    
        try {
            Plotly.relayout("threatTrendChart", updateLayout);
            Plotly.restyle("threatDistributionChart", { 'marker.line.color': isDark ? "#1e293b" : "#ffffff" });
            Plotly.relayout("threatDistributionChart", { 'annotations[0].font.color': isDark ? "#f8fafc" : "#1e293b" });
            Plotly.relayout("scoreTrendChart", updateLayout);
        } catch (e) {
            console.error("Error updating chart themes:", e);
        }
    });
}

// =============================
// DROPDOWN LOGIC
// =============================
function handleTrendSelectChange(selectId, chartId, isScore = false) {
    const select = document.getElementById(selectId);
    if (!select) return;
    select.addEventListener("change", (e) => {
        const val = e.target.value;
        if (val === "custom") {
            alert("Custom date range picker will be implemented in a future update.");
            return;
        }

        const days = parseInt(val);
        let x = [];
        let y = [];
        const today = new Date();

        if (days === 1) {
            // Generate 24-hour data
            for (let i = 23; i >= 0; i--) {
                let d = new Date(today);
                d.setHours(d.getHours() - i);
                x.push(d.toLocaleTimeString('en-US', { hour: 'numeric', hour12: true }));
                y.push(isScore ? Math.floor(Math.random() * 25) + 70 : Math.floor(Math.random() * 45) + 5);
            }
        } else {
            // Generate daily data
            for (let i = days - 1; i >= 0; i--) {
                let d = new Date(today);
                d.setDate(d.getDate() - i);
                x.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
                y.push(isScore ? Math.floor(Math.random() * 25) + 70 : Math.floor(Math.random() * 45) + 5);
            }
        }
        
        Plotly.update(chartId, { x: [x], y: [y] });
    });
}

handleTrendSelectChange("threatTrendSelect", "threatTrendChart", false);
handleTrendSelectChange("scoreTrendSelect", "scoreTrendChart", true);
