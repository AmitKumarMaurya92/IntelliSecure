// =============================
// FETCH DATA FROM BACKEND API
// =============================

// Ensure headers carry auth tokens if necessary (currently auth is optional/mocked depending on setup)
const apiHeaders = { "Content-Type": "application/json" };

async function loadDashboardStats() {
    try {
        const response = await fetch('/api/dashboard/stats', { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();

        document.getElementById("totalLogs").innerText = data.total_logs.toLocaleString();
        document.getElementById("activeThreats").innerText = data.active_threats.toLocaleString();
        document.getElementById("criticalAlerts").innerText = data.critical_alerts.toLocaleString();
        document.getElementById("securityScore").innerText = data.security_score.score;
        
        // Update security score color based on risk level
        const scoreEl = document.getElementById("securityScore");
        if (data.security_score.score < 50) scoreEl.style.color = "#ef4444";
        else if (data.security_score.score < 80) scoreEl.style.color = "#f59e0b";
        else scoreEl.style.color = "#10b981";
        
    } catch (err) {
        console.error("Failed to load dashboard stats:", err);
    }
}

async function loadAlerts() {
    try {
        const response = await fetch('/api/threats/active', { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const alerts = await response.json();
        renderAlerts(alerts);
    } catch (err) {
        console.error("Failed to load alerts:", err);
    }
}

function renderAlerts(alerts) {
    const alertsList = document.getElementById("alertsList");
    alertsList.innerHTML = ""; 

    if (alerts.length === 0) {
        alertsList.innerHTML = "<p style='color:#94a3b8; font-size:14px;'>No active threats detected.</p>";
        return;
    }

    alerts.slice(0, 8).forEach(alert => {
        let severityClass = "";
        let iconClass = "fa-triangle-exclamation";
        
        if (alert.severity === "Critical") { severityClass = "High"; iconClass = "fa-shield-virus"; }
        else if (alert.severity === "High") { severityClass = "High"; iconClass = "fa-bug"; }
        else if (alert.severity === "Medium") { severityClass = "Medium"; iconClass = "fa-satellite-dish"; }
        else { severityClass = "Low"; iconClass = "fa-circle-info"; }

        // Format datetime nicely
        const dateObj = new Date(alert.timestamp);
        const timeStr = dateObj.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

        alertsList.innerHTML += `
            <div class="alert-item">
                <div class="alert-left">
                    <div class="alert-icon ${severityClass}"><i class="fa-solid ${iconClass}"></i></div>
                    <div class="alert-info">
                        <h5>${alert.threat_type}</h5>
                        <p>${alert.source} • ID: ${alert.id}</p>
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
async function loadAttackSources() {
    try {
        const response = await fetch('/api/dashboard/top-sources', { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const sources = await response.json();
        
        const listEl = document.getElementById("attackSourcesList");
        listEl.innerHTML = "";
        
        if (sources.length === 0) {
            listEl.innerHTML = "<p style='color:#94a3b8; font-size:14px;'>No sources detected.</p>";
            return;
        }

        const maxCount = Math.max(...sources.map(s => s.count)) || 1;
        const colors = ["#ef4444", "#f59e0b", "#8b5cf6", "#2563eb", "#06b6d4"];
        
        sources.forEach((src, idx) => {
            let widthPct = (src.count / maxCount) * 100;
            let color = colors[idx % colors.length];
            listEl.innerHTML += `
                <div class="source-item">
                    <div class="source-ip">${src.source}</div>
                    <div class="source-bar-container">
                        <div class="source-bar" style="width: ${widthPct}%; background: ${color}"></div>
                    </div>
                    <div class="source-count">${src.count}</div>
                </div>
            `;
        });
    } catch (err) {
        console.error("Failed to load top sources:", err);
    }
}

// =============================
// THREAT TREND CHART
// =============================
async function loadThreatTrend(days = 7) {
    try {
        const response = await fetch(`/api/dashboard/threat-trend?days=${days}`, { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();

        Plotly.newPlot("threatTrendChart", [{
            x: data.dates,
            y: data.counts,
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

    } catch (err) {
        console.error("Failed to load threat trend:", err);
    }
}

// =============================
// THREAT DISTRIBUTION (Donut)
// =============================
async function loadThreatDistribution() {
    try {
        const response = await fetch('/api/dashboard/threat-distribution', { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();

        const threatColors = ["#ef4444", "#f59e0b", "#8b5cf6", "#2563eb", "#94a3b8", "#10b981", "#ec4899"];
        
        let total = data.values.reduce((a,b) => a+b, 0);
        let annotationsText = total > 0 ? `${total}<br><span style='font-size:11px;color:#64748b;font-weight:500'>Total</span>` : "0";

        Plotly.newPlot("threatDistributionChart", [{
            values: data.values,
            labels: data.labels,
            type: "pie",
            hole: .65,
            marker: {
                colors: threatColors.slice(0, data.labels.length),
                line: { color: "#ffffff", width: 2 }
            },
            textinfo: "none",
            hoverinfo: "label+value"
        }], {
            margin: { t: 0, b: 0, l: 0, r: 0 },
            showlegend: false,
            paper_bgcolor: "transparent",
            plot_bgcolor: "transparent",
            annotations: [{
                font: { size: 20, weight: 700, color: "#1e293b" },
                showarrow: false,
                text: annotationsText,
                x: 0.5,
                y: 0.5
            }]
        }, {displayModeBar: false, responsive: true});

        // Render custom legend
        const legendContainer = document.getElementById("threatLegend");
        if(legendContainer) {
            legendContainer.innerHTML = "";
            data.labels.forEach((label, i) => {
                let pct = total > 0 ? Math.round((data.values[i]/total)*100) : 0;
                legendContainer.innerHTML += `
                    <div class="legend-item">
                        <div class="legend-left">
                            <span class="legend-dot" style="background: ${threatColors[i % threatColors.length]}"></span>
                            <span>${label}</span>
                        </div>
                        <span class="legend-pct">${pct}%</span>
                    </div>
                `;
            });
        }
    } catch (err) {
        console.error("Failed to load threat distribution:", err);
    }
}

// =============================
// INITIALIZE
// =============================
function initDashboard() {
    loadDashboardStats();
    loadAlerts();
    loadAttackSources();
    loadThreatTrend(7);
    loadThreatDistribution();
    
    // Draw placeholder for score trend as we don't have historical score endpoint
    Plotly.newPlot("scoreTrendChart", [{
        x: ["Today"],
        y: [100],
        type: "scatter",
        mode: "lines+markers",
        line: { color: "#10b981", width: 2 },
        marker: { size: 6, color: "#10b981" }
    }], {
        margin: { t: 20, l: 30, r: 10, b: 30 },
        xaxis: { showgrid: false, zeroline: false },
        yaxis: { showgrid: true, gridcolor: "#f1f5f9", zeroline: false, range: [0, 100] }
    }, {displayModeBar: false});
}

initDashboard();

// =============================
// REAL-TIME CLOCK & REFRESH
// =============================
setInterval(() => {
    loadDashboardStats();
    loadAlerts();
    loadAttackSources();
}, 30000); // 30 sec polling

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
        
        const themeIcon = document.getElementById("theme-icon");
        if (themeIcon) {
            themeIcon.className = isDark ? "fa-regular fa-moon" : "fa-regular fa-sun";
        }
        
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
        } catch (e) {}
    });
}

// =============================
// DROPDOWN LOGIC
// =============================
const trendSelect = document.getElementById("trendRangeSelect");
if (trendSelect) {
    trendSelect.addEventListener("change", (e) => {
        const val = e.target.value;
        if (val === "custom") {
            alert("Custom date range picker will be implemented in a future update.");
            return;
        }
        loadThreatTrend(parseInt(val));
    });
}
