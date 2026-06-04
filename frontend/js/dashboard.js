// =============================
// FETCH DATA FROM BACKEND API
// =============================

// Ensure headers carry auth tokens if necessary (currently auth is optional/mocked depending on setup)
const apiHeaders = { "Content-Type": "application/json" };
const token = localStorage.getItem("access_token");
if (token) {
    apiHeaders["Authorization"] = `Bearer ${token}`;
} else {
    window.location.href = "/login";
}

// Global fetch interceptor to handle session timeouts (401 Unauthorized)
const originalFetch = window.fetch;
window.fetch = async function() {
    const response = await originalFetch.apply(this, arguments);
    if (response.status === 401) {
        console.warn("Session expired. Redirecting to login...");
        localStorage.removeItem("access_token");
        window.location.href = "/login";
    }
    return response;
};

// =============================
// DATE FILTER UTILS
// =============================
function appendDateQuery(url) {
    const dateInput = document.getElementById("topbar-date-input");
    if (dateInput && dateInput.value) {
        // Only append date query if it's explicitly set by user, otherwise fallback to default (today or all-time)
        return url.includes('?') ? `${url}&date=${dateInput.value}` : `${url}?date=${dateInput.value}`;
    }
    return url;
}

async function loadDashboardStats() {
    try {
        const response = await fetch(appendDateQuery('/api/dashboard/stats'), { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();

        document.getElementById("totalLogs").innerText = data.total_logs.toLocaleString();
        document.getElementById("activeThreats").innerText = data.active_threats.toLocaleString();
        document.getElementById("criticalAlerts").innerText = data.critical_alerts.toLocaleString();
        document.getElementById("securityScore").innerText = data.security_score;

        // Update security score color based on risk level
        const scoreEl = document.getElementById("securityScore");
        if (data.security_score < 50) scoreEl.style.color = "#ef4444";
        else if (data.security_score < 80) scoreEl.style.color = "#f59e0b";
        else scoreEl.style.color = "#10b981";

        // Update topbar notification badge
        const notifBadge = document.getElementById("topbar-notification-badge");
        if (notifBadge) {
            if (data.active_threats > 0) {
                notifBadge.innerText = data.active_threats;
                notifBadge.style.display = "inline-flex";
            } else {
                notifBadge.style.display = "none";
            }
        }

        // Update System Status in sidebar
        const sysStatusContainer = document.getElementById("sidebar-system-status");
        const sysStatusIcon = document.getElementById("sidebar-status-icon");
        const sysStatusMain = document.getElementById("sidebar-status-main");
        const sysStatusSub = document.getElementById("sidebar-status-sub");

        if (sysStatusContainer && sysStatusIcon && sysStatusMain && sysStatusSub) {
            let bgColor, borderColor, iconColor, mainColor, iconClass, mainText, subText;
            
            if (data.security_score < 50 || data.risk_level === 'Critical') {
                bgColor = "var(--light-red)";
                borderColor = "rgba(239, 68, 68, 0.3)";
                iconColor = "var(--red)";
                mainColor = "var(--red)";
                iconClass = "fa-shield-virus";
                mainText = "At Risk";
                subText = "Critical threats detected";
            } else if (data.security_score < 80 || data.risk_level === 'High' || data.risk_level === 'Medium') {
                bgColor = "var(--light-yellow)";
                borderColor = "rgba(245, 158, 11, 0.3)";
                iconColor = "var(--yellow)";
                mainColor = "var(--yellow)";
                iconClass = "fa-triangle-exclamation";
                mainText = "Warning";
                subText = "Review active alerts";
            } else {
                bgColor = "var(--light-green)";
                borderColor = "rgba(16, 185, 129, 0.3)";
                iconColor = "var(--green)";
                mainColor = "var(--green)";
                iconClass = "fa-shield";
                mainText = "Protected";
                subText = "All systems are secure";
            }

            sysStatusContainer.style.background = bgColor;
            sysStatusContainer.style.borderColor = borderColor;
            sysStatusIcon.className = `fa-solid ${iconClass} check-icon`;
            sysStatusIcon.style.color = iconColor;
            sysStatusMain.style.color = mainColor;
            sysStatusMain.innerText = mainText;
            sysStatusSub.innerText = subText;
        }

    } catch (err) {
        console.error("Failed to load dashboard stats:", err);
    }
}

async function loadAlerts() {
    try {
        const response = await fetch(appendDateQuery('/api/threats/active'), { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();
        renderAlerts(data.alerts || []);
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
        const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

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
        const response = await fetch(appendDateQuery('/api/dashboard/top-sources'), { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();
        const sources = data.sources || [];

        const listEl = document.getElementById("attackSourcesList");
        listEl.innerHTML = "";

        if (sources.length === 0) {
            listEl.innerHTML = "<p style='color:#94a3b8; font-size:14px;'>No sources detected.</p>";
            return;
        }

        const maxCount = Math.max(...sources.map(s => s.alert_count)) || 1;
        const colors = ["#ef4444", "#f59e0b", "#8b5cf6", "#2563eb", "#06b6d4"];

        sources.forEach((src, idx) => {
            let widthPct = (src.alert_count / maxCount) * 100;
            let color = colors[idx % colors.length];
            listEl.innerHTML += `
                <div class="source-item">
                    <div class="source-ip">${src.source}</div>
                    <div class="source-bar-container">
                        <div class="source-bar" style="width: ${widthPct}%; background: ${color}"></div>
                    </div>
                    <div class="source-count">${src.alert_count}</div>
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
        const response = await fetch(appendDateQuery(`/api/dashboard/threat-trend?days=${days}`), { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();

        const trend = data.trend || [];
        const xDates = trend.map(item => item.date);
        const yCounts = trend.map(item => item.count);

        Plotly.newPlot("threatTrendChart", [{
            x: xDates,
            y: yCounts,
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
            autosize: true,
            xaxis: { showgrid: false, zeroline: false },
            yaxis: { showgrid: true, gridcolor: "#f1f5f9", zeroline: false }
        }, { displayModeBar: false, responsive: true });

    } catch (err) {
        console.error("Failed to load threat trend:", err);
    }
}

// =============================
// THREAT DISTRIBUTION (Donut)
// =============================
async function loadThreatDistribution() {
    try {
        const response = await fetch(appendDateQuery('/api/dashboard/threat-distribution'), { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();

        const dist = data.distribution || [];
        const values = dist.map(item => item.count);
        const labels = dist.map(item => item.threat_type);
        const apiColors = dist.map(item => item.color);

        const threatColors = ["#ef4444", "#f59e0b", "#8b5cf6", "#2563eb", "#94a3b8", "#10b981", "#ec4899"];

        let total = values.reduce((a, b) => a + b, 0);
        let annotationsText = total > 0 ? `${total}<br><span style='font-size:11px;color:#64748b;font-weight:500'>Total</span>` : "0";

        Plotly.newPlot("threatDistributionChart", [{
            values: values,
            labels: labels,
            type: "pie",
            hole: .65,
            marker: {
                colors: apiColors.length > 0 ? apiColors : threatColors.slice(0, labels.length),
                line: { color: "#ffffff", width: 2 }
            },
            textinfo: "none",
            hoverinfo: "label+value"
        }], {
            margin: { t: 0, b: 0, l: 0, r: 0 },
            showlegend: false,
            paper_bgcolor: "transparent",
            plot_bgcolor: "transparent",
            autosize: true,
            annotations: [{
                font: { size: 20, weight: 700, color: "#1e293b" },
                showarrow: false,
                text: annotationsText,
                x: 0.5,
                y: 0.5
            }]
        }, { displayModeBar: false, responsive: true });

        // Render custom legend
        const legendContainer = document.getElementById("threatLegend");
        if (legendContainer) {
            legendContainer.innerHTML = "";
            labels.forEach((label, i) => {
                let pct = total > 0 ? Math.round((values[i] / total) * 100) : 0;
                let color = apiColors[i] || threatColors[i % threatColors.length];
                legendContainer.innerHTML += `
                    <div class="legend-item">
                        <div class="legend-left">
                            <span class="legend-dot" style="background: ${color}"></span>
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
    setupTopbar();
    loadDashboardStats();
    loadAlerts();
    loadAttackSources();
    loadThreatTrend(7);
    loadThreatDistribution();

    loadScoreTrend();
}

function setupTopbar() {
    // 1. Set current date
    const dateEl = document.getElementById("current-date-text");
    const dateInput = document.getElementById("topbar-date-input");
    const datePickerDiv = document.getElementById("topbar-date");
    
    if (dateEl) {
        const options = { year: 'numeric', month: 'short', day: 'numeric' };
        const today = new Date();
        dateEl.innerText = today.toLocaleDateString('en-US', options);
        
        if (dateInput) {
            // Set the default input value to today for the native picker (YYYY-MM-DD format)
            const yyyy = today.getFullYear();
            const mm = String(today.getMonth() + 1).padStart(2, '0');
            const dd = String(today.getDate()).padStart(2, '0');
            dateInput.value = `${yyyy}-${mm}-${dd}`;
            
            // Make the whole button clickable to open the native calendar
            if (datePickerDiv) {
                datePickerDiv.addEventListener('click', () => {
                    try {
                        dateInput.showPicker();
                    } catch (e) {
                        dateInput.focus();
                    }
                });
            }
            
            // Listen for changes
            dateInput.addEventListener('change', (e) => {
                if (e.target.value) {
                    const selectedDate = new Date(e.target.value);
                    dateEl.innerText = selectedDate.toLocaleDateString('en-US', options);
                    
                    // Reload dashboard data with new date filter
                    loadDashboardStats();
                    loadAlerts();
                    loadAttackSources();
                    loadThreatTrend(7);
                    loadThreatDistribution();
                    loadScoreTrend();
                }
            });
        }
    }

    // 2. Setup notification click to open alerts
    const notifBtn = document.getElementById("topbar-notification-btn");
    if (notifBtn) {
        notifBtn.addEventListener("click", () => {
            const alertsMenuLink = document.querySelector('.sidebar .menu li[data-target="view-alerts"]');
            if (alertsMenuLink) {
                alertsMenuLink.click();
            }
        });
    }
}

async function loadScoreTrend() {
    try {
        const response = await fetch('/api/security-score/history', { headers: apiHeaders });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();

        if (!data || !data.trend || data.trend.length === 0) return;

        const xValues = data.trend.map(t => t.date);
        const yValues = data.trend.map(t => t.score);
        const lineColor = data.risk_color || "#10b981";

        Plotly.newPlot("scoreTrendChart", [{
            x: xValues,
            y: yValues,
            type: "scatter",
            mode: "lines+markers",
            line: { color: lineColor, width: 3, shape: "spline" },
            marker: { size: 8, color: lineColor, line: { color: "#ffffff", width: 2 } },
            fill: "tozeroy",
            fillcolor: lineColor + "20"
        }], {
            margin: { t: 20, l: 30, r: 20, b: 30 },
            autosize: true,
            xaxis: { showgrid: false, zeroline: false },
            yaxis: { showgrid: true, gridcolor: "#f1f5f9", zeroline: false, range: [0, 100] },
            hovermode: "closest"
        }, { displayModeBar: false, responsive: true });
    } catch (err) {
        console.error("Failed to load score trend:", err);
    }
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
    // Sync avatar initial and welcome message with name on page load
    const topbarName = document.getElementById("topbar-name");
    const topbarAvatar = document.getElementById("topbar-avatar");
    const topbarWelcome = document.getElementById("topbar-welcome");
    
    if (topbarName) {
        const currentName = topbarName.textContent.trim();
        if (topbarAvatar) topbarAvatar.textContent = currentName.charAt(0).toUpperCase();
        if (topbarWelcome) topbarWelcome.innerHTML = `Welcome back, ${currentName} 👋`;
    }

    // =============================
    // MOBILE SIDEBAR TOGGLE
    // =============================
    const sidebar = document.querySelector(".sidebar");
    const sidebarOverlay = document.getElementById("sidebarOverlay");
    const menuToggle = document.querySelector(".menu-toggle");

    function openMobileSidebar() {
        if (sidebar) sidebar.classList.add("mobile-open");
        if (sidebarOverlay) sidebarOverlay.classList.add("active");
        document.body.style.overflow = "hidden";
    }

    function closeMobileSidebar() {
        if (sidebar) sidebar.classList.remove("mobile-open");
        if (sidebarOverlay) sidebarOverlay.classList.remove("active");
        document.body.style.overflow = "";
    }

    if (menuToggle) {
        menuToggle.addEventListener("click", () => {
            if (sidebar && sidebar.classList.contains("mobile-open")) {
                closeMobileSidebar();
            } else {
                openMobileSidebar();
            }
        });
    }

    if (sidebarOverlay) {
        sidebarOverlay.addEventListener("click", closeMobileSidebar);
    }

    // Close sidebar on window resize above mobile breakpoint
    window.addEventListener("resize", () => {
        if (window.innerWidth > 768) {
            closeMobileSidebar();
        }
        // Trigger Plotly chart resize for all visible Plotly charts
        triggerPlotlyResize();
    });

    function triggerPlotlyResize() {
        const plotlyCharts = document.querySelectorAll(".js-plotly-plot");
        plotlyCharts.forEach(chart => {
            try { Plotly.Plots.resize(chart); } catch(e) {}
        });
    }

    // =============================
    // SPA NAVIGATION LOGIC
    // =============================
    const menuItems = document.querySelectorAll(".sidebar .menu li");
    const viewSections = document.querySelectorAll(".view-section");
    const topbarTitle = document.querySelector(".topbar-left h1");

    // Map targets to display titles
    const titleMap = {
        "view-dashboard": "Dashboard",
        "view-real-time": "Real-Time Monitor",
        "view-threats": "Threats",
        "view-alerts": "Alerts",
        "view-logs": "Logs",
        "view-devices": "Devices (LAN)",
        "view-security-score": "Security Score",
        "view-attack-trends": "Attack Trends",
        "view-risk-analysis": "Risk Analysis",
        "view-reports": "Reports",
        "view-export-reports": "Export Reports",
        "view-settings": "Settings",
        "view-users": "Users",
        "view-help": "Help & Learn"
    };

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

            // Update topbar title
            if (topbarTitle && titleMap[targetId]) {
                topbarTitle.textContent = titleMap[targetId];
            }

            // Close mobile sidebar after navigation
            if (window.innerWidth <= 768) {
                closeMobileSidebar();
            }

            // Lazy-init the real-time monitor view on first activation
            if (targetId === "view-real-time" && typeof window.initRealtimeMonitorView === "function") {
                window.initRealtimeMonitorView();
            }

            // Resize charts after view switch (needed for Plotly/Chart.js)
            setTimeout(() => {
                triggerPlotlyResize();
                // Also trigger Chart.js resize for canvases
                const canvases = targetView ? targetView.querySelectorAll("canvas") : [];
                canvases.forEach(c => {
                    const chartInstance = Chart.getChart(c);
                    if (chartInstance) chartInstance.resize();
                });
            }, 100);
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
            'legend.font.color': fontColor
        };

        try {
            Plotly.relayout("threatTrendChart", updateLayout);
            Plotly.restyle("threatDistributionChart", { 'marker.line.color': isDark ? "#1e293b" : "#ffffff" });
            Plotly.relayout("threatDistributionChart", { 'annotations[0].font.color': isDark ? "#f8fafc" : "#1e293b" });
            Plotly.relayout("scoreTrendChart", updateLayout);
        } catch (e) { }
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

// =============================
// PROFILE DROPDOWN LOGIC
// =============================
const profileToggle = document.getElementById("profile-menu-toggle");
const profileDropdown = document.getElementById("profile-dropdown");
const profileChevron = document.getElementById("profile-chevron");

if (profileToggle && profileDropdown) {
    profileToggle.addEventListener("click", (e) => {
        e.stopPropagation();
        const isVisible = profileDropdown.style.display === "block";
        profileDropdown.style.display = isVisible ? "none" : "block";
        if (profileChevron) {
            profileChevron.style.transform = isVisible ? "rotate(0deg)" : "rotate(180deg)";
        }
    });

    document.addEventListener("click", (e) => {
        if (!profileToggle.contains(e.target)) {
            profileDropdown.style.display = "none";
            if (profileChevron) {
                profileChevron.style.transform = "rotate(0deg)";
            }
        }
    });

    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", (e) => {
            localStorage.removeItem("access_token");
        });
    }
}
