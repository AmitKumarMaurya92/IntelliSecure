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
        document.getElementById("securityScore").innerText = data.security_score + "/100";
    } catch (err) {
        console.error("Failed to load dashboard stats:", err);
        // Fallback placeholder data if API fails
        document.getElementById("totalLogs").innerText = (24532).toLocaleString();
        document.getElementById("activeThreats").innerText = "28";
        document.getElementById("criticalAlerts").innerText = "7";
        document.getElementById("securityScore").innerText = "87/100";
    }
}

async function loadAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const alerts = await response.json();
        
        const alertsTable = document.getElementById("alertsTable");
        alertsTable.innerHTML = ""; // Clear table

        alerts.forEach(alert => {
            let severityClass = "";
            if (alert.severity === "High" || alert.severity === "Critical") severityClass = "high";
            else if (alert.severity === "Medium") severityClass = "medium";
            else severityClass = "low";

            // Fallback for missing time attribute from API
            let timeStr = alert.time || new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

            alertsTable.innerHTML += `
                <tr>
                    <td>${alert.threat}</td>
                    <td><span class="${severityClass}">${alert.severity}</span></td>
                    <td>${timeStr}</td>
                </tr>
            `;
        });
    } catch (err) {
        console.error("Failed to load alerts:", err);
    }
}

// =============================
// THREAT TREND CHART
// =============================
Plotly.newPlot("threatTrendChart", [
    {
        x: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        y: [5, 8, 12, 18, 10, 14, 20],
        type: "scatter",
        mode: "lines+markers",
        line: { width: 3 }
    }
], {
    margin: { t: 10 },
    paper_bgcolor: "white",
    plot_bgcolor: "white"
});

// =============================
// THREAT DISTRIBUTION
// =============================
Plotly.newPlot("threatDistributionChart", [
    {
        values: [40, 25, 15, 10, 10],
        labels: ["Brute Force", "Port Scan", "Unauthorized Access", "Malware", "Other"],
        type: "pie",
        hole: .55
    }
], {
    margin: { t: 10 }
});

// =============================
// SECURITY SCORE TREND
// =============================
Plotly.newPlot("scoreTrendChart", [
    {
        x: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
        y: [60, 65, 72, 78, 84, 87],
        type: "scatter",
        mode: "lines+markers"
    }
], {
    margin: { t: 10 }
});

// =============================
// ATTACK SOURCES
// =============================
Plotly.newPlot("attackSourcesChart", [
    {
        x: ["192.168.1.10", "192.168.1.15", "192.168.1.22", "192.168.1.30"],
        y: [20, 15, 10, 8],
        type: "bar"
    }
], {
    margin: { t: 10 }
});

// =============================
// INITIALIZE
// =============================
loadDashboardStats();
loadAlerts();

// =============================
// REAL-TIME CLOCK
// =============================
setInterval(() => {
    console.log("Monitoring Logs...");
    // Optionally auto-refresh stats
    // loadDashboardStats();
    // loadAlerts();
}, 5000);
