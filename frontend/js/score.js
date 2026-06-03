// =============================
// SECURITY SCORE MODULE
// =============================
let scoreDoughnutChart = null;
let scoreLineChart = null;

const apiHeadersScore = { "Content-Type": "application/json" };
const tokenScore = localStorage.getItem("access_token");
if (tokenScore) {
    apiHeadersScore["Authorization"] = `Bearer ${tokenScore}`;
}

const isDarkModeScore = document.body.classList.contains('dark-theme');
const chartTextColor = isDarkModeScore ? '#cbd5e1' : '#475569';
const chartGridColor = isDarkModeScore ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)';

async function fetchSecurityScore() {
    try {
        const response = await fetch('/api/security-score/', { headers: apiHeadersScore });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();
        
        renderDoughnutChart(data.score, data.risk_color);
        renderBreakdown(data.breakdown);
        renderRecommendations(data.risk_level, data.breakdown);
        
        document.getElementById('score-center-value').innerText = data.score;
        document.getElementById('score-center-value').style.color = data.risk_color;
        document.getElementById('score-risk-label').innerText = `Risk Level: ${data.risk_level}`;
        document.getElementById('score-risk-label').style.color = data.risk_color;
        
        if(data.trend) {
            renderLineChart(data.trend, data.risk_color);
        }
        
    } catch (err) {
        console.error("Failed to load security score:", err);
        document.getElementById('score-risk-label').innerText = "Error loading data";
    }
}

function renderDoughnutChart(score, color) {
    const ctx = document.getElementById('score-doughnut-chart').getContext('2d');
    
    if (scoreDoughnutChart) {
        scoreDoughnutChart.destroy();
    }
    
    scoreDoughnutChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [
                    color,
                    isDarkModeScore ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)'
                ],
                borderWidth: 0,
                cutout: '80%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                animateScale: true,
                animateRotate: true
            },
            plugins: { tooltip: { enabled: false } }
        }
    });
}

function renderLineChart(trendData, color) {
    const ctx = document.getElementById('score-line-chart').getContext('2d');
    
    if (scoreLineChart) {
        scoreLineChart.destroy();
    }
    
    const labels = trendData.map(d => d.date);
    const scores = trendData.map(d => d.score);
    
    scoreLineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Security Score',
                data: scores,
                borderColor: color,
                backgroundColor: color + '33', // 20% opacity
                borderWidth: 2,
                pointBackgroundColor: color,
                pointBorderColor: '#fff',
                pointRadius: 4,
                pointHoverRadius: 6,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: { color: chartGridColor, drawBorder: false },
                    ticks: { color: chartTextColor }
                },
                x: {
                    grid: { display: false, drawBorder: false },
                    ticks: { color: chartTextColor }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: isDarkModeScore ? '#1e293b' : '#fff',
                    titleColor: isDarkModeScore ? '#fff' : '#0f172a',
                    bodyColor: isDarkModeScore ? '#cbd5e1' : '#475569',
                    borderColor: chartGridColor,
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false
                }
            }
        }
    });
}

function renderBreakdown(breakdown) {
    const list = document.getElementById('score-breakdown-list');
    list.innerHTML = '';
    
    const labels = {
        'failed_logins': 'Failed Logins',
        'malware_detected': 'Malware Detected',
        'port_scan_sources': 'Port Scans',
        'unauthorized_accesses': 'Unauthorized File Access',
        'active_critical_alerts': 'Active Critical Alerts'
    };
    
    for (const [key, data] of Object.entries(breakdown)) {
        const title = labels[key] || key;
        const widthPercent = (data.penalty / data.max_penalty) * 100;
        const color = widthPercent > 0 ? 'var(--red)' : 'var(--green)';
        
        list.innerHTML += `
            <div class="penalty-item">
                <div class="penalty-header">
                    <span>${title} (${data.value} events)</span>
                    <span style="color: ${color};">-${data.penalty} pts</span>
                </div>
                <div class="penalty-bar-bg">
                    <div class="penalty-bar-fill" style="width: ${widthPercent}%; background: ${color};"></div>
                </div>
            </div>
        `;
    }
}

function renderRecommendations(riskLevel, breakdown) {
    const ul = document.getElementById('score-recommendations-list');
    ul.innerHTML = '';
    
    let recs = [];
    
    if (breakdown.failed_logins.penalty > 10) {
        recs.push("High number of failed logins. Consider enforcing stricter lockout policies or reviewing active brute force alerts.");
    }
    if (breakdown.malware_detected.penalty > 0) {
        recs.push("Malware infections detected recently. Ensure endpoint quarantine processes are fully active.");
    }
    if (breakdown.active_critical_alerts.penalty > 0) {
        recs.push(`You have ${breakdown.active_critical_alerts.value} unresolved Critical alerts. Resolve them immediately to restore score.`);
    }
    
    if (recs.length === 0) {
        if (riskLevel === "Low") {
            recs.push("Your network posture is excellent. Continue monitoring for anomalies.");
        } else {
            recs.push("Review recent logs for suspicious activity to improve score.");
        }
    }
    
    ul.innerHTML = recs.map(r => `<li><i class="fa-solid fa-circle-check"></i> ${r}</li>`).join('');
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("refresh-score-btn")?.addEventListener("click", () => {
        fetchSecurityScore();
    });
    
    // Initial fetch if on score tab
    // We can just fetch it right away
    fetchSecurityScore();
});
