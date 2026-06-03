// =============================
// RISK ANALYSIS MODULE
// =============================
let riskBarChart = null;

const apiHeadersRisk = { "Content-Type": "application/json" };
const tokenRisk = localStorage.getItem("access_token");
if (tokenRisk) {
    apiHeadersRisk["Authorization"] = `Bearer ${tokenRisk}`;
}

const isDarkModeRisk = document.body.classList.contains('dark-theme');
const chartTextColorRisk = isDarkModeRisk ? '#cbd5e1' : '#475569';
const chartGridColorRisk = isDarkModeRisk ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)';

async function fetchRiskData() {
    try {
        const response = await fetch('/api/risk/entities?limit=10', { headers: apiHeadersRisk });
        if (!response.ok) throw new Error("API Error fetching risk data");
        
        const data = await response.json();
        const entities = data.entities || [];
        
        renderRiskBarChart(entities);
        renderRiskTable(entities);

    } catch (err) {
        console.error("Failed to load risk analysis data:", err);
        document.getElementById('risk-table-body').innerHTML = `
            <tr><td colspan="4" style="text-align:center; padding:20px; color:var(--red);">Failed to load risk data.</td></tr>
        `;
    }
}

function renderRiskBarChart(entities) {
    const ctx = document.getElementById('risk-bar-chart').getContext('2d');
    
    if (riskBarChart) {
        riskBarChart.destroy();
    }
    
    // Use only top 10 for the chart
    const topEntities = entities.slice(0, 10);
    const labels = topEntities.map(e => e.entity);
    const scores = topEntities.map(e => e.score);
    const bgColors = topEntities.map(e => e.color);
    
    riskBarChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Risk Score',
                data: scores,
                backgroundColor: bgColors,
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: { color: chartGridColorRisk, drawBorder: false },
                    ticks: { color: chartTextColorRisk }
                },
                x: {
                    grid: { display: false, drawBorder: false },
                    ticks: { color: chartTextColorRisk, maxRotation: 45, minRotation: 0 }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: isDarkModeRisk ? '#1e293b' : '#fff',
                    titleColor: isDarkModeRisk ? '#fff' : '#0f172a',
                    bodyColor: isDarkModeRisk ? '#cbd5e1' : '#475569',
                    borderColor: chartGridColorRisk,
                    borderWidth: 1,
                    padding: 10
                }
            }
        }
    });
}

function renderRiskTable(entities) {
    const tbody = document.getElementById('risk-table-body');
    tbody.innerHTML = '';
    
    if (entities.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:20px;">No high-risk entities found.</td></tr>`;
        return;
    }
    
    entities.forEach(e => {
        // Construct factors HTML list
        const factorsHtml = e.factors.map(f => `<span class="risk-factor-pill">${f}</span>`).join('');
        
        tbody.innerHTML += `
            <tr>
                <td style="font-weight:600;">${e.entity}</td>
                <td><span class="status-badge" style="background:${e.color}20; color:${e.color}; border: 1px solid ${e.color}50;">${e.level}</span></td>
                <td style="font-size:18px; font-weight:700; color:${e.color};">${e.score}</td>
                <td>
                    <div style="display:flex; flex-wrap:wrap; gap:6px;">
                        ${factorsHtml}
                    </div>
                </td>
            </tr>
        `;
    });
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("refresh-risk-btn")?.addEventListener("click", () => {
        fetchRiskData();
    });
    
    fetchRiskData();
});
