// =============================
// ATTACK TRENDS MODULE
// =============================
let trendsTimelineChart = null;
let trendsDistributionChart = null;

const apiHeadersTrends = { "Content-Type": "application/json" };
const tokenTrends = localStorage.getItem("access_token");
if (tokenTrends) {
    apiHeadersTrends["Authorization"] = `Bearer ${tokenTrends}`;
}

const isDarkModeTrends = document.body.classList.contains('dark-theme');
const chartTextColorTrends = isDarkModeTrends ? '#cbd5e1' : '#475569';
const chartGridColorTrends = isDarkModeTrends ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)';

async function fetchTrendsData() {
    try {
        const [trendRes, distRes, topRes] = await Promise.all([
            fetch('/api/dashboard/threat-trend', { headers: apiHeadersTrends }),
            fetch('/api/dashboard/threat-distribution', { headers: apiHeadersTrends }),
            fetch('/api/dashboard/top-sources', { headers: apiHeadersTrends })
        ]);

        if (!trendRes.ok || !distRes.ok || !topRes.ok) {
            throw new Error("API Error while fetching trends");
        }

        const trendData = await trendRes.json();
        const distData = await distRes.json();
        const topData = await topRes.json();

        renderTrendsTimeline(trendData.trend);
        renderTrendsDistribution(distData.distribution, distData.total_active);
        renderTopSources(topData.sources);

    } catch (err) {
        console.error("Failed to load attack trends data:", err);
    }
}

function renderTrendsTimeline(trendArray) {
    const ctx = document.getElementById('trends-timeline-chart').getContext('2d');
    
    if (trendsTimelineChart) {
        trendsTimelineChart.destroy();
    }
    
    const labels = trendArray.map(d => d.date);
    const counts = trendArray.map(d => d.count);
    
    // Create gradient
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(239, 68, 68, 0.5)'); // red with opacity
    gradient.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

    trendsTimelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threats Detected',
                data: counts,
                borderColor: '#ef4444', // Red
                backgroundColor: gradient,
                borderWidth: 2,
                pointBackgroundColor: '#ef4444',
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
                    grid: { color: chartGridColorTrends, drawBorder: false },
                    ticks: { color: chartTextColorTrends, stepSize: 1 }
                },
                x: {
                    grid: { display: false, drawBorder: false },
                    ticks: { color: chartTextColorTrends }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: isDarkModeTrends ? '#1e293b' : '#fff',
                    titleColor: isDarkModeTrends ? '#fff' : '#0f172a',
                    bodyColor: isDarkModeTrends ? '#cbd5e1' : '#475569',
                    borderColor: chartGridColorTrends,
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false
                }
            }
        }
    });
}

function renderTrendsDistribution(distribution, totalActive) {
    const ctx = document.getElementById('trends-distribution-chart').getContext('2d');
    
    if (trendsDistributionChart) {
        trendsDistributionChart.destroy();
    }


    const labels = distribution.map(d => d.threat_type);
    const data = distribution.map(d => d.count);
    const colors = distribution.map(d => d.color);

    trendsDistributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 0,
                cutout: '75%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                animateScale: true,
                animateRotate: true
            },
            plugins: { 
                legend: { 
                    position: 'right',
                    labels: { color: chartTextColorTrends, usePointStyle: true, boxWidth: 8 }
                },
                tooltip: {
                    backgroundColor: isDarkModeTrends ? '#1e293b' : '#fff',
                    titleColor: isDarkModeTrends ? '#fff' : '#0f172a',
                    bodyColor: isDarkModeTrends ? '#cbd5e1' : '#475569',
                    borderColor: chartGridColorTrends,
                    borderWidth: 1,
                    padding: 10
                }
            }
        },
        plugins: [{
            id: 'textCenter',
            beforeDraw: function(chart) {
                var width = chart.width,
                    height = chart.height,
                    ctx = chart.ctx;

                ctx.restore();
                ctx.font = "bold 32px Inter, sans-serif";
                ctx.textBaseline = "middle";
                ctx.fillStyle = chartTextColorTrends;

                var text = totalActive.toString(),
                    textX = Math.round(chart.chartArea.left + (chart.chartArea.right - chart.chartArea.left - ctx.measureText(text).width) / 2),
                    textY = Math.round(chart.chartArea.top + (chart.chartArea.bottom - chart.chartArea.top) / 2);

                ctx.fillText(text, textX, textY);
                ctx.save();
            }
        }]
    });
}

function renderTopSources(sources) {
    const list = document.getElementById('trends-top-sources');
    list.innerHTML = '';

    if (!sources || sources.length === 0) {
        list.innerHTML = `<p style="text-align:center; color:var(--text-muted); margin-top:30px;">No attack sources detected.</p>`;
        return;
    }

    list.innerHTML = sources.map((s, index) => {
        let badgeColor = index === 0 ? 'var(--red)' : (index === 1 ? 'var(--yellow)' : 'var(--primary-blue)');
        return `
            <li class="top-attacker-item">
                <div class="attacker-rank" style="background:${badgeColor};">${index + 1}</div>
                <div class="attacker-info">
                    <span class="attacker-ip">${s.source}</span>
                    <span class="attacker-count">${s.count} alerts</span>
                </div>
            </li>
        `;
    }).join('');
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("refresh-trends-btn")?.addEventListener("click", () => {
        fetchTrendsData();
    });
    
    fetchTrendsData();
});
