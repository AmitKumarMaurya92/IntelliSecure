// =============================
// THREATS MODULE
// =============================
let currentThreatsPage = 1;
const THREATS_PER_PAGE = 20;
let totalThreats = 0;
let currentXaiAlertId = null;

const apiHeadersThreats = { "Content-Type": "application/json" };
const tokenThreats = localStorage.getItem("access_token");
if (tokenThreats) {
    apiHeadersThreats["Authorization"] = `Bearer ${tokenThreats}`;
}

async function fetchThreatStats() {
    try {
        const response = await fetch('/api/threats/stats', { headers: apiHeadersThreats });
        if (!response.ok) return;
        const stats = await response.json();
        
        document.getElementById('stat-total').innerText = stats.total.toLocaleString();
        document.getElementById('stat-active').innerText = stats.active.toLocaleString();
        document.getElementById('stat-resolved').innerText = stats.resolved.toLocaleString();
        document.getElementById('stat-critical').innerText = stats.by_severity.Critical.toLocaleString();
    } catch (err) {
        console.error("Failed to load threat stats:", err);
    }
}

async function loadThreats(page = 1) {
    try {
        currentThreatsPage = page;
        const tbody = document.getElementById("threats-table-body");
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px;">Loading threats...</td></tr>`;

        const status = document.getElementById("threat-status-filter").value;
        const severity = document.getElementById("threat-severity-filter").value;
        
        const offset = (page - 1) * THREATS_PER_PAGE;
        let url = `/api/threats/?limit=${THREATS_PER_PAGE}&offset=${offset}`;
        
        if (status === "active") url += "&resolved=false";
        if (status === "resolved") url += "&resolved=true";
        if (severity !== "all") url += `&severity=${severity}`;

        const response = await fetch(url, { headers: apiHeadersThreats });
        if (!response.ok) throw new Error("API Error");
        const data = await response.json();

        totalThreats = data.total;
        
        if (data.alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px;">No threats found.</td></tr>`;
        } else {
            tbody.innerHTML = data.alerts.map(alert => {
                const date = new Date(alert.timestamp).toLocaleString();
                const statusBadge = alert.resolved 
                    ? `<span style="color:var(--green);font-weight:600;"><i class="fa-solid fa-check"></i> Resolved</span>`
                    : `<span style="color:var(--red);font-weight:600;"><i class="fa-solid fa-circle-exclamation"></i> Active</span>`;
                
                return `
                    <tr>
                        <td>${date}</td>
                        <td><strong>${alert.threat_type}</strong></td>
                        <td><span class="rtm-severity-badge ${alert.severity}">${alert.severity}</span></td>
                        <td>${alert.source}</td>
                        <td>${statusBadge}</td>
                        <td>
                            <button class="btn-outline" style="padding:4px 10px; font-size:12px;" onclick="openXaiModal(${alert.id})">
                                <i class="fa-solid fa-microchip"></i> Analyze
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        updatePagination();
        fetchThreatStats();
    } catch (err) {
        console.error("Failed to load threats:", err);
        document.getElementById("threats-table-body").innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--red);">Failed to load threats.</td></tr>`;
    }
}

function updatePagination() {
    const totalPages = Math.max(1, Math.ceil(totalThreats / THREATS_PER_PAGE));
    document.getElementById("threats-page-info").innerText = `Page ${currentThreatsPage} of ${totalPages}`;
    
    document.getElementById("threats-prev-btn").disabled = currentThreatsPage <= 1;
    document.getElementById("threats-next-btn").disabled = currentThreatsPage >= totalPages;
}

// XAI Modal Logic
async function openXaiModal(alertId) {
    currentXaiAlertId = alertId;
    const modal = document.getElementById("xai-modal");
    const modalBody = document.getElementById("xai-modal-body");
    const resolveBtn = document.getElementById("xai-resolve-btn");
    
    modal.style.display = "flex";
    resolveBtn.style.display = "none";
    
    modalBody.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x" style="color:var(--primary-blue);"></i><p style="margin-top:10px;">AI Analyzing Threat...</p></div>`;
    
    try {
        const [explainRes, recsRes] = await Promise.all([
            fetch(`/api/threats/${alertId}/explain`, { headers: apiHeadersThreats }),
            fetch(`/api/threats/${alertId}/recommendations`, { headers: apiHeadersThreats })
        ]);
        
        if (!explainRes.ok) throw new Error("Explain API failed");
        
        const explainData = await explainRes.json();
        const recsData = recsRes.ok ? await recsRes.json() : { recommendations: [] };
        
        const alert = explainData.alert;
        const xai = explainData.explanation;
        
        if (!alert.resolved) {
            resolveBtn.style.display = "inline-block";
        }
        
        modalBody.innerHTML = `
            <div class="xai-alert-details" style="background:var(--bg-color); padding:15px; border-radius:10px; margin-bottom:15px;">
                <h4 style="margin-bottom:10px;">${alert.threat_type}</h4>
                <p style="font-size:13px; margin-bottom:5px;"><strong>Source:</strong> ${alert.source} | <strong>Severity:</strong> <span class="rtm-severity-badge ${alert.severity}">${alert.severity}</span></p>
                <p style="font-size:13px; margin-bottom:5px;"><strong>Detected:</strong> ${new Date(alert.timestamp).toLocaleString()}</p>
                <p style="font-size:13px; color:var(--text-muted);"><strong>Description:</strong> ${alert.description}</p>
            </div>
            
            <div class="xai-section" style="margin-bottom:15px;">
                <h5 style="margin-bottom:10px; color:var(--primary-blue);"><i class="fa-solid fa-brain"></i> AI Explanation</h5>
                <div class="xai-box" style="background:var(--light-blue); padding:15px; border-radius:10px; font-size:13px; border:1px solid rgba(37, 99, 235, 0.2);">
                    <p style="margin-bottom:8px;"><strong>Reasoning:</strong> ${xai.technical_reason || 'N/A'}</p>
                    <p><strong>Potential Impact:</strong> ${xai.impact || 'N/A'}</p>
                </div>
            </div>
            
            <div class="xai-section">
                <h5 style="margin-bottom:10px; color:var(--green);"><i class="fa-solid fa-shield-halved"></i> Mitigation Recommendations</h5>
                <ul class="xai-recs-list" style="list-style:none; padding:0; font-size:13px;">
                    ${recsData.recommendations.map(r => `<li style="margin-bottom:6px; background:var(--light-green); padding:10px; border-radius:8px; display:flex; gap:10px;"><i class="fa-solid fa-check" style="color:var(--green); margin-top:2px;"></i> <span>${r}</span></li>`).join('') || '<li>No specific recommendations available.</li>'}
                </ul>
            </div>
        `;
    } catch (err) {
        console.error("XAI fetch error:", err);
        modalBody.innerHTML = `<p style="color:var(--red);">Failed to generate AI analysis. See console for details.</p>`;
    }
}

async function resolveCurrentThreat() {
    if (!currentXaiAlertId) return;
    try {
        const response = await fetch(`/api/threats/${currentXaiAlertId}/resolve`, {
            method: 'POST',
            headers: apiHeadersThreats
        });
        
        if (response.ok) {
            document.getElementById("xai-modal").style.display = "none";
            loadThreats(currentThreatsPage);
            if (typeof loadDashboardStats === 'function') loadDashboardStats();
        } else {
            alert("Failed to resolve threat.");
        }
    } catch (err) {
        console.error(err);
        alert("Error resolving threat.");
    }
}

// Event Listeners
document.addEventListener("DOMContentLoaded", () => {
    const refreshBtn = document.getElementById("refresh-threats-btn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => loadThreats(1));
        document.getElementById("threat-status-filter").addEventListener("change", () => loadThreats(1));
        document.getElementById("threat-severity-filter").addEventListener("change", () => loadThreats(1));
        
        document.getElementById("threats-prev-btn").addEventListener("click", () => {
            if (currentThreatsPage > 1) loadThreats(currentThreatsPage - 1);
        });
        
        document.getElementById("threats-next-btn").addEventListener("click", () => {
            const totalPages = Math.ceil(totalThreats / THREATS_PER_PAGE);
            if (currentThreatsPage < totalPages) loadThreats(currentThreatsPage + 1);
        });
        
        document.getElementById("close-xai-modal").addEventListener("click", () => {
            document.getElementById("xai-modal").style.display = "none";
        });
        document.getElementById("xai-cancel-btn").addEventListener("click", () => {
            document.getElementById("xai-modal").style.display = "none";
        });
        
        document.getElementById("xai-resolve-btn").addEventListener("click", resolveCurrentThreat);
        
        // Initial load
        loadThreats(1);
    }
});
