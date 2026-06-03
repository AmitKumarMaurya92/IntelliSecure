// =============================
// ALERTS MODULE
// =============================

const apiHeadersAlerts = { "Content-Type": "application/json" };
const tokenAlerts = localStorage.getItem("access_token");
if (tokenAlerts) {
    apiHeadersAlerts["Authorization"] = `Bearer ${tokenAlerts}`;
}

async function fetchAlertsFeed() {
    const listContainer = document.getElementById('alerts-feed-list');
    
    try {
        const response = await fetch('/api/threats/active', { headers: apiHeadersAlerts });
        if (!response.ok) throw new Error("API Error fetching active alerts");
        
        const data = await response.json();
        const alerts = data.alerts || [];
        
        // Update topbar notification badge
        const badge = document.getElementById('topbar-notification-badge');
        if (badge) {
            badge.innerText = alerts.length;
            badge.style.display = alerts.length > 0 ? 'inline-flex' : 'none';
        }
        
        if (alerts.length === 0) {
            listContainer.innerHTML = `
                <div style="text-align:center; padding:60px; color:var(--text-muted);">
                    <div style="background:var(--green); width:80px; height:80px; border-radius:50%; display:flex; align-items:center; justify-content:center; margin: 0 auto 20px auto; color:white; opacity:0.8;">
                        <i class="fa-solid fa-check fa-3x"></i>
                    </div>
                    <h3 style="color:var(--text-main); margin-bottom:10px;">All Caught Up!</h3>
                    <p>There are no active security alerts. Your network is safe.</p>
                </div>
            `;
            return;
        }
        
        listContainer.innerHTML = '';
        
        alerts.forEach(alert => {
            const date = new Date(alert.timestamp).toLocaleString();
            
            // Map severity to colors and icons
            let color = 'var(--blue)';
            let bgColor = 'rgba(59, 130, 246, 0.1)';
            let icon = 'fa-circle-info';
            
            if (alert.severity === 'Critical') {
                color = 'var(--red)';
                bgColor = 'rgba(239, 68, 68, 0.1)';
                icon = 'fa-shield-virus';
            } else if (alert.severity === 'High') {
                color = 'var(--orange)';
                bgColor = 'rgba(249, 115, 22, 0.1)';
                icon = 'fa-triangle-exclamation';
            } else if (alert.severity === 'Medium') {
                color = 'var(--yellow)';
                bgColor = 'rgba(234, 179, 8, 0.1)';
                icon = 'fa-satellite-dish';
            }
            
            listContainer.innerHTML += `
                <div class="alert-feed-card" id="alert-card-${alert.id}">
                    <div class="alert-feed-icon" style="background-color: ${bgColor}; color: ${color};">
                        <i class="fa-solid ${icon}"></i>
                    </div>
                    <div class="alert-feed-content">
                        <div class="alert-feed-header">
                            <span class="alert-feed-title">${alert.threat_type} <span style="font-size:12px; font-weight:normal; color:${color}; padding-left:5px;">(${alert.severity})</span></span>
                            <span class="alert-feed-time">${date}</span>
                        </div>
                        <div class="alert-feed-desc">
                            <strong>Source:</strong> ${alert.source}<br>
                            ${alert.description}
                        </div>
                        <div class="alert-feed-actions">
                            <button class="btn-success" onclick="resolveAlertFromFeed(${alert.id})"><i class="fa-solid fa-check"></i> Resolve Alert</button>
                        </div>
                    </div>
                </div>
            `;
        });

    } catch (err) {
        console.error("Failed to load alerts feed:", err);
        listContainer.innerHTML = `
            <div style="text-align:center; padding:40px; color:var(--red);">
                <i class="fa-solid fa-triangle-exclamation fa-2x" style="margin-bottom: 15px;"></i>
                <p>Failed to load notifications.</p>
            </div>
        `;
    }
}

async function resolveAlertFromFeed(id) {
    // Optimistically hide the card
    const card = document.getElementById(`alert-card-${id}`);
    if (card) {
        card.style.opacity = '0.5';
        card.style.pointerEvents = 'none';
        const btn = card.querySelector('.btn-success');
        if (btn) btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Resolving...';
    }
    
    try {
        const response = await fetch(`/api/threats/${id}/resolve`, {
            method: 'POST',
            headers: apiHeadersAlerts,
            body: JSON.stringify({ notes: "Resolved from Alerts Notification Center" })
        });
        
        if (!response.ok) throw new Error("Failed to resolve alert");
        
        // Refresh the feed completely to update badge and UI
        await fetchAlertsFeed();
        
        // Also try to refresh other relevant views if their global functions exist
        if (typeof fetchThreatsData === "function") fetchThreatsData();
        if (typeof fetchDashboardData === "function") fetchDashboardData();
        if (typeof fetchScoreData === "function") fetchScoreData();
        
    } catch (err) {
        console.error("Error resolving alert:", err);
        alert("Failed to resolve alert. See console for details.");
        if (card) {
            card.style.opacity = '1';
            card.style.pointerEvents = 'auto';
            const btn = card.querySelector('.btn-success');
            if (btn) btn.innerHTML = '<i class="fa-solid fa-check"></i> Resolve Alert';
        }
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("refresh-alerts-btn")?.addEventListener("click", () => {
        fetchAlertsFeed();
    });
    
    // Auto-refresh when the Alerts tab is clicked
    document.getElementById("topbar-notification-btn")?.addEventListener("click", () => {
        // Just trigger a fetch immediately
        fetchAlertsFeed();
    });
    
    // Initial fetch to set the badge on page load
    fetchAlertsFeed();
});
