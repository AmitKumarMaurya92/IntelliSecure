// =============================
// LOGS MODULE
// =============================
let currentLogsType = 'login';
let currentLogsPage = 1;
const LOGS_PER_PAGE = 25;
let logsStats = {};

const apiHeadersLogs = { "Content-Type": "application/json" };
const tokenLogs = localStorage.getItem("access_token");
if (tokenLogs) {
    apiHeadersLogs["Authorization"] = `Bearer ${tokenLogs}`;
}
// Check Role for Sync button
function checkAdminRoleForLogs() {
    try {
        if (!tokenLogs) return;
        const payload = JSON.parse(atob(tokenLogs.split('.')[1]));
        if (payload.role === "Admin" || payload.role === "Analyst") {
            const btn = document.getElementById("sync-logs-btn");
            if(btn) btn.style.display = "inline-flex";
        }
    } catch(e) {}
}

async function fetchLogStats() {
    try {
        const res = await fetch('/api/logs/stats', { headers: apiHeadersLogs });
        if (!res.ok) return;
        const data = await res.json();
        logsStats = data.by_type;
        
        document.getElementById('badge-login').innerText = (logsStats.login || 0).toLocaleString();
        document.getElementById('badge-network').innerText = (logsStats.network || 0).toLocaleString();
        document.getElementById('badge-file').innerText = (logsStats.file_access || 0).toLocaleString();
        document.getElementById('badge-malware').innerText = (logsStats.malware || 0).toLocaleString();
        document.getElementById('badge-usb').innerText = (logsStats.usb || 0).toLocaleString();
    } catch(e) {
        console.error("Failed to load log stats:", e);
    }
}

async function loadLogs(type, page = 1) {
    currentLogsType = type;
    currentLogsPage = page;
    
    // Update active tab UI
    document.querySelectorAll('.log-tab').forEach(tab => {
        if (tab.dataset.type === type) tab.classList.add('active');
        else tab.classList.remove('active');
    });
    
    const tbody = document.getElementById("logs-table-body");
    const thead = document.getElementById("logs-table-head");
    if(!tbody || !thead) return;
    
    tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:20px;"><i class="fa-solid fa-circle-notch fa-spin" style="color:var(--primary-blue);"></i> Loading...</td></tr>`;
    
    // Render specific headers
    if (type === 'login') {
        thead.innerHTML = `<tr><th>Timestamp</th><th>Username</th><th>IP Address</th><th>Status</th></tr>`;
    } else if (type === 'network') {
        thead.innerHTML = `<tr><th>Timestamp</th><th>Source IP</th><th>Dest IP</th><th>Port</th><th>Proto</th><th>Action</th></tr>`;
    } else if (type === 'file') {
        thead.innerHTML = `<tr><th>Timestamp</th><th>Username</th><th>File Path</th><th>Access</th><th>Status</th></tr>`;
    } else if (type === 'malware') {
        thead.innerHTML = `<tr><th>Timestamp</th><th>File Name</th><th>Signature</th><th>Action Taken</th></tr>`;
    } else if (type === 'usb') {
        thead.innerHTML = `<tr><th>Timestamp</th><th>Username</th><th>Device Name</th><th>Action</th></tr>`;
    }
    
    const offset = (page - 1) * LOGS_PER_PAGE;
    
    try {
        const response = await fetch(`/api/logs/${type}?limit=${LOGS_PER_PAGE}&offset=${offset}`, { headers: apiHeadersLogs });
        if (!response.ok) throw new Error("API Error");
        const logs = await response.json();
        
        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:20px;">No logs found.</td></tr>`;
        } else {
            tbody.innerHTML = logs.map(log => {
                const date = new Date(log.timestamp).toLocaleString();
                if (type === 'login') {
                    const badge = log.status === 'Success' ? `<span style="color:var(--green);font-weight:600;"><i class="fa-solid fa-check"></i> Success</span>` : `<span style="color:var(--red);font-weight:600;"><i class="fa-solid fa-xmark"></i> Failed</span>`;
                    return `<tr><td>${date}</td><td>${log.username}</td><td>${log.ip_address}</td><td>${badge}</td></tr>`;
                } else if (type === 'network') {
                    let badge = `<span style="color:var(--primary-blue);font-weight:600;">${log.action}</span>`;
                    if(log.action==='Block') badge = `<span style="color:var(--red);font-weight:600;">Block</span>`;
                    if(log.action==='Flagged') badge = `<span style="color:var(--yellow);font-weight:600;">Flagged</span>`;
                    return `<tr><td>${date}</td><td>${log.source_ip}</td><td>${log.destination_ip}</td><td>${log.port}</td><td>${log.protocol}</td><td>${badge}</td></tr>`;
                } else if (type === 'file') {
                    const badge = log.status === 'Allowed' ? `<span style="color:var(--green);font-weight:600;"><i class="fa-solid fa-check"></i> Allowed</span>` : `<span style="color:var(--red);font-weight:600;"><i class="fa-solid fa-xmark"></i> Denied</span>`;
                    return `<tr><td>${date}</td><td>${log.username}</td><td style="word-break: break-all;">${log.file_path}</td><td>${log.access_type}</td><td>${badge}</td></tr>`;
                } else if (type === 'malware') {
                    const badge = log.action_taken === 'Quarantined' ? `<span style="color:var(--yellow);font-weight:600;">Quarantined</span>` : (log.action_taken === 'Deleted' ? `<span style="color:var(--red);font-weight:600;">Deleted</span>` : `<span style="color:var(--primary-blue);font-weight:600;">${log.action_taken}</span>`);
                    return `<tr><td>${date}</td><td>${log.file_name}</td><td>${log.signature}</td><td>${badge}</td></tr>`;
                } else if (type === 'usb') {
                    let badge = `<span style="color:var(--green);font-weight:600;">${log.action}</span>`;
                    if(log.action === 'Blocked') badge = `<span style="color:var(--red);font-weight:600;">Blocked</span>`;
                    else if(log.action === 'Disconnected') badge = `<span style="color:var(--yellow);font-weight:600;">Disconnected</span>`;
                    return `<tr><td>${date}</td><td>${log.username}</td><td>${log.device_name}</td><td>${badge}</td></tr>`;
                }
            }).join('');
        }
        
        updateLogsPagination(logs.length);
    } catch (err) {
        console.error(`Failed to load ${type} logs:`, err);
        tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; color:var(--red);">Failed to load logs.</td></tr>`;
    }
}

function updateLogsPagination(currentPageCount) {
    let totalForType = 0;
    if(currentLogsType === 'login') totalForType = logsStats.login || 0;
    if(currentLogsType === 'network') totalForType = logsStats.network || 0;
    if(currentLogsType === 'file') totalForType = logsStats.file_access || 0;
    if(currentLogsType === 'malware') totalForType = logsStats.malware || 0;
    if(currentLogsType === 'usb') totalForType = logsStats.usb || 0;
    
    const totalPages = Math.max(1, Math.ceil(totalForType / LOGS_PER_PAGE));
    const info = document.getElementById("logs-page-info");
    if(info) info.innerText = `Page ${currentLogsPage} of ${totalPages}`;
    
    const prevBtn = document.getElementById("logs-prev-btn");
    if(prevBtn) prevBtn.disabled = currentLogsPage <= 1;
    
    const nextBtn = document.getElementById("logs-next-btn");
    if(nextBtn) {
        if (currentPageCount < LOGS_PER_PAGE) {
            nextBtn.disabled = true;
        } else {
            nextBtn.disabled = currentLogsPage >= totalPages;
        }
    }
}

async function syncTelemetry() {
    const btn = document.getElementById("sync-logs-btn");
    btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Syncing...`;
    btn.disabled = true;
    
    try {
        const response = await fetch('/api/logs/sync', {
            method: 'POST',
            headers: apiHeadersLogs
        });
        if(response.ok) {
            const data = await response.json();
            alert(`Sync complete!\\nLogin: ${data.stats.login_added}\\nNetwork: ${data.stats.network_added}\\nFile: ${data.stats.file_added}\\nMalware: ${data.stats.malware_added}\\nUSB: ${data.stats.usb_added}`);
            await fetchLogStats();
            loadLogs(currentLogsType, 1);
        } else {
            alert("Failed to sync telemetry.");
        }
    } catch (err) {
        console.error(err);
        alert("Error syncing telemetry.");
    } finally {
        btn.innerHTML = `<i class="fa-solid fa-cloud-arrow-down"></i> Sync Telemetry`;
        btn.disabled = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    checkAdminRoleForLogs();
    
    document.querySelectorAll('.log-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const type = e.currentTarget.dataset.type;
            loadLogs(type, 1);
        });
    });
    
    const refreshLogsBtn = document.getElementById("refresh-logs-btn");
    if (refreshLogsBtn) {
        refreshLogsBtn.addEventListener("click", () => {
            fetchLogStats().then(() => loadLogs(currentLogsType, currentLogsPage));
        });
        
        document.getElementById("sync-logs-btn")?.addEventListener("click", syncTelemetry);
        
        document.getElementById("logs-prev-btn")?.addEventListener("click", () => {
            if (currentLogsPage > 1) loadLogs(currentLogsType, currentLogsPage - 1);
        });
        
        document.getElementById("logs-next-btn")?.addEventListener("click", () => {
            loadLogs(currentLogsType, currentLogsPage + 1);
        });
        
        fetchLogStats().then(() => loadLogs('login', 1));
    }
});
