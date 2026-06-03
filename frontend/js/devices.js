// =============================
// DEVICES (LAN) MODULE
// =============================
let currentDeviceTab = 'all';

const apiHeadersDevices = { "Content-Type": "application/json" };
const tokenDevices = localStorage.getItem("access_token");
if (tokenDevices) {
    apiHeadersDevices["Authorization"] = `Bearer ${tokenDevices}`;
}

// Check Role for Scan button
function checkAdminRoleForDevices() {
    try {
        if (!tokenDevices) return;
        const payload = JSON.parse(atob(tokenDevices.split('.')[1]));
        if (payload.role === "Admin" || payload.role === "Analyst") {
            const btn = document.getElementById("scan-lan-btn");
            if(btn) btn.style.display = "inline-flex";
        }
    } catch(e) {}
}

async function fetchDeviceInventory() {
    const tbody = document.getElementById("devices-table-body");
    if(!tbody) return;
    
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px;"><i class="fa-solid fa-circle-notch fa-spin" style="color:var(--primary-blue);"></i> Loading inventory...</td></tr>`;
    
    try {
        const endpoint = currentDeviceTab === 'unknown' ? '/api/devices/unknown' : '/api/devices/';
        const response = await fetch(endpoint, { headers: apiHeadersDevices });
        if (!response.ok) throw new Error("API Error");
        
        const data = await response.json();
        const devices = currentDeviceTab === 'unknown' ? data.unknown_devices : data.devices;
        
        // Update Stats
        if (currentDeviceTab === 'all') {
            document.getElementById("stat-devices-total").innerText = data.total_online || 0;
            const unknownCount = devices ? devices.filter(d => !d.is_known).length : 0;
            const knownCount = (data.total_online || 0) - unknownCount;
            document.getElementById("stat-devices-known").innerText = knownCount;
            document.getElementById("stat-devices-unknown").innerText = unknownCount;
            
            if (data.last_scan) {
                const scanDate = new Date(data.last_scan);
                document.getElementById("stat-devices-last-scan").innerText = scanDate.toLocaleString();
            } else {
                document.getElementById("stat-devices-last-scan").innerText = "Never";
            }
        }
        
        if (!devices || devices.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px;">No devices found.</td></tr>`;
            return;
        }
        
        tbody.innerHTML = devices.map(d => {
            const knownBadge = d.is_known 
                ? `<span style="color:var(--green);font-weight:600;"><i class="fa-solid fa-check"></i> Known</span>` 
                : `<span style="color:var(--red);font-weight:600;"><i class="fa-solid fa-user-secret"></i> Unknown</span>`;
            
            return `<tr>
                <td style="font-family:monospace; font-weight:600;">${d.ip_address}</td>
                <td style="font-family:monospace; color:var(--text-muted);">${d.mac_address || 'Unknown'}</td>
                <td>${d.vendor || 'Unknown Vendor'}</td>
                <td>${d.os_prediction || 'N/A'}</td>
                <td>${knownBadge}</td>
            </tr>`;
        }).join('');
        
    } catch (err) {
        console.error("Failed to load device inventory:", err);
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--red);">Failed to load devices.</td></tr>`;
    }
}

async function triggerLanScan() {
    const btn = document.getElementById("scan-lan-btn");
    if(!btn) return;
    
    btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning Network...`;
    btn.disabled = true;
    
    try {
        const response = await fetch('/api/devices/scan?subnet=192.168.1.0/24', {
            method: 'POST',
            headers: apiHeadersDevices
        });
        if(response.ok) {
            const data = await response.json();
            alert(`Scan complete! Found ${data.total_online} devices online.`);
            // Reset to 'all' tab after scan
            document.querySelectorAll('.log-tab').forEach(t => t.classList.remove('active'));
            const allTab = document.querySelector('.log-tab[data-device-tab="all"]');
            if (allTab) allTab.classList.add('active');
            currentDeviceTab = 'all';
            
            fetchDeviceInventory();
        } else {
            alert("Failed to perform network scan.");
        }
    } catch (err) {
        console.error(err);
        alert("Error performing network scan.");
    } finally {
        btn.innerHTML = `<i class="fa-solid fa-radar"></i> Scan Network`;
        btn.disabled = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    checkAdminRoleForDevices();
    
    const deviceTabs = document.querySelectorAll('.log-tab[data-device-tab]');
    if(deviceTabs.length > 0) {
        deviceTabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                document.querySelectorAll('.log-tab[data-device-tab]').forEach(t => t.classList.remove('active'));
                e.currentTarget.classList.add('active');
                currentDeviceTab = e.currentTarget.dataset.deviceTab;
                fetchDeviceInventory();
            });
        });
        
        document.getElementById("scan-lan-btn")?.addEventListener("click", triggerLanScan);
        document.getElementById("refresh-devices-btn")?.addEventListener("click", fetchDeviceInventory);
        
        // Initial fetch
        fetchDeviceInventory();
    }
});
