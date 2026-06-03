// =============================
// REPORTS MODULE
// =============================

const apiHeadersReports = { "Content-Type": "application/json" };
const tokenReports = localStorage.getItem("access_token");
if (tokenReports) {
    apiHeadersReports["Authorization"] = `Bearer ${tokenReports}`;
}

async function fetchReportsList() {
    const listBody = document.getElementById('reports-list-body');
    if (!listBody) return;
    
    listBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px;">Loading reports...</td></tr>';
    
    try {
        const response = await fetch('/api/reports/list', { headers: apiHeadersReports });
        if (!response.ok) throw new Error("API Error fetching reports");
        
        const data = await response.json();
        const reports = data.reports || [];
        
        if (reports.length === 0) {
            listBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px;">No reports generated yet.</td></tr>';
            return;
        }
        
        listBody.innerHTML = '';
        
        reports.forEach(report => {
            const date = new Date(report.created_at).toLocaleString();
            const icon = report.type === 'PDF' ? 'fa-file-pdf text-red' : 'fa-file-powerpoint text-orange';
            
            listBody.innerHTML += `
                <tr>
                    <td><i class="fa-solid ${icon}" style="margin-right:8px;"></i> ${report.filename}</td>
                    <td><span class="badge-${report.type === 'PDF' ? 'active' : 'inactive'}" style="background:${report.type === 'PDF' ? 'rgba(239, 68, 68, 0.1); color: var(--red)' : 'rgba(249, 115, 22, 0.1); color: var(--orange)'}">${report.type}</span></td>
                    <td>${report.size_kb} KB</td>
                    <td>${date}</td>
                    <td>
                        <button class="btn-primary btn-sm" onclick="downloadReport('${report.filename}')"><i class="fa-solid fa-download"></i> Download</button>
                    </td>
                </tr>
            `;
        });
        
    } catch (err) {
        console.error("Failed to load reports list:", err);
        listBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--red);">Failed to load reports.</td></tr>';
    }
}

async function generateReport(format) {
    const btnId = format === 'pdf' ? 'generate-pdf-btn' : 'generate-ppt-btn';
    const btn = document.getElementById(btnId);
    const originalText = btn.innerHTML;
    
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Generating...';
    btn.disabled = true;
    
    try {
        const response = await fetch(`/api/reports/generate?format=${format}`, {
            method: 'POST',
            headers: apiHeadersReports
        });
        
        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.detail || "Failed to generate report");
        }
        
        // Trigger browser download of the blob
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        // Extract filename from headers if possible, else default
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = `IntelliSecure_Report.${format === 'ppt' ? 'pptx' : 'pdf'}`;
        if (contentDisposition && contentDisposition.includes('filename=')) {
            filename = contentDisposition.split('filename=')[1].replace(/["']/g, "");
        }
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        
        // Refresh the list
        fetchReportsList();
        
    } catch (err) {
        console.error("Error generating report:", err);
        alert(`Error: ${err.message}`);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function downloadReport(filename) {
    // Create an invisible iframe/link to trigger a standard GET download
    // Including auth headers via fetch and then blob
    fetch(`/api/reports/download/${filename}`, { headers: apiHeadersReports })
        .then(response => {
            if (!response.ok) throw new Error("Failed to download file");
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
        })
        .catch(err => {
            console.error(err);
            alert("Error downloading file.");
        });
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("generate-pdf-btn")?.addEventListener("click", () => generateReport('pdf'));
    document.getElementById("generate-ppt-btn")?.addEventListener("click", () => generateReport('ppt'));
    document.getElementById("refresh-reports-list-btn")?.addEventListener("click", fetchReportsList);
    
    // Auto-refresh when Reports tab is clicked
    document.querySelectorAll('[data-target="view-reports"]').forEach(el => {
        el.addEventListener('click', fetchReportsList);
    });
    
    // Initial fetch
    fetchReportsList();
});
