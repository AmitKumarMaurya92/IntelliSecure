// =============================
// EXPORT MODULE
// =============================

const apiHeadersExport = { "Content-Type": "application/json" };
const tokenExport = localStorage.getItem("access_token");
if (tokenExport) {
    apiHeadersExport["Authorization"] = `Bearer ${tokenExport}`;
}

async function triggerDataExport() {
    const datasetSelect = document.getElementById("export-dataset-select");
    const formatRadios = document.getElementsByName("export_format");
    
    if (!datasetSelect || formatRadios.length === 0) return;

    const dataset = datasetSelect.value;
    let format = "csv";
    for (const radio of formatRadios) {
        if (radio.checked) {
            format = radio.value;
            break;
        }
    }

    const btn = document.getElementById("trigger-export-btn");
    const statusText = document.getElementById("export-status-text");
    const originalText = btn.innerHTML;
    
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Generating Download...';
    btn.disabled = true;
    statusText.style.display = "block";
    statusText.style.color = "var(--text-muted)";
    statusText.innerText = `Fetching ${dataset} data from database...`;

    try {
        const response = await fetch(`/api/export/${dataset}?format=${format}`, {
            method: 'GET',
            headers: {
                "Authorization": `Bearer ${tokenExport}` // Omitting Content-Type for GET request
            }
        });

        if (!response.ok) {
            let errorDetail = "Failed to export data.";
            try {
                const errData = await response.json();
                errorDetail = errData.detail || errorDetail;
            } catch (e) {
                errorDetail = `Server Error: ${response.status}`;
            }
            throw new Error(errorDetail);
        }

        // Trigger blob download
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        
        // Try to get filename from header
        let filename = `export_${dataset}.${format}`;
        const contentDisposition = response.headers.get('Content-Disposition');
        if (contentDisposition && contentDisposition.includes('filename=')) {
            filename = contentDisposition.split('filename=')[1].replace(/["']/g, "");
        }
        
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        
        statusText.innerText = "Download complete!";
        statusText.style.color = "var(--green)";
        setTimeout(() => { statusText.style.display = "none"; }, 3000);

    } catch (err) {
        console.error("Export error:", err);
        statusText.innerText = err.message;
        statusText.style.color = "var(--red)";
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const exportBtn = document.getElementById("trigger-export-btn");
    if (exportBtn) {
        exportBtn.addEventListener("click", triggerDataExport);
    }
});
