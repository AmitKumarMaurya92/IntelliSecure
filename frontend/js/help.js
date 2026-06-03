// =============================
// HELP & LEARN MODULE
// =============================

const apiHeadersHelp = { "Content-Type": "application/json" };
const tokenHelp = localStorage.getItem("access_token");
if (tokenHelp) {
    apiHeadersHelp["Authorization"] = `Bearer ${tokenHelp}`;
}

async function loadGlossary(query = "") {
    const grid = document.getElementById("glossary-grid");
    if (!grid) return;

    try {
        let url = "/api/education/glossary";
        if (query.length >= 2) {
            url = `/api/education/glossary/search?q=${encodeURIComponent(query)}`;
        }
        
        const response = await fetch(url, { headers: apiHeadersHelp });
        if (!response.ok) throw new Error("Failed to load glossary");
        
        const data = await response.json();
        const items = data.terms || data.results || {};
        
        grid.innerHTML = "";
        
        const keys = Object.keys(items);
        if (keys.length === 0) {
            grid.innerHTML = `<div style="grid-column: 1/-1; text-align:center; padding:40px; color:var(--text-muted);">No glossary terms found.</div>`;
            return;
        }

        keys.forEach(key => {
            const term = items[key];
            const card = document.createElement("div");
            card.className = "score-card";
            card.innerHTML = `
                <h3 style="margin-bottom: 10px; color: var(--primary-blue);">${term.term}</h3>
                <span style="display:inline-block; padding:3px 8px; background:var(--light-blue); color:var(--primary-blue); border-radius:4px; font-size:11px; font-weight:bold; margin-bottom:15px; text-transform:uppercase;">
                    ${term.category}
                </span>
                <p style="color: var(--text-muted); font-size: 14px; line-height: 1.5;">${term.definition}</p>
            `;
            grid.appendChild(card);
        });

    } catch (err) {
        console.error("Error loading glossary:", err);
        grid.innerHTML = `<div style="grid-column: 1/-1; text-align:center; padding:40px; color:var(--red);">Error loading glossary.</div>`;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    // Load glossary when view changes to view-help
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.target.id === 'view-help' && mutation.target.classList.contains('active')) {
                loadGlossary();
            }
        });
    });
    
    const helpView = document.getElementById('view-help');
    if (helpView) {
        observer.observe(helpView, { attributes: true, attributeFilter: ['class'] });
        if (helpView.classList.contains('active')) {
            loadGlossary();
        }
    }

    // Search functionality
    const searchInput = document.getElementById("glossary-search");
    if (searchInput) {
        let timeout = null;
        searchInput.addEventListener("input", (e) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                const q = e.target.value.trim();
                if (q.length === 0 || q.length >= 2) {
                    loadGlossary(q);
                }
            }, 300);
        });
    }
});
