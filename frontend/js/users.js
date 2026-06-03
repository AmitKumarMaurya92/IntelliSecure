// =============================
// USERS MODULE
// =============================

const apiHeadersUsers = { "Content-Type": "application/json" };
const tokenUsers = localStorage.getItem("access_token");
if (tokenUsers) {
    apiHeadersUsers["Authorization"] = `Bearer ${tokenUsers}`;
}

async function loadUsers() {
    const tableBody = document.getElementById("users-table-body");
    if (!tableBody) return;

    try {
        const response = await fetch("/api/users/", { headers: apiHeadersUsers });
        if (!response.ok) throw new Error("Failed to load users");
        const users = await response.json();
        
        tableBody.innerHTML = "";
        
        users.forEach(user => {
            const tr = document.createElement("tr");
            
            // Status Badge
            const statusBadge = user.is_active 
                ? `<span style="padding:4px 8px; background:var(--light-green); color:var(--green); border-radius:4px; font-size:12px; font-weight:bold;">Active</span>`
                : `<span style="padding:4px 8px; background:var(--light-red); color:var(--red); border-radius:4px; font-size:12px; font-weight:bold;">Inactive</span>`;
                
            // Role Badge
            let roleColor = "var(--text-muted)";
            if (user.role === "Admin") roleColor = "var(--primary-blue)";
            if (user.role === "Analyst") roleColor = "var(--orange)";
            
            tr.innerHTML = `
                <td style="font-weight:bold;">${user.username}</td>
                <td style="color:var(--text-muted);">${user.email}</td>
                <td style="color:${roleColor}; font-weight:bold;">${user.role}</td>
                <td>${statusBadge}</td>
                <td>
                    <button class="btn-outline" style="padding:5px 10px; font-size:12px; margin-right:5px;" onclick="toggleUserStatus(${user.id})">Toggle Status</button>
                    <button class="btn-outline" style="padding:5px 10px; font-size:12px;" onclick="changeUserRole(${user.id})">Change Role</button>
                </td>
            `;
            tableBody.appendChild(tr);
        });

        if (users.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px;">No users found.</td></tr>`;
        }
    } catch (err) {
        console.error("Error loading users:", err);
        tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--red);">Error loading users.</td></tr>`;
    }
}

async function toggleUserStatus(userId) {
    try {
        const response = await fetch(`/api/users/${userId}/status`, {
            method: 'POST',
            headers: apiHeadersUsers
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Failed to change status");
        }
        loadUsers();
    } catch (err) {
        alert(err.message);
    }
}

async function changeUserRole(userId) {
    const newRole = prompt("Enter new role (Admin, Analyst, User):", "User");
    if (!newRole) return;
    
    try {
        const response = await fetch(`/api/users/${userId}/role?role=${newRole}`, {
            method: 'POST',
            headers: apiHeadersUsers
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Failed to change role");
        }
        loadUsers();
    } catch (err) {
        alert(err.message);
    }
}

// Global scope for onclick handlers
window.toggleUserStatus = toggleUserStatus;
window.changeUserRole = changeUserRole;

document.addEventListener("DOMContentLoaded", () => {
    // Load users when view changes to view-users
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.target.id === 'view-users' && mutation.target.classList.contains('active')) {
                loadUsers();
            }
        });
    });
    
    const usersView = document.getElementById('view-users');
    if (usersView) {
        observer.observe(usersView, { attributes: true, attributeFilter: ['class'] });
        if (usersView.classList.contains('active')) {
            loadUsers();
        }
    }
});
