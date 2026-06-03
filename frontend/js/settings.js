// =============================
// SETTINGS MODULE
// =============================

const apiHeadersSettings = { "Content-Type": "application/json" };
const tokenSettings = localStorage.getItem("access_token");
if (tokenSettings) {
    apiHeadersSettings["Authorization"] = `Bearer ${tokenSettings}`;
}

document.addEventListener("DOMContentLoaded", () => {
    // ─── Elements ───
    const darkModeToggle = document.getElementById("dark-mode-toggle");
    const saveBtn = document.getElementById("save-settings-btn");
    
    // Inputs
    const langSelect = document.getElementById("setting-language");
    const timeSelect = document.getElementById("setting-timezone");
    const retSelect = document.getElementById("setting-log-retention");
    const autoDelToggle = document.getElementById("setting-auto-delete");
    const compLogsToggle = document.getElementById("setting-compress-logs");
    const autoRefSelect = document.getElementById("setting-auto-refresh");
    const soundToggle = document.getElementById("setting-sound-alerts");
    const secTipsToggle = document.getElementById("setting-security-tips");
    
    // Profile Edit Elements
    const fullNameInput = document.getElementById("settings-fullname");
    const profileDisplayName = document.getElementById("profile-display-name");
    const avatarImg = document.getElementById("profile-avatar-img");
    const avatarUploadInput = document.getElementById("avatar-upload-input");
    const avatarEditBtn = document.getElementById("avatar-edit-btn");
    const avatarRemoveBtn = document.getElementById("avatar-remove-btn");
    
    let currentAvatarBase64 = null;
    const defaultAvatarUrl = "https://ui-avatars.com/api/?name=Admin+User&background=2563eb&color=fff&size=150";

    // ─── Fetch Preferences ───
    async function loadPreferences() {
        try {
            const res = await fetch("/api/settings/", { headers: apiHeadersSettings });
            if (!res.ok) throw new Error("Failed to load settings");
            const prefs = await res.json();
            
            if (langSelect) langSelect.value = prefs.language;
            if (timeSelect) timeSelect.value = prefs.timezone;
            if (retSelect) retSelect.value = prefs.log_retention_days;
            if (autoDelToggle) autoDelToggle.checked = prefs.auto_delete_logs;
            if (compLogsToggle) compLogsToggle.checked = prefs.compress_old_logs;
            if (autoRefSelect) autoRefSelect.value = prefs.auto_refresh_interval;
            if (soundToggle) soundToggle.checked = prefs.sound_alerts;
            if (secTipsToggle) secTipsToggle.checked = prefs.show_security_tips;
            if (fullNameInput && prefs.full_name) {
                fullNameInput.value = prefs.full_name;
                if (profileDisplayName) profileDisplayName.textContent = prefs.full_name;
            }
            if (prefs.avatar_base64) {
                currentAvatarBase64 = prefs.avatar_base64;
                if (avatarImg) avatarImg.src = prefs.avatar_base64;
            } else {
                currentAvatarBase64 = null;
                if (avatarImg) avatarImg.src = defaultAvatarUrl;
            }
        } catch (err) {
            console.error(err);
        }
    }

    // Load preferences when viewing settings tab
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.target.id === 'view-settings' && mutation.target.classList.contains('active')) {
                loadPreferences();
            }
        });
    });
    
    const settingsView = document.getElementById('view-settings');
    if (settingsView) {
        observer.observe(settingsView, { attributes: true, attributeFilter: ['class'] });
        // Initial load if active
        if (settingsView.classList.contains('active')) loadPreferences();
    }

    // ─── Save Preferences ───
    if (saveBtn) {
        saveBtn.addEventListener("click", async () => {
            const originalText = saveBtn.innerHTML;
            saveBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Saving...`;
            saveBtn.disabled = true;

            const updateData = {
                language: langSelect ? langSelect.value : undefined,
                timezone: timeSelect ? timeSelect.value : undefined,
                log_retention_days: retSelect ? parseInt(retSelect.value) : undefined,
                auto_delete_logs: autoDelToggle ? autoDelToggle.checked : undefined,
                compress_old_logs: compLogsToggle ? compLogsToggle.checked : undefined,
                auto_refresh_interval: autoRefSelect ? parseInt(autoRefSelect.value) : undefined,
                sound_alerts: soundToggle ? soundToggle.checked : undefined,
                show_security_tips: secTipsToggle ? secTipsToggle.checked : undefined,
                full_name: fullNameInput ? fullNameInput.value : undefined,
                avatar_base64: currentAvatarBase64
            };

            try {
                const res = await fetch("/api/settings/", {
                    method: "PUT",
                    headers: apiHeadersSettings,
                    body: JSON.stringify(updateData)
                });
                
                if (!res.ok) throw new Error("Failed to save settings");
                
                // Show success
                saveBtn.innerHTML = `<i class="fa-solid fa-check"></i> Saved!`;
                saveBtn.style.background = "var(--green)";
                setTimeout(() => {
                    saveBtn.innerHTML = originalText;
                    saveBtn.style.background = "";
                    saveBtn.disabled = false;
                }, 2000);
            } catch (err) {
                console.error(err);
                alert("Error saving settings.");
                saveBtn.innerHTML = originalText;
                saveBtn.disabled = false;
            }
        });
    }

    // ─── Profile Logic ───
    if (fullNameInput && profileDisplayName) {
        fullNameInput.addEventListener("input", (e) => {
            profileDisplayName.textContent = e.target.value || "Admin User";
        });
    }

    if (avatarEditBtn && avatarUploadInput) {
        avatarEditBtn.addEventListener("click", () => {
            avatarUploadInput.click();
        });
    }

    if (avatarUploadInput) {
        avatarUploadInput.addEventListener("change", (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (ev) => {
                    currentAvatarBase64 = ev.target.result;
                    if (avatarImg) avatarImg.src = currentAvatarBase64;
                };
                reader.readAsDataURL(file);
            }
        });
    }

    if (avatarRemoveBtn) {
        avatarRemoveBtn.addEventListener("click", () => {
            currentAvatarBase64 = null;
            if (avatarImg) avatarImg.src = defaultAvatarUrl;
            if (avatarUploadInput) avatarUploadInput.value = "";
        });
    }

    // ─── Session Management Logic ───
    const currentSessionBrowser = document.getElementById("current-session-browser");
    const currentSessionIp = document.getElementById("current-session-ip");
    const currentSessionTime = document.getElementById("current-session-time");
    
    const otherSessionsToggle = document.getElementById("other-sessions-toggle");
    const otherSessionsCount = document.getElementById("other-sessions-count");
    const otherSessionsIcon = document.getElementById("other-sessions-icon");
    const otherSessionsList = document.getElementById("other-sessions-list");
    const logoutOthersBtn = document.getElementById("logout-others-btn");

    async function loadSessions() {
        if (!currentSessionBrowser) return; // Not on settings page
        try {
            const res = await fetch("/api/settings/sessions", { headers: apiHeadersSettings });
            if (!res.ok) throw new Error("Failed to load sessions");
            const data = await res.json();
            
            // Populate Current Session
            if (data.current) {
                currentSessionBrowser.textContent = `${data.current.device} • ${data.current.location}`;
                currentSessionIp.textContent = data.current.ip_address;
                currentSessionTime.textContent = data.current.started_at;
            }
            
            // Populate Other Sessions
            if (data.others) {
                otherSessionsCount.textContent = data.others.length;
                
                if (data.others.length > 0) {
                    otherSessionsList.innerHTML = data.others.map(s => `
                        <div style="background: var(--bg-main); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; margin-bottom: 8px;">
                            <div style="font-size: 12px; font-weight: 600; margin-bottom: 3px;">${s.device}</div>
                            <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 3px;">${s.location} • ${s.ip_address}</div>
                            <div style="font-size: 10px; color: var(--text-muted);">Started ${s.started_at}</div>
                        </div>
                    `).join("");
                    logoutOthersBtn.disabled = false;
                    logoutOthersBtn.style.opacity = "1";
                    logoutOthersBtn.style.cursor = "pointer";
                } else {
                    otherSessionsList.innerHTML = `<div style="font-size: 12px; color: var(--text-muted); text-align: center; padding: 10px;">No other active sessions.</div>`;
                    logoutOthersBtn.disabled = true;
                    logoutOthersBtn.style.opacity = "0.5";
                    logoutOthersBtn.style.cursor = "not-allowed";
                }
            }
        } catch (err) {
            console.error("Error loading sessions:", err);
        }
    }

    if (otherSessionsToggle && otherSessionsList) {
        otherSessionsToggle.addEventListener("click", () => {
            const isHidden = otherSessionsList.style.display === "none";
            otherSessionsList.style.display = isHidden ? "block" : "none";
            otherSessionsIcon.style.transform = isHidden ? "rotate(90deg)" : "rotate(0deg)";
        });
    }

    if (logoutOthersBtn) {
        logoutOthersBtn.addEventListener("click", async () => {
            if (logoutOthersBtn.disabled) return;
            
            const originalText = logoutOthersBtn.innerHTML;
            logoutOthersBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Logging out...`;
            logoutOthersBtn.disabled = true;
            
            try {
                const res = await fetch("/api/settings/sessions/others", {
                    method: "DELETE",
                    headers: apiHeadersSettings
                });
                
                if (!res.ok) throw new Error("Failed to logout other sessions");
                
                logoutOthersBtn.innerHTML = `<i class="fa-solid fa-check"></i> Logged Out Successfully`;
                setTimeout(() => {
                    logoutOthersBtn.innerHTML = originalText;
                    loadSessions();
                }, 1500);
            } catch (err) {
                console.error(err);
                alert("Error logging out sessions.");
                logoutOthersBtn.innerHTML = originalText;
                logoutOthersBtn.disabled = false;
            }
        });
    }
    
    // Auto-load sessions if on settings view
    if (settingsView && settingsView.classList.contains('active')) {
        loadSessions();
    }
    
    const origObserverCallback = observer._callback; 
    // We already have an observer, but we need to hook loadSessions into it. 
    // An easier way is to just add another observer for sessions.
    const sessionObserver = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.target.id === 'view-settings' && mutation.target.classList.contains('active')) {
                loadSessions();
            }
        });
    });
    if (settingsView) {
        sessionObserver.observe(settingsView, { attributes: true, attributeFilter: ['class'] });
    }

    // ─── Settings Tabs Logic ───
    const settingsTabs = document.querySelectorAll('.settings-tab');
    const settingsSections = document.querySelectorAll('.settings-content-section');

    settingsTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            settingsTabs.forEach(t => {
                t.classList.remove('active');
                t.style.background = 'transparent';
                t.style.color = 'var(--text-muted)';
            });

            // Add active class to clicked tab
            tab.classList.add('active');
            tab.style.background = 'var(--primary-blue)';
            tab.style.color = 'white';

            // Hide all sections
            settingsSections.forEach(section => {
                section.style.display = 'none';
            });

            // Show target section
            const targetId = `settings-content-${tab.getAttribute('data-tab')}`;
            const targetSection = document.getElementById(targetId);
            if (targetSection) {
                targetSection.style.display = 'block';
            }
        });
    });
});
