document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const toggleToRegister = document.getElementById("toggle-to-register");
    const toggleToLogin = document.getElementById("toggle-to-login");
    const loginView = document.getElementById("login-view");
    const registerView = document.getElementById("register-view");
    const authSubtitleText = document.getElementById("auth-subtitle-text");

    const loginForm = document.getElementById("login-form");
    const registerForm = document.getElementById("register-form");

    const notification = document.getElementById("auth-notification");
    const notificationMessage = document.getElementById("notification-message");

    // Toggle Views
    toggleToRegister.addEventListener("click", (e) => {
        e.preventDefault();
        hideNotification();
        loginView.style.display = "none";
        registerView.style.display = "block";
        authSubtitleText.textContent = "Create security operator credentials";
    });

    toggleToLogin.addEventListener("click", (e) => {
        e.preventDefault();
        hideNotification();
        registerView.style.display = "none";
        loginView.style.display = "block";
        authSubtitleText.textContent = "AI Threat Monitoring & Incident Response";
    });

    // Helper functions for notifications
    function showNotification(message, type = "error") {
        notificationMessage.textContent = message;
        notification.className = "notification " + type;
        notification.style.display = "flex";
    }

    function hideNotification() {
        notification.style.display = "none";
    }

    // Handle Registration API Submission
    registerForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        hideNotification();

        const username = document.getElementById("register-username").value.trim();
        const email = document.getElementById("register-email").value.trim();
        const password = document.getElementById("register-password").value;
        const role = document.getElementById("register-role").value;

        try {
            const response = await fetch("/api/auth/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, email, password, role }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Registration failed. Please check inputs.");
            }

            // Successfully registered! Transition back to login
            showNotification(`Success! ${data.username} registered with role ${data.role}. Please login.`, "success");
            
            // Auto fill username and swap forms
            document.getElementById("login-username").value = data.username;
            document.getElementById("login-password").value = "";
            
            registerView.style.display = "none";
            loginView.style.display = "block";
            authSubtitleText.textContent = "AI Threat Monitoring & Incident Response";
            registerForm.reset();
        } catch (error) {
            showNotification(error.message, "error");
        }
    });

    // Handle Login API Submission
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        hideNotification();

        const username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value;

        try {
            const response = await fetch("/api/auth/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Invalid system user ID or passkey.");
            }

            // Save JWT securely
            localStorage.setItem("access_token", data.access_token);
            
            showNotification("Access granted. Decrypting security feed...", "success");
            
            // Redirect to dashboard after a brief delay for high premium polish effect
            setTimeout(() => {
                window.location.href = "/dashboard";
            }, 1000);
        } catch (error) {
            showNotification(error.message, "error");
        }
    });
});
