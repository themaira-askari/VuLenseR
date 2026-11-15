
const AUTH_API_BASE = "http://127.0.0.1:8000";
const AUTH_TOKEN_KEY = "vulenser_access_token";

window.VULENSER_API_BASE = AUTH_API_BASE;
window.VULENSER_USER = null;

let selectedPortal = null;

// ===============================
// SESSION MANAGEMENT
// ===============================

function getAuthToken() {
    return sessionStorage.getItem(AUTH_TOKEN_KEY);
}

function setAuthSession(data) {
    sessionStorage.setItem(AUTH_TOKEN_KEY, data.access_token);
    window.VULENSER_USER = data.user;

    showAuthenticatedApp(data.user);

    window.dispatchEvent(
        new CustomEvent("vulenser:authenticated", {
            detail: data.user
        })
    );
}

function clearAuthSession() {
    sessionStorage.removeItem(AUTH_TOKEN_KEY);
    window.VULENSER_USER = null;
}

// ===============================
// AUTHENTICATED API REQUEST
// ===============================

window.vulenserAuthFetch = async function(url, options = {}) {
    const headers = new Headers(options.headers || {});
    const token = getAuthToken();

    if (token) {
        headers.set("Authorization", `Bearer ${token}`);
    }

    const response = await fetch(url, {
        ...options,
        headers
    });

    if (response.status === 401) {
        clearAuthSession();
        showAuthScreen();

        throw new Error("Your session expired. Please sign in again.");
    }

    return response;
};

// ===============================
// SCREEN MANAGEMENT
// ===============================

function showAuthScreen() {
    document.getElementById("authShell")?.classList.remove("hidden");
    document.getElementById("appContainer")?.classList.add("hidden");

    showPortalSelection();
}

function showPortalSelection() {
    selectedPortal = null;

    document.getElementById("portalSelection")?.classList.remove("hidden");
    document.getElementById("backToPortals")?.classList.add("hidden");
    document.querySelector(".auth-tabs")?.classList.add("hidden");

    document.getElementById("loginForm")?.classList.add("hidden");
    document.getElementById("registerForm")?.classList.add("hidden");

    document.getElementById("adminLoginNotice")?.classList.add("hidden");
}

function selectPortal(role) {
    selectedPortal = role;

    document.getElementById("portalSelection")?.classList.add("hidden");
    document.getElementById("backToPortals")?.classList.remove("hidden");

    const tabs = document.querySelector(".auth-tabs");
    tabs?.classList.remove("hidden");

    const registerTab = document.getElementById("showRegister");
    const adminNotice = document.getElementById("adminLoginNotice");

    if (role === "admin") {
        // Admin can only log in.
        registerTab?.classList.add("hidden");
        adminNotice?.classList.remove("hidden");

        switchAuthTab("login");
    } else {
        // Normal users can log in or register.
        registerTab?.classList.remove("hidden");
        adminNotice?.classList.add("hidden");

        switchAuthTab("login");
    }
}

// ===============================
// DASHBOARD MANAGEMENT
// ===============================


function showAuthenticatedApp(user) {
    document.getElementById("authShell")?.classList.add("hidden");
    document.getElementById("appContainer")?.classList.remove("hidden");

    const isAdmin = user.role === "admin";

    // Update profile
    const name = document.getElementById("profileName");
    const role = document.getElementById("profileRole");
    const avatar = document.getElementById("profileAvatar");

    if (name) name.textContent = user.name;

    if (role) {
        role.textContent = isAdmin ? "Administrator" : "User Workspace";
    }

    if (avatar) {
        avatar.textContent = (user.name || "U")
            .trim().charAt(0).toUpperCase();
    }

    // Show only the navigation items for the current role
    document.querySelectorAll(".nav-item[data-view]").forEach(item => {
        const view = item.dataset.view;

        const visible = isAdmin
            ? view === "admin"
            : view !== "admin";

        item.classList.toggle("hidden", !visible);
    });

    // Open the correct interface immediately
    if (typeof window.showView === "function") {
        window.showView(isAdmin ? "admin" : "dashboard");
    }
}


// ===============================
// LOGIN / REGISTER TABS
// ===============================

function switchAuthTab(mode) {
    const login = mode === "login";

    document.getElementById("loginForm")
        ?.classList.toggle("hidden", !login);

    document.getElementById("registerForm")
        ?.classList.toggle("hidden", login);

    document.getElementById("showLogin")
        ?.classList.toggle("active", login);

    document.getElementById("showRegister")
        ?.classList.toggle("active", !login);
}

// ===============================
// AUTHENTICATION REQUEST
// ===============================

async function submitAuthForm(path, body, errorId, button) {
    const error = document.getElementById(errorId);

    if (error) {
        error.textContent = "";
        error.style.color = "red";
    }

    if (button) {
        button.disabled = true;
    }

    try {
        let response;

        try {
            response = await fetch(`${AUTH_API_BASE}/auth/${path}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body)
            });
        } catch (networkError) {
            throw new Error(
                `Cannot reach the server at ${AUTH_API_BASE}. ` +
                "Start the backend first: uvicorn main:app --reload"
            );
        }

        // The server may return plain text on a crash, so never assume JSON.
        let data = {};
        try {
            data = await response.json();
        } catch (parseError) {
            data = {};
        }

        if (!response.ok) {
            const detail = Array.isArray(data.detail)
                ? data.detail.map(item => item.msg).join(" ")
                : data.detail;

            throw new Error(
                detail || `Request failed (HTTP ${response.status}).`
            );
        }

        if (!data.access_token || !data.user) {
            throw new Error("Unexpected response from the server.");
        }

        // Registration now signs the new user in and opens their workspace.
        if (path === "register") {
            selectedPortal = "user";
            document.getElementById("registerForm")?.reset();
            setAuthSession(data);
            return;
        }

        // Login: the account role must match the portal that was chosen.
        if (selectedPortal && data.user.role !== selectedPortal) {
            throw new Error(
                `This account is not registered as ${selectedPortal}. ` +
                "Please select the correct portal."
            );
        }

        setAuthSession(data);

    } catch (err) {
        if (error) {
            error.textContent =
                err.message || "Unable to connect to the server.";
            error.style.color = "red";
        }
        console.error("Auth error:", err);
    } finally {
        if (button) {
            button.disabled = false;
        }
    }
}

// ===============================
// PAGE EVENT LISTENERS
// ===============================

document.addEventListener("DOMContentLoaded", () => {

    // Portal selection
    document.getElementById("userPortal")
        ?.addEventListener("click", () => selectPortal("user"));

    document.getElementById("adminPortal")
        ?.addEventListener("click", () => selectPortal("admin"));

    // Back to portal selection
    document.getElementById("backToPortals")
        ?.addEventListener("click", showPortalSelection);

    // Login/Register tabs
    document.getElementById("showLogin")
        ?.addEventListener("click", () => switchAuthTab("login"));

    document.getElementById("showRegister")
        ?.addEventListener("click", () => {
            if (selectedPortal === "user") {
                switchAuthTab("register");
            }
        });

    // Login form
    document.getElementById("loginForm")
        ?.addEventListener("submit", event => {
            event.preventDefault();

            const button = event.currentTarget.querySelector(
                "button[type=submit]"
            );

            submitAuthForm(
                "login",
                {
                    email: document.getElementById("loginEmail").value.trim().toLowerCase(),
                    password: document.getElementById("loginPassword").value
                },
                "loginError",
                button
            );
        });

    // Registration form
    document.getElementById("registerForm")
        ?.addEventListener("submit", event => {
            event.preventDefault();

            if (selectedPortal !== "user") {
                return;
            }

            const button = event.currentTarget.querySelector(
                "button[type=submit]"
            );

            submitAuthForm(
                "register",
                {
                    name: document.getElementById("registerName").value.trim(),
                    email: document.getElementById("registerEmail").value.trim().toLowerCase(),
                    password: document.getElementById("registerPassword").value
                },
                "registerError",
                button
            );
        });

    // Logout
    document.getElementById("logoutButton")
        ?.addEventListener("click", () => {
            clearAuthSession();
            showAuthScreen();
        });

    // Check existing session
    const token = getAuthToken();

    if (!token) {
        showAuthScreen();
        return;
    }

    fetch(`${AUTH_API_BASE}/auth/me`, {
        headers: {
            Authorization: `Bearer ${token}`
        }
    })
        .then(async response => {
            if (!response.ok) {
                throw new Error("Session expired");
            }

            return response.json();
        })
        .then(data => {
            window.VULENSER_USER = data.user;

            showAuthenticatedApp(data.user);

            window.dispatchEvent(
                new CustomEvent("vulenser:authenticated", {
                    detail: data.user
                })
            );
        })
        .catch(() => {
            clearAuthSession();
            showAuthScreen();
        });
});
