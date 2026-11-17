
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
// PROFILE RENDERING (per-user, stored on the server)
// ===============================

function userInitial(user) {
    return (user?.name || "U").trim().charAt(0).toUpperCase();
}

function renderUserProfile(user) {
    if (!user) return;
    const isAdmin = user.role === "admin";

    document.querySelectorAll("[data-user-name]").forEach(el => { el.textContent = user.name; });
    document.querySelectorAll("[data-user-email]").forEach(el => { el.textContent = user.email; });

    const profileName = document.getElementById("profileName");
    if (profileName) profileName.textContent = user.name;

    const role = document.getElementById("profileRole");
    if (role) role.textContent = isAdmin ? "Administrator" : "User Workspace";

    // Picture: if a photo exists show ONLY the photo (no letter); otherwise show the initial.
    document.querySelectorAll("[data-avatar]").forEach(el => {
        if (user.avatar) {
            el.textContent = "";
            el.style.backgroundImage = `url("${user.avatar}")`;
            el.classList.add("has-photo");
        } else {
            el.textContent = userInitial(user);
            el.style.backgroundImage = "";
            el.classList.remove("has-photo");
        }
    });

    const removeBtn = document.getElementById("removePhotoButton");
    if (removeBtn) removeBtn.disabled = !user.avatar;
    const photoText = document.getElementById("photoBtnText");
    if (photoText) photoText.textContent = user.avatar ? "Change photo" : "Upload photo";
}

function setProfileMessage(id, text, ok) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text || "";
    el.classList.toggle("ok", !!ok);
    el.classList.toggle("err", !ok && !!text);
}

function openProfileModal() {
    const user = window.VULENSER_USER;
    if (!user) return;
    document.getElementById("profilePopover")?.classList.add("hidden");
    document.getElementById("profileNameInput").value = user.name || "";
    document.getElementById("profileEmailInput").value = user.email || "";
    document.getElementById("profileRoleInput").value = user.role === "admin" ? "Administrator" : "User";
    document.getElementById("profileSinceInput").value = user.created_at
        ? new Date(user.created_at).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })
        : "—";
    document.getElementById("currentPasswordInput").value = "";
    document.getElementById("newPasswordInput").value = "";
    setProfileMessage("profileMessage", "");
    setProfileMessage("passwordMessage", "");
    renderUserProfile(user);
    document.getElementById("profileEditor")?.classList.remove("hidden");
    document.getElementById("profileNameInput")?.focus();
}

function closeProfileModal() {
    document.getElementById("profileEditor")?.classList.add("hidden");
}

async function profileRequest(path, options = {}) {
    const response = await window.vulenserAuthFetch(`${AUTH_API_BASE}/auth/${path}`, options);
    let data = {};
    try { data = await response.json(); } catch (e) { data = {}; }
    if (!response.ok) {
        const detail = Array.isArray(data.detail) ? data.detail.map(i => i.msg).join(" ") : data.detail;
        throw new Error(detail || `Request failed (HTTP ${response.status}).`);
    }
    return data;
}

function applyUpdatedUser(user) {
    window.VULENSER_USER = user;
    renderUserProfile(user);
}

function setupProfileUI() {
    const popover = document.getElementById("profilePopover");
    const profileOpen = document.getElementById("profileOpen");

    const toggleMenu = () => popover?.classList.toggle("hidden");
    profileOpen?.addEventListener("click", e => { e.stopPropagation(); toggleMenu(); });
    profileOpen?.addEventListener("keydown", e => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); toggleMenu(); }
    });
    popover?.addEventListener("click", e => e.stopPropagation());

    // click outside / Escape closes menu and modal
    document.addEventListener("click", () => popover?.classList.add("hidden"));
    document.addEventListener("keydown", e => {
        if (e.key === "Escape") { popover?.classList.add("hidden"); closeProfileModal(); }
    });

    document.getElementById("menuProfile")?.addEventListener("click", openProfileModal);
    document.getElementById("menuSettings")?.addEventListener("click", () => {
        popover?.classList.add("hidden");
        if (typeof window.showView === "function") window.showView("settings");
    });

    document.getElementById("closeProfileEditor")?.addEventListener("click", closeProfileModal);
    document.getElementById("cancelProfileEditor")?.addEventListener("click", closeProfileModal);
    document.getElementById("profileEditor")?.addEventListener("click", e => {
        if (e.target.id === "profileEditor") closeProfileModal();
    });

    // Save name
    document.getElementById("saveProfileEditor")?.addEventListener("click", async event => {
        const button = event.currentTarget;
        const name = document.getElementById("profileNameInput").value.trim();
        if (name.length < 2) { setProfileMessage("profileMessage", "Please enter your full name (at least 2 characters).", false); return; }
        button.disabled = true;
        try {
            const data = await profileRequest("profile", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name })
            });
            applyUpdatedUser(data.user);
            setProfileMessage("profileMessage", "Profile updated.", true);
        } catch (err) {
            setProfileMessage("profileMessage", err.message, false);
        } finally { button.disabled = false; }
    });

    // Upload picture (saved immediately after choosing a file)
    document.getElementById("profilePhotoInput")?.addEventListener("change", async event => {
        const input = event.currentTarget;
        const file = input.files?.[0];
        if (!file) return;
        if (!/^image\/(png|jpeg|webp)$/.test(file.type) || file.size > 2 * 1024 * 1024) {
            setProfileMessage("profileMessage", "Choose a PNG, JPG or WEBP image up to 2 MB.", false);
            input.value = "";
            return;
        }
        const form = new FormData();
        form.append("file", file);
        try {
            const data = await profileRequest("avatar", { method: "POST", body: form });
            applyUpdatedUser(data.user);
            setProfileMessage("profileMessage", "Profile picture updated.", true);
        } catch (err) {
            setProfileMessage("profileMessage", err.message, false);
        } finally { input.value = ""; }
    });

    // Remove picture
    document.getElementById("removePhotoButton")?.addEventListener("click", async () => {
        try {
            const data = await profileRequest("avatar", { method: "DELETE" });
            applyUpdatedUser(data.user);
            setProfileMessage("profileMessage", "Profile picture removed.", true);
        } catch (err) {
            setProfileMessage("profileMessage", err.message, false);
        }
    });

    // Change password
    document.getElementById("changePasswordButton")?.addEventListener("click", async event => {
        const button = event.currentTarget;
        const current = document.getElementById("currentPasswordInput").value;
        const next = document.getElementById("newPasswordInput").value;
        if (!current || next.length < 8) { setProfileMessage("passwordMessage", "Enter your current password and a new one with at least 8 characters.", false); return; }
        button.disabled = true;
        try {
            await profileRequest("change-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ current_password: current, new_password: next })
            });
            document.getElementById("currentPasswordInput").value = "";
            document.getElementById("newPasswordInput").value = "";
            setProfileMessage("passwordMessage", "Password updated successfully.", true);
        } catch (err) {
            setProfileMessage("passwordMessage", err.message, false);
        } finally { button.disabled = false; }
    });

    // Logout
    document.getElementById("logoutButton")?.addEventListener("click", () => {
        popover?.classList.add("hidden");
        closeProfileModal();
        clearAuthSession();
        showAuthScreen();
    });
}

// ===============================
// DASHBOARD MANAGEMENT
// ===============================


function showAuthenticatedApp(user) {
    document.getElementById("authShell")?.classList.add("hidden");
    document.getElementById("appContainer")?.classList.remove("hidden");

    const isAdmin = user.role === "admin";

    // Update name / role / picture everywhere (sidebar, menu, profile modal)
    renderUserProfile(user);

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

    setupProfileUI();

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
