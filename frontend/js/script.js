/* =========================================
   SDLC VuLenseR
   RAG-Based Requirement Analyzer
========================================= */

const API_BASE_URL = "http://127.0.0.1:8000";

const HISTORY_KEY = "vulenser_analysis_history";
const THEME_KEY = "vulenser_theme";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

const getElement = (id) => document.getElementById(id);

let currentAnalysis = null;
let analysisHistory = loadHistory();


/* =========================================
   INITIALIZATION
========================================= */

document.addEventListener("DOMContentLoaded", () => {

    initializeNavigation();
    initializeTheme();
    initializeAnalyzer();
    initializeHistory();
    initializeReports();

    updateDashboard();
    updateHistory();
    updateReports();
    updateCharacterCount();

    createIcons();

    console.log("SDLC VuLenseR initialized.");

});


function createIcons() {
    if (window.lucide) {
        window.lucide.createIcons();
    }
}


/* =========================================
   NAVIGATION
========================================= */

function initializeNavigation() {

    $$(".nav-item[data-view]").forEach((item) => {

        item.addEventListener("click", () => {
            showView(item.dataset.view);
        });

    });

    $$("[data-go]").forEach((button) => {

        button.addEventListener("click", () => {
            showView(button.dataset.go);
        });

    });

    getElement("menuToggle")?.addEventListener("click", () => {

        getElement("sidebar")?.classList.toggle("sidebar-open");

    });

}


function showView(viewName) {

    $$(".nav-item[data-view]").forEach((item) => {

        item.classList.toggle(
            "active",
            item.dataset.view === viewName
        );

    });


    $$(".page-section").forEach((section) => {

        section.classList.toggle(
            "active",
            section.id === viewName
        );

    });


    const names = {
        dashboard: "Dashboard",
        analyzer: "Requirement Analyzer",
        history: "Analysis History",
        reports: "Reports",
        settings: "Settings"
    };

    const breadcrumb = getElement("breadcrumbTitle");

    if (breadcrumb) {
        breadcrumb.textContent = names[viewName] || viewName;
    }

    getElement("sidebar")?.classList.remove("sidebar-open");

    if (viewName === "history") updateHistory();
    if (viewName === "reports") updateReports();

}


/* =========================================
   THEME
========================================= */

function initializeTheme() {

    const savedTheme = localStorage.getItem(THEME_KEY) || "system";

    applyTheme(savedTheme);

    getElement("themeSelect")?.addEventListener("change", (event) => {

        applyTheme(event.target.value);

    });

    getElement("themeToggle")?.addEventListener("click", () => {

        const current = document.documentElement.dataset.theme;

        applyTheme(current === "dark" ? "light" : "dark");

    });

    window.matchMedia("(prefers-color-scheme: dark)")
        .addEventListener("change", () => {

            if (localStorage.getItem(THEME_KEY) === "system") {
                applyTheme("system");
            }

        });

}


function applyTheme(theme) {

    let activeTheme = theme;

    if (theme === "system") {

        activeTheme = window.matchMedia(
            "(prefers-color-scheme: dark)"
        ).matches ? "dark" : "light";

    }

    document.documentElement.dataset.theme = activeTheme;

    localStorage.setItem(THEME_KEY, theme);

    const select = getElement("themeSelect");

    if (select) {
        select.value = theme;
    }

    const icon = $("#themeToggle i");

    if (icon) {

        icon.setAttribute(
            "data-lucide",
            activeTheme === "dark" ? "sun" : "moon"
        );

        createIcons();

    }

}


/* =========================================
   ANALYZER
========================================= */

function initializeAnalyzer() {

    const form = getElement("analyzeForm");
    const input = getElement("requirementInput");

    if (!form || !input) return;

    input.addEventListener("input", updateCharacterCount);

    form.addEventListener("submit", async (event) => {

        event.preventDefault();

        await analyzeRequirement();

    });

    getElement("clearRequirement")?.addEventListener("click", () => {

        input.value = "";

        updateCharacterCount();
        hideResults();

        input.focus();

    });

    getElement("copyResults")?.addEventListener("click", copyResults);

    getElement("downloadReport")?.addEventListener("click", downloadReport);

}


function updateCharacterCount() {

    const input = getElement("requirementInput");
    const counter = getElement("characterCount");

    if (!input || !counter) return;

    counter.textContent =
        `${input.value.length.toLocaleString()} characters`;

}


/* =========================================
   API REQUEST
========================================= */

async function analyzeRequirement() {

    const input = getElement("requirementInput");
    const button = getElement("analyzeButton");

    const requirement = input?.value.trim();

    if (!requirement || requirement.length < 5) {

        showToast("Please enter a valid software requirement.");

        input?.focus();

        return;

    }

    button.disabled = true;

    showLoading();
    hideResults();

    try {

        const response = await fetch(
            `${API_BASE_URL}/analyze`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    requirement: requirement
                })
            }
        );


        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.detail || "Analysis failed."
            );

        }


        if (!data.success) {
            throw new Error("The analysis was not successful.");
        }


        currentAnalysis = {

            id: Date.now(),

            original_requirement:
                data.original_requirement || requirement,

            refined_requirement:
                data.refined_requirement || "",

            violations:
                Array.isArray(data.violations)
                    ? data.violations
                    : [],

            missing_requirements:
                Array.isArray(data.missing_requirements)
                    ? data.missing_requirements
                    : [],

            overall_score:
                Number(data.overall_score) || 0,

            created_at: new Date().toISOString()

        };


        saveAnalysis(currentAnalysis);

        displayResults(currentAnalysis);

        updateDashboard();
        updateHistory();
        updateReports();

        showToast("Analysis completed successfully.");


    } catch (error) {

        console.error("Analysis error:", error);

        if (error.message.includes("Failed to fetch")) {

            showToast(
                "Cannot connect to backend. Please start FastAPI."
            );

        } else {

            showToast(error.message);

        }

    } finally {

        hideLoading();

        button.disabled = false;

    }

}


/* =========================================
   DISPLAY RESULTS
========================================= */

function displayResults(analysis) {

    setText(
        "originalRequirement",
        analysis.original_requirement
    );

    setText(
        "refinedRequirement",
        analysis.refined_requirement || "No refined requirement available."
    );

    displayScore(analysis.overall_score);

    displayFindings(
        "violationsList",
        analysis.violations,
        "No violations or issues identified."
    );

    displayFindings(
        "missingRequirementsList",
        analysis.missing_requirements,
        "No important missing requirements identified."
    );


    getElement("resultsSection")?.classList.remove("hidden");

    createIcons();

    getElement("resultsSection")?.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

}


function setText(id, value) {

    const element = getElement(id);

    if (element) {
        element.textContent = value ?? "";
    }

}


/* =========================================
   SCORE
========================================= */

function displayScore(score) {

    const value = Math.max(
        0,
        Math.min(100, Number(score) || 0)
    );

    setText("overallScore", `${value}/100`);

    setText("scoreCircleValue", `${value}%`);

    const description = getElement("scoreDescription");
    const circle = getElement("scoreCircle");

    if (value >= 80) {

        if (description) {
            description.textContent = "Good requirement quality";
        }

    } else if (value >= 50) {

        if (description) {
            description.textContent = "Requirement needs improvement";
        }

    } else {

        if (description) {
            description.textContent = "Significant improvements needed";
        }

    }

    if (circle) {

        circle.style.background =
            `conic-gradient(var(--primary) ${value * 3.6}deg, var(--primary-light) 0deg)`;

    }

}


/* =========================================
   FINDINGS
========================================= */

function displayFindings(containerId, findings, emptyMessage) {

    const container = getElement(containerId);

    if (!container) return;

    container.replaceChildren();

    if (!Array.isArray(findings) || !findings.length) {

        const empty = document.createElement("div");

        empty.className = "empty-state";

        const message = document.createElement("span");

        message.textContent = emptyMessage;

        empty.appendChild(message);

        container.appendChild(empty);

        return;

    }


    findings.forEach((finding) => {

        const item = document.createElement("article");

        item.className = "finding-item";


        const top = document.createElement("div");

        top.className = "finding-top";


        const title = document.createElement("h4");

        title.textContent =
            finding.title || "Identified finding";


        top.appendChild(title);


        if (finding.severity) {

            const severity = document.createElement("span");

            const severityValue =
                String(finding.severity).toLowerCase();

            const allowed = ["high", "medium", "low"];

            const safeSeverity = allowed.includes(severityValue)
                ? severityValue
                : "low";

            severity.className =
                `severity severity-${safeSeverity}`;

            severity.textContent =
                capitalize(safeSeverity);

            top.appendChild(severity);

        }


        const description = document.createElement("p");

        description.textContent =
            finding.description || "No additional description.";


        item.append(top, description);

        container.appendChild(item);

    });

}


/* =========================================
   LOADING
========================================= */

function showLoading() {

    getElement("loadingState")?.classList.remove("hidden");

}

function hideLoading() {

    getElement("loadingState")?.classList.add("hidden");

}

function hideResults() {

    getElement("resultsSection")?.classList.add("hidden");

    currentAnalysis = null;

}


/* =========================================
   HISTORY STORAGE
========================================= */

function loadHistory() {

    try {

        const data = JSON.parse(
            localStorage.getItem(HISTORY_KEY) || "[]"
        );

        return Array.isArray(data) ? data : [];

    } catch {

        return [];

    }

}


function saveHistory() {

    try {

        localStorage.setItem(
            HISTORY_KEY,
            JSON.stringify(analysisHistory)
        );

    } catch (error) {

        console.error("History saving error:", error);

        showToast("Unable to save analysis history.");

    }

}


function saveAnalysis(analysis) {

    analysisHistory.unshift(analysis);

    saveHistory();

}


/* =========================================
   HISTORY PAGE
========================================= */

function initializeHistory() {

    getElement("historySearch")?.addEventListener(
        "input",
        updateHistory
    );


    getElement("clearHistory")?.addEventListener("click", () => {

        if (!analysisHistory.length) {

            showToast("History is already empty.");

            return;

        }

        if (!confirm("Are you sure you want to clear all analysis history?")) {
            return;
        }

        analysisHistory = [];

        saveHistory();

        updateHistory();
        updateDashboard();
        updateReports();

        showToast("Analysis history cleared.");

    });

}


function updateHistory() {

    const container = getElement("historyList");

    if (!container) return;

    const search = (
        getElement("historySearch")?.value || ""
    ).toLowerCase().trim();


    const filtered = analysisHistory.filter((item) => {

        return (
            item.original_requirement || ""
        ).toLowerCase().includes(search);

    });


    container.replaceChildren();


    if (!filtered.length) {

        container.innerHTML = `
            <div class="empty-state">
                <i data-lucide="history"></i>
                <strong>No analysis history</strong>
                <span>Your completed analyses will appear here.</span>
            </div>
        `;

        createIcons();

        return;

    }


    filtered.forEach((item) => {

        const card = document.createElement("article");

        card.className = "history-item";


        const info = document.createElement("div");

        info.className = "history-item-info";


        const title = document.createElement("h4");

        title.textContent = truncateText(
            item.original_requirement,
            100
        );


        const date = document.createElement("p");

        date.textContent = formatDate(item.created_at);


        info.append(title, date);


        const actions = document.createElement("div");

        actions.className = "history-meta";


        const risk = detectRisk(item.violations);


        const badge = document.createElement("span");

        badge.className = `risk-badge risk-${risk}`;

        badge.textContent = `${capitalize(risk)} risk`;


        const viewButton = document.createElement("button");

        viewButton.className = "secondary-button";

        viewButton.textContent = "View";


        viewButton.addEventListener("click", () => {

            currentAnalysis = item;

            displayResults(item);

            showView("analyzer");

        });


        actions.append(badge, viewButton);

        card.append(info, actions);

        container.appendChild(card);

    });

}


/* =========================================
   DASHBOARD
========================================= */

function updateDashboard() {

    setText(
        "totalAnalyses",
        analysisHistory.length
    );


    const highRisks = analysisHistory.filter((item) => {

        return detectRisk(item.violations) === "high";

    }).length;


    setText("highRisks", highRisks);


    let average = 0;

    if (analysisHistory.length) {

        const total = analysisHistory.reduce(
            (sum, item) => sum + (Number(item.overall_score) || 0),
            0
        );

        average = Math.round(
            total / analysisHistory.length
        );

    }


    setText(
        "averageScore",
        analysisHistory.length ? `${average}%` : "--"
    );


    updateRecentActivity();

}


function updateRecentActivity() {

    const container = getElement("recentActivity");

    if (!container) return;

    container.replaceChildren();


    const recent = analysisHistory.slice(0, 4);


    if (!recent.length) {

        container.innerHTML = `
            <div class="empty-state">
                <i data-lucide="inbox"></i>
                <strong>No analyses yet</strong>
                <span>Your recent activity will appear here.</span>
            </div>
        `;

        createIcons();

        return;

    }


    recent.forEach((item) => {

        const row = document.createElement("div");

        row.className = "activity-item";


        const info = document.createElement("div");

        const title = document.createElement("h4");

        title.textContent = truncateText(
            item.original_requirement,
            65
        );


        const date = document.createElement("p");

        date.textContent = formatDate(item.created_at);


        info.append(title, date);


        const score = document.createElement("span");

        score.className = "risk-badge risk-low";

        score.textContent =
            `${Number(item.overall_score) || 0}%`;


        row.append(info, score);

        container.appendChild(row);

    });

}


function detectRisk(violations) {

    if (!Array.isArray(violations)) return "low";

    const severities = violations.map((item) => {

        return String(item.severity || "").toLowerCase();

    });


    if (severities.includes("high")) return "high";

    if (severities.includes("medium")) return "medium";

    return "low";

}


/* =========================================
   COPY RESULTS
========================================= */

async function copyResults() {

    if (!currentAnalysis) {

        showToast("No analysis available to copy.");

        return;

    }

    try {

        await navigator.clipboard.writeText(
            buildReportText(currentAnalysis)
        );

        showToast("Analysis copied successfully.");

    } catch (error) {

        console.error(error);

        showToast("Clipboard access failed.");

    }

}


/* =========================================
   REPORT EXPORT
========================================= */

function buildReportText(analysis) {

    const violations = analysis.violations.map((item, index) => {

        return `${index + 1}. ${item.title}
Severity: ${item.severity || "Not specified"}
${item.description}`;

    }).join("\n\n");


    const missing = analysis.missing_requirements.map((item, index) => {

        return `${index + 1}. ${item.title}
${item.description}`;

    }).join("\n\n");


    return `
SDLC VuLenseR
SECURE REQUIREMENT ANALYSIS REPORT

Date: ${formatDate(analysis.created_at)}

OVERALL SCORE
${analysis.overall_score}/100

ORIGINAL REQUIREMENT
${analysis.original_requirement}

REFINED REQUIREMENT
${analysis.refined_requirement}

VIOLATIONS / ISSUES
${violations || "No issues identified."}

MISSING REQUIREMENTS
${missing || "No missing requirements identified."}
`.trim();

}


function downloadReport() {

    if (!currentAnalysis) {

        showToast("No analysis available to export.");

        return;

    }


    const content = buildReportText(currentAnalysis);


    const blob = new Blob(
        [content],
        { type: "text/plain;charset=utf-8" }
    );


    const url = URL.createObjectURL(blob);


    const link = document.createElement("a");

    link.href = url;

    link.download =
        `VuLenseR_Report_${Date.now()}.txt`;


    document.body.appendChild(link);

    link.click();

    link.remove();

    URL.revokeObjectURL(url);


    showToast("Report downloaded successfully.");

}


/* =========================================
   REPORTS PAGE
========================================= */

function initializeReports() {

    updateReports();

}


function updateReports() {

    const container = getElement("reportsContent");

    if (!container) return;

    container.replaceChildren();


    if (!analysisHistory.length) {

        container.innerHTML = `
            <div class="empty-state">
                <i data-lucide="file-chart-column"></i>
                <strong>No reports available</strong>
                <span>Analyze a requirement to generate a report.</span>
                <button class="primary-button" data-go="analyzer">
                    Create New Analysis
                </button>
            </div>
        `;

        container.querySelector("[data-go]")?.addEventListener(
            "click",
            () => showView("analyzer")
        );

        createIcons();

        return;

    }


    analysisHistory.forEach((item) => {

        const card = document.createElement("article");

        card.className = "report-card";


        const info = document.createElement("div");

        info.className = "report-info";


        const title = document.createElement("h3");

        title.textContent = truncateText(
            item.original_requirement,
            90
        );


        const date = document.createElement("p");

        date.textContent = formatDate(item.created_at);


        info.append(title, date);


        const button = document.createElement("button");

        button.className = "secondary-button";

        button.textContent = "Export";


        button.addEventListener("click", () => {

            currentAnalysis = item;

            downloadReport();

        });


        card.append(info, button);

        container.appendChild(card);

    });

}


/* =========================================
   UTILITIES
========================================= */

function truncateText(text, maxLength = 80) {

    const value = String(text ?? "");

    return value.length <= maxLength
        ? value
        : value.slice(0, maxLength).trim() + "...";

}


function formatDate(value) {

    if (!value) return "Unknown date";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "Unknown date";
    }

    return date.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
    });

}


function capitalize(value) {

    const text = String(value || "");

    return text
        ? text.charAt(0).toUpperCase() + text.slice(1)
        : "";

}


/* =========================================
   TOAST
========================================= */

function showToast(message) {

    const toast = getElement("toast");

    if (!toast) {

        console.log(message);

        return;

    }


    toast.textContent = message;

    toast.classList.add("show");


    clearTimeout(showToast.timeout);


    showToast.timeout = setTimeout(() => {

        toast.classList.remove("show");

    }, 3000);

}