/* =========================================
   SDLC VuLenser
   RAG-Based Requirement Analyzer
========================================= */

const API_BASE_URL = window.VULENSER_API_BASE || "http://127.0.0.1:8000";

const HISTORY_KEY = "vulenser_analysis_history";
const THEME_KEY = "vulenser_theme";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

const getElement = (id) => document.getElementById(id);

let currentAnalysis = null;
let analysisHistory = [];


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

    window.addEventListener("vulenser:authenticated", () => {
        refreshUserHistory();
    });

    console.log("SDLC VuLenser initialized.");

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

    // Mobile Sidebar Toggle
    getElement("menuToggle")?.addEventListener("click", () => {

        getElement("sidebar")?.classList.toggle("sidebar-open");

    });

    // Desktop Sidebar Collapse / Expand
    const sidebarToggle = getElement("sidebarToggle");
    const appContainer = getElement("appContainer");

    sidebarToggle?.addEventListener("click", () => {

        if (!appContainer) return;

        const isCollapsed = appContainer.classList.toggle(
            "sidebar-collapsed"
        );

        const icon = sidebarToggle.querySelector("i");

        if (icon) {
            icon.setAttribute(
                "data-lucide",
                isCollapsed ? "panel-left-open" : "panel-left-close"
            );
        }

        sidebarToggle.setAttribute(
            "title",
            isCollapsed ? "Expand sidebar" : "Collapse sidebar"
        );

        sidebarToggle.setAttribute(
            "aria-label",
            isCollapsed ? "Expand sidebar" : "Collapse sidebar"
        );

        if (typeof createIcons === "function") {
            createIcons();
        }

    });

}




function showView(viewName) {

    const user = window.VULENSER_USER;
    const isAdmin = user?.role === "admin";

    // Prevent users from opening Admin Panel
    if (viewName === "admin" && !isAdmin) {
        viewName = "dashboard";
    }

    // Prevent admins from opening User Workspace pages (Settings is allowed for everyone)
    if (isAdmin && viewName !== "admin" && viewName !== "settings") {
        viewName = "admin";
    }

    $$(".nav-item[data-view]").forEach(item => {
        item.classList.toggle(
            "active",
            item.dataset.view === viewName
        );
    });

    $$(".page-section").forEach(section => {
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
        admin: "Admin Panel",
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

window.showView = showView;



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
    const documentInput = getElement("requirementDocument");

    if (!form || !input) return;

    input.addEventListener("input", updateCharacterCount);

    // Maximum file size: 20 KB
    documentInput?.addEventListener("change", function () {

        const file = this.files?.[0];

        if (!file) return;

        const MAX_FILE_SIZE = 20 * 1024;

        if (file.size > MAX_FILE_SIZE) {

            showToast("File size must not exceed 20 KB.");

            this.value = "";

            return;
        }

    });

    form.addEventListener("submit", async (event) => {

        event.preventDefault();

        await analyzeRequirement();

    });

    getElement("clearRequirement")?.addEventListener("click", () => {

        input.value = "";

        if (documentInput) {
            documentInput.value = "";
        }

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
const documentInput = getElement("requirementDocument");
const selectedDocument = documentInput?.files?.[0];

// Maximum upload size: 20 KB
const MAX_FILE_SIZE = 20 * 1024;

if (selectedDocument && selectedDocument.size > MAX_FILE_SIZE) {

    showToast("File size must not exceed 20 KB.");

    if (documentInput) {
        documentInput.value = "";
    }

    return;
}

    if ((!requirement || requirement.length < 5) && !selectedDocument) {

        showToast("Please enter a valid software requirement.");

        input?.focus();

        return;

    }

    button.disabled = true;

    showLoading();
    hideResults();

    try {

        const uploadedFile = selectedDocument;
        let response;
        if (uploadedFile) {
           if (uploadedFile.size > 20 * 1024) {
    throw new Error("Document must be 20 KB or smaller.");
}
            const formData = new FormData();
            formData.append("file", uploadedFile);
            response = await window.vulenserAuthFetch(`${API_BASE_URL}/analyze-document`, { method: "POST", body: formData });
        } else {
            response = await window.vulenserAuthFetch(`${API_BASE_URL}/analyze`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ requirement })
            });
        }


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


            quality_attributes:
                data.quality_attributes && typeof data.quality_attributes === "object"
                    ? data.quality_attributes
                    : {},

            quality_findings:
                Array.isArray(data.quality_findings)
                    ? data.quality_findings
                    : [],

            security_findings:
                Array.isArray(data.security_findings)
                    ? data.security_findings
                    : (Array.isArray(data.violations) ? data.violations : []),

            missing_security_requirements:
                Array.isArray(data.missing_security_requirements)
                    ? data.missing_security_requirements
                    : (Array.isArray(data.missing_requirements) ? data.missing_requirements : []),

          

            violations:
                Array.isArray(data.security_findings)
                    ? data.security_findings
                    : (Array.isArray(data.violations) ? data.violations : []),

            missing_requirements:
                Array.isArray(data.missing_security_requirements)
                    ? data.missing_security_requirements
                    : (Array.isArray(data.missing_requirements) ? data.missing_requirements : []),

            overall_score: Number.isFinite(Number(data.overall_score))
                ? Number(data.overall_score)
                : 100,

            retrieved_references:
                Array.isArray(data.retrieved_references) ? data.retrieved_references : [],

            rag_evidence_used: Boolean(data.rag_evidence_used),

            summary: data.summary && typeof data.summary === "object" ? data.summary : null,
            requirements: Array.isArray(data.requirements) ? data.requirements : [],
            all_quality_findings: Array.isArray(data.all_quality_findings) ? data.all_quality_findings : [],
            document_findings: Array.isArray(data.document_findings) ? data.document_findings : [],
            timings: data.timings && typeof data.timings === "object" ? data.timings : {},

            created_at: new Date().toISOString()

        };


        await saveAnalysis(currentAnalysis);

        displayResults(currentAnalysis);
        if (getElement("requirementDocument")) getElement("requirementDocument").value = "";

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

    displayScore(analysis.overall_score);

    // quality = blocks only (one per factor that really has an issue)
    const blocks = analysis.quality_attributes || {};
    displayQualityAttributes(blocks);
    if (Object.keys(blocks).length) {
        getElement("qualityFindingsList")?.replaceChildren();
    } else {
        displayFindings(
            "qualityFindingsList",
            [],
            "No significant quality issues were detected."
        );
    }

    // security = one simple list, grouped by OWASP Top 10 / ASVS reference
    displaySecurityFlaws([
        ...(analysis.security_findings || analysis.violations || []),
        ...(analysis.missing_security_requirements || analysis.missing_requirements || [])
    ]);

    getElement("resultsSection")?.classList.remove("hidden");

    createIcons();

    getElement("resultsSection")?.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

}




function displayQualityAttributes(attributes) {
    const container = getElement("qualityAttributes");
    if (!container) return;

    container.replaceChildren();

    // Fixed attributes are no longer produced; only old saved analyses still have them.
    if (!attributes || !Object.keys(attributes).length) return;

    // one block per factor the backend picked for THIS requirement (old history keys still work)
    Object.entries(attributes).forEach(([name, data]) => {
        data = data || {};
        const card = document.createElement("article");
        card.className = "quality-attribute";

        const heading = document.createElement("h4");
        heading.textContent = capitalize(name);

        const rating = document.createElement("span");
        const value = ["Good", "Moderate", "Poor"].includes(data.rating)
            ? data.rating
            : "Not assessed";
        rating.className = `quality-rating quality-${value.toLowerCase().replaceAll(" ", "-")}`;
        rating.textContent = value;

        const reason = document.createElement("p");
        reason.textContent = data.reason || "No separate explanation was provided.";

        card.append(heading, rating, reason);
        container.appendChild(card);
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

// Security flaws: a plain-language risk sentence + its real OWASP reference.
// Flaws that have a knowledge-base reference are grouped under Top 10 / ASVS.
function displaySecurityFlaws(findings) {
    const container = getElement("violationsList");
    if (!container) return;
    container.replaceChildren();

    const all = Array.isArray(findings) ? findings : [];
    const referenced = all.filter((f) => f.basis === "owasp" && f.reference_document);
    const shown = referenced.length ? referenced : all;   // hide unreferenced ones if we have referenced ones

    if (!shown.length) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        const message = document.createElement("span");
        message.textContent = "No relevant security flaws identified.";
        empty.appendChild(message);
        container.appendChild(empty);
        return;
    }

    const isTop10 = (f) => /top 10/i.test(f.reference_document || "");
    const isAsvs = (f) => /asvs/i.test(f.reference_document || "");
    const groups = [
        ["OWASP Top 10", shown.filter(isTop10)],
        ["OWASP ASVS", shown.filter((f) => !isTop10(f) && isAsvs(f))],
        ["", shown.filter((f) => !isTop10(f) && !isAsvs(f))]
    ];

    groups.forEach(([groupName, items]) => {
        if (!items.length) return;

        if (groupName) {
            const groupTitle = document.createElement("h4");
            groupTitle.className = "eyebrow";
            groupTitle.textContent = groupName;
            container.appendChild(groupTitle);
        }

        items.forEach((finding) => {
            const item = document.createElement("article");
            item.className = "finding-item";

            const top = document.createElement("div");
            top.className = "finding-top";

            const title = document.createElement("h4");
            title.textContent = finding.basis === "owasp" && finding.reference_document
                ? finding.reference_document
                : (finding.title || "Security flaw");
            top.appendChild(title);

            const level = String(finding.severity || "").toLowerCase();
            if (["high", "medium", "low"].includes(level)) {
                const badge = document.createElement("span");
                badge.className = `severity severity-${level}`;
                badge.textContent = capitalize(level);
                top.appendChild(badge);
            }

            const text = document.createElement("p");
            text.textContent = finding.description || "";

            item.append(top, text);
            container.appendChild(item);
        });
    });
}


function displayFindings(containerId, findings, emptyMessage, simple = false) {

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


        item.append(top);

        const metaParts = simple ? [] : [
            finding.requirement_id || (Array.isArray(finding.requirement_ids) ? finding.requirement_ids.join(", ") : ""),
            finding.category,
            finding.location
        ].filter(Boolean);
        if (metaParts.length) {
            const meta = document.createElement("p");
            meta.className = "finding-evidence";
            meta.textContent = metaParts.join(" | ");
            item.appendChild(meta);
        }

        item.append(description);

        if (!simple && finding.recommendation) {
            const recommendation = document.createElement("p");
            recommendation.className = "finding-recommendation";
            recommendation.textContent = `Suggested improvement: ${finding.recommendation}`;
            item.appendChild(recommendation);
        }

        // simple mode (security): show a reference only when it is a real OWASP knowledge-base one
        const reference = finding.reference_document || finding.source;
        if (reference && (!simple || finding.basis === "owasp")) {
            const evidence = document.createElement("p");
            evidence.className = "finding-evidence";
            evidence.textContent = simple
                ? `Reference: ${reference}`
                : `Reference: ${reference}${finding.reference_category ? ` | ${finding.reference_category}` : ""}`;
            item.appendChild(evidence);
        }

        if (!simple && finding.evidence_quote) {
            const quote = document.createElement("blockquote");
            quote.textContent = `Evidence: “${finding.evidence_quote}”`;
            item.appendChild(quote);
        }

        container.appendChild(item);

    });

}


/* =========================================
   LOADING
========================================= */

let loadingTimer = null;

function showLoading() {

    getElement("loadingState")?.classList.remove("hidden");

    // The API call is one request, so show the typical stage order while waiting.
    const stages = [
        "Reading the document and identifying requirements...",
        "Evaluating requirement quality...",
        "Retrieving relevant OWASP evidence...",
        "Running the security analysis...",
        "Validating findings and preparing the report..."
    ];
    let stage = 0;
    const message = getElement("loadingMessage");
    if (message) message.textContent = stages[0];
    clearInterval(loadingTimer);
    loadingTimer = setInterval(() => {
        stage = Math.min(stage + 1, stages.length - 1);
        if (message) message.textContent = stages[stage];
    }, 6000);

}

function hideLoading() {

    clearInterval(loadingTimer);

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
        const userId = window.VULENSER_USER?.id || "guest";
        const data = JSON.parse(localStorage.getItem(`${HISTORY_KEY}_${userId}`) || "[]");
        return Array.isArray(data) ? data : [];
    } catch { return []; }
}

function saveHistory() {
    try {
        const userId = window.VULENSER_USER?.id || "guest";
        localStorage.setItem(`${HISTORY_KEY}_${userId}`, JSON.stringify(analysisHistory));
    } catch (error) {
        console.error("History saving error:", error);
        showToast("Unable to cache analysis history.");
    }
}

async function saveAnalysis(analysis) {
    analysisHistory.unshift(analysis);
    saveHistory();
    try {
        await window.vulenserAuthFetch(`${API_BASE_URL}/analyses`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ original_requirement: analysis.original_requirement, result: {
                quality_attributes: analysis.quality_attributes || {},
                quality_findings: analysis.quality_findings || [],
                all_quality_findings: analysis.all_quality_findings || [],
                document_findings: analysis.document_findings || [],
                summary: analysis.summary || null,
                requirements: analysis.requirements || [],
                security_findings: analysis.security_findings || analysis.violations || [],
                missing_security_requirements: analysis.missing_security_requirements || analysis.missing_requirements || [],
            
                violations: analysis.security_findings || analysis.violations || [],
                missing_requirements: analysis.missing_security_requirements || analysis.missing_requirements || [],
                overall_score: analysis.overall_score,
                retrieved_references: analysis.retrieved_references || [],
                rag_evidence_used: Boolean(analysis.rag_evidence_used)
            }})
        });
    } catch (error) { console.error("Server history save failed:", error); }
}

async function refreshUserHistory() {
    try {
        const response = await window.vulenserAuthFetch(`${API_BASE_URL}/analyses`);
        const data = await response.json();
        if (response.ok && Array.isArray(data.analyses)) {
            analysisHistory = data.analyses;
            saveHistory();
            updateDashboard();
            updateHistory();
            updateReports();
        } else {
            analysisHistory = loadHistory();
        }
    } catch (error) {
        console.error("Unable to load saved analyses:", error);
        analysisHistory = loadHistory();
    }
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
        window.vulenserAuthFetch(`${API_BASE_URL}/analyses`, { method: "DELETE" })
            .catch(error => console.error("Server history clear failed:", error));

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

    const securityFindings = analysis.security_findings || analysis.violations || [];
    const missingSecurity = analysis.missing_security_requirements || analysis.missing_requirements || [];
    const qualityFindings = analysis.quality_findings || [];

    const quality = qualityFindings.map((item, index) => {
        return `${index + 1}. ${item.title}
${item.description}
Suggested improvement: ${item.recommendation || "Not provided"}`;
    }).join("\n\n");

    const violations = securityFindings.map((item, index) => {

        return `${index + 1}. ${item.title}
Severity: ${item.severity || "Not specified"}
${item.description}
Reference document: ${item.reference_document || item.source || "Original requirement"}
Reference category: ${item.reference_category || item.basis || "Requirement"}
Evidence: ${item.evidence_quote || "Based on submitted requirement"}`;

    }).join("\n\n");


    const missing = missingSecurity.map((item, index) => {

        return `${index + 1}. ${item.title}
${item.description}
Reference document: ${item.reference_document || item.source || "Original requirement"}
Reference category: ${item.reference_category || item.basis || "Requirement"}
Evidence: ${item.evidence_quote || "Based on submitted requirement"}`;

    }).join("\n\n");


    return `
SDLC VuLenser
SECURE REQUIREMENT ANALYSIS REPORT

Date: ${formatDate(analysis.created_at)}

OVERALL QUALITY SCORE
${analysis.overall_score}/100

REQUIREMENT QUALITY FINDINGS
${quality || "No quality issues identified."}

ORIGINAL REQUIREMENT
${analysis.original_requirement}

VIOLATIONS / ISSUES
${violations || "No issues identified."}

MISSING SECURITY REQUIREMENTS
${missing || "No missing security requirements identified."}



RAG EVIDENCE USED
${analysis.rag_evidence_used ? "Yes" : "No directly relevant knowledge-base evidence was retrieved."}
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
        `SDLC_VuLenser_Report_${Date.now()}.txt`;


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
