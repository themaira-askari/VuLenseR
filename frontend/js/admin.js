const ADMIN_API = "http://127.0.0.1:8000";

async function adminRequest(path, options = {}) {
    const response = await window.vulenserAuthFetch(`${ADMIN_API}${path}`, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Admin request failed.");
    return data;
}

function adminToast(message) {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2800);
}

function setAdminText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value ?? "0";
}

function makeCell(value) {
    const cell = document.createElement("td");
    cell.textContent = value ?? "—";
    return cell;
}

function makeStatusCell(value) {
    const cell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `status-pill ${value === "Completed" || value === "Indexed" ? "" : "inactive"}`;
    badge.textContent = value || "Unknown";
    cell.appendChild(badge);
    return cell;
}

function formatAdminDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function loadAdminOverview() {
    const data = await adminRequest("/admin/overview");
    setAdminText("adminTotalAnalyses", data.total_analyses);
    setAdminText("adminTotalViolations", data.total_violations);
    setAdminText("adminTotalSecurityFlaws", data.total_security_flaws);
    setAdminText("adminDocumentCount", data.document_count);
    setAdminText("adminIndexedChunks", data.indexed_chunks);

    const body = document.getElementById("adminRecentActivity");
    if (!body) return;
    body.replaceChildren();
    if (!data.recent_activity.length) {
        const row = document.createElement("tr");
        const cell = makeCell("No analysis activity yet.");
        cell.colSpan = 6;
        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    data.recent_activity.forEach(item => {
        const row = document.createElement("tr");
        row.append(
            makeCell((item.requirement || "").length > 75 ? `${item.requirement.slice(0, 75)}…` : item.requirement),
            makeCell(item.user),
            makeCell(item.violations),
            makeCell(item.security_flaws),
            makeCell(item.score == null ? "—" : `${item.score}/100`),
            makeCell(formatAdminDate(item.created_at))
        );
        body.appendChild(row);
    });
}

async function loadAdminDocuments() {
    const data = await adminRequest("/admin/documents");
    const body = document.getElementById("adminDocumentsTable");
    if (!body) return;
    body.replaceChildren();

    if (!data.documents.length) {
        const row = document.createElement("tr");
        const cell = makeCell("No knowledge-base documents found.");
        cell.colSpan = 10;
        row.appendChild(cell);
        body.appendChild(row);
    }

    data.documents.forEach(doc => {
        const row = document.createElement("tr");
        row.append(
            makeCell(doc.name),
            makeCell(doc.category),
            makeCell(doc.version),
            makeCell(doc.format),
            makeStatusCell(doc.extraction_status),
            makeStatusCell(doc.chunking_status),
            makeCell(`${doc.indexed_chunks}/${doc.chunks}`),
            makeStatusCell(doc.embedding_status),
            makeStatusCell(doc.indexing_status)
        );

        const actionCell = document.createElement("td");
        const remove = document.createElement("button");
        remove.className = "danger";
        remove.textContent = "Delete";
        remove.addEventListener("click", async () => {
            if (!confirm(`Delete ${doc.name} and rebuild the knowledge base?`)) return;
            try {
                await adminRequest(`/admin/documents/${encodeURIComponent(doc.category)}/${encodeURIComponent(doc.name)}`, { method: "DELETE" });
                await refreshAdmin();
                adminToast("Document deleted and knowledge base rebuilt.");
            } catch (error) { adminToast(error.message); }
        });
        actionCell.appendChild(remove);
        row.appendChild(actionCell);
        body.appendChild(row);
    });

    const totalChunks = data.documents.reduce((sum, item) => sum + item.chunks, 0);
    const indexedChunks = data.documents.reduce((sum, item) => sum + item.indexed_chunks, 0);
    setAdminText("indexingSummary", `${indexedChunks} of ${totalChunks} document chunks indexed.`);
}

async function refreshAdmin() {
    try {
        await Promise.all([loadAdminOverview(), loadAdminDocuments()]);
    } catch (error) {
        adminToast(error.message);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("refreshAdmin")?.addEventListener("click", refreshAdmin);
    document.getElementById("refreshDocuments")?.addEventListener("click", () => loadAdminDocuments().catch(error => adminToast(error.message)));

    document.getElementById("uploadDocumentButton")?.addEventListener("click", async () => {
        const fileInput = document.getElementById("knowledgeDocument");
        const file = fileInput?.files?.[0];
        if (!file) {
            adminToast("Select a document first.");
            return;
        }

        const form = new FormData();
        form.append("file", file);
        form.append("category", document.getElementById("documentCategory").value);
        form.append("replace_existing", document.getElementById("replaceDocument").checked ? "true" : "false");

        const button = document.getElementById("uploadDocumentButton");
        button.disabled = true;
        try {
            const data = await adminRequest("/admin/documents", { method: "POST", body: form });
            fileInput.value = "";
            document.getElementById("replaceDocument").checked = false;
            await refreshAdmin();
            adminToast(`Document indexed successfully (${data.indexed_chunks} chunks).`);
        } catch (error) {
            adminToast(error.message);
        } finally {
            button.disabled = false;
        }
    });

    document.getElementById("retryIndexing")?.addEventListener("click", async () => {
        const button = document.getElementById("retryIndexing");
        button.disabled = true;
        try {
            const data = await adminRequest("/admin/documents/reindex", { method: "POST" });
            await refreshAdmin();
            adminToast(`Knowledge base re-indexed (${data.indexed_chunks} chunks).`);
        } catch (error) {
            adminToast(error.message);
        } finally {
            button.disabled = false;
        }
    });

    window.addEventListener("vulenser:authenticated", event => {
        if (event.detail.role === "admin") refreshAdmin();
    });
});
