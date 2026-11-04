"""
rag_engine.py - ChromaDB based RAG layer for the Hybrid Requirements Vulnerability Analyzer.

Kaam:
    requirement text -> (semantic top-k) -> relevant OWASP / secure-requirement chunks -> context string
    Ye string main.py ke zariye ai_engine ko "rag_context" ke tor par jati hai.

Design:
    - Knowledge base code ke andar hai (KNOWLEDGE_BASE): 10 OWASP Top 10 2021 summaries +
      rule_engine ki har category ke liye ek secure-requirement pattern + 2 extra chunks.
    - ChromaDB client sirf ek baar banta hai (cached), har request par nahi.
    - Koi bhi failure (model download, DB error) request ko nahi todta: empty string wapas aati hai
      aur pipeline bina RAG ke chalti hai.
    - chromadb import lazy hai, isliye is module ke tests chromadb ke bina bhi chalte hain.

Env (sab optional):
    CHROMA_DB_PATH     default "./chroma_db"
    RAG_MAX_DISTANCE   agar set ho to is se zyada distance wale chunks drop ho jate hain
                       (distance collection ke default metric mein hai; pehle logs dekh kar tune karein)

IMPORTANT: KNOWLEDGE_BASE edit karein to KB_VERSION badal dein, warna purani collection use hoti rahegi.
"""

import logging
import os
import threading
import time
from typing import Dict, List, Optional

logger = logging.getLogger("srs_analyzer.rag")

DB_PATH = os.getenv("CHROMA_DB_PATH", "./chroma_db")
KB_VERSION = "1"
COLLECTION_NAME = f"srs_security_kb_v{KB_VERSION}"
DEFAULT_TOP_K = 3
RETRY_AFTER_SECONDS = 60  # init fail ho to itni der tak dobara try nahi karte

A01 = "A01:2021 Broken Access Control"
A02 = "A02:2021 Cryptographic Failures"
A03 = "A03:2021 Injection"
A04 = "A04:2021 Insecure Design"
A05 = "A05:2021 Security Misconfiguration"
A06 = "A06:2021 Vulnerable and Outdated Components"
A07 = "A07:2021 Identification and Authentication Failures"
A08 = "A08:2021 Software and Data Integrity Failures"
A09 = "A09:2021 Security Logging and Monitoring Failures"
A10 = "A10:2021 Server-Side Request Forgery (SSRF)"

_SRC_OWASP = "OWASP Top 10 2021 (summary)"
_SRC_PATTERN = "Secure requirement pattern (project guidance)"
_SRC_STD = "IEEE 830 / ISO 29148 guidance"


def _kb(id_: str, owasp: str, topic: str, source: str, text: str) -> Dict[str, str]:
    return {"id": id_, "owasp": owasp, "topic": topic, "source": source, "text": text}


KNOWLEDGE_BASE: List[Dict[str, str]] = [
    # ---- 10 OWASP Top 10 2021 category summaries ----
    _kb("owasp-a01", A01, "owasp_a01", _SRC_OWASP,
        "Broken Access Control: every request must be authorized on the server using deny-by-default rules. "
        "Enforce ownership and role checks on each object and function, apply least privilege, and never rely "
        "on hidden UI elements or client-supplied identifiers for access decisions."),
    _kb("owasp-a02", A02, "owasp_a02", _SRC_OWASP,
        "Cryptographic Failures: classify sensitive data and protect it in transit (TLS) and at rest with strong, "
        "current algorithms and proper key management. Store passwords only as salted hashes made with a slow "
        "password-hashing function (Argon2id, bcrypt or scrypt), never in plain text or reversible encryption."),
    _kb("owasp-a03", A03, "owasp_a03", _SRC_OWASP,
        "Injection: treat all external input as untrusted. Validate on the server with allow-lists, use "
        "parameterized queries or prepared statements for database access, and apply context-aware output "
        "encoding to prevent SQL, command and cross-site scripting attacks."),
    _kb("owasp-a04", A04, "owasp_a04", _SRC_OWASP,
        "Insecure Design: security requirements must be defined during requirements and design, not added later. "
        "Use threat modeling, abuse cases and secure design patterns, and state limits (rate, size, quota) and "
        "failure behavior explicitly."),
    _kb("owasp-a05", A05, "owasp_a05", _SRC_OWASP,
        "Security Misconfiguration: ship with secure defaults, remove unused features and default credentials, "
        "harden servers and frameworks, and show users only generic error messages without stack traces or "
        "system details."),
    _kb("owasp-a06", A06, "owasp_a06", _SRC_OWASP,
        "Vulnerable and Outdated Components: keep an inventory of third-party libraries, pin versions, scan "
        "dependencies for known vulnerabilities (CVEs) with software composition analysis, and define a "
        "patch and update process."),
    _kb("owasp-a07", A07, "owasp_a07", _SRC_OWASP,
        "Identification and Authentication Failures: protect authentication with multi-factor authentication "
        "where risk warrants, throttling or lockout and CAPTCHA against brute force, generic login errors, a "
        "strong password policy, and secure session management with timeouts and invalidation on logout."),
    _kb("owasp-a08", A08, "owasp_a08", _SRC_OWASP,
        "Software and Data Integrity Failures: verify the integrity of code, updates and data using digital "
        "signatures or checksums, protect the CI/CD pipeline, and avoid deserializing untrusted data."),
    _kb("owasp-a09", A09, "owasp_a09", _SRC_OWASP,
        "Security Logging and Monitoring Failures: log authentication events, access-control failures and "
        "input-validation failures with enough context, protect logs from tampering, keep credentials and "
        "sensitive personal data out of logs, and alert on suspicious activity."),
    _kb("owasp-a10", A10, "owasp_a10", _SRC_OWASP,
        "Server-Side Request Forgery (SSRF): when the server fetches a user-supplied URL, validate the "
        "destination against an allow-list, restrict schemes and ports, block internal and link-local address "
        "ranges, and do not return raw responses to the user."),

    # ---- one pattern per rule_engine.SECURITY_CONTROLS category (topic == category key) ----
    _kb("pattern-password_reset", A07, "password_reset", _SRC_PATTERN,
        "Password reset requirement pattern: the system shall send a single-use, time-limited reset token "
        "(for example valid for 15 minutes) and invalidate it after use or when a new one is requested; "
        "shall rate-limit reset requests; shall show the same generic response whether or not the account "
        "exists to prevent user enumeration; and shall notify the user after a password change."),
    _kb("pattern-login", A07, "login", _SRC_PATTERN,
        "Login requirement pattern: the system shall authenticate users over TLS, support multi-factor "
        "authentication for sensitive accounts, throttle or lock out repeated failed attempts, show generic "
        "error messages that do not reveal whether the username or the password was wrong, and create a "
        "secure session after successful login."),
    _kb("pattern-file_upload", A04, "file_upload", _SRC_PATTERN,
        "File upload requirement pattern: the system shall validate file type by content (MIME/signature) and "
        "not only by extension, enforce a maximum file size and per-user quota, scan files for malware, rename "
        "files on storage, and store them outside the web root without execute permission."),
    _kb("pattern-logging_audit", A09, "logging_audit", _SRC_PATTERN,
        "Logging and audit requirement pattern: the system shall record security events (logins, failures, "
        "privilege changes, access denials) with timestamp, user and source, protect logs against tampering "
        "(append-only or integrity-protected), mask or exclude passwords and personal data, and define a "
        "retention period."),
    _kb("pattern-admin_privileges", A01, "admin_privileges", _SRC_PATTERN,
        "Administrator privilege requirement pattern: the system shall grant admin rights on a least-privilege "
        "basis, require multi-factor authentication for administrative access, separate administrative "
        "functions by role, optionally restrict admin access by IP allow-list, and audit every administrative "
        "action."),
    _kb("pattern-ssrf_fetch", A10, "ssrf_fetch", _SRC_PATTERN,
        "Outbound request requirement pattern: when the system fetches a URL or calls a webhook supplied by a "
        "user, it shall allow only approved destinations (allow-list), accept only http/https, block private, "
        "loopback and link-local IP ranges, limit redirects, and apply timeouts."),
    _kb("pattern-encryption_transit_rest", A02, "encryption_transit_rest", _SRC_PATTERN,
        "Encryption requirement pattern: the system shall protect data in transit with TLS 1.2 or higher "
        "(TLS 1.3 preferred), encrypt sensitive data at rest with a strong algorithm such as AES-256, and "
        "manage keys securely with defined rotation; passwords shall be hashed with Argon2id or bcrypt."),
    _kb("pattern-session", A07, "session", _SRC_PATTERN,
        "Session management requirement pattern: the system shall expire sessions after an idle timeout and an "
        "absolute lifetime, issue a new session identifier after login, invalidate the session on logout, and "
        "set cookies with the Secure, HttpOnly and SameSite attributes."),
    _kb("pattern-api", A01, "api", _SRC_PATTERN,
        "API requirement pattern: every endpoint shall authenticate the caller and authorize each request on "
        "the server, validate request schema and parameters, apply rate limiting, restrict CORS to approved "
        "origins, and keep secrets and tokens out of URLs."),
    _kb("pattern-input", A03, "input", _SRC_PATTERN,
        "Input handling requirement pattern: the system shall validate all user input on the server against "
        "an allow-list of type, length and format, use parameterized queries for database access, and encode "
        "output for its context (HTML, URL, JavaScript)."),
    _kb("pattern-payment", A02, "payment", _SRC_PATTERN,
        "Payment requirement pattern: the system shall process card data only through a PCI DSS compliant "
        "gateway, use tokenization instead of storing card numbers, never store the card security code, "
        "transmit payment data over TLS, and log payment events without card data."),
    _kb("pattern-role", A01, "role", _SRC_PATTERN,
        "Role-based access requirement pattern: the system shall define roles and their permissions "
        "explicitly (RBAC), grant the minimum rights needed, deny by default, enforce role checks on the "
        "server for every function, and review role assignments periodically."),
    _kb("pattern-error", A05, "error", _SRC_PATTERN,
        "Error handling requirement pattern: the system shall show users a generic error message without "
        "stack traces, SQL errors or internal paths, record the technical detail in secure logs, and fail "
        "closed (deny access) when an error occurs in a security check."),
    _kb("pattern-data", A02, "data", _SRC_PATTERN,
        "Sensitive data requirement pattern: the system shall classify user data, collect only what is "
        "needed, encrypt sensitive fields at rest, mask them when displayed, and restrict access to them by "
        "role."),
    _kb("pattern-object_access", A01, "object_access", _SRC_PATTERN,
        "Object-level access requirement pattern (IDOR prevention): when a user views, edits, downloads or "
        "deletes a record, the system shall verify on the server that the record belongs to that user or that "
        "the user's role permits access, regardless of the identifier supplied in the request, and return "
        "an authorization error otherwise."),
    _kb("pattern-privacy_gdpr", A04, "privacy_gdpr", _SRC_PATTERN,
        "Privacy requirement pattern: the system shall collect personal data only with a stated purpose and "
        "user consent, minimize what is stored, define a retention period, support access and erasure "
        "requests from data subjects, and anonymize data used for analytics where possible."),
    _kb("pattern-account_lockout", A07, "account_lockout", _SRC_PATTERN,
        "Brute-force protection requirement pattern: after a defined number of failed login attempts (for "
        "example 5) the system shall temporarily lock the account or apply increasing delays, may require "
        "CAPTCHA, shall rate-limit by account and by source IP, and shall notify the user of repeated "
        "failures."),
    _kb("pattern-backup_recovery", A05, "backup_recovery", _SRC_PATTERN,
        "Backup and recovery requirement pattern: the system shall encrypt backups, restrict access to them "
        "by role, keep at least one copy offline or in a separate location, define a retention period, and "
        "test restoration at defined intervals."),
    _kb("pattern-third_party_deps", A06, "third_party_deps", _SRC_PATTERN,
        "Third-party component requirement pattern: the project shall maintain an inventory of libraries, pin "
        "dependency versions, scan dependencies for known vulnerabilities (CVEs) on every build, take "
        "components only from trusted sources, and patch critical findings within a defined time."),
    _kb("pattern-config_deploy", A05, "config_deploy", _SRC_PATTERN,
        "Deployment and configuration requirement pattern: the system shall ship with secure defaults and no "
        "default credentials, disable unused services and debug features in production, keep secrets out of "
        "source code, and apply configuration through a reviewed CI/CD pipeline."),

    # ---- extra chunks ----
    _kb("pattern-integrity_updates", A08, "integrity_updates", _SRC_PATTERN,
        "Update and integrity requirement pattern: the system shall install software updates only when their "
        "digital signature or checksum is verified, shall protect the build and deployment pipeline with "
        "access control and review, and shall not deserialize untrusted data."),
    _kb("std-requirement_writing", "N/A", "requirement_writing", _SRC_STD,
        "Writing testable requirements: use 'shall' for mandatory behavior, replace vague words (fast, secure, "
        "user-friendly, if possible, as needed) with measurable values and explicit conditions, state one "
        "requirement per sentence, and add acceptance criteria so each requirement can be verified by a test."),
]


# ---------------------------------------------------------------------------
# Collection handling (cached, thread-safe)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_collection = None
_last_failure: Optional[float] = None


def _seed(collection) -> None:
    """KNOWLEDGE_BASE ko collection mein upsert karta hai (dobara chalane par duplicate nahi banta)."""
    collection.upsert(
        ids=[item["id"] for item in KNOWLEDGE_BASE],
        documents=[item["text"] for item in KNOWLEDGE_BASE],
        metadatas=[
            {"owasp": item["owasp"], "topic": item["topic"], "source": item["source"]}
            for item in KNOWLEDGE_BASE
        ],
    )


def _get_collection():
    """Cached ChromaDB collection; fail ho to None (aur 60s tak dobara koshish nahi)."""
    global _collection, _last_failure

    if _collection is not None:
        return _collection

    with _lock:
        if _collection is not None:
            return _collection
        if _last_failure is not None and time.monotonic() - _last_failure < RETRY_AFTER_SECONDS:
            return None
        try:
            import chromadb  # lazy: tests aur chromadb-less environments ke liye

            client = chromadb.PersistentClient(path=DB_PATH)
            collection = client.get_or_create_collection(name=COLLECTION_NAME)
            if collection.count() != len(KNOWLEDGE_BASE):
                logger.info("Seeding RAG knowledge base (%d chunks)", len(KNOWLEDGE_BASE))
                _seed(collection)
            _collection = collection
            _last_failure = None
            logger.info("RAG ready: collection=%s chunks=%d", COLLECTION_NAME, collection.count())
        except Exception:
            _last_failure = time.monotonic()
            logger.exception("RAG initialization failed; continuing without RAG")
            return None
    return _collection


def warm_up() -> bool:
    """Server start par call karein. Pehli baar embedding model download hota hai (internet chahiye)."""
    collection = _get_collection()
    if collection is None:
        return False
    try:
        collection.query(query_texts=["warm up"], n_results=1)
        return True
    except Exception:
        logger.exception("RAG warm-up query failed")
        return False


def is_ready() -> bool:
    return _collection is not None


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
def _max_distance() -> Optional[float]:
    raw = os.getenv("RAG_MAX_DISTANCE", "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        logger.warning("Invalid RAG_MAX_DISTANCE=%r ignored", raw)
        return None


def _format_context(hits: List[dict]) -> str:
    lines = []
    for hit in hits:
        meta = hit.get("meta") or {}
        label = " | ".join(p for p in (meta.get("owasp", ""), meta.get("topic", "")) if p)
        lines.append(f"- [{label}] {hit['doc']}" if label else f"- {hit['doc']}")
    return "\n".join(lines)


def retrieve_relevant_context(requirement_text: str, n_results: int = DEFAULT_TOP_K) -> str:
    """Requirement ke liye top-k relevant chunks ek string mein. Kabhi raise nahi karta; fail par ''."""
    if not isinstance(requirement_text, str) or not requirement_text.strip():
        return ""

    collection = _get_collection()
    if collection is None:
        return ""

    n = max(1, min(int(n_results), len(KNOWLEDGE_BASE)))
    try:
        result = collection.query(
            query_texts=[requirement_text],
            n_results=n,
            include=["documents", "metadatas", "distances"],
        )
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        dists = (result.get("distances") or [[]])[0]
    except Exception:
        logger.exception("RAG query failed")
        return ""

    limit = _max_distance()
    hits = []
    for i, doc in enumerate(docs):
        dist = dists[i] if i < len(dists) else None
        meta = metas[i] if i < len(metas) else {}
        logger.info("RAG hit: topic=%s distance=%s", (meta or {}).get("topic"), dist)
        if limit is not None and dist is not None and dist > limit:
            continue
        hits.append({"doc": doc, "meta": meta})

    return _format_context(hits)
