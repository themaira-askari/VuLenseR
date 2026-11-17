
import hashlib
from pathlib import Path

import chromadb

from ingestion.document_loader import load_owasp_documents
from ingestion.text_chunker import chunk_text, chunk_by_sections, extract_control_id


# ==================================================
# 1. DATABASE CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "chroma_db"

COLLECTION_NAME = "owasp_security_knowledge"

_client = None
_collection = None

BATCH_SIZE = 16


def get_collection():

    global _client, _collection

    if _collection is None:

        _client = chromadb.PersistentClient(
            path=str(DB_PATH)
        )

        _collection = _client.get_or_create_collection(
            name=COLLECTION_NAME
        )

    return _collection


# ==================================================
# 2. GENERATE STABLE CHUNK IDS
# ==================================================

def generate_chunk_id(source, index):

    source_hash = hashlib.sha1(
        str(source).encode("utf-8")
    ).hexdigest()[:12]

    return f"{source_hash}_{index}"


# ==================================================
# 3. STORE AND SYNCHRONIZE OWASP DOCUMENTS
# ==================================================

def store_owasp_documents():

    collection = get_collection()

    documents = load_owasp_documents()

    all_chunks = []
    all_ids = []
    all_metadata = []

    valid_sources = set()
    source_chunk_counts = {}

    # Generate chunks from all documents
    for document in documents:

        content = document.get("content", "")
        source = str(document.get("source", "Unknown"))
        category = str(document.get("category", "General"))

        if not content or not content.strip():
            continue

        valid_sources.add((source, category))

        # Hybrid section-based + boundary-aware chunking (keeps heading hierarchy).
        chunks = chunk_by_sections(content)

        source_chunk_counts[source] = 0

        for index, chunk_info in enumerate(chunks):

            chunk = chunk_info["text"]

            if not chunk or not chunk.strip():
                continue

            chunk_id = generate_chunk_id(
                source,
                index
            )

            all_chunks.append(chunk)
            all_ids.append(chunk_id)

            all_metadata.append({
                "source": source,
                "category": category,
                "chunk_index": index,
                "section": chunk_info["section"][:300],
                "control_id": extract_control_id(
                    source, chunk_info["section"], chunk
                )
            })

            source_chunk_counts[source] += 1

    if not all_chunks:
        raise ValueError(
            "No valid OWASP document chunks generated."
        )

    if len(all_ids) != len(set(all_ids)):
        raise ValueError(
            "Duplicate chunk IDs detected."
        )

    total_chunks = len(all_chunks)

    # Show document-wise chunk counts
    print("\n========== DOCUMENT CHUNKS ==========")

    for source, count in source_chunk_counts.items():
        print(f"{source}: {count} chunks")

    print("Total generated:", total_chunks)
    print("Unique IDs:", len(set(all_ids)))

    # Index in small batches
    print("\nStarting ChromaDB indexing...", flush=True)

    for start in range(0, total_chunks, BATCH_SIZE):

        end = min(
            start + BATCH_SIZE,
            total_chunks
        )

        collection.upsert(
            ids=all_ids[start:end],
            documents=all_chunks[start:end],
            metadatas=all_metadata[start:end]
        )

        print(
            f"Indexed: {end}/{total_chunks}",
            flush=True
        )

    # Remove outdated records after successful indexing
    existing = collection.get(
        include=["metadatas"]
    )

    current_ids = set(all_ids)
    stale_ids = []

    for old_id, metadata in zip(
        existing.get("ids", []),
        existing.get("metadatas", [])
    ):

        metadata = metadata or {}

        old_source = metadata.get("source", "")
        old_category = metadata.get("category", "")

        old_source_key = (
            old_source,
            old_category
        )

        # Remove records from old sources and old chunk positions
        if (
            old_source_key not in valid_sources
            or old_id not in current_ids
        ):
            stale_ids.append(old_id)

    # Delete outdated records
    if stale_ids:

        print(
            f"Removing {len(stale_ids)} outdated chunks...",
            flush=True
        )

        collection.delete(
            ids=stale_ids
        )

    # Final database verification
    final_count = collection.count()

    print("\n========== OWASP INDEXING REPORT ==========")

    print("Documents loaded:", len(documents))
    print("Sources indexed:", len(valid_sources))
    print("Generated chunks:", total_chunks)
    print("Old chunks removed:", len(stale_ids))
    print("Database records:", final_count)

    if final_count == total_chunks:

        print("SUCCESS: Database is synchronized.")

    else:

        print(
            "WARNING: Database count does not match "
            "generated chunks."
        )

    print("===========================================\n")

    return total_chunks


# ==================================================
# 4. REBUILD KNOWLEDGE BASE
# ==================================================

def rebuild_owasp_knowledge_base():

    # Safely synchronize the existing collection.
    # Does not delete the entire database.

    return store_owasp_documents()


# ==================================================
# 5. FORMAT RETRIEVED RESULTS
# ==================================================

def format_results(results):

    retrieved = []

    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    for index, document in enumerate(documents):

        metadata = (
            metadatas[index]
            if index < len(metadatas) and metadatas[index]
            else {}
        )

        distance = (
            distances[index]
            if index < len(distances)
            else None
        )

        retrieved.append({

            "content": document,

            "source": metadata.get(
                "source",
                "Unknown"
            ),

            "category": metadata.get(
                "category",
                "General"
            ),

            "chunk_index": metadata.get(
                "chunk_index"
            ),

            "section": metadata.get("section", ""),

            "control_id": metadata.get("control_id", ""),

            "distance": distance
        })

    return retrieved


# ==================================================
# 6. CATEGORY-BASED RETRIEVAL
# ==================================================

def query_category(
    query: str,
    category: str,
    n_results: int = 6
) -> list:

    collection = get_collection()

    if not query or not query.strip():
        raise ValueError("Search query cannot be empty.")

    if n_results <= 0:
        raise ValueError("n_results must be greater than zero.")

    category_records = collection.get(
        where={"category": category},
        include=["metadatas"]
    )

    category_count = len(
        category_records.get("ids", [])
    )

    if category_count == 0:
        return []

    results = collection.query(

        query_texts=[query.strip()],

        n_results=min(
            n_results,
            category_count
        ),

        where={
            "category": category
        },

        include=[
            "documents",
            "metadatas",
            "distances"
        ]
    )

    return format_results(results)


# ==================================================
# 7. GENERAL RETRIEVAL
# ==================================================

def query_all_categories(
    query: str,
    n_results: int = 6
) -> list:

    collection = get_collection()

    if not query or not query.strip():
        raise ValueError("Search query cannot be empty.")

    if n_results <= 0:
        raise ValueError("n_results must be greater than zero.")

    total = collection.count()

    if total == 0:
        return []

    results = collection.query(

        query_texts=[query.strip()],

        n_results=min(
            n_results,
            total
        ),

        include=[
            "documents",
            "metadatas",
            "distances"
        ]
    )

    return format_results(results)


# ==================================================
# 8. RETRIEVE RELEVANT OWASP DOCUMENTATION
# ==================================================

def _query_terms(text: str) -> set:
    import re

    stop_words = {
        "the", "and", "for", "with", "from", "that", "this", "should",
        "shall", "must", "will", "can", "may", "system", "user", "users",
        "able", "allow", "using", "use", "into", "their", "they", "are",
        "was", "were", "has", "have", "had", "when", "where", "which",
        "what", "who", "how", "its", "all", "any", "not", "only",
    }
    tokens = set(re.findall(r"[a-z0-9]{3,}", str(text).lower()))
    return tokens - stop_words


def _is_relevant_chunk(query: str, chunk: dict) -> bool:
    """Combine Chroma distance with term overlap to suppress weak matches."""
    distance = chunk.get("distance")
    query_terms = _query_terms(query)
    chunk_terms = _query_terms(chunk.get("content", ""))
    overlap = query_terms.intersection(chunk_terms)

    # Chroma's default L2 distance is lower for closer matches.
    # A close semantic match may pass without literal word overlap.
    if isinstance(distance, (int, float)) and distance <= 1.25:
        return True
    if overlap:
        return True
    return False


# Related security concepts used to expand a requirement into a richer query.
SECURITY_CONCEPTS = {
    ("login", "log in", "sign in", "signin", "password", "credential", "account"):
        "authentication password credential brute force session multi-factor",
    ("register", "registration", "sign up", "signup"):
        "authentication account creation password policy identity verification",
    ("admin", "role", "permission", "privilege", "access", "authorize", "authorise"):
        "authorization access control least privilege role permission",
    ("upload", "file", "attachment", "document", "download"):
        "file upload validation malicious file storage path traversal",
    ("payment", "card", "credit", "billing", "bank", "personal", "email", "address", "profile", "health"):
        "sensitive data protection encryption privacy personal information",
    ("search", "form", "input", "submit", "query", "comment", "field"):
        "input validation injection sanitization output encoding",
    ("session", "cookie", "token", "jwt", "remember"):
        "session management token expiry cookie secure logout",
    ("api", "endpoint", "integration", "third party", "library", "dependency", "plugin"):
        "api security supply chain dependency integrity",
    ("log", "audit", "monitor", "alert", "report", "history"):
        "security logging monitoring alerting audit trail",
    ("error", "exception", "failure", "timeout", "retry"):
        "error handling exceptional conditions information disclosure fail secure",
    ("backup", "restore", "recovery", "delete", "data"):
        "backup recovery data integrity retention",
    ("reset", "forgot", "otp", "verification code"):
        "password reset account recovery one-time code",
}


def expand_query(query: str) -> str:
    """Add related security concepts so retrieval is not limited to literal words."""
    lowered = str(query).lower()
    additions = []
    for triggers, concepts in SECURITY_CONCEPTS.items():
        if any(trigger in lowered for trigger in triggers):
            additions.append(concepts)
    return f"{query.strip()}\nRelated security concepts: {' '.join(additions)}" if additions else query.strip()


def _keyword_score(query_terms: set, chunk: dict) -> float:
    """Share of query terms found in the chunk text, section title and control id."""
    if not query_terms:
        return 0.0
    haystack = " ".join([
        str(chunk.get("content", "")),
        str(chunk.get("section", "")),
        str(chunk.get("control_id", "")),
    ])
    return len(query_terms & _query_terms(haystack)) / len(query_terms)


def retrieve_relevant_chunks(
    query: str,
    n_results: int = 6
) -> list:
    """Hybrid retrieval: semantic search + keyword/metadata score, then relevance filter."""
    if not query or not query.strip():
        raise ValueError("Search query cannot be empty.")
    if n_results <= 0:
        raise ValueError("n_results must be greater than zero.")

    collection = get_collection()
    if collection.count() == 0:
        return []

    query = query.strip()[:3000]
    expanded = expand_query(query)

    # Retrieve a wider candidate set, then re-rank and filter weak matches.
    candidates = query_all_categories(
        query=expanded,
        n_results=min(max(n_results * 3, n_results), collection.count())
    )

    expanded_terms = _query_terms(expanded)
    scored = []

    for item in candidates:
        if not item.get("content", "").strip():
            continue
        if not _is_relevant_chunk(query, item):
            continue

        distance = item.get("distance")
        semantic = 1.0 / (1.0 + float(distance)) if isinstance(distance, (int, float)) else 0.0
        keyword = _keyword_score(expanded_terms, item)
        item["score"] = round(0.65 * semantic + 0.35 * keyword, 4)
        scored.append(item)

    # Deterministic order: identical input always gives identical evidence.
    scored.sort(key=lambda c: (
        -c["score"],
        str(c.get("source", "")),
        c.get("chunk_index") if isinstance(c.get("chunk_index"), int) else 0,
    ))

    return scored[:n_results]
