
import hashlib
from pathlib import Path

import chromadb

from ingestion.document_loader import load_owasp_documents
from ingestion.text_chunker import chunk_text


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

        chunks = chunk_text(content)

        source_chunk_counts[source] = 0

        for index, chunk in enumerate(chunks):

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
                "chunk_index": index
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

def retrieve_relevant_chunks(
    query: str,
    n_results: int = 6
) -> list:

    if not query or not query.strip():

        raise ValueError(
            "Search query cannot be empty."
        )

    if n_results <= 0:

        raise ValueError(
            "n_results must be greater than zero."
        )

    collection = get_collection()

    if collection.count() == 0:

        raise RuntimeError(
            "OWASP knowledge base is empty. "
            "Run document ingestion first."
        )

    return query_all_categories(
        query=query.strip(),
        n_results=n_results
    )
