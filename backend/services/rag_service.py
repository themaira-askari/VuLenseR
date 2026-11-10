
import hashlib
import chromadb
from pathlib import Path

from ingestion.document_loader import load_owasp_documents
from ingestion.text_chunker import chunk_text


# --------------------------------------------------
# 1. DATABASE SETUP
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "chroma_db"

client = chromadb.PersistentClient(path=str(DB_PATH))

COLLECTION_NAME = "owasp_security_knowledge"

collection = client.get_or_create_collection(
    name=COLLECTION_NAME
)


# --------------------------------------------------
# 2. STORE DOCUMENTS
# --------------------------------------------------

def store_owasp_documents():

    documents = load_owasp_documents()

    all_chunks = []
    all_ids = []
    all_metadata = []

    for document in documents:

        content = document.get("content", "")
        source = document.get("source", "Unknown")
        category = document.get("category", "General")

        if not content.strip():
            continue

        chunks = chunk_text(content)

        for chunk_index, chunk in enumerate(chunks):

            if not chunk.strip():
                continue

            # Stable ID based on source and chunk position.
            source_hash = hashlib.sha1(
                source.encode("utf-8")
            ).hexdigest()[:12]

            chunk_id = f"{source_hash}_{chunk_index}"

            all_chunks.append(chunk)
            all_ids.append(chunk_id)

            all_metadata.append({
                "source": str(source),
                "category": str(category)
            })

    if not all_chunks:
        raise ValueError(
            "No OWASP document chunks were found."
        )

    collection.upsert(
        documents=all_chunks,
        ids=all_ids,
        metadatas=all_metadata
    )

    print(
        f"Successfully stored {len(all_chunks)} OWASP chunks."
    )

    return len(all_chunks)


# --------------------------------------------------
# 3. REBUILD KNOWLEDGE BASE
# --------------------------------------------------

def rebuild_owasp_knowledge_base():
    """
    Delete the old collection and ingest all documents again.
    Use this after changing document loading or chunking.
    """

    global collection

    try:
        client.delete_collection(
            name=COLLECTION_NAME
        )
    except Exception:
        pass

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME
    )

    return store_owasp_documents()


# --------------------------------------------------
# 4. CATEGORY-BASED RETRIEVAL
# --------------------------------------------------

def query_category(
    query: str,
    category: str,
    n_results: int
) -> list:

    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        where={"category": category},
        include=[
            "documents",
            "metadatas",
            "distances"
        ]
    )

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
            "source": metadata.get("source", "Unknown"),
            "category": metadata.get("category", "General"),
            "distance": distance
        })

    return retrieved



# --------------------------------------------------
# 5. GENERAL RETRIEVAL
# --------------------------------------------------

def query_all_categories(
    query: str,
    n_results: int
) -> list:

    total_chunks = collection.count()

    if total_chunks == 0:
        return []

    result_count = min(
        n_results,
        total_chunks
    )

    results = collection.query(
        query_texts=[query],
        n_results=result_count,
        include=[
            "documents",
            "metadatas",
            "distances"
        ]
    )

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
            "source": metadata.get("source", "Unknown"),
            "category": metadata.get("category", "General"),
            "distance": distance
        })

    return retrieved


# --------------------------------------------------
# 6. RETRIEVE RELEVANT DOCUMENTATION
# --------------------------------------------------

def retrieve_relevant_chunks(
    query: str,
    n_results: int = 6
) -> list:

    if not query or not query.strip():
        raise ValueError("Search query cannot be empty.")

    if collection.count() == 0:
        raise RuntimeError(
            "OWASP knowledge base is empty. "
            "Run document ingestion first."
        )

    # Balanced retrieval.
    asvs_chunks = query_category(
        query,
        "ASVS",
        4
    )

    top10_chunks = query_category(
        query,
        "Top 10",
        2
    )

    combined = asvs_chunks + top10_chunks

    # Fill remaining slots if one category has fewer documents.
    if len(combined) < n_results:

        additional_chunks = query_all_categories(
            query,
            n_results
        )

        existing = {
            (
                item["source"],
                item["content"]
            )
            for item in combined
        }

        for item in additional_chunks:

            key = (
                item["source"],
                item["content"]
            )

            if key not in existing:
                combined.append(item)
                existing.add(key)

            if len(combined) >= n_results:
                break

    return combined[:n_results]
