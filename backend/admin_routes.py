import json
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form

from database import get_connection
from auth_service import require_admin
from ingestion.document_loader import OWASP_PATH, load_docx, load_markdown
from ingestion.text_chunker import chunk_text
from services import rag_service

router = APIRouter(prefix="/admin", tags=["Administration"])
MAX_DOCUMENT_SIZE = 10 * 1024 * 1024


def _category_folder(category: str) -> Path:
    if category == "ASVS":
        return OWASP_PATH / "asvs"
    if category == "Top 10":
        return OWASP_PATH / "top10"
    raise HTTPException(status_code=400, detail="Category must be ASVS or Top 10.")


def _read_document(path: Path) -> str:
    if path.suffix.lower() == ".docx":
        return load_docx(path)
    if path.suffix.lower() == ".md":
        return load_markdown(path)
    raise ValueError("Unsupported document format.")


def _indexed_chunk_count(filename: str) -> tuple[int, int]:
    """Return stored vector count and count of vectors with embeddings."""
    try:
        result = rag_service.get_collection().get(
            where={"source": filename},
            include=["metadatas", "embeddings"]
        )
        ids = result.get("ids") or []
        embeddings = result.get("embeddings")
        embedding_count = len(embeddings) if embeddings is not None else 0
        return len(ids), embedding_count
    except Exception:
        return 0, 0


def _document_list():
    items = []
    for category, folder in (("ASVS", OWASP_PATH / "asvs"), ("Top 10", OWASP_PATH / "top10")):
        folder.mkdir(parents=True, exist_ok=True)
        for path in sorted(folder.iterdir()):
            if not path.is_file() or path.suffix.lower() not in (".docx", ".md"):
                continue

            item = {
                "name": path.name,
                "category": category,
                "format": path.suffix.lower().lstrip("." ).upper(),
                "version": _extract_version(path.name),
                "size": path.stat().st_size,
                "modified_at": path.stat().st_mtime,
                "extraction_status": "Pending",
                "chunking_status": "Pending",
                "embedding_status": "Pending",
                "indexing_status": "Not indexed",
                "chunks": 0,
                "indexed_chunks": 0,
            }

            try:
                content = _read_document(path)
                item["extraction_status"] = "Completed" if content.strip() else "Empty"
                chunks = chunk_text(content) if content.strip() else []
                item["chunks"] = len(chunks)
                item["chunking_status"] = "Completed" if chunks else "No chunks"
                indexed_count, embedding_count = _indexed_chunk_count(path.name)
                item["indexed_chunks"] = indexed_count
                item["embedding_status"] = (
                    "Completed" if chunks and embedding_count == len(chunks)
                    else "Pending"
                )
                item["indexing_status"] = (
                    "Indexed" if chunks and indexed_count == len(chunks)
                    else "Not indexed" if indexed_count == 0
                    else "Needs re-indexing"
                )
            except Exception as error:
                item["extraction_status"] = f"Failed ({type(error).__name__})"
                item["chunking_status"] = "Blocked"
                item["embedding_status"] = "Blocked"
                item["indexing_status"] = "Failed"

            items.append(item)
    return items


def _extract_version(filename: str) -> str:
    match = re.search(r"(?:version|ver|v)[-_ ]?(\d+(?:\.\d+)*)", filename, re.IGNORECASE)
    return match.group(1) if match else "Not specified"


@router.get("/overview")
def overview(admin: dict = Depends(require_admin)):
    with get_connection() as connection:
        total_analyses = connection.execute(
            "SELECT COUNT(*) FROM analyses"
        ).fetchone()[0]
        rows = connection.execute(
            """SELECT a.id, a.original_requirement, a.result_json, a.created_at,
                      u.name AS user_name
               FROM analyses a
               LEFT JOIN users u ON u.id = a.user_id
               ORDER BY a.id DESC LIMIT 8"""
        ).fetchall()
        all_results = connection.execute(
            "SELECT result_json FROM analyses"
        ).fetchall()

    total_violations = 0
    total_security_flaws = 0
    for row in all_results:
        try:
            result = json.loads(row["result_json"] or "{}")
            total_violations += len(result.get("violations") or [])
            # The current analysis service stores its second finding group
            # under missing_requirements; these are shown as security gaps.
            total_security_flaws += len(result.get("missing_requirements") or [])
        except (TypeError, json.JSONDecodeError):
            continue

    recent_activity = []
    for row in rows:
        try:
            result = json.loads(row["result_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            result = {}
        recent_activity.append({
            "id": row["id"],
            "user": row["user_name"] or "Unknown user",
            "requirement": row["original_requirement"],
            "created_at": row["created_at"],
            "violations": len(result.get("violations") or []),
            "security_flaws": len(result.get("missing_requirements") or []),
            "score": result.get("overall_score"),
        })

    documents = _document_list()
    indexed_chunks = sum(item["indexed_chunks"] for item in documents)
    return {
        "total_analyses": total_analyses,
        "total_violations": total_violations,
        "total_security_flaws": total_security_flaws,
        "document_count": len(documents),
        "indexed_chunks": indexed_chunks,
        "recent_activity": recent_activity,
    }


@router.get("/documents")
def list_documents(admin: dict = Depends(require_admin)):
    return {"documents": _document_list()}


@router.post("/documents")
async def upload_document(
    file: UploadFile = File(...),
    category: str = Form(...),
    replace_existing: bool = Form(False),
    admin: dict = Depends(require_admin),
):
    folder = _category_folder(category)
    filename = Path(file.filename or "").name
    if not filename or filename.startswith(".") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,119}", filename):
        raise HTTPException(status_code=400, detail="Use a simple filename with letters, numbers, spaces, dots, underscores or hyphens.")

    expected = ".docx" if category == "ASVS" else ".md"
    if Path(filename).suffix.lower() != expected:
        raise HTTPException(status_code=400, detail=f"{category} documents must be {expected} files.")

    content = await file.read(MAX_DOCUMENT_SIZE + 1)
    if not content or len(content) > MAX_DOCUMENT_SIZE:
        raise HTTPException(status_code=400, detail="File must be non-empty and no larger than 10 MB.")
    if category == "ASVS" and not content.startswith(b"PK"):
        raise HTTPException(status_code=400, detail="The uploaded file does not appear to be a valid DOCX document.")
    if category == "Top 10":
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Markdown documents must use UTF-8 encoding.")

    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / filename
    if destination.exists() and not replace_existing:
        raise HTTPException(status_code=409, detail="A document with this filename already exists. Enable replace to update it.")

    previous = destination.read_bytes() if destination.exists() else None
    destination.write_bytes(content)
    try:
        chunks = rag_service.rebuild_owasp_knowledge_base()
    except Exception as error:
        if previous is None:
            destination.unlink(missing_ok=True)
        else:
            destination.write_bytes(previous)
        try:
            rag_service.rebuild_owasp_knowledge_base()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Document was not indexed; previous file state restored. Details: {type(error).__name__}")

    return {
        "message": "Document uploaded and knowledge base re-indexed.",
        "document": {"name": filename, "category": category, "size": len(content)},
        "indexed_chunks": chunks,
    }


@router.delete("/documents/{category}/{filename}")
def delete_document(category: str, filename: str, admin: dict = Depends(require_admin)):
    folder = _category_folder(category)
    safe_name = Path(filename).name
    if safe_name != filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")
    path = folder / safe_name
    if not path.is_file() or path.suffix.lower() not in (".docx", ".md"):
        raise HTTPException(status_code=404, detail="Document not found.")

    backup = path.read_bytes()
    path.unlink()
    try:
        chunks = rag_service.rebuild_owasp_knowledge_base()
    except Exception as error:
        path.write_bytes(backup)
        try:
            rag_service.rebuild_owasp_knowledge_base()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Document was not removed from the knowledge base. Details: {type(error).__name__}")

    return {"message": "Document deleted and knowledge base re-indexed.", "indexed_chunks": chunks}


@router.post("/documents/reindex")
def retry_indexing(admin: dict = Depends(require_admin)):
    try:
        chunks = rag_service.rebuild_owasp_knowledge_base()
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Knowledge base indexing failed: {type(error).__name__}")
    return {"message": "Knowledge base re-indexed successfully.", "indexed_chunks": chunks}
