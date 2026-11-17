from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pathlib import Path
from io import BytesIO
from docx import Document
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

from services.combined_analysis_service import (
    analyze_combined_requirement,
    analyze_requirement_document,
)
from ingestion.requirement_parser import parse_text, parse_docx, parse_pdf_reader
from database import init_database, save_analysis, get_user_analyses, clear_user_analyses
from auth_service import get_current_user
from auth_routes import router as auth_router
from admin_routes import router as admin_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="SDLC VuLenser API",
    description="RAG-based Software Requirement Analysis",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(admin_router)

MAX_REQUIREMENT_UPLOAD_BYTES = 20 * 1024
MAX_REQUIREMENT_TEXT_CHARS = 40000


class RequirementRequest(BaseModel):
    requirement: str = Field(
        ..., min_length=5, max_length=MAX_REQUIREMENT_TEXT_CHARS,
        description="Software requirement to analyze"
    )

class AnalysisSaveRequest(BaseModel):
    original_requirement: str = Field(min_length=5)
    result: dict

@app.get("/")
def home():
    return {"message": "SDLC VuLenser API is running.", "status": "online"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/analyze")
def analyze(request: RequirementRequest, user: dict = Depends(get_current_user)):
    requirement = request.requirement.strip()
    if not requirement:
        raise HTTPException(status_code=400, detail="Requirement cannot be empty.")
    try:
        result = analyze_combined_requirement(requirement)
        return {"success": True, "original_requirement": requirement, **result}
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error))
    except Exception as error:
        print("Analysis Error:", error)
        raise HTTPException(status_code=500, detail="An unexpected error occurred during analysis.")


@app.post("/analyze-document")
async def analyze_document(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    """Extract a short user requirement document, then run the same flaw detector."""
    name = Path((file.filename or "").replace(chr(92), "/")).name
    suffix = Path(name).suffix.lower()
    allowed = {".pdf", ".docx", ".txt", ".md"}
    if suffix not in allowed:
        raise HTTPException(status_code=415, detail="Allowed formats: PDF, DOCX, TXT and MD.")
    raw = await file.read(MAX_REQUIREMENT_UPLOAD_BYTES + 1)
    if not raw:
        raise HTTPException(status_code=400, detail="The selected document is empty.")
    if len(raw) > MAX_REQUIREMENT_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Document must be 20 KB or smaller.")
    try:
        # Keep the original location (paragraph / table row / page / line) of every block.
        if suffix == ".docx":
            blocks = parse_docx(raw)
        elif suffix == ".pdf":
            if PdfReader is None:
                raise HTTPException(status_code=503, detail="PDF support is unavailable. Install pypdf.")
            reader = PdfReader(BytesIO(raw))
            if len(reader.pages) > 10:
                raise HTTPException(status_code=413, detail="Please upload a document of 10 pages or fewer.")
            blocks = parse_pdf_reader(reader)
        else:
            blocks = parse_text(raw)
        requirement = "\n".join(block["text"] for block in blocks)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read this document. Please check that it is a valid, text-based file.")
    requirement = requirement.strip()
    if len(requirement) < 5:
        raise HTTPException(status_code=400, detail="No readable requirement text was found in this document.")
    if len(requirement) > MAX_REQUIREMENT_TEXT_CHARS:
        raise HTTPException(status_code=413, detail="Extracted text is too long (maximum 40,000 characters).")
    try:
        result = analyze_requirement_document(blocks)
        return {"success": True, "original_requirement": requirement, "document_name": name, **result}
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as error:
        print("Document Analysis Error:", error)
        raise HTTPException(status_code=500, detail="Document analysis failed. Please try a smaller or text-based document.")

@app.get("/analyses")
def list_my_analyses(user: dict = Depends(get_current_user)):
    return {"analyses": get_user_analyses(user["id"])}

@app.post("/analyses")
def save_my_analysis(request: AnalysisSaveRequest, user: dict = Depends(get_current_user)):
    analysis_id = save_analysis(user["id"], request.original_requirement, request.result)
    return {"id": analysis_id, "message": "Analysis saved."}

@app.delete("/analyses")
def delete_my_analyses(user: dict = Depends(get_current_user)):
    clear_user_analyses(user["id"])
    return {"message": "Your analysis history has been cleared."}
