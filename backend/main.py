from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from services.combined_analysis_service import analyze_combined_requirement
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
    title="SDLC VuLenseR API",
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

class RequirementRequest(BaseModel):
    requirement: str = Field(..., min_length=5, description="Software requirement to analyze")

class AnalysisSaveRequest(BaseModel):
    original_requirement: str = Field(min_length=5)
    result: dict

@app.get("/")
def home():
    return {"message": "SDLC VuLenseR API is running.", "status": "online"}

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
