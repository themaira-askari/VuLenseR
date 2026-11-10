from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from services.combined_analysis_service import (
    analyze_combined_requirement
)


app = FastAPI(
    title="SDLC VuLenseR API",
    description="RAG-based Software Requirement Analysis",
    version="2.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


class RequirementRequest(BaseModel):
    requirement: str = Field(
        ...,
        min_length=5,
        description="Software requirement to analyze"
    )


@app.get("/")
def home():
    return {
        "message": "SDLC VuLenseR API is running.",
        "status": "online"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/analyze")
def analyze(request: RequirementRequest):

    requirement = request.requirement.strip()

    if not requirement:
        raise HTTPException(
            status_code=400,
            detail="Requirement cannot be empty."
        )

    try:
        result = analyze_combined_requirement(requirement)

        return {
            "success": True,
            "original_requirement": requirement,
            **result
        }

    except RuntimeError as error:
        raise HTTPException(
            status_code=502,
            detail=str(error)
        )

    except Exception as error:
        print("Analysis Error:", error)

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during analysis."
        )