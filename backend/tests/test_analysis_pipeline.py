import json
import sys
import types

# The pipeline tests mock retrieval. This lightweight stub allows the tests to
# run even when ChromaDB is not installed in the test runner environment.
try:
    import chromadb  # noqa: F401
except ImportError:
    chromadb_stub = types.ModuleType("chromadb")
    chromadb_stub.PersistentClient = object
    sys.modules["chromadb"] = chromadb_stub

try:
    import openai  # noqa: F401
except ImportError:
    openai_stub = types.ModuleType("openai")
    openai_stub.OpenAI = object
    sys.modules["openai"] = openai_stub

from services import combined_analysis_service as pipeline
from services import rag_service


def test_extract_json_accepts_markdown_fence():
    assert pipeline.extract_json('```json\n{"ok": true}\n```') == {"ok": True}


def test_quality_score_is_deterministic():
    findings = [
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
    ]
    assert pipeline.calculate_quality_score(findings) == 78
    assert pipeline.calculate_quality_score([]) == 100


def test_owasp_finding_requires_exact_retrieved_quote():
    chunks = [{
        "source": "top10/A01.md",
        "category": "Top 10",
        "content": "Access control decisions should be enforced on the server side.",
    }]
    valid = [{
        "title": "Missing Access Check",
        "description": "The requirement does not define access checks.",
        "recommendation": "Specify server-side authorization checks.",
        "severity": "High",
        "basis": "owasp",
        "reference_id": 1,
        "evidence_quote": "Access control decisions should be enforced",
    }]
    invalid = [{
        **valid[0],
        "evidence_quote": "This quote does not exist in the source",
    }]
    assert len(pipeline._validate_findings(valid, chunks, 5)) == 1
    assert pipeline._validate_findings(invalid, chunks, 5) == []


def test_pipeline_returns_separate_quality_and_security_results(monkeypatch):
    responses = [
        json.dumps({
            "quality_attributes": {
                "clarity": {"rating": "Moderate", "reason": "The actor is clear."},
                "completeness": {"rating": "Poor", "reason": "A condition is missing."},
                "ambiguity": {"rating": "Moderate", "reason": "One term is broad."},
                "testability": {"rating": "Poor", "reason": "No acceptance condition exists."},
            },
            "quality_findings": [{
                "title": "Missing Acceptance Criteria",
                "description": "The expected login result is not measurable.",
                "recommendation": "Specify the expected successful and failed outcomes.",
                "severity": "Medium",
                "basis": "requirement",
            }],
           
        }),
        json.dumps({
            "security_findings": [{
                "title": "Unclear Access Control",
                "description": "The requirement does not define how account access is checked.",
                "recommendation": "Specify server-side authorization checks.",
                "severity": "High",
                "basis": "owasp",
                "reference_id": 1,
                "evidence_quote": "Access control decisions should be enforced",
            }],
            "missing_security_requirements": [],
          
        }),
    ]
    calls = []

    def fake_generate(prompt):
        calls.append(prompt)
        return responses.pop(0)

    chunks = [{
        "source": "top10/A01_2025-Broken_Access_Control.md",
        "category": "Top 10",
        "content": "Access control decisions should be enforced on the server side.",
        "distance": 0.8,
    }]

    monkeypatch.setattr(pipeline, "generate_response", fake_generate)
    monkeypatch.setattr(pipeline, "retrieve_relevant_chunks", lambda *args, **kwargs: chunks)

    result = pipeline.analyze_combined_requirement("The user should be able to log in.")

    assert len(calls) == 2
    assert "FIRST analyse requirement quality only" in calls[0]
    assert "separate security review" in calls[1]
    assert result["quality_findings"][0]["title"] == "Missing Acceptance Criteria"
    assert result["security_findings"][0]["source"].endswith("A01_2025-Broken_Access_Control.md")
    assert result["overall_score"] == 93
    assert "improved_requirement" not in result


def test_owasp_finding_is_rejected_without_retrieved_evidence(monkeypatch):
    responses = [
        json.dumps({
            "quality_attributes": {},
            "quality_findings": [],
          
        }),
        json.dumps({
            "security_findings": [{
                "title": "Invented OWASP Finding",
                "description": "This must not be accepted without a source.",
                "recommendation": "Specify controls.",
                "severity": "High",
                "basis": "owasp",
                "reference_id": 1,
                "evidence_quote": "A made up evidence quote that is not real",
            }],
            "missing_security_requirements": [],
          
        }),
    ]
    monkeypatch.setattr(pipeline, "generate_response", lambda prompt: responses.pop(0))
    monkeypatch.setattr(pipeline, "retrieve_relevant_chunks", lambda *args, **kwargs: [])

    result = pipeline.analyze_combined_requirement("The user can sign in.")

    assert result["security_findings"] == []
    assert result["retrieved_references"] == []
    assert result["rag_evidence_used"] is False


def test_relevance_filter_rejects_distant_unrelated_chunks():
    assert rag_service._is_relevant_chunk(
        "customer billing address",
        {"content": "The application should rotate encryption keys.", "distance": 1.8},
    ) is False
    assert rag_service._is_relevant_chunk(
        "customer billing address",
        {"content": "Unrelated excerpt", "distance": 0.9},
    ) is True


def test_quality_findings_use_rubric_categories_and_original_reference(monkeypatch):
    response = json.dumps({"quality_findings": [
        {"requirement_id": "REQ-001", "category": "verifiable", "title": "No Test Condition",
         "description": "Nothing measurable.", "recommendation": "Add a limit.",
         "severity": "High", "evidence_quote": "should be fast"},
        {"requirement_id": "REQ-001", "category": "Invented-Standard-X", "title": "Odd Issue",
         "description": "Something else.", "severity": "Low", "evidence_quote": "not in text"},
    ]})
    monkeypatch.setattr(pipeline, "generate_response", lambda prompt: response)
    reqs = {"REQ-001": {"text": "The page should be fast.", "location": "", "original_id": ""}}
    findings = pipeline._analyse_quality(reqs, True)
    assert findings[0]["category"] == "Verifiable"
    assert findings[1]["category"] == "Other"
    assert findings[0]["evidence_quote"] == "should be fast"
    assert findings[1]["evidence_quote"] == ""
    assert all(f["reference_document"] == "Original Requirement" for f in findings)


def test_security_reference_label_comes_from_metadata_only():
    chunk = {"source": "top10/A01_2025-Broken_Access_Control.md", "category": "Top 10"}
    assert pipeline.reference_label(chunk) == "OWASP Top 10:2025 A01 Broken Access Control"


def test_document_analysis_extracts_separates_and_limits_display(monkeypatch):
    blocks = [
        {"text": "Introduction to the system.", "location": "Paragraph 1"},
        {"text": "FR-1 The system shall list orders and shall email invoices.", "location": "Paragraph 2"},
        {"text": "FR-2 The system shall be fast.", "location": "Paragraph 3"},
    ]
    extraction = json.dumps({"requirements": [
        {"block": "B2", "original_id": "FR-1", "text": "The system shall list orders"},
        {"block": "B2", "original_id": "FR-1", "text": "The system shall email invoices"},
        {"block": "B3", "original_id": "FR-2", "text": "The system shall be fast"},
        {"block": "B3", "original_id": "", "text": "Totally invented requirement about drones"},
    ]})
    quality = json.dumps({"quality_findings": [
        {"requirement_id": "REQ-003", "category": "Verifiable", "title": "Not Measurable",
         "description": "No limit.", "severity": "High", "evidence_quote": "shall be fast"}
    ] + [
        {"requirement_id": "REQ-001", "category": "Other", "title": f"Minor {i}",
         "description": "Minor.", "severity": "Low", "evidence_quote": ""} for i in range(5)
    ]})
    doc_level = json.dumps({"quality_findings": [
        {"requirement_ids": ["REQ-001", "REQ-002"], "category": "Duplicated",
         "title": "Overlap", "description": "Overlap.", "severity": "Medium"}]})
    security = json.dumps({"security_findings": [], "missing_security_requirements": []})

    def fake(prompt):
        if "extract software requirements" in prompt:
            return extraction
        if "complete requirement set" in prompt:
            return doc_level
        if "Security Requirements Analyst" in prompt:
            return security
        return quality

    monkeypatch.setattr(pipeline, "generate_response", fake)
    monkeypatch.setattr(pipeline, "retrieve_relevant_chunks", lambda *a, **k: [])
    result = pipeline.analyze_requirement_document(blocks)

    assert result["summary"]["total_requirements"] == 3          # invented one rejected
    assert result["requirements"][2]["location"] == "Paragraph 3"
    assert len(result["quality_findings"]) == 4                   # UI limit
    assert len(result["all_quality_findings"]) == 6               # all retained
    assert len(result["document_findings"]) == 1
    assert result["quality_findings"][0]["severity"] == "High"


def test_asvs_reference_uses_real_row_id_not_table_header():
    content = "# | Description | Level\n6.3.1 | Verify that controls to prevent credential stuffing are implemented | 1"
    chunks = [{"source": "asvs/OWASP_ASVS.docx", "category": "ASVS", "content": content, "section": "| Description | Level"}]
    finding = [{"title": "No Brute Force Limit", "description": "Anyone can keep guessing passwords.",
                "basis": "owasp", "reference_id": 1, "severity": "High",
                "evidence_quote": "Verify that controls to prevent credential stuffing are implemented"}]
    out = pipeline._validate_findings(finding, chunks, 8)
    assert out[0]["reference_document"] == "OWASP ASVS 5.0 – V6.3.1"


def test_quality_blocks_only_show_factors_with_issues():
    findings = [
        {"category": "Unambiguous", "title": "Vague", "description": "Vague word.", "severity": "High", "scope": "requirement"},
        {"category": "Unambiguous", "title": "Vague 2", "description": "Again.", "severity": "Low", "scope": "requirement"},
        {"category": "Other", "title": "Missing Trigger", "description": "No trigger.", "severity": "Medium", "scope": "requirement"},
    ]
    blocks = pipeline._quality_blocks(findings)
    assert list(blocks) == ["Unambiguous", "Missing Trigger"]   # one block per factor, nothing for clean factors
    assert blocks["Unambiguous"]["rating"] == "Poor"
