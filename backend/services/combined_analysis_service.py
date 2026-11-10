
import json
import re

from services.gemini_service import generate_response
from services.rag_service import retrieve_relevant_chunks


# ==================================================
# 1. REQUIREMENT UTILITIES
# ==================================================

def get_requirement_length(requirement: str) -> int:
    return len(requirement.split())


def get_max_refined_words(requirement: str) -> int:
    original_words = get_requirement_length(requirement)
    return max(original_words + 20, int(original_words * 1.7))


def clean(value: str) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        " ",
        str(value).lower()
    ).strip()


# ==================================================
# 2. JSON EXTRACTION
# ==================================================

def extract_json(response: str) -> dict:

    if not response:
        raise RuntimeError("AI returned an empty response.")

    text = str(response).strip()

    text = re.sub(
        r"^```(?:json)?\s*",
        "",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(r"\s*```$", "", text)

    try:
        result = json.loads(text)

        if isinstance(result, dict):
            return result

    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()

    for index, character in enumerate(text):

        if character != "{":
            continue

        try:
            result, _ = decoder.raw_decode(text[index:])

            if isinstance(result, dict):
                return result

        except json.JSONDecodeError:
            continue

    print("\n========== INVALID AI JSON ==========")
    print(text[:4000])
    print("=====================================\n")

    raise RuntimeError("AI returned invalid JSON.")


# ==================================================
# 3. FORMAT OWASP DOCUMENTATION
# ==================================================

def format_owasp_context(chunks: list) -> str:

    if not chunks:
        return "No relevant OWASP documentation was retrieved."

    formatted_context = []

    for index, chunk in enumerate(chunks, start=1):

        formatted_context.append(
            f"""
REFERENCE ID: {index}
Source: {chunk.get("source", "Unknown")}
Category: {chunk.get("category", "Unknown")}

Evidence:
{chunk.get("content", "")}
"""
        )

    return "\n".join(formatted_context)


# ==================================================
# 4. VALIDATE AI FINDINGS
# ==================================================

def validate_findings(
    findings: list,
    retrieved_chunks: list,
    limit: int,
    finding_type: str
) -> list:

    if not isinstance(findings, list):
        return []

    verified = []
    seen = set()

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        title = str(
            finding.get("title", "")
        ).strip()

        description = str(
            finding.get("description", "")
        ).strip()

        recommendation = str(
            finding.get("recommendation", "")
        ).strip()

        if not title or not description:
            continue

        basis = str(
            finding.get("basis", "")
        ).strip().lower()

        if basis not in ("requirement", "owasp"):
            continue

        source = ""
        evidence_quote = ""

        # OWASP findings require actual retrieved evidence.
        if basis == "owasp":

            try:
                reference_id = int(
                    finding.get("reference_id")
                )

                if reference_id < 1:
                    continue

                chunk = retrieved_chunks[reference_id - 1]

                original_content = str(
                    chunk.get("content", "")
                )

                quote = str(
                    finding.get("evidence_quote", "")
                ).strip()

                normalized_quote = clean(quote)
                normalized_content = clean(original_content)

                if len(normalized_quote.split()) < 4:
                    continue

                if normalized_quote not in normalized_content:
                    continue

                source = str(
                    chunk.get("source", "Unknown")
                )

                evidence_quote = quote

            except (TypeError, ValueError, IndexError):
                continue

        # Remove exact duplicate findings.
        duplicate_key = clean(title)

        if duplicate_key in seen:
            continue

        seen.add(duplicate_key)

        item = {
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "basis": basis,
            "source": source,
            "evidence_quote": evidence_quote,
            "evidence": evidence_quote
        }

        if finding_type == "violation":

            severity = str(
                finding.get("severity", "Low")
            ).capitalize()

            if severity not in ("High", "Medium", "Low"):
                severity = "Low"

            item["severity"] = severity

        verified.append(item)

        if len(verified) >= limit:
            break

    return verified


# ==================================================
# 5. REMOVE DUPLICATE FINDINGS
# ==================================================

def remove_overlap(
    violations: list,
    missing_requirements: list
) -> list:

    violation_titles = {
        clean(item.get("title", ""))
        for item in violations
    }

    violation_evidence = {
        clean(item.get("evidence_quote", ""))
        for item in violations
        if item.get("evidence_quote")
    }

    filtered = []

    for item in missing_requirements:

        title = clean(item.get("title", ""))
        evidence = clean(item.get("evidence_quote", ""))

        if title and title in violation_titles:
            continue

        if evidence and evidence in violation_evidence:
            continue

        filtered.append(item)

    return filtered


# ==================================================
# 6. ANALYZE REQUIREMENT AND SECURITY FINDINGS
# ==================================================

def analyze_findings(
    requirement: str,
    retrieved_chunks: list
) -> dict:

    context = format_owasp_context(retrieved_chunks)

    prompt = f"""
You are a professional Software Requirements
and Application Security Analyst.

Analyze the original requirement using:
1. The original requirement.
2. The retrieved OWASP documentation.

ORIGINAL REQUIREMENT:
{requirement}

RETRIEVED OWASP DOCUMENTATION:
{context}

YOUR TASK:

Identify only relevant and meaningful findings.

FINDING TYPES:

A. VIOLATIONS

An existing weakness, ambiguity, contradiction,
or security risk in the stated requirement.

B. MISSING REQUIREMENTS

A specific condition that is necessary to make
the requirement sufficiently clear, complete,
or secure, but is not specified.

FINDING BASIS:

Every finding must use one of these values:

1. "requirement"

Use this when the problem is directly visible
in the original requirement.

2. "owasp"

Use this only when the retrieved OWASP evidence
directly supports the finding.

For every OWASP finding:
- Provide the correct reference_id.
- Copy an exact evidence_quote.
- Never invent a reference or quotation.

STRICT RULES:

1. Do not invent vulnerabilities.
2. Do not treat every unspecified security control
   as a vulnerability.
3. Do not report unrelated security recommendations.
4. Do not duplicate the same issue in both lists.
5. Do not invent technical values.
6. Keep findings specific and actionable.
7. Do not recommend features unrelated to the
   original requirement.
8. A requirement-based finding must be visible
   from the original requirement itself.
9. An OWASP finding must be supported by its
   actual retrieved evidence.
10. If there is no meaningful finding, return
    an empty array.

RETURN ONLY VALID JSON:

{{
    "violations": [
        {{
            "title": "Short issue title",
            "description": "Explain the issue",
            "severity": "High, Medium or Low",
            "recommendation": "Relevant improvement",
            "basis": "requirement or owasp",
            "reference_id": null,
            "evidence_quote": ""
        }}
    ],
    "missing_requirements": [
        {{
            "title": "Missing requirement",
            "description": "Explain what is missing",
            "recommendation": "What should be specified",
            "basis": "requirement or owasp",
            "reference_id": null,
            "evidence_quote": ""
        }}
    ]
}}
"""

    response = generate_response(prompt)
    result = extract_json(response)

    violations = validate_findings(
        result.get("violations", []),
        retrieved_chunks,
        5,
        "violation"
    )

    missing_requirements = validate_findings(
        result.get("missing_requirements", []),
        retrieved_chunks,
        5,
        "missing requirement"
    )

    missing_requirements = remove_overlap(
        violations,
        missing_requirements
    )

    return {
        "violations": violations,
        "missing_requirements": missing_requirements
    }


# ==================================================
# 7. CHECK REFINEMENT SCOPE
# ==================================================

def is_scope_safe(
    original_requirement: str,
    refined_requirement: str,
    violations: list,
    missing_requirements: list
) -> bool:

    original = clean(original_requirement)
    refined = clean(refined_requirement)

    # Only OWASP-verified findings can justify
    # adding a security control to the refinement.
    verified_owasp_text = " ".join(
        clean(
            item.get("title", "") + " " +
            item.get("description", "") + " " +
            item.get("recommendation", "") + " " +
            item.get("evidence_quote", "")
        )
        for item in violations + missing_requirements
        if item.get("basis") == "owasp"
    )

    supported_text = original + " " + verified_owasp_text

    # Features that must not be invented.
    restricted_features = [
        r"\bmulti factor authentication\b",
        r"\btwo factor authentication\b",
        r"\bmfa\b",
        r"\botp\b",
        r"\bone time password\b",
        r"\bpassword recovery\b",
        r"\bpassword reset\b",
        r"\bemail verification\b",
        r"\bemail confirmation\b",
        r"\brate limit(?:ing|ed)?\b",
        r"\blimit(?:ing|ed)? failed login attempts\b",
        r"\baccount lockout\b",
        r"\bbiometric authentication\b",
        r"\bcaptcha\b",
        r"\bsession management\b",
        r"\bpassword polic(?:y|ies)\b",
        r"\bminimum password length\b",
        r"\bpassword complexity\b",
        r"\bpassword expiration\b"
    ]

    for pattern in restricted_features:

        if re.search(pattern, refined, re.IGNORECASE):

            if not re.search(
                pattern,
                supported_text,
                re.IGNORECASE
            ):
                return False

    # Avoid unsupported vague security claims.
    vague_phrases = [
        "securely",
        "properly",
        "robustly",
        "in a secure manner"
    ]

    for phrase in vague_phrases:

        if phrase in refined:
            return False

    return True


# ==================================================
# 8. GENERATE REFINED REQUIREMENT
# ==================================================

def generate_refined_requirement(
    original_requirement: str,
    violations: list,
    missing_requirements: list,
    max_words: int
) -> str:

    # Requirement-based findings can improve wording,
    # but cannot authorize new functionality.
    verified_owasp_findings = [
        item
        for item in violations + missing_requirements
        if item.get("basis") == "owasp"
    ]

    security_context = json.dumps(
        verified_owasp_findings,
        indent=2,
        ensure_ascii=False
    )

    prompt = f"""
You are an expert Software Requirements Engineer.

Rewrite the original requirement into a clear,
concise and testable requirement.

ORIGINAL REQUIREMENT:
{original_requirement}

VERIFIED OWASP FINDINGS:
{security_context}

MAIN OBJECTIVE:

Improve the original requirement without changing
its intended functionality or introducing new features.

STRICT RULES:

1. Preserve the original actors, actions and purpose.
2. Improve grammar, clarity and requirement structure.
3. Do not invent additional functionality.
4. Do not add password recovery, MFA, OTP,
   email verification, account lockout, CAPTCHA,
   session management or other features unless
   they are explicitly stated in the original
   requirement or supported by a verified,
   directly relevant OWASP finding.
5. Requirement-based findings must never be used
   to introduce new functionality.
6. Do not contradict the original requirement.
7. Do not add unrelated security recommendations.
8. Do not invent numerical values or technical
   specifications.
9. Do not use vague words such as securely,
   properly or robustly without a testable condition.
10. Do not force every finding into the refinement.
11. Keep the result concise and proportional
    to the original requirement.
12. Preserve all original functionality.
13. Only add security controls supported by
    verified OWASP findings.

MAXIMUM WORD COUNT: {max_words}

Return ONLY the rewritten requirement.
No heading, explanation or quotation marks.
"""

    for attempt in range(2):

        response = generate_response(prompt)

        refined = str(response or "").strip()

        refined = re.sub(
            r"^```(?:text)?\s*|\s*```$",
            "",
            refined,
            flags=re.IGNORECASE
        ).strip()

        refined = re.sub(
            r"^(refined requirement|improved requirement)\s*:\s*",
            "",
            refined,
            flags=re.IGNORECASE
        ).strip()

        if not refined:
            continue

        if len(refined.split()) > max_words:
            continue

        if is_scope_safe(
            original_requirement,
            refined,
            violations,
            missing_requirements
        ):
            return refined

        print(
            f"Refinement attempt {attempt + 1} "
            "rejected: unsupported functionality detected."
        )

    # Safety fallback: never return an invented feature.
    print(
        "AI refinement rejected. "
        "Preserving the original requirement."
    )

    return original_requirement


# ==================================================
# 9. CALCULATE QUALITY SCORE
# ==================================================

def calculate_quality_score(
    violations: list,
    missing_requirements: list
) -> int:

    score = 100

    severity_deductions = {
        "high": 15,
        "medium": 8,
        "low": 3
    }

    for violation in violations:

        severity = str(
            violation.get("severity", "low")
        ).lower()

        score -= severity_deductions.get(severity, 3)

    score -= len(missing_requirements) * 5

    return max(0, min(100, score))


# ==================================================
# 10. MAIN ANALYSIS PIPELINE
# ==================================================

def analyze_combined_requirement(requirement: str) -> dict:

    requirement = requirement.strip()

    if not requirement:
        raise RuntimeError("Requirement cannot be empty.")

    print("\n========== REQUIREMENT ANALYSIS ==========")
    print("Original Requirement:", requirement)

    # STEP 1: Retrieve OWASP evidence.
    retrieved_chunks = retrieve_relevant_chunks(
        requirement,
        n_results=6
    )

    print(
        f"\nRAG retrieved {len(retrieved_chunks)} chunks."
    )

    for index, chunk in enumerate(retrieved_chunks, start=1):

        print(
            f"Reference {index} | "
            f"Source: {chunk.get('source')} | "
            f"Category: {chunk.get('category')} | "
            f"Distance: {chunk.get('distance')}"
        )

    # STEP 2: Analyze findings.
    findings = analyze_findings(
        requirement,
        retrieved_chunks
    )

    violations = findings["violations"]

    missing_requirements = findings[
        "missing_requirements"
    ]

    # STEP 3: Refine the requirement.
    max_words = get_max_refined_words(requirement)

    refined_requirement = generate_refined_requirement(
        original_requirement=requirement,
        violations=violations,
        missing_requirements=missing_requirements,
        max_words=max_words
    )

    # STEP 4: Calculate score.
    overall_score = calculate_quality_score(
        violations,
        missing_requirements
    )

    print("\n========== FINAL RESULTS ==========")
    print("Refined Requirement:", refined_requirement)

    print("\nViolations:", len(violations))

    for item in violations:
        print("-", item["title"], "|", item["severity"])

    print("\nMissing Requirements:", len(missing_requirements))

    for item in missing_requirements:
        print("-", item["title"])

    print("\nOverall Score:", overall_score)
    print("===================================\n")

    return {
        "refined_requirement": refined_requirement,
        "violations": violations,
        "missing_requirements": missing_requirements,
        "overall_score": overall_score
    }
