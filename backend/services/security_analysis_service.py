 """ import re

from services.gemini_service import generate_response
from services.rag_service import retrieve_relevant_chunks


def get_requirement_length(requirement: str) -> dict:
    """Requirement length ke mutabiq security analysis limit karta hai."""

    word_count = len(requirement.split())

    if word_count <= 30:
        return {
            "level": "short",
            "finding_limit": "2-3 most relevant findings maximum",
            "refinement_limit": "1-3 sentences maximum"
        }

    elif word_count <= 100:
        return {
            "level": "medium",
            "finding_limit": "3-5 relevant findings maximum",
            "refinement_limit": "3-5 sentences maximum"
        }

    else:
        return {
            "level": "long",
            "finding_limit": (
                "Summarize relevant findings by section or security category"
            ),
            "refinement_limit": (
                "Refine relevant requirement sections only. "
                "Avoid rewriting unaffected content."
            )
        }


def analyze_security_requirement(requirement: str) -> dict:
    """
    Requirement ka scope-based security analysis karta hai
    using relevant OWASP knowledge retrieved through RAG.
    """

    length_config = get_requirement_length(requirement)

    # Step 1: Relevant OWASP evidence retrieve karna
    retrieved_results = retrieve_relevant_chunks(
        query=requirement,
        n_results=5
    )

    relevant_chunks = (
        retrieved_results.get("documents", [[]])[0]
    )

    metadata = (
        retrieved_results.get("metadatas", [[]])[0]
    )

    # Step 2: Retrieved evidence organize karna
    owasp_context = ""

    for index, chunk in enumerate(relevant_chunks):

        source = (
            metadata[index].get("source", "Unknown source")
            if index < len(metadata)
            else "Unknown source"
        )

        category = (
            metadata[index].get("category", "Unknown category")
            if index < len(metadata)
            else "Unknown category"
        )

        owasp_context += f"""
Source: {source}
Category: {category}

Evidence:
{chunk}

---
"""

    if not owasp_context.strip():
        owasp_context = (
            "No relevant OWASP evidence was retrieved "
            "from the knowledge base. Do not make "
            "unsupported OWASP claims."
        )

    # Step 3: Security analysis prompt
    prompt = f"""
You are a professional Software Security Requirements Analyst.

Analyze the following requirement strictly within its scope.

ORIGINAL REQUIREMENT:
{requirement}

REQUIREMENT LENGTH:
{length_config["level"]}

FINDING LIMIT:
{length_config["finding_limit"]}

REFINEMENT LIMIT:
{length_config["refinement_limit"]}

RETRIEVED OWASP KNOWLEDGE:
{owasp_context}

YOUR TASK:

Identify relevant security weaknesses and suggest appropriate
security improvements for the given requirement.

CRITICAL SCOPE RULES:

1. Analyze only the functionality explicitly stated or clearly
   implied by the original requirement.

2. Do not assume the application contains features that are
   not mentioned in the requirement.

3. Do not automatically report missing MFA, password reset,
   session management, account lockout, logging, or other
   controls unless they are relevant to the stated functionality.

4. For example, if the requirement only concerns user registration,
   focus on registration-related security, such as secure password
   handling, input validation, and protection of user data.

5. Do not treat every possible security control as mandatory
   for every software requirement.

6. Distinguish between:
   - Actual security weakness
   - Relevant missing security control
   - Optional improvement
   - Not applicable to the requirement's scope

7. Do not report optional improvements as confirmed vulnerabilities.

8. Avoid duplicate findings and lengthy explanations.

OWASP EVIDENCE RULES:

9. Use only the provided retrieved evidence for OWASP-related claims.

10. Mention a source filename only when it is available
    in the retrieved evidence.

11. Never invent OWASP categories, references, section numbers,
    rule IDs, or source filenames.

12. If the retrieved evidence does not support a finding,
    do not present that finding as an OWASP-based claim.

13. If no relevant OWASP evidence is available, clearly state:
    "No directly relevant OWASP evidence was retrieved."

REFINEMENT RULES:

14. Preserve the original functionality.

15. Add only relevant and proportionate security controls.

16. Do not introduce unrelated application features.

17. Keep the refined requirement concise and testable.

18. Keep the response proportional to the original requirement.

19. For short requirements, provide a short analysis and refinement.

20. For long requirements, summarize security findings by
    relevant section or category instead of repeating everything.

OUTPUT FORMAT:

## Security Analysis

Provide a brief overall assessment in 1-2 sentences.

## Identified Security Risks

List only relevant risks.
For each finding use:

- **Finding:** Short description
- **Severity:** High / Medium / Low
- **Reason:** One concise sentence

Do not force findings if no meaningful risk exists.

## Missing Security Controls

List only security controls that are relevant to the original
requirement but are missing or insufficient.

If no relevant missing controls are identified, state that.

## OWASP Evidence and Sources

Provide only directly relevant retrieved evidence.

Mention source filename and a concise explanation.
Do not add unsupported references.

At the end, write the refined requirement using EXACTLY these markers:

SECURITY_REFINED_REQUIREMENT_START
Write the concise security refined requirement here.
SECURITY_REFINED_REQUIREMENT_END

Do not omit or rename these markers.
"""

    # Step 4: AI response
    response = generate_response(prompt)

    if response == "API_ERROR":
        return {
            "analysis": "API_ERROR",
            "refined_requirement": "API_ERROR"
        }

    # Step 5: Security refined requirement extract karna
    match = re.search(
        r"SECURITY_REFINED_REQUIREMENT_START\s*"
        r"(.*?)\s*SECURITY_REFINED_REQUIREMENT_END",
        response,
        re.IGNORECASE | re.DOTALL
    )

    if match:

        refined_requirement = match.group(1).strip()

        analysis = (
            response[:match.start()].strip()
            + "\n"
            + response[match.end():].strip()
        ).strip()

    else:

        refined_requirement = (
            "Unable to extract the security refined requirement. "
            "Please review the security analysis."
        )

        analysis = response.strip()

    return {
        "analysis": analysis,
        "refined_requirement": refined_requirement
    }
    """