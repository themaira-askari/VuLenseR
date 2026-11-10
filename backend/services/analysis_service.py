"""  import re

from services.gemini_service import generate_response


def get_requirement_length(requirement: str) -> dict:
    """Requirement ki length ke mutabiq analysis ka size determine karta hai."""

    word_count = len(requirement.split())

    if word_count <= 30:
        return {
            "level": "short",
            "analysis_limit": "2-3 concise issues maximum",
            "refinement_limit": "1-3 sentences maximum"
        }

    elif word_count <= 100:
        return {
            "level": "medium",
            "analysis_limit": "3-5 relevant issues maximum",
            "refinement_limit": "3-5 sentences maximum"
        }

    else:
        return {
            "level": "long",
            "analysis_limit": "Summarize key issues by relevant section",
            "refinement_limit": (
                "Refine the requirement section-wise. "
                "Do not unnecessarily rewrite unaffected content."
            )
        }


def analyze_requirement(requirement: str) -> dict:

    length_config = get_requirement_length(requirement)

    prompt = f"""
You are a professional Software Requirements Analyst.

Analyze the following software requirement.

ORIGINAL REQUIREMENT:
{requirement}

REQUIREMENT LENGTH:
{length_config["level"]}

ANALYSIS SIZE:
{length_config["analysis_limit"]}

REFINEMENT SIZE:
{length_config["refinement_limit"]}

Evaluate these four quality attributes:

1. Clarity
2. Completeness
3. Ambiguity
4. Testability

For each attribute provide:
- Rating: Good, Moderate, or Poor
- A brief reason in one sentence

Then identify the most important problems in the requirement.

IMPORTANT RULES:

1. Preserve the original functionality and intended meaning.

2. Do not invent new features, modules, workflows, or requirements.

3. Do not add security controls. Security analysis is handled separately.

4. Only identify actual problems present in the original requirement.

5. Do not create problems merely to make the analysis longer.

6. Keep the analysis proportional to the original requirement length.

7. For short requirements, use concise bullets instead of lengthy explanations.

8. For long requirements, summarize issues by relevant section or topic.
   Do not reproduce or analyze every sentence individually.

9. Do not repeat the same problem under multiple headings.

10. The refined requirement must be clear, complete, unambiguous,
    and testable while preserving original functionality.

11. Do not add unnecessary introductions, conclusions, or commentary.

OUTPUT FORMAT:

## Quality Attributes

| Attribute | Rating | Reason |
| Clarity | Good/Moderate/Poor | Brief reason |
| Completeness | Good/Moderate/Poor | Brief reason |
| Ambiguity | Good/Moderate/Poor | Brief reason |
| Testability | Good/Moderate/Poor | Brief reason |

## Identified Problems

Provide only relevant problems as concise bullet points.
If no significant problems exist, state that clearly.

At the end, write the refined requirement using EXACTLY these markers:

GENERAL_REFINED_REQUIREMENT_START
Write the refined requirement here.
GENERAL_REFINED_REQUIREMENT_END

Do not omit or rename these markers.
"""

    response = generate_response(prompt)

    if response == "API_ERROR":
        return {
            "analysis": "API_ERROR",
            "refined_requirement": "API_ERROR"
        }

    match = re.search(
        r"GENERAL_REFINED_REQUIREMENT_START\s*"
        r"(.*?)\s*GENERAL_REFINED_REQUIREMENT_END",
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
            "Unable to extract the general refined requirement. "
            "Please review the general analysis."
        )

        analysis = response.strip()

    return {
        "analysis": analysis,
        "refined_requirement": refined_requirement
    }
     """