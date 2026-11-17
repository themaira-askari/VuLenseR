"""Standard-guided quality rubric (ISO/IEC/IEEE 29148 requirement characteristics).

The rubric lives in code, so no standard document has to be stored in the RAG
knowledge base. It is passed to the LLM as evaluation guidance; the LLM decides
which criteria apply to each requirement and may report another justified issue
as category "Other".

NOTE: criteria names/descriptions are a concise paraphrase of the 29148
characteristics. Verify wording against your licensed copy of the standard
before citing it in a report.
"""

# Characteristics of a single, well-formed requirement.
INDIVIDUAL_CRITERIA = {
    "Necessary": "The requirement states something the stakeholders actually need; it is not redundant or gold-plating.",
    "Appropriate": "The requirement is stated at the right level of abstraction and does not prescribe design/implementation without reason.",
    "Unambiguous": "The wording can be interpreted in only one way; no vague terms such as 'fast', 'user-friendly', 'as appropriate', 'etc.'.",
    "Complete": "The requirement has what is needed to understand it: actor, condition/trigger, action, input/output, and limits where relevant.",
    "Singular": "The requirement states one capability or constraint only; compound statements should be split.",
    "Feasible": "The requirement can realistically be implemented within known constraints.",
    "Verifiable": "A test, inspection, analysis or demonstration can prove it is met (measurable acceptance condition).",
    "Correct": "The requirement accurately reflects the stated need and uses correct, consistent terms.",
    "Conforming": "The requirement follows a clear requirement style ('shall' statement, grammar, consistent format).",
}

# Characteristics of a SET of requirements (the whole document).
SET_CRITERIA = {
    "Consistent": "Requirements do not contradict each other and use the same terms for the same concepts.",
    "Complete": "The set does not leave out needed functions, dependencies or constraints that other requirements rely on.",
    "Duplicated": "Requirements that repeat or overlap each other unnecessarily.",
    "Dependencies": "A requirement depends on something that is not specified anywhere in the document.",
    "Comprehensible": "The set is organised and worded so readers can understand scope and terminology.",
}

OTHER_CATEGORY = "Other"


def _lookup(name: str, criteria: dict) -> str:
    """Return the canonical criterion name for a model-supplied category."""
    wanted = "".join(ch for ch in str(name or "").lower() if ch.isalnum())
    for canonical in criteria:
        if "".join(ch for ch in canonical.lower() if ch.isalnum()) == wanted:
            return canonical
    return OTHER_CATEGORY


def canonical_individual_category(name: str) -> str:
    return _lookup(name, INDIVIDUAL_CRITERIA)


def canonical_set_category(name: str) -> str:
    return _lookup(name, SET_CRITERIA)


def _format(criteria: dict) -> str:
    return "\n".join(f"- {name}: {text}" for name, text in criteria.items())


def individual_rubric_text() -> str:
    return _format(INDIVIDUAL_CRITERIA)


def set_rubric_text() -> str:
    return _format(SET_CRITERIA)


INDIVIDUAL_CATEGORY_CHOICES = "|".join(list(INDIVIDUAL_CRITERIA) + [OTHER_CATEGORY])
SET_CATEGORY_CHOICES = "|".join(list(SET_CRITERIA) + [OTHER_CATEGORY])
