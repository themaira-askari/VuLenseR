"""Focused regression tests for requirement scanning edge cases."""

from rule_engine import find_ambiguity, scan_requirement_text


def test_etcetera_is_not_reported_as_open_ended_term():
    findings = find_ambiguity("The system stores etcetera in a metadata field.")
    assert not any(item["category"] == "open_ended" for item in findings)


def test_etc_is_reported_as_open_ended_term():
    findings = find_ambiguity("The system stores logs, etc.")
    assert any(item["category"] == "open_ended" for item in findings)


def test_100_percent_requires_a_token_boundary():
    false_positive = find_ambiguity("The reference value is 2100%.")
    actual_term = find_ambiguity("The service shall achieve 100% availability.")
    assert not any(item["term"] == "100%" for item in false_positive)
    assert any(item["term"] == "100%" for item in actual_term)


def test_requirement_risk_score_stays_within_ten_point_scale():
    requirement = (
        "Users can reset password and login, upload files, access their own records, "
        "and use payment APIs. It must be fast, easy, robust, secure, scalable, reliable, "
        "efficient, modern, simple, safe, flexible, intuitive, quickly, easily, some, "
        "many, several, various, should, may, might, could, always, never, completely, "
        "better, faster, improved, minimal, maximum, if possible, etc."
    )
    result = scan_requirement_text(requirement)
    assert 0 <= result["risk_score"] <= 10
