import re

# ---------------------------------------------------------------------------
# 1. Ambiguity patterns (IEEE 830 / ISO 29148 style) with weights
# ---------------------------------------------------------------------------
AMBIGUITY_PATTERNS = {
    "vague_adjective": {
        "words": ["fast", "user-friendly", "robust", "easy", "flexible", "intuitive",
                  "adequate", "efficient", "modern", "simple", "secure", "scalable",
                  "reliable", "seamless", "lightweight", "optimized", "safe"],
        "weight": 1.0,
    },
    "vague_adverb": {
        "words": ["quickly", "easily", "promptly", "seamlessly", "optimally", "efficiently"],
        "weight": 1.0,
    },
    "quantifier": {
        "words": ["some", "many", "several", "few", "various", "multiple", "most", "all"],
        "weight": 0.5,
    },
    "escape_clause": {
        "words": ["if possible", "as appropriate", "where applicable", "as required",
                  "if feasible", "when necessary", "as needed"],
        "weight": 1.5,
    },
    "open_ended": {
        "words": ["etc", "and so on", "including but not limited to", "such as"],
        "weight": 1.0,
    },
    "weak_verb": {
        "words": ["should", "may", "might", "could", "can"],
        "weight": 0.5,
    },
    "unverifiable": {
        "words": ["always", "never", "completely"],
        "weight": 1.0,
    },
    "comparative": {
        "words": ["better", "faster", "improved", "minimal", "maximum"],
        "weight": 1.0,
    },
}

SPECIAL_AMBIGUITY = [
    (r"(?<!\w)100\s?%(?!\w)", "unverifiable", "100%", 1.0),
]

RATE_LIMIT_PATTERNS = [
    r"rate[\s-]limit\w*",
    r"throttl\w*",
    r"\blimit\w*\s+(?:the\s+)?(?:number|rate|frequency)\s+of\s+(?:\w+\s+){0,2}(?:requests|attempts)",
    r"requests?\s+per\s+(?:account|user|ip|minute|hour)",
]

# ---------------------------------------------------------------------------
# 2. Security controls: triggers -> expected control groups
# ---------------------------------------------------------------------------
SECURITY_CONTROLS = {
    "password_reset": {
        "triggers": [
            r"reset\w*\s+(?:\w+\s+){0,2}password",
            r"forgot\w*\s+password",
            r"password\s+(?:recovery|reset)",
            r"change\w*\s+(?:\w+\s+){0,2}password",
        ],
        "expected_groups": {
            "token_control": [r"expir\w+", r"single[\s-]use", r"one[\s-]time",
                              r"time[\s-](?:bound|limited)", r"usable\s+only\s+once",
                              r"valid\s+(?:only\s+)?for\s+(?:\w+\s+){0,2}(?:seconds?|minutes?|hours?)",
                              r"short[\s-]lived"],
            "rate_limiting": RATE_LIMIT_PATTERNS,
            "enumeration_prevention": [r"generic\s+(?:response|message)",
                                       r"(?:not|never|without)\s+reveal\w*",
                                       r"enumerat\w+",
                                       r"(?:same|identical|uniform)\s+(?:\w+\s+)?(?:response|message)",
                                       r"regardless\s+of\s+whether"],
        },
        "owasp": "A07:2021 Identification and Authentication Failures",
        "severity": "high",
    },
    "login": {
        "triggers": [r"\blogin\b", r"sign\s+in", r"log\s+in", r"authenticat\w*", r"user\s+access"],
        "expected_groups": {
            "authentication_factor": [r"\bmfa\b", r"multi[\s-]factor", r"\b2fa\b", r"\botp\b"],
            "account_protection": [r"lockout", r"account\s+lock\w*", r"\bcaptcha\b"] + RATE_LIMIT_PATTERNS,
            "session_security": [r"secure\s+sessions?", r"sessions?\s+timeout"],
        },
        "owasp": "A07:2021 Identification and Authentication Failures",
        "severity": "high",
    },
    "file_upload": {
        "triggers": [r"\buploads?\b", r"\buploading\b", r"attach\s+files?", r"document\s+submission"],
        "expected_groups": {
            "validation": [r"mime\s+validat\w+", r"type\s+check", r"file\s+type\s+validat\w+"],
            "constraints": [r"size\s+limit", r"quota"],
            "safety": [r"malware\s+scan", r"virus\s+scan", r"\brename\b"],
        },
        "owasp": "A04:2021 Insecure Design",
        "severity": "high",
    },
    "logging_audit": {
        "triggers": [r"security\s+log", r"audit\s+trail", r"track\s+activity"],
        "expected_groups": {
            "integrity": [r"log\s+integrit\w+", r"tamper[\s-]proof", r"immutable"],
            "privacy": [r"no\s+sensitive\s+data", r"mask\w*", r"redact\w*"],
        },
        "owasp": "A09:2021 Security Logging and Monitoring Failures",
        "severity": "medium",
    },
    "admin_privileges": {
        "triggers": [r"\badmin\b", r"administrator", r"superuser", r"privilege\s+escalation"],
        "expected_groups": {
            "verification": [r"\bmfa\b", r"multi[\s-]factor"],
            "network": [r"ip\s+restrict\w+", r"ip\s+allowlist"],
            "segregation": [r"separate\s+privilege", r"least\s+privilege"],
        },
        "owasp": "A01:2021 Broken Access Control",
        "severity": "critical",
    },
    "ssrf_fetch": {
        "triggers": [r"fetch\s+url", r"external\s+url", r"webhook", r"external\s+request"],
        "expected_groups": {
            "destination_control": [r"allowlist", r"url\s+validat\w+", r"block\s+internal\s+ip"],
        },
        "owasp": "A10:2021 Server-Side Request Forgery (SSRF)",
        "severity": "high",
    },
    "encryption_transit_rest": {
        "triggers": [r"data\s+in\s+transit", r"data\s+at\s+rest", r"stored\s+securely"],
        "expected_groups": {
            "transport": [r"\btls\b", r"\bssl\b", r"https"],
            "storage_algorithms": [r"\baes\b", r"bcrypt", r"argon2", r"key\s+(?:rotation|management)"],
        },
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "high",
    },
    "session": {
        "triggers": [r"\bsessions?\b", r"user\s+session"],
        "expected_groups": {
            "lifecycle": [r"timeout", r"expir\w+", r"invalidat\w+"],
            "cookie_flags": [r"secure\s+cookie", r"httponly"],
        },
        "owasp": "A07:2021 Identification and Authentication Failures",
        "severity": "high",
    },
    "api": {
        "triggers": [r"\bapi\b", r"endpoint", r"rest\s+api"],
        "expected_groups": {
            "protection": RATE_LIMIT_PATTERNS + [r"\btokens?\b", r"\bjwt\b", r"oauth"],
            "validation": [r"authoriz\w*", r"validat\w+", r"\bcors\b"],
        },
        "owasp": "A01:2021 Broken Access Control",
        "severity": "high",
    },
    "input": {
        "triggers": [r"\binputs?\b", r"form\s+data", r"user\s+input",
                     r"(?:request|query|url)\s+parameters?"],
        "expected_groups": {
            "sanitization": [r"sanitiz\w*", r"validat\w*", r"\bescap\w*", r"parameteri[sz]\w*",
                             r"injection\s+prevent\w*"],
        },
        "owasp": "A03:2021 Injection",
        "severity": "critical",
    },
    "payment": {
        "triggers": [r"payment", r"credit\s+card", r"checkout"],
        "expected_groups": {
            "compliance_security": [r"pci[\s-]dss", r"tokeniz\w*", r"secure\s+gateway", r"encrypt\w*"],
        },
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "critical",
    },
    "role": {
        "triggers": [r"\broles?\b", r"access\s+rights?", r"authoriz\w*"],
        "expected_groups": {
            "framework": [r"\brbac\b", r"access\s+control", r"least\s+privilege"],
        },
        "owasp": "A01:2021 Broken Access Control",
        "severity": "high",
    },
    "error": {
        "triggers": [r"system\s+error", r"unhandled\s+exception", r"failure\s+handling"],
        "expected_groups": {
            "safe_display": [r"generic\s+error", r"stack\s+trace", r"secure\s+logging"],
        },
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "medium",
    },
    "data": {
        "triggers": [r"user\s+data", r"sensitive\s+data", r"database\s+records"],
        "expected_groups": {
            "protection": [r"encrypt\w*", r"mask\w*", r"securely\s+stored"],
        },
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "high",
    },
    "object_access": {
        "triggers": [r"\b(?:view|download|edit|delete|access|retrieve)\w*\s+(?:\w+\s+){0,2}(?:their|own|other|any)\b"],
        "expected_groups": {
            "ownership_check": [r"authoriz\w*", r"\bacl\b", r"access\s+control",
                                r"owner(?:ship)?\s+check", r"object[\s-]level"],
        },
        "owasp": "A01:2021 Broken Access Control",
        "severity": "high",
    },
    "privacy_gdpr": {
        "triggers": [r"gdpr", r"personal\s+data", r"user\s+privacy", r"data\s+subject"],
        "expected_groups": {
            "compliance": [r"consent", r"retention\s+policy", r"right\s+to\s+erasure", r"anonymiz\w*"],
        },
        "owasp": "A04:2021 Insecure Design",
        "severity": "high",
    },
    "account_lockout": {
        "triggers": [r"brute[\s-]force", r"repeated\s+failed", r"multiple\s+attempts"],
        "expected_groups": {
            "defense": [r"lockout", r"account\s+lock\w*", r"\bcaptcha\b"] + RATE_LIMIT_PATTERNS,
        },
        "owasp": "A07:2021 Identification and Authentication Failures",
        "severity": "high",
    },
    "backup_recovery": {
        "triggers": [r"\bbackups?\b", r"disaster\s+recovery", r"data\s+restore"],
        "expected_groups": {
            "backup_security": [r"encrypt\w*", r"access\s+control", r"retention"],
        },
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "medium",
    },
    "third_party_deps": {
        "triggers": [r"third[\s-]party", r"external\s+librar\w+", r"software\s+dependenc\w+",
                     r"npm\s+package", r"open[\s-]source\s+(?:component|librar\w+)"],
        "expected_groups": {
            "management": [r"version\s+pin\w*", r"cve\s+scan\w*", r"\bsca\b", r"vulnerability\s+scan\w*"],
        },
        "owasp": "A06:2021 Vulnerable and Outdated Components",
        "severity": "high",
    },
    "config_deploy": {
        "triggers": [r"deployment", r"server\s+config\w*", r"production\s+setup"],
        "expected_groups": {
            "hardening": [r"secure\s+default\w*", r"hardening", r"no\s+default\s+credential\w*", r"ci/cd"],
        },
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "high",
    },
}

SEVERITY_WEIGHT = {"critical": 5, "high": 3, "medium": 2}


# ---------------------------------------------------------------------------
# IEEE 830 / ISO 29148 Standard Guideline Generator (Exact Format)
# ---------------------------------------------------------------------------
def get_ieee_guideline(category: str, term: str):
    guidelines = {
        "weak_verb": {
            "standard": "IEEE 830 / ISO 29148",
            "suggestion": f"Use 'shall' or 'must' instead of '{term}' because modal verbs introduce ambiguity and optionality."
        },
        "vague_adjective": {
            "standard": "IEEE 830 / ISO 29148",
            "suggestion": f"Use specific quantitative metrics instead of '{term}' because subjective adjectives are non-measurable and untestable."
        },
        "vague_adverb": {
            "standard": "IEEE 830 / ISO 29148",
            "suggestion": f"Use precise performance criteria instead of '{term}' because adverbs lack concrete benchmarks."
        },
        "quantifier": {
            "standard": "IEEE 830 / ISO 29148",
            "suggestion": f"Use exact numerical values instead of '{term}' because vague quantifiers create scope ambiguity."
        },
        "escape_clause": {
            "standard": "IEEE 830 / ISO 29148",
            "suggestion": f"Use explicit fallback conditions instead of '{term}' because escape clauses allow bypassing requirements."
        },
        "open_ended": {
            "standard": "IEEE 830 / ISO 29148",
            "suggestion": f"Use an explicit closed list instead of '{term}' because open-ended terms leave requirements unbounded."
        },
        "unverifiable": {
            "standard": "IEEE 830 / ISO 29148",
            "suggestion": f"Use verifiable operational boundaries instead of '{term}' because absolute terms cannot be universally verified."
        },
        "comparative": {
            "standard": "IEEE 830 / ISO 29148",
            "suggestion": f"Use an absolute baseline metric instead of '{term}' because comparative terms lack a reference baseline."
        }
    }
    
    default_guide = {
        "standard": "IEEE 830 / ISO 29148",
        "suggestion": f"Use a precise and explicit term instead of '{term}' because ambiguous phrasing leads to misinterpretation."
    }
    
    return guidelines.get(category, default_guide)


# ---------------------------------------------------------------------------
# Engine Functions
# ---------------------------------------------------------------------------
def find_ambiguity(text: str):
    """Ambiguity terms dhoondta hai aur IEEE/ISO standards ke mutabiq suggestion sath deta hai."""
    found = []
    text_lower = text.lower()

    for pattern, category, term, weight in SPECIAL_AMBIGUITY:
        if re.search(pattern, text_lower):
            guide = get_ieee_guideline(category, term)
            found.append({
                "category": category, 
                "term": term, 
                "weight": weight,
                "standard": guide["standard"],
                "suggestion": guide["suggestion"]
            })

    for category, info in AMBIGUITY_PATTERNS.items():
        for w in info["words"]:
            if re.search(rf"(?<!\w){re.escape(w)}(?!\w)", text_lower):
                guide = get_ieee_guideline(category, w)
                found.append({
                    "category": category, 
                    "term": w, 
                    "weight": info["weight"],
                    "standard": guide["standard"],
                    "suggestion": guide["suggestion"]
                })
    return found


def check_security_controls(text: str):
    """Triggers match karta hai, phir missing control groups report karta hai."""
    text_lower = text.lower()
    findings = []

    for key, data in SECURITY_CONTROLS.items():
        matched = [p for p in data["triggers"] if re.search(p, text_lower)]
        if not matched:
            continue

        missing_groups = [
            group for group, patterns in data["expected_groups"].items()
            if not any(re.search(p, text_lower) for p in patterns)
        ]
        if missing_groups:
            findings.append({
                "category": key,
                "owasp_mapping": data["owasp"],
                "severity": data["severity"],
                "triggers_matched": matched,
                "missing_control_groups": missing_groups,
            })
    return findings


def scan_requirement_text(req_text: str):
    """Ek requirement scan karta hai; same OWASP category dobara aaye to half weight."""
    ambiguities = find_ambiguity(req_text)
    security_gaps = check_security_controls(req_text)

    ambiguity_score = sum(item["weight"] for item in ambiguities)

    security_score = 0.0
    counted_owasp = set()
    for gap in security_gaps:
        base = SEVERITY_WEIGHT.get(gap["severity"], 2)
        if gap["owasp_mapping"] not in counted_owasp:
            security_score += base
            counted_owasp.add(gap["owasp_mapping"])
        else:
            security_score += base * 0.5

    return {
        "requirement": req_text,
        "ambiguities_found": ambiguities,
        "security_gaps_found": security_gaps,
        # The UI presents this as a score out of 10, so keep the value in range.
        "risk_score": min(10.0, round(ambiguity_score + security_score, 1)),
    }


def split_requirements(srs_text: str):
    """Lines ko requirements mein todta hai; headings aur chhoti lines skip."""
    reqs = []
    for line in srs_text.split("\n"):
        line = line.strip()
        if len(line) <= 10 or line.startswith("#"):
            continue
        reqs.append(line)
    return reqs


def scan_full_srs(srs_full_text: str):
    """Poora SRS analyze karta hai."""
    lines = split_requirements(srs_full_text)
    analysis, total_risk = [], 0.0

    for line in lines:
        result = scan_requirement_text(line)
        if result["risk_score"] > 0:
            analysis.append(result)
            total_risk += result["risk_score"]

    return {
        "total_requirements_scanned": len(lines),
        "flagged_issues_count": len(analysis),
        "overall_srs_risk_score": round(total_risk, 1),
        "detailed_findings": analysis,
    }


if __name__ == "__main__":
    import json
    demo = "Users can reset their password by entering their email address."
    print(json.dumps(scan_requirement_text(demo), indent=2))