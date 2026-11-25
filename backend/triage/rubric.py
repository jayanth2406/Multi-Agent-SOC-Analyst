"""Severity rubric and taxonomy from docs/requirements-specification.md.

Kept dependency-free so the alert generator, the checker and (later) the
Triage agent can all import the same rules.
"""

from __future__ import annotations

CATEGORIES = {
    "C1": "Reconnaissance",
    "C2": "Credential attack",
    "C3": "Account compromise and lateral movement",
    "C4": "Exploitation",
    "C5": "Malware and malicious execution",
    "C6": "Command and control, exfiltration",
    "C7": "Denial of service",
    "B1": "Authorised activity",
    "B2": "User error",
    "U0": "Unclassified",
}

DISPOSITIONS = ("TP", "BTP", "FP", "needs_investigation")

LEVELS = ("Informational", "Low", "Medium", "High", "Critical")
TIERS = ("Low", "Standard", "High", "Critical")

# Stage (rows 1-4) x asset tier (columns) -> severity. Stage 0 is Informational.
SEVERITY_TABLE = {
    1: {"Low": "Low", "Standard": "Low", "High": "Low", "Critical": "Medium"},
    2: {"Low": "Low", "Standard": "Medium", "High": "Medium", "Critical": "High"},
    3: {"Low": "Medium", "Standard": "High", "High": "High", "Critical": "Critical"},
    4: {"Low": "High", "Standard": "High", "High": "Critical", "Critical": "Critical"},
}


def max_tier(*tiers: str | None) -> str:
    """The most critical of the tiers given (unknown tiers are ignored)."""
    known = [t for t in tiers if t in TIERS]
    if not known:
        raise ValueError("no known asset tier given")
    return max(known, key=TIERS.index)


def severity(stage: int, tier: str, spread: bool = False, ongoing: bool = False) -> str:
    """Final severity: table lookup, then at most one level up for modifiers."""
    if stage == 0:
        return "Informational"
    base = SEVERITY_TABLE[stage][tier]
    if spread or ongoing:
        return LEVELS[min(LEVELS.index(base) + 1, len(LEVELS) - 1)]
    return base


def investigation_depth(level: str) -> str:
    """Light for Informational and Low, full otherwise (before safeguards)."""
    return "light" if level in ("Informational", "Low") else "full"
