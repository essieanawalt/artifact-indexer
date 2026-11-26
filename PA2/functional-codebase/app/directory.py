# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Local static mock data for faculty course and lab association (~100%)
# Human Modifications: None yet
# Verification: tests/test_authz.py download tests (prof-course, prof-lab, prof-other)
# Confidence: High
"""Static, fictional mock directory: which courses and labs each faculty member (token sub) is associated with.

This is the only source of faculty association. It is never read from tokens or requests.
"""

FACULTY_UNITS: dict[str, frozenset[tuple[str, str]]] = {
    "prof-one": frozenset({("course", "CS763"), ("lab", "lab-robotics")}),
    "prof-course": frozenset({("course", "CS763")}),
    "prof-lab": frozenset({("lab", "lab-robotics")}),
    "prof-other": frozenset({("course", "CS999"), ("lab", "lab-vision")}),
}


def faculty_units(sub: str) -> frozenset[tuple[str, str]]:
    return FACULTY_UNITS.get(sub, frozenset())
