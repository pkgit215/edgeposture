"""Chore #36 — README content-shape guard.

The customer-facing README must NOT advertise internal phase tracking
and MUST state v0.1 PoC status + reference ROADMAP.md. This pytest is
the regression guard so a future PR doesn't sneak the dev content back.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"

_PHASE_PATTERN = re.compile(r"\bPhase\s+\d+(\.\d+)*\b", re.IGNORECASE)


def test_readme_does_not_advertise_internal_phase_tracking():
    text = README.read_text(encoding="utf-8")
    hits = [m.group(0) for m in _PHASE_PATTERN.finditer(text)]
    assert not hits, (
        "README leaks internal phase tracking — move developer content "
        "to docs/DEVELOPMENT.md. Offending strings: " + ", ".join(hits)
    )


def test_readme_states_v0_1_status():
    text = README.read_text(encoding="utf-8")
    assert "v0.1" in text, (
        "README must state current status as v0.1 — see "
        "the `## Status` section spec in Chore #36."
    )


def test_readme_references_roadmap_md():
    text = README.read_text(encoding="utf-8")
    assert "ROADMAP.md" in text, (
        "README must link ROADMAP.md instead of inline phase listings."
    )


def test_readme_references_demo_url():
    """Sanity — the customer should hit the live demo above the fold."""
    text = README.read_text(encoding="utf-8")
    assert "d96qfmakzi.us-east-1.awsapprunner.com" in text, (
        "README lost the live-demo callout — that's the entire above-the-fold hook."
    )
