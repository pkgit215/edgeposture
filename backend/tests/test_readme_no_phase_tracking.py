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


# --- Chore: v0.1 beta clarification ---------------------------------------

DEMO_MD = ROOT / "DEMO.md"

_NON_FUNCTIONAL_INSTRUCTIONS = (
    "paste your AWS Account ID",
    "paste your Role ARN",
)


def test_readme_and_demo_md_advertise_beta_status():
    """v0.1 is beta — both customer-facing docs must say so unambiguously.
    Catches a future regression where the beta callout is silently dropped."""
    for path in (README, DEMO_MD):
        text = path.read_text(encoding="utf-8").lower()
        assert "beta" in text, (
            f"{path.name} no longer mentions beta status — keep the v0.1 "
            f"callout unmissable per Chore: README beta clarification."
        )


def test_readme_and_demo_md_omit_nonfunctional_self_serve_instructions():
    """v0.1 hosted instance only trusts the maintainer's AWS account.
    Instructing customers to paste their Account ID / Role ARN dead-ends
    them — those phrases must NOT appear in customer-facing docs until
    the multi-tenant onboarding flow ships."""
    for path in (README, DEMO_MD):
        lower = path.read_text(encoding="utf-8").lower()
        for phrase in _NON_FUNCTIONAL_INSTRUCTIONS:
            assert phrase.lower() not in lower, (
                f"{path.name} contains non-functional v0.1 instruction "
                f"{phrase!r} — the self-serve audit flow against the "
                f"customer's own AWS account is not wired in yet."
            )


# --- Distribution-model honesty ------------------------------------------

ROADMAP = ROOT / "ROADMAP.md"


def test_readme_and_roadmap_state_distribution_model_is_undecided():
    """The distribution path (self-host / SaaS / Marketplace / hybrid)
    is explicitly undecided. README and ROADMAP must both say so —
    no assuming `self-host` as the locked-in answer."""
    for path in (README, ROADMAP):
        text = path.read_text(encoding="utf-8").lower()
        assert "undecided" in text, (
            f"{path.name} must state distribution model is undecided. "
            f"Per the chore-readme-beta PR, both README + ROADMAP cite "
            f"the open question explicitly so readers don't infer "
            f"self-host is locked in."
        )
