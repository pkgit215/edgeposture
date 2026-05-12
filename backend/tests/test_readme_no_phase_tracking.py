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


# --- Value-prop lede: bypass-led, not cost-led ----------------------------

_DOLLAR_PER_PERIOD_RE = re.compile(
    r"\$\d+\s*/\s*(mo|month|year|yr)\b", re.IGNORECASE,
)
_LEDE_LINE_BUDGET = 40


def test_readme_lede_features_bypass_detection_phrase():
    """The README must lead with the bypass story, verbatim. The
    user-approved value-prop paragraph contains the phrase
    'reached your origin uninspected' — guard against future copy
    drift that re-centres the lede on cost savings."""
    text = README.read_text(encoding="utf-8").lower()
    assert "reached your origin uninspected" in text, (
        "README lost the bypass-led value-prop. Restore the user-approved "
        "paragraph that contains 'reached your origin uninspected'."
    )


def test_readme_lede_does_not_lead_with_dollar_cost_figures():
    """No literal `$XX/mo` style cost figures may appear in the top
    of the README. Cost mentions are fine deeper in the file (IAM
    policy section, Status section, etc.); they just can't be the
    hook. Buyers care about coverage, not $5/mo."""
    lines = README.read_text(encoding="utf-8").splitlines()[:_LEDE_LINE_BUDGET]
    leaked = []
    for i, line in enumerate(lines, start=1):
        m = _DOLLAR_PER_PERIOD_RE.search(line)
        if m:
            leaked.append(f"line {i}: {m.group(0)} ({line.strip()!r})")
    assert not leaked, (
        f"README lede (top {_LEDE_LINE_BUDGET} lines) leads with cost — "
        f"move the dollar figure deeper. Offending matches: " + "; ".join(leaked)
    )


# --- Above-the-fold screenshots ------------------------------------------

_SCREENSHOTS_DIR = ROOT / "docs" / "screenshots"
_REQUIRED_SCREENSHOTS = ("dashboard.png", "pdf-exec-summary.png", "connect.png")
_README_IMG_RE = re.compile(
    r"!\[[^\]]*\]\(docs/screenshots/[^\)]+\.png\)",
)


def test_readme_screenshot_files_exist_on_disk():
    """Each markdown image reference in README points at a real PNG
    under docs/screenshots/. A broken image in the lede is much worse
    than no image — fail loudly at test time, not at GitHub render time."""
    for name in _REQUIRED_SCREENSHOTS:
        path = _SCREENSHOTS_DIR / name
        assert path.is_file(), f"missing committed screenshot: {path}"
        # 5 kB is a sanity floor — a stub/empty PNG (~few hundred bytes)
        # would still pass `is_file()` but render as a broken icon.
        assert path.stat().st_size > 5_000, (
            f"{path} is suspiciously small ({path.stat().st_size} B) — "
            f"likely an empty placeholder. Re-capture from the live demo."
        )


def test_readme_references_exactly_three_screenshots():
    text = README.read_text(encoding="utf-8")
    refs = _README_IMG_RE.findall(text)
    assert len(refs) == 3, (
        f"README must contain exactly 3 docs/screenshots/*.png image "
        f"references (Dashboard, PDF, Connect). Found {len(refs)}: {refs}"
    )
