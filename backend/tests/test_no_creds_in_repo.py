"""Chore — credentials/PII regression guard.

Wraps `scripts/check-no-creds.sh` in a pytest so `pytest -q` blocks any
future commit that leaks the real-account / real-domain strings or any
OpenAI key / Mongo URI shape. See the script's header comments for the
exact patterns + exemption list.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-no-creds.sh"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_repo_has_no_credentials_or_pii():
    assert SCRIPT.is_file(), f"missing guard script: {SCRIPT}"
    # The script must remain executable so CI / pre-commit can call it
    # directly. Tests that bypass that via `bash <script>` would mask a
    # broken `chmod +x`.
    assert SCRIPT.stat().st_mode & 0o111, (
        f"{SCRIPT} is not executable — run "
        f"`chmod +x scripts/check-no-creds.sh`"
    )
    result = subprocess.run(
        [str(SCRIPT)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    # Stitch stdout+stderr into the assertion message so a failing test
    # immediately shows the offending file:line pair.
    output = (result.stdout or "") + (result.stderr or "")
    assert result.returncode == 0, (
        "check-no-creds.sh reported credential / PII leakage:\n" + output
    )
    assert "clean" in output.lower()
