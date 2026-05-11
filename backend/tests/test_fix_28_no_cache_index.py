"""Fix #28 — Cache-Control headers on the SPA static mount.

Problem: After App Runner redeploys, browsers kept loading the previous
build's hashed bundle because `index.html` (whose URL is stable) was
being cached. Vite already hashes asset filenames, so the hashed assets
themselves are safe to cache aggressively — it's only `index.html` (and
the SPA-fallback responses that serve it for client-side routes) that
must NOT be cached.

These tests reload the `main` module against a temp SPA_DIST so we can
exercise the production code path end-to-end via TestClient.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["RULEIQ_TESTING"] = "1"
os.environ.setdefault("EXTERNAL_ID_SECRET", "a" * 64)

import mongomock
import pytest
from fastapi.testclient import TestClient

from services import db as db_mod


def _make_fake_dist(tmp_path: Path) -> Path:
    """Create a minimal Vite-shaped dist tree under tmp_path/static."""
    dist = tmp_path / "static"
    dist.mkdir()
    (dist / "index.html").write_text(
        "<!doctype html><html><body>RULEIQ_SPA_OK</body></html>"
    )
    (dist / "assets").mkdir()
    (dist / "assets" / "index-abc123.js").write_text(
        "// hashed bundle — filename changes per build"
    )
    (dist / "assets" / "index-def456.css").write_text("body{}")
    # Top-level non-asset file (favicon-shaped).
    (dist / "favicon.ico").write_bytes(b"\x00\x00")
    return dist


@pytest.fixture
def fresh_app_with_dist(tmp_path, monkeypatch):
    """Reimport `main` against a fresh RULEIQ_SPA_DIST → returns TestClient."""
    dist = _make_fake_dist(tmp_path)
    monkeypatch.setenv("RULEIQ_SPA_DIST", str(dist))
    import main as _main  # noqa: PLC0415

    fresh = importlib.reload(_main)
    db_mod.set_test_db(mongomock.MongoClient()["ruleiq_fix28_cache"])
    client = TestClient(fresh.app)
    try:
        yield client, dist
    finally:
        db_mod.clear_test_db()


def _cache_control_disables_caching(value: str) -> bool:
    """A Cache-Control header is treated as no-cache iff it includes
    `no-cache`, `no-store`, or `must-revalidate`."""
    v = value.lower()
    return ("no-cache" in v) or ("no-store" in v) or ("must-revalidate" in v)


# --- index.html ------------------------------------------------------------


def test_root_html_returns_no_cache_headers(fresh_app_with_dist):
    """`GET /` must NOT be cached so the browser fetches a fresh
    index.html on every navigation — that's how it picks up the new
    hashed bundle filenames after a deploy."""
    client, _ = fresh_app_with_dist
    resp = client.get("/")
    assert resp.status_code == 200
    assert "RULEIQ_SPA_OK" in resp.text
    cc = resp.headers.get("cache-control", "")
    assert _cache_control_disables_caching(cc), (
        f"index.html missing no-cache directive; got Cache-Control={cc!r}"
    )
    # Pragma + Expires belt-and-braces (old HTTP/1.0 caches / proxies).
    assert resp.headers.get("pragma", "").lower() == "no-cache"
    assert resp.headers.get("expires") == "0"


def test_spa_fallback_route_returns_no_cache_headers(fresh_app_with_dist):
    """The SPA fallback (any unknown path serves index.html so that
    /demo, /connect, /history all bootstrap the SPA) must ALSO carry
    no-cache — otherwise direct-load of /demo gets stale HTML."""
    client, _ = fresh_app_with_dist
    for path in ("/demo", "/connect", "/history",
                  "/some/deep/spa/route"):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} status {resp.status_code}"
        assert "RULEIQ_SPA_OK" in resp.text
        cc = resp.headers.get("cache-control", "")
        assert _cache_control_disables_caching(cc), (
            f"SPA fallback {path!r} cached; Cache-Control={cc!r}"
        )


# --- hashed assets ---------------------------------------------------------


def test_hashed_assets_get_immutable_long_cache(fresh_app_with_dist):
    """Filenames under /assets/* are content-hashed by Vite, so caching
    them for a year is correct — and a huge win for repeat visitors."""
    client, _ = fresh_app_with_dist
    for asset in ("/assets/index-abc123.js", "/assets/index-def456.css"):
        resp = client.get(asset)
        assert resp.status_code == 200, asset
        cc = resp.headers.get("cache-control", "").lower()
        assert "max-age=31536000" in cc, (
            f"{asset} missing 1-year max-age; got {cc!r}"
        )
        assert "immutable" in cc, (
            f"{asset} missing `immutable` directive; got {cc!r}"
        )
        # MUST NOT carry the no-cache directives meant for index.html —
        # otherwise we'd defeat the cache we just opted into.
        assert "no-cache" not in cc, (
            f"{asset} mistakenly carries no-cache; got {cc!r}"
        )


# --- regression guards -----------------------------------------------------


def test_api_routes_unaffected_by_static_cache_policy(fresh_app_with_dist):
    """The new headers must NOT bleed onto API responses."""
    client, _ = fresh_app_with_dist
    resp = client.get("/api/health")
    assert resp.status_code == 200
    # API responses should not be forced to carry any of these headers.
    assert "max-age=31536000" not in resp.headers.get("cache-control", "")
