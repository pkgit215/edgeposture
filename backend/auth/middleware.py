"""Auth middleware — gate `/api/*` behind the session cookie except for
explicitly public routes (`/api/demo/*`, `/api/health`, `/api/openapi.json`,
`/api/docs`, `/api/redoc`).

OAuth routes live under `/auth/` and bypass this middleware entirely.

Test bypass: when `EDGEPOSTURE_TESTING=1`, every `/api/*` request is treated
as authenticated. This keeps the 231 existing pytest cases green; the
Phase 1 auth tests explicitly clear `EDGEPOSTURE_TESTING` to exercise real
enforcement.
"""
from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from auth import sessions

# Exact-path public allowlist + prefix allowlist.
_PUBLIC_EXACT = {
    "/api/health",
    "/api/openapi.json",
    "/api/docs",
    "/api/redoc",
}
_PUBLIC_PREFIXES = (
    "/api/demo/",
    # /api/dist/* serves the deploy-artifact tarballs that Cloud9 pulls
    # to apply branches to git. Must remain public — anonymous curl
    # from outside any session is the whole point of the apply
    # pipeline. Do NOT remove this without an explicit replacement.
    "/api/dist/",
)


def _is_public(path: str) -> bool:
    if not path.startswith("/api/"):
        # SPA assets, /auth/*, /, anything else — middleware doesn't gate it.
        return True
    if path in _PUBLIC_EXACT:
        return True
    return any(path.startswith(p) for p in _PUBLIC_PREFIXES)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if _is_public(path):
            return await call_next(request)
        # Test bypass — preserves the existing 231 pytest cases that
        # hit /api/audits without a session cookie. Phase 1 auth tests
        # explicitly unset EDGEPOSTURE_TESTING.
        if os.environ.get("EDGEPOSTURE_TESTING") == "1":
            return await call_next(request)
        cookie = request.cookies.get(sessions.COOKIE_NAME)
        if not cookie:
            return JSONResponse(
                {"error": "authentication_required"}, status_code=401,
            )
        tenant = sessions.lookup_tenant_by_session_cookie(cookie)
        if not tenant:
            return JSONResponse(
                {"error": "authentication_required"}, status_code=401,
            )
        # Stash on request.state so downstream handlers can read it
        # (Phase 2 will use this to scope queries by tenant_id).
        request.state.tenant = tenant
        return await call_next(request)
