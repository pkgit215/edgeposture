"""EdgePosture auth package — Phase 1 of SaaS onboarding (#45).

Google OAuth Authorization Code flow, server-side. Session is a signed
HTTP-only cookie carrying a session_id; the session record lives in
MongoDB and the tenant_id is resolved server-side from the session.

Scope is INTENTIONALLY narrow:
  * Google OAuth only (Microsoft deferred)
  * `tenants` collection only (no per-tenant scoping of existing
    collections — that lands in Phase 2)
  * No ExternalId derivation (Phase 3) — `external_id` is a placeholder
    uuid4 generated at tenant creation
"""
