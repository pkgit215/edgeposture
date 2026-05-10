// Same-origin in production (App Runner serves both API and SPA).
// Override via VITE_API_BASE for local dev pointing at a separate backend.
const BASE = import.meta.env.VITE_API_BASE || "";

async function request(path, options = {}) {
  const resp = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`${resp.status} ${resp.statusText}: ${text}`);
  }
  return resp.json();
}

export const api = {
  setupInfo: () => request("/api/setup-info"),
  createAudit: (body) =>
    request("/api/audits", { method: "POST", body: JSON.stringify(body) }),
  listAudits: () => request("/api/audits"),
  getAudit: (id) => request(`/api/audits/${id}`),
  getAuditRules: (id) => request(`/api/audits/${id}/rules`),
  getAuditFindings: (id) => request(`/api/audits/${id}/findings`),
};
