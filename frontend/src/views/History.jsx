import { useEffect, useState } from "react";
import { api } from "../api.js";
import { formatLocalTimestamp } from "../lib/datetime.js";

export default function History({ onOpenAudit }) {
  const [audits, setAudits] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api
      .listAudits()
      .then(setAudits)
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-6 text-red-800">
        Failed to load audits: <span className="font-mono">{error}</span>
      </div>
    );
  }

  if (!audits) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-12 text-center text-slate-500">
        Loading…
      </div>
    );
  }

  if (audits.length === 0) {
    return (
      <div
        data-testid="history-empty"
        className="rounded-xl border border-slate-200 bg-white p-12 text-center text-slate-500"
      >
        No audits yet. Run your first one from the Connect tab.
      </div>
    );
  }

  return (
    <section data-testid="history-table">
      <h2 className="text-lg font-semibold text-slate-900 mb-3">Audits</h2>
      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3 text-left">Created</th>
              <th className="px-4 py-3 text-left">Account</th>
              <th className="px-4 py-3 text-left">Source</th>
              <th className="px-4 py-3 text-right">Rules</th>
              <th className="px-4 py-3 text-right">Findings</th>
              <th className="px-4 py-3 text-right">$ waste</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {audits.map((a) => (
              <tr key={a.id} data-testid="history-row" className="hover:bg-slate-50">
                <td className="px-4 py-3 text-slate-700">
                  {a.created_at ? formatLocalTimestamp(a.created_at) : "—"}
                </td>
                <td className="px-4 py-3 font-mono text-xs">{a.account_id}</td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded-md border px-2 py-0.5 text-xs font-medium ${
                      a.data_source === "aws"
                        ? "bg-emerald-100 text-emerald-800 border-emerald-200"
                        : "bg-slate-100 text-slate-700 border-slate-200"
                    }`}
                  >
                    {a.data_source === "aws" ? "AWS" : a.data_source || "—"}
                  </span>
                </td>
                <td className="px-4 py-3 text-right font-mono">{a.rule_count}</td>
                <td className="px-4 py-3 text-right font-mono">
                  {a.findings_count ?? 0}
                </td>
                <td className="px-4 py-3 text-right font-mono">
                  ${(a.estimated_waste_usd ?? 0).toFixed(2)}
                </td>
                <td className="px-4 py-3">
                  <StatusPill status={a.status} />
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="inline-flex items-center gap-3">
                    <RerunButton audit={a} />
                    <button
                      type="button"
                      onClick={() => onOpenAudit(a.id)}
                      data-testid="history-view-btn"
                      className="text-xs text-blue-600 hover:underline"
                    >
                      View
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function StatusPill({ status }) {
  const tone =
    status === "complete"
      ? "bg-emerald-100 text-emerald-800 border-emerald-200"
      : status === "failed"
        ? "bg-red-100 text-red-800 border-red-200"
        : "bg-amber-100 text-amber-800 border-amber-200";
  return (
    <span className={`rounded-md border px-2 py-0.5 text-xs font-medium ${tone}`}>
      {status}
    </span>
  );
}

function RerunButton({ audit }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  const eligible =
    audit.status === "complete" && audit.data_source === "aws";
  if (!eligible) return null;

  const onClick = async () => {
    if (busy) return;
    setBusy(true);
    setMsg(null);
    try {
      const out = await api.rerunAudit({
        account_id: audit.account_id,
        region: audit.region || "us-east-1",
      });
      setMsg(out.audit_run_id ? "Started — refresh to see status" : "Started");
    } catch (e) {
      // 404 from backend → no saved role.
      if (e && /404|No saved role/i.test(String(e.message))) {
        setMsg("No saved role — use Connect");
      } else {
        setMsg("Re-run failed");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <span className="inline-flex items-center gap-2">
      <button
        type="button"
        onClick={onClick}
        disabled={busy}
        data-testid="history-rerun-btn"
        title="Re-run this audit using the saved role ARN"
        className="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {busy ? "Re-running…" : "Re-run"}
      </button>
      {msg && (
        <span data-testid="history-rerun-msg" className="text-xs text-slate-500">
          {msg}
        </span>
      )}
    </span>
  );
}

