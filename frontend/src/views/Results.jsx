import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { formatLocalTimestamp } from "../lib/datetime.js";

const TYPE_STYLES = {
  dead_rule: "bg-red-50 text-red-800 border-red-200",
  bypass_candidate: "bg-orange-50 text-orange-800 border-orange-200",
  conflict: "bg-purple-50 text-purple-800 border-purple-200",
  rule_conflict: "bg-purple-50 text-purple-800 border-purple-200",
  quick_win: "bg-green-50 text-green-800 border-green-200",
  stranded_rule: "bg-amber-50 text-amber-800 border-amber-200",
  // FMS pill is ALWAYS blue, regardless of severity.
  fms_review: "bg-blue-600 text-white border-blue-700",
  orphaned_web_acl: "bg-amber-50 text-amber-800 border-amber-200",
  count_mode_with_hits: "bg-sky-50 text-sky-800 border-sky-200",
  count_mode_high_volume: "bg-sky-100 text-sky-900 border-sky-300",
  count_mode_long_duration: "bg-sky-50 text-sky-700 border-sky-200",
  managed_rule_override_count: "bg-indigo-50 text-indigo-800 border-indigo-200",
};

const SEVERITY_STYLES = {
  high: "bg-red-600 text-white",
  medium: "bg-amber-500 text-white",
  low: "bg-gray-400 text-white",
};

export default function Results({ auditId, onGoConnect }) {
  const [run, setRun] = useState(null);
  const [rules, setRules] = useState(null);
  const [findings, setFindings] = useState(null);
  const [error, setError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [severityFilter, setSeverityFilter] = useState(null);
  const startedAtRef = useRef(Date.now());

  useEffect(() => {
    if (!auditId) return;
    let cancelled = false;
    let timeoutId = null;
    let intervalId = null;
    startedAtRef.current = Date.now();
    setRun(null);
    setRules(null);
    setFindings(null);
    setError(null);
    setElapsed(0);

    intervalId = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAtRef.current) / 1000));
    }, 1000);

    const tick = async () => {
      try {
        const r = await api.getAudit(auditId);
        if (cancelled) return;
        setRun(r);
        if (r.status === "complete") {
          const [rs, fs] = await Promise.all([
            api.getAuditRules(auditId),
            api.getAuditFindings(auditId),
          ]);
          if (cancelled) return;
          setRules(rs);
          setFindings(fs);
          clearInterval(intervalId);
          return;
        }
        if (r.status === "failed") {
          clearInterval(intervalId);
          return;
        }
        timeoutId = setTimeout(tick, 3000);
      } catch (e) {
        if (cancelled) return;
        setError(e.message);
      }
    };
    tick();
    return () => {
      cancelled = true;
      if (timeoutId) clearTimeout(timeoutId);
      if (intervalId) clearInterval(intervalId);
    };
  }, [auditId]);

  if (!auditId) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-12 text-center text-slate-500">
        <p>No audit selected.</p>
        <button
          type="button"
          onClick={onGoConnect}
          className="mt-4 text-sm text-blue-600 underline"
        >
          Run one from Connect
        </button>
      </div>
    );
  }

  if (error) {
    return (
      <div
        data-testid="results-error"
        className="rounded-xl border border-red-200 bg-red-50 p-6 text-red-800"
      >
        <h2 className="text-lg font-semibold">Failed to load audit</h2>
        <p className="text-sm mt-2 font-mono">{error}</p>
      </div>
    );
  }

  if (!run || run.status === "pending" || run.status === "running") {
    return (
      <div className="space-y-6">
        <ResultsHeader auditId={auditId} run={run} />
        <div
          data-testid="results-progress"
          className="rounded-xl border border-slate-200 bg-white p-12 text-center"
        >
          <Spinner />
          <p className="mt-4 text-sm text-slate-600">
            Audit status: <span className="font-medium">{run?.status || "pending"}</span>
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Elapsed: {elapsed}s. You can switch to History in the meantime.
          </p>
        </div>
      </div>
    );
  }

  if (run.status === "failed") {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-6 text-red-800">
        <h2 className="text-lg font-semibold">Audit failed</h2>
        <p className="mt-2 text-sm font-mono break-words">{run.failure_reason || "(no reason)"}</p>
        <p className="mt-3 text-xs text-red-700">
          Data source attempted: {run.data_source}
        </p>
      </div>
    );
  }

  const visibleFindings = severityFilter
    ? findings?.filter((f) => f.severity === severityFilter)
    : findings;

  const maxSeverity = (findings || []).reduce((acc, f) => {
    if (f.severity === "high") return "high";
    if (f.severity === "medium" && acc !== "high") return "medium";
    return acc;
  }, "low");

  const findingNamesByType = (() => {
    const map = new Map();
    for (const f of findings || []) {
      if (f.type === "dead_rule" || f.type === "bypass_candidate") {
        for (const name of f.affected_rules || []) {
          if (!map.has(name)) map.set(name, f);
        }
      }
    }
    return map;
  })();

  const zeroHit = (rules || []).filter((r) => r.hit_count === 0).length;

  return (
    <div className="space-y-8">
      <ResultsHeader auditId={auditId} run={run} />
      <HeadlinePanel
        run={run}
        rulesCount={rules?.length || 0}
        findings={findings || []}
        zeroHit={zeroHit}
        maxSeverity={maxSeverity}
        severityFilter={severityFilter}
        setSeverityFilter={setSeverityFilter}
      />

      <FindingsList findings={visibleFindings || []} />

      <WebACLPanel webAcls={run.web_acls || []} />

      <RuleBrowser rules={rules || []} flaggedMap={findingNamesByType} />

      {run.estimated_waste_breakdown && run.estimated_waste_breakdown.length > 0 && (
        <WasteBreakdown breakdown={run.estimated_waste_breakdown} total={run.estimated_waste_usd} />
      )}
    </div>
  );
}

function ResultsHeader({ auditId, run }) {
  const status = run?.status || "pending";
  const isComplete = status === "complete";
  const downloadUrl = `/api/audits/${auditId}/report.pdf`;
  const onDownload = () => {
    if (!isComplete) return;
    window.location.href = downloadUrl;
  };
  return (
    <div
      data-testid="results-header"
      className="flex items-center justify-between gap-4"
    >
      <div>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          Audit Results
        </h1>
        <p className="mt-1 text-xs text-slate-500 font-mono">
          {auditId} · status: {status}
          {run?.created_at && (
            <> · started {formatLocalTimestamp(run.created_at)}</>
          )}
        </p>
      </div>
      <button
        type="button"
        data-testid="download-pdf-btn"
        onClick={onDownload}
        disabled={!isComplete}
        title={
          isComplete
            ? "Download PDF report"
            : "Audit must finish before report is available"
        }
        className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500"
      >
        <svg
          width="14"
          height="14"
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d="M10 3a1 1 0 0 1 1 1v7.586l2.293-2.293a1 1 0 1 1 1.414 1.414l-4 4a1 1 0 0 1-1.414 0l-4-4a1 1 0 0 1 1.414-1.414L9 11.586V4a1 1 0 0 1 1-1zm-7 13a1 1 0 1 1 0 2h14a1 1 0 1 1 0-2H3z" />
        </svg>
        Download Report (PDF)
      </button>
    </div>
  );
}

function HeadlinePanel({ run, rulesCount, findings, zeroHit, maxSeverity, severityFilter, setSeverityFilter }) {
  const findingsCount = findings.length;
  const sev = { high: 0, medium: 0, low: 0 };
  let bypassCount = 0;
  let strandedCount = 0;
  for (const f of findings) {
    if (sev[f.severity] !== undefined) sev[f.severity]++;
    if (f.type === "bypass_candidate") bypassCount++;
    if (f.evidence === "stranded" || f.type === "stranded_rule") strandedCount++;
  }
  const findingsTone =
    findingsCount === 0
      ? "text-slate-500"
      : maxSeverity === "high"
        ? "text-red-600"
        : maxSeverity === "medium"
          ? "text-amber-600"
          : "text-slate-700";
  const dataSource = run.data_source === "aws" ? "AWS account" : "Demo data";
  const dataSourceTone =
    run.data_source === "aws"
      ? "bg-emerald-100 text-emerald-800 border-emerald-200"
      : "bg-slate-100 text-slate-700 border-slate-200";
  return (
    <div data-testid="headline-panel" className="space-y-3">
      <div className="rounded-xl border border-slate-200 bg-white p-6">
        <div className="flex items-start justify-between gap-6">
          <div>
            <div className="text-xs uppercase tracking-wide text-slate-500">
              Audit findings
            </div>
            <button
              type="button"
              onClick={() => setSeverityFilter((s) => (s ? null : maxSeverity))}
              data-testid="findings-tile"
              className="text-left"
            >
              <div className={`text-5xl font-bold mt-1 ${findingsTone}`}>
                {findingsCount}
              </div>
            </button>
            <div className="mt-2 text-sm text-slate-700">
              <span data-testid="sev-high" className="font-semibold text-red-600">
                {sev.high} high
              </span>
              {"  ·  "}
              <span data-testid="sev-medium" className="font-semibold text-amber-600">
                {sev.medium} medium
              </span>
              {"  ·  "}
              <span data-testid="sev-low" className="font-semibold text-slate-500">
                {sev.low} low
              </span>
            </div>
            {bypassCount > 0 && (
              <p
                data-testid="security-lead"
                className="mt-3 text-sm font-medium text-red-700"
              >
                Including {bypassCount} potential security gap
                {bypassCount === 1 ? "" : "s"} where attack-shaped traffic
                reached the origin.
              </p>
            )}
            {strandedCount > 0 && (
              <p className="mt-1 text-sm text-amber-700">
                {strandedCount} stranded rule{strandedCount === 1 ? "" : "s"} protecting nothing.
              </p>
            )}
            {severityFilter && (
              <p className="mt-2 text-xs text-slate-500">
                Filtered to <b>{severityFilter}</b> severity. Click the number to clear.
              </p>
            )}
          </div>
          <div className="flex flex-col items-end gap-2 text-right">
            <span
              data-testid="data-source-badge"
              className={`inline-block rounded-md border px-2 py-1 text-xs font-medium ${dataSourceTone}`}
            >
              {dataSource}
            </span>
            <div className="text-xs text-slate-500">
              <div>{rulesCount} rules analyzed</div>
              <div className="mt-1">{zeroHit} with zero hits</div>
              <div
                data-testid="cost-line"
                className="mt-2 text-[11px] text-slate-400"
              >
                Cost optimization: $
                {(run.estimated_waste_usd ?? 0).toFixed(2)}/mo
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, valueClass = "" }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`text-3xl font-semibold text-slate-900 ${valueClass}`}>
        {value}
      </div>
    </div>
  );
}

function FindingsList({ findings }) {
  if (findings.length === 0) {
    return (
      <section>
        <h2 className="text-lg font-semibold text-slate-900 mb-3">Findings</h2>
        <div className="rounded-xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500">
          No findings for this filter.
        </div>
      </section>
    );
  }
  return (
    <section data-testid="findings-list">
      <h2 className="text-lg font-semibold text-slate-900 mb-3">Findings</h2>
      <div className="space-y-3">
        {findings.map((f, i) => (
          <FindingCard key={i} f={f} />
        ))}
      </div>
    </section>
  );
}

function FindingCard({ f }) {
  const sev = SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.low;
  const typePill = TYPE_STYLES[f.type] || "bg-slate-100 text-slate-700 border-slate-200";
  const isFms = f.type === "fms_review";
  const [showRem, setShowRem] = useState(f.severity === "high");
  const remediation = f.remediation;
  return (
    <article
      data-testid="finding-card"
      data-finding-type={f.type}
      className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <span
            data-testid="severity-badge"
            className={`rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${sev}`}
          >
            {f.severity}
          </span>
          <span className="text-xs text-slate-500">
            score {f.severity_score} · confidence {(f.confidence * 100).toFixed(0)}%
          </span>
        </div>
        <span
          data-testid="type-pill"
          className={`rounded-full border px-2 py-0.5 text-xs font-medium ${typePill}`}
        >
          {f.type.replace(/_/g, " ")}
        </span>
      </div>
      <h3 className="mt-3 text-base font-semibold text-slate-900">{f.title}</h3>
      <p className="mt-1 text-sm text-slate-700">{f.description}</p>
      {f.affected_rules?.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {f.affected_rules.map((r) => (
            <span
              key={r}
              className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-xs text-slate-700"
            >
              {r}
            </span>
          ))}
        </div>
      )}
      <div className="mt-3 border-l-2 border-slate-300 pl-3 text-sm italic text-slate-600">
        {f.recommendation}
      </div>
      {isFms && (
        <p className="mt-3 text-xs text-blue-700">
          Controlled by your central security admin via Firewall Manager — cannot be modified here.
        </p>
      )}
      {remediation && (
        <div
          data-testid="remediation-block"
          className={`mt-4 rounded-lg border-l-4 bg-slate-50 ${
            f.severity === "high"
              ? "border-red-500"
              : f.severity === "medium"
                ? "border-amber-500"
                : "border-slate-400"
          }`}
        >
          <button
            type="button"
            data-testid="remediation-toggle"
            onClick={() => setShowRem((v) => !v)}
            className="flex w-full items-center justify-between px-4 py-2 text-sm font-semibold text-slate-800 hover:bg-slate-100"
            aria-expanded={showRem}
          >
            <span>Remediation</span>
            <span className="text-xs text-slate-500">{showRem ? "Hide" : "Show"}</span>
          </button>
          {showRem && (
            <div className="space-y-3 px-4 pb-4 text-sm text-slate-700">
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Suggested actions
                </div>
                <ul className="mt-1 list-disc space-y-1 pl-5">
                  {(remediation.suggested_actions || []).map((a, i) => (
                    <li key={i}>{a}</li>
                  ))}
                </ul>
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Verify by
                </div>
                <p className="mt-1">{remediation.verify_by}</p>
              </div>
              <p
                data-testid="remediation-disclaimer"
                className="text-[11px] italic leading-snug text-slate-500"
              >
                {remediation.disclaimer}
              </p>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

function RuleBrowser({ rules, flaggedMap }) {
  const [expanded, setExpanded] = useState({});
  if (rules.length === 0) {
    return null;
  }
  return (
    <section data-testid="rule-browser">
      <h2 className="text-lg font-semibold text-slate-900 mb-3">Rules</h2>
      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3 text-left">Rule</th>
              <th className="px-4 py-3 text-right">Hits</th>
              <th className="px-4 py-3 text-left">Last fired</th>
              <th className="px-4 py-3 text-left">Action</th>
              <th className="px-4 py-3 text-left">Tags</th>
              <th className="px-4 py-3 text-right">JSON</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rules.map((r, i) => {
              const flag = flaggedMap.get(r.rule_name);
              const showJson = expanded[i];
              return (
                <Fragment key={i}>
                  <tr
                    data-testid="rule-row"
                    data-rule-name={r.rule_name}
                    className="hover:bg-slate-50"
                  >
                    <td className="px-4 py-3 font-mono text-xs text-slate-800">
                      <div className="flex items-center gap-2">
                        <span>{r.rule_name}</span>
                        {flag && (
                          <span
                            data-testid="flagged-tag"
                            className="rounded bg-red-50 border border-red-200 px-1.5 py-0.5 text-[10px] font-semibold text-red-700"
                          >
                            Flagged
                          </span>
                        )}
                        {Array.isArray(r.managed_rule_overrides) &&
                          r.managed_rule_overrides.length > 0 && (
                            <span
                              data-testid="override-badge"
                              title={r.managed_rule_overrides
                                .map((o) => `${o.name}: ${o.action}`)
                                .join("\n")}
                              className="rounded bg-indigo-50 border border-indigo-200 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-700"
                            >
                              {r.managed_rule_overrides.length} override
                              {r.managed_rule_overrides.length === 1 ? "" : "s"}
                            </span>
                          )}
                      </div>
                      {flag ? (
                        <p className="mt-1 text-[11px] text-slate-600 italic">
                          {flag.description}
                        </p>
                      ) : (
                        r.ai_explanation && (
                          <p className="mt-1 text-[11px] text-slate-500">
                            {r.ai_explanation}
                          </p>
                        )
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {r.hit_count === 0 ? (
                        <span
                          data-testid="never-fired"
                          className="text-red-600 font-semibold"
                        >
                          Never fired
                        </span>
                      ) : (
                        <span className="font-mono">{r.hit_count.toLocaleString()}</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-600">
                      {r.last_fired ? (
                        <span title={r.last_fired} className="font-mono text-xs">
                          {formatLocalTimestamp(r.last_fired)}
                        </span>
                      ) : (
                        <span>—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-700">{r.action}</td>
                    <td className="px-4 py-3">
                      {r.fms_managed && (
                        <span
                          data-testid="fms-pill"
                          className="rounded-full border border-blue-700 bg-blue-600 px-2 py-0.5 text-xs font-medium text-white"
                        >
                          FMS managed
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => setExpanded((e) => ({ ...e, [i]: !e[i] }))}
                        className="text-xs text-blue-600 hover:underline"
                      >
                        {showJson ? "Hide" : "Show"} JSON
                      </button>
                    </td>
                  </tr>
                  {showJson && (
                    <tr className="bg-slate-50">
                      <td colSpan={6} className="px-4 py-3">
                        <pre className="overflow-x-auto rounded bg-slate-900 p-3 text-[11px] text-slate-100">
                          <code>{JSON.stringify(r.statement_json, null, 2)}</code>
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function WasteBreakdown({ breakdown, total }) {
  return (
    <section>
      <h2 className="text-lg font-semibold text-slate-900 mb-3">
        Waste breakdown
      </h2>
      <div className="rounded-xl border border-slate-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3 text-left">Rule</th>
              <th className="px-4 py-3 text-right">$/month</th>
              <th className="px-4 py-3 text-left">Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {breakdown.map((b, i) => (
              <tr key={i}>
                <td className="px-4 py-3 font-mono text-xs">{b.rule_name}</td>
                <td className="px-4 py-3 text-right font-mono">${b.monthly_usd.toFixed(2)}</td>
                <td className="px-4 py-3 text-slate-600">{b.reason}</td>
              </tr>
            ))}
            <tr className="bg-slate-50 font-semibold">
              <td className="px-4 py-3">Total</td>
              <td className="px-4 py-3 text-right font-mono">${(total ?? 0).toFixed(2)}</td>
              <td />
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}

function WebACLPanel({ webAcls }) {
  if (!webAcls || webAcls.length === 0) return null;
  const orphanCount = webAcls.filter((a) => a.attached === false).length;
  return (
    <section data-testid="web-acl-panel">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-900">Web ACL Attachment</h2>
        {orphanCount > 0 && (
          <span
            data-testid="orphan-count"
            className="rounded-full bg-amber-50 border border-amber-200 px-3 py-1 text-xs font-semibold text-amber-800"
          >
            {orphanCount} orphaned
          </span>
        )}
      </div>
      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3 text-left">Web ACL</th>
              <th className="px-4 py-3 text-left">Scope</th>
              <th className="px-4 py-3 text-left">Attached resources</th>
              <th className="px-4 py-3 text-left">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {webAcls.map((a, i) => {
              const attached = a.attached === true;
              const unknown = a.attached === null || a.attached === undefined;
              const resources = a.attached_resources || [];
              return (
                <tr
                  key={`${a.name}-${i}`}
                  data-testid="web-acl-row"
                  data-attached={attached ? "1" : unknown ? "?" : "0"}
                  className={attached ? "" : unknown ? "" : "bg-amber-50/40"}
                >
                  <td className="px-4 py-3 font-mono text-xs text-slate-800">
                    {a.name}
                  </td>
                  <td className="px-4 py-3 text-slate-600">{a.scope || "REGIONAL"}</td>
                  <td className="px-4 py-3 text-slate-700">
                    {attached ? (
                      <ResourceList resources={resources} />
                    ) : unknown ? (
                      <span className="italic text-slate-500">could not verify</span>
                    ) : (
                      <span className="italic text-slate-500">none</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {attached ? (
                      <span className="rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-xs font-semibold text-emerald-700">
                        Attached
                      </span>
                    ) : unknown ? (
                      <span className="rounded-full border border-slate-200 bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-700">
                        Unknown
                      </span>
                    ) : (
                      <span
                        data-testid="orphan-badge"
                        className="rounded-full border border-amber-300 bg-amber-100 px-2 py-0.5 text-xs font-bold uppercase tracking-wide text-amber-800"
                      >
                        Orphaned
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function _consoleUrlForResource(r) {
  // r is either a string ARN (legacy) or a dict {arn,type,id,friendly}.
  if (!r || typeof r === "string") return null;
  const { type, id, arn } = r;
  if (!type) return null;
  if (type === "CLOUDFRONT" && id) {
    return `https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/distributions/${id}`;
  }
  if (type === "ALB" && arn) {
    return `https://console.aws.amazon.com/ec2/home#LoadBalancers:search=${encodeURIComponent(
      arn,
    )}`;
  }
  if (type === "API_GW" && id) {
    return `https://console.aws.amazon.com/apigateway/main/apis/${id}/overview`;
  }
  return null;
}

function ResourceList({ resources }) {
  if (!resources || resources.length === 0) {
    return <span className="italic text-slate-500">no resources</span>;
  }
  const visible = resources.slice(0, 3);
  const extra = resources.length - visible.length;
  return (
    <div className="flex flex-col gap-1">
      {visible.map((r, idx) => {
        const isDict = r && typeof r === "object";
        const label =
          (isDict && (r.friendly || r.id)) || (isDict ? r.arn : r) || "—";
        const sub = isDict
          ? r.type + (r.id && r.id !== label ? ` · ${r.id}` : "")
          : null;
        const url = _consoleUrlForResource(r);
        return (
          <div key={idx} data-testid="attached-resource" className="leading-tight">
            {url ? (
              <a
                href={url}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-xs text-blue-700 hover:underline"
              >
                {label}
              </a>
            ) : (
              <span className="font-mono text-xs text-slate-800">{label}</span>
            )}
            {sub && (
              <span className="ml-1 text-[10px] uppercase tracking-wide text-slate-500">
                {sub}
              </span>
            )}
          </div>
        );
      })}
      {extra > 0 && (
        <span className="text-[11px] text-slate-500 italic">
          +{extra} more
        </span>
      )}
    </div>
  );
}

function Spinner() {
  return (
    <div className="mx-auto h-10 w-10 animate-spin rounded-full border-2 border-slate-300 border-t-slate-900" />
  );
}

function relativeTime(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const diff = Math.floor((Date.now() - t) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
