import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";

const ROLE_ARN_RE = /^arn:aws:iam::\d{12}:role\/.+$/;
const REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "eu-west-1",
  "eu-central-1",
  "ap-southeast-1",
  "ap-northeast-1",
];

export default function Connect({ onAuditStarted }) {
  const [info, setInfo] = useState(null);
  const [error, setError] = useState(null);
  const [roleArn, setRoleArn] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [submitting, setSubmitting] = useState(false);
  const [showInline, setShowInline] = useState(false);

  useEffect(() => {
    api
      .setupInfo()
      .then(setInfo)
      .catch((e) => setError(e.message));
  }, []);

  const accountId = useMemo(() => {
    const m = roleArn.match(/^arn:aws:iam::(\d{12}):role\//);
    return m ? m[1] : null;
  }, [roleArn]);

  const arnOk = ROLE_ARN_RE.test(roleArn);

  const openQuickCreate = () => {
    if (!info?.cfn_quick_create_url) return;
    window.open(info.cfn_quick_create_url, "_blank", "noopener,noreferrer");
  };

  const runRealAudit = async () => {
    if (!arnOk || !info) return;
    setSubmitting(true);
    setError(null);
    try {
      const out = await api.createAudit({
        account_id: accountId,
        role_arn: roleArn,
        external_id: info.external_id,
        region,
      });
      onAuditStarted(out.audit_run_id);
    } catch (e) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  };

  const runDemoAudit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const out = await api.createAudit({
        account_id: "123456789012",
        region: "us-east-1",
      });
      onAuditStarted(out.audit_run_id);
    } catch (e) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-10">
      <div data-testid="hero">
        <h1 className="text-4xl font-bold text-slate-900 tracking-tight">
          RuleIQ
        </h1>
        <p className="mt-2 text-lg text-slate-600">
          AI-powered AWS WAF audits.
        </p>
      </div>

      {error && (
        <div
          data-testid="connect-error"
          className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"
        >
          {error}
        </div>
      )}

      <section className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm space-y-6">
        <div>
          <h2 className="text-xl font-semibold text-slate-900">
            Connect your AWS account
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Click the button below. AWS opens a Quick-Create CloudFormation
            stack pre-filled with the trust policy and read-only IAM permissions
            RuleIQ needs.
          </p>
        </div>

        <button
          type="button"
          onClick={openQuickCreate}
          disabled={!info}
          data-testid="quick-create-btn"
          className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 disabled:bg-slate-300 disabled:cursor-not-allowed transition"
        >
          {info ? "Connect AWS account → Quick-Create role" : "Loading…"}
        </button>

        {!info && (
          <div data-testid="connect-skeleton" className="space-y-3 pt-4">
            <div className="h-4 w-2/3 rounded bg-slate-200 animate-pulse" />
            <div className="h-4 w-1/2 rounded bg-slate-200 animate-pulse" />
          </div>
        )}

        {info && (
          <div className="space-y-5 pt-4">
            <p className="text-sm text-slate-600">
              Once your CloudFormation stack reaches{" "}
              <code className="rounded bg-slate-100 px-1">CREATE_COMPLETE</code>
              , paste the Role ARN below.
            </p>

            <Field label="Role ARN" htmlFor="role-arn">
              <input
                id="role-arn"
                data-testid="role-arn-input"
                type="text"
                placeholder="arn:aws:iam::123456789012:role/RuleIQAuditRole"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value.trim())}
                className="w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
              />
              {roleArn && !arnOk && (
                <p
                  data-testid="role-arn-error"
                  className="mt-1 text-xs text-red-600"
                >
                  Must match arn:aws:iam::&lt;12 digit account&gt;:role/&lt;name&gt;
                </p>
              )}
            </Field>

            <Field label="ExternalId (read-only, paired with this tenant)">
              <ExternalIdReadOnly value={info.external_id} />
            </Field>

            <Field label="Region" htmlFor="region">
              <select
                id="region"
                data-testid="region-select"
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                className="rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
              >
                {REGIONS.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </Field>

            <div className="flex items-center gap-3 pt-2">
              <button
                type="button"
                onClick={runRealAudit}
                disabled={!arnOk || submitting}
                data-testid="run-audit-btn"
                className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:bg-slate-300 disabled:cursor-not-allowed transition"
              >
                {submitting ? "Starting…" : "Run audit"}
              </button>
              <button
                type="button"
                onClick={runDemoAudit}
                disabled={submitting}
                data-testid="run-demo-btn"
                className="text-sm text-slate-600 underline underline-offset-2 hover:text-slate-900 disabled:text-slate-300"
              >
                Or skip setup → run a demo audit
              </button>
            </div>
          </div>
        )}
      </section>

      {info && (
        <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <button
            type="button"
            onClick={() => setShowInline((v) => !v)}
            data-testid="manual-toggle"
            className="text-sm font-medium text-slate-700 hover:text-slate-900"
          >
            {showInline ? "▾" : "▸"} Manual setup (no CFN)
          </button>
          {showInline && (
            <div className="mt-4 space-y-3">
              <p className="text-xs text-slate-600">
                If you prefer to create the role by hand, attach this inline
                policy and use the trust statement from{" "}
                <code className="rounded bg-slate-100 px-1">
                  cloudformation/customer-role.yaml
                </code>
                .
              </p>
              <CopyBlock value={JSON.stringify(info.inline_iam_json, null, 2)} />
            </div>
          )}
        </section>
      )}
    </div>
  );
}

function Field({ label, htmlFor, children }) {
  return (
    <div>
      <label
        htmlFor={htmlFor}
        className="block text-sm font-medium text-slate-700 mb-1"
      >
        {label}
      </label>
      {children}
    </div>
  );
}

function ExternalIdReadOnly({ value }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* ignore */
    }
  };
  return (
    <div className="flex items-center gap-2">
      <input
        readOnly
        value={value}
        data-testid="external-id-input"
        className="flex-1 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-sm text-slate-700"
      />
      <button
        type="button"
        onClick={onCopy}
        data-testid="external-id-copy"
        className="rounded-md border border-slate-300 px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-100"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

function CopyBlock({ value }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-md bg-slate-900 p-4 text-xs text-slate-100">
        <code>{value}</code>
      </pre>
      <button
        type="button"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          } catch {}
        }}
        className="absolute right-2 top-2 rounded bg-slate-700 px-2 py-1 text-xs text-white hover:bg-slate-600"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}
