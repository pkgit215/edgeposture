import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { formatLocalTimestamp } from "../lib/datetime.js";

const ACCOUNT_ID_RE = /^\d{12}$/;
const ROLE_ARN_RE = /^arn:aws:iam::(\d{12}):role\/.+$/;
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
  const [accountId, setAccountId] = useState("");
  // base = setup-info response without account_id (policy + template URL only)
  const [base, setBase] = useState(null);
  // info = setup-info response with the account_id, includes external_id + CFN URL
  const [info, setInfo] = useState(null);
  const [loadingInfo, setLoadingInfo] = useState(false);
  const [savedAccount, setSavedAccount] = useState(null);
  const [roleArn, setRoleArn] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [showInline, setShowInline] = useState(false);

  // Step 0: fetch the static portion (policy + template URL) once.
  useEffect(() => {
    api.setupInfo().then(setBase).catch((e) => setError(e.message));
  }, []);

  const accountIdValid = ACCOUNT_ID_RE.test(accountId);

  // Step 1: when a valid account_id is entered, fetch BOTH the deterministic
  // ExternalId + CFN URL AND any saved account memory in parallel. Debounced.
  useEffect(() => {
    if (!accountIdValid) {
      setInfo(null);
      setSavedAccount(null);
      return;
    }
    setLoadingInfo(true);
    setError(null);
    const handle = setTimeout(() => {
      Promise.all([
        api.setupInfo(accountId),
        api.getAccount(accountId).catch(() => null), // 404 is fine
      ])
        .then(([resp, saved]) => {
          setInfo(resp);
          setSavedAccount(saved && saved.role_arn ? saved : null);
          if (saved && saved.role_arn) {
            // Pre-fill the role ARN from memory. User can still override.
            setRoleArn((current) => (current ? current : saved.role_arn));
          }
          setLoadingInfo(false);
        })
        .catch((e) => {
          setError(e.message);
          setLoadingInfo(false);
        });
    }, 200);
    return () => clearTimeout(handle);
  }, [accountId, accountIdValid]);

  const arnAccountId = useMemo(() => {
    const m = roleArn.match(ROLE_ARN_RE);
    return m ? m[1] : null;
  }, [roleArn]);

  const arnOk = ROLE_ARN_RE.test(roleArn);
  const arnAccountMatches = arnOk && arnAccountId === accountId;

  const openQuickCreate = () => {
    if (!info?.cfn_quick_create_url) return;
    window.open(info.cfn_quick_create_url, "_blank", "noopener,noreferrer");
  };

  const runRealAudit = async () => {
    if (!arnOk || !accountIdValid || !info) return;
    setSubmitting(true);
    setError(null);
    try {
      // Note: we send only {account_id, role_arn, region}. The backend
      // recomputes the ExternalId server-side via HMAC. Tamper-proof.
      const out = await api.createAudit({
        account_id: accountId,
        role_arn: roleArn,
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

      {/* Step 1: Account ID */}
      <section className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm space-y-5">
        <div>
          <div className="flex items-baseline gap-3">
            <span className="rounded-full bg-blue-600 px-2.5 py-0.5 text-xs font-semibold text-white">
              Step 1
            </span>
            <h2 className="text-xl font-semibold text-slate-900">
              Enter your AWS Account ID
            </h2>
          </div>
          <p className="mt-2 text-sm text-slate-600">
            Your 12-digit account ID is used to derive a stable, per-tenant
            ExternalId so the IAM role you create stays linked to RuleIQ across
            page reloads.
          </p>
        </div>

        <Field label="AWS Account ID" htmlFor="account-id">
          <input
            id="account-id"
            data-testid="account-id-input"
            type="text"
            inputMode="numeric"
            placeholder="123456789012"
            value={accountId}
            onChange={(e) =>
              setAccountId(e.target.value.replace(/\D/g, "").slice(0, 12))
            }
            className="w-full max-w-xs rounded-md border border-slate-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
          />
          {accountId && !accountIdValid && (
            <p
              data-testid="account-id-error"
              className="mt-1 text-xs text-red-600"
            >
              Account ID must be exactly 12 digits.
            </p>
          )}
        </Field>
      </section>

      {/* Step 2: connect via CFN — only when account_id is valid */}
      {accountIdValid && (
        <section className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm space-y-6">
          <div>
            <div className="flex items-baseline gap-3">
              <span className="rounded-full bg-blue-600 px-2.5 py-0.5 text-xs font-semibold text-white">
                Step 2
              </span>
              <h2 className="text-xl font-semibold text-slate-900">
                Create the IAM trust role
              </h2>
            </div>
            <p className="mt-2 text-sm text-slate-600">
              Click the button — AWS opens a Quick-Create CloudFormation stack
              pre-filled with the ExternalId below. Wait for{" "}
              <code className="rounded bg-slate-100 px-1">CREATE_COMPLETE</code>
              , then come back here.
            </p>
          </div>

          {loadingInfo && !info && (
            <div data-testid="connect-skeleton" className="space-y-3 pt-2">
              <div className="h-4 w-2/3 rounded bg-slate-200 animate-pulse" />
              <div className="h-4 w-1/2 rounded bg-slate-200 animate-pulse" />
            </div>
          )}

          {info && (
            <>
              <Field label="ExternalId (deterministic, copy if needed)">
                <ExternalIdReadOnly value={info.external_id} />
              </Field>

              <button
                type="button"
                onClick={openQuickCreate}
                data-testid="quick-create-btn"
                className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 transition"
              >
                Open AWS Quick-Create →
              </button>
            </>
          )}
        </section>
      )}

      {/* Step 3: Role ARN + Run */}
      {accountIdValid && info && (
        <section className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm space-y-5">
          <div>
            <div className="flex items-baseline gap-3">
              <span className="rounded-full bg-blue-600 px-2.5 py-0.5 text-xs font-semibold text-white">
                Step 3
              </span>
              <h2 className="text-xl font-semibold text-slate-900">
                Paste the Role ARN and run
              </h2>
            </div>
          </div>

          <Field label="Role ARN" htmlFor="role-arn">
            <input
              id="role-arn"
              data-testid="role-arn-input"
              type="text"
              placeholder={`arn:aws:iam::${accountId}:role/RuleIQAuditRole`}
              value={roleArn}
              onChange={(e) => setRoleArn(e.target.value.trim())}
              className="w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
            />
            {savedAccount && savedAccount.last_audit_at && (
              <p
                data-testid="saved-account-badge"
                className="mt-1 text-xs text-slate-500"
              >
                <span className="inline-flex items-center gap-1 rounded bg-slate-100 px-1.5 py-0.5 font-medium text-slate-700">
                  Pre-filled from memory
                </span>{" "}
                Last audit: {formatLocalTimestamp(savedAccount.last_audit_at)}
              </p>
            )}
            {roleArn && !arnOk && (
              <p
                data-testid="role-arn-error"
                className="mt-1 text-xs text-red-600"
              >
                Must match arn:aws:iam::&lt;12 digit account&gt;:role/&lt;name&gt;
              </p>
            )}
            {arnOk && !arnAccountMatches && (
              <p
                data-testid="role-arn-account-mismatch"
                className="mt-1 text-xs text-amber-700"
              >
                Heads up — the Role ARN's account ({arnAccountId}) doesn't
                match the account you entered above ({accountId}).
              </p>
            )}
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

          <div className="flex items-center gap-3 pt-1">
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
        </section>
      )}

      {/* Demo shortcut when no account id has been entered yet */}
      {!accountIdValid && (
        <section className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-600">
          Just want to see what RuleIQ outputs?{" "}
          <button
            type="button"
            onClick={runDemoAudit}
            disabled={submitting}
            data-testid="run-demo-shortcut"
            className="font-semibold text-slate-900 underline underline-offset-2 hover:text-blue-700 disabled:text-slate-400"
          >
            {submitting ? "Starting…" : "Run a demo audit"}
          </button>
          — it uses fixture WAF rules, no AWS connection needed.
        </section>
      )}

      {/* Manual setup, only meaningful when we have the static base info */}
      {base && (
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
                . The ExternalId in your trust policy must equal the value
                shown in Step 2 above for your account ID.
              </p>
              <CopyBlock value={JSON.stringify(base.inline_iam_json, null, 2)} />
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
          } catch {
            /* ignore */
          }
        }}
        className="absolute right-2 top-2 rounded bg-slate-700 px-2 py-1 text-xs text-white hover:bg-slate-600"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}
