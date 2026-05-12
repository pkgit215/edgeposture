import { useEffect, useState } from "react";
import Connect from "./views/Connect.jsx";
import Results from "./views/Results.jsx";
import History from "./views/History.jsx";

export default function App() {
  // Issue #22 — `/demo` route renders the Results view against the
  // pre-canned `/api/demo/audit` fixture. No AWS setup required.
  const isDemo = typeof window !== "undefined" && window.location.pathname === "/demo";
  const [view, setView] = useState(isDemo ? "demo" : "connect");
  const [auditId, setAuditId] = useState(null);

  useEffect(() => {
    if (!isDemo && view === "demo") setView("connect");
  }, [isDemo, view]);

  const goResults = (id) => {
    setAuditId(id);
    setView("results");
  };
  const goConnect = () => {
    // Leaving demo → put the user back on `/` so refresh stays on Connect.
    if (typeof window !== "undefined" && window.location.pathname === "/demo") {
      window.location.assign("/");
      return;
    }
    setView("connect");
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Nav view={view} setView={setView} isDemo={isDemo} />
      <main className="max-w-6xl mx-auto px-6 py-10">
        {view === "demo" && (
          <>
            <DemoBanner onGoConnect={goConnect} />
            <Results
              auditId="demo"
              demoMode
              onGoConnect={goConnect}
            />
          </>
        )}
        {view === "connect" && <Connect onAuditStarted={goResults} />}
        {view === "results" && (
          <Results auditId={auditId} onGoConnect={() => setView("connect")} />
        )}
        {view === "history" && <History onOpenAudit={goResults} />}
      </main>
      <footer className="max-w-6xl mx-auto px-6 py-8 text-xs text-slate-500">
        EdgePosture · WAF posture audits
      </footer>
    </div>
  );
}

function DemoBanner({ onGoConnect }) {
  return (
    <div
      data-testid="demo-banner"
      className="mb-6 rounded-lg border border-slate-200 bg-slate-100 px-4 py-3 text-sm text-slate-800 flex items-center justify-between gap-3"
    >
      <span>
        <span aria-hidden="true">📊</span> You're viewing a sample audit. To run
        EdgePosture against your own AWS account,
      </span>
      <a
        href="/"
        data-testid="demo-banner-cta"
        onClick={(e) => {
          e.preventDefault();
          onGoConnect();
        }}
        className="font-semibold text-blue-700 hover:underline whitespace-nowrap"
      >
        Set up an audit →
      </a>
    </div>
  );
}

function Nav({ view, setView }) {
  const link = (key, label) => (
    <button
      type="button"
      onClick={() => setView(key)}
      data-testid={`nav-${key}`}
      className={`px-3 py-2 text-sm rounded-md transition ${
        view === key
          ? "bg-slate-900 text-white"
          : "text-slate-700 hover:bg-slate-200"
      }`}
    >
      {label}
    </button>
  );
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="h-8 w-8 rounded bg-slate-900 text-white grid place-items-center text-sm font-bold">
            R
          </div>
          <div className="font-semibold text-slate-900">EdgePosture</div>
          <div className="text-xs text-slate-500 ml-2 hidden sm:block">
            WAF posture audit
          </div>
        </div>
        <nav className="flex items-center gap-1">
          {link("connect", "Connect")}
          {link("results", "Results")}
          {link("history", "History")}
        </nav>
      </div>
    </header>
  );
}
