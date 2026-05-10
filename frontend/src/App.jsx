import { useState } from "react";
import Connect from "./views/Connect.jsx";
import Results from "./views/Results.jsx";
import History from "./views/History.jsx";

export default function App() {
  const [view, setView] = useState("connect");
  const [auditId, setAuditId] = useState(null);

  const goResults = (id) => {
    setAuditId(id);
    setView("results");
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Nav view={view} setView={setView} />
      <main className="max-w-6xl mx-auto px-6 py-10">
        {view === "connect" && <Connect onAuditStarted={goResults} />}
        {view === "results" && (
          <Results auditId={auditId} onGoConnect={() => setView("connect")} />
        )}
        {view === "history" && <History onOpenAudit={goResults} />}
      </main>
      <footer className="max-w-6xl mx-auto px-6 py-8 text-xs text-slate-500">
        RuleIQ · AI-powered AWS WAF audits · Phase 3
      </footer>
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
          <div className="font-semibold text-slate-900">RuleIQ</div>
          <div className="text-xs text-slate-500 ml-2 hidden sm:block">
            AWS WAF audit
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
