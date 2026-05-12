import { useEffect, useState } from "react";

export default function AppPlaceholder() {
  const [me, setMe] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch("/api/me", { credentials: "include" })
      .then((r) => {
        if (r.status === 401) {
          window.location.assign("/login");
          return null;
        }
        return r.json();
      })
      .then((data) => {
        if (data) setMe(data);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const signOut = async () => {
    await fetch("/auth/logout", {
      method: "POST",
      credentials: "include",
    });
    window.location.assign("/login");
  };

  if (error) {
    return (
      <div className="p-6 text-red-700" data-testid="app-error">
        {error}
      </div>
    );
  }
  if (!me) {
    return (
      <div className="p-6 text-slate-500" data-testid="app-loading">
        Loading…
      </div>
    );
  }
  return (
    <div className="min-h-screen bg-slate-50">
      <header className="border-b border-slate-200 bg-white">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="font-semibold text-slate-900">EdgePosture</div>
          <div className="flex items-center gap-3 text-sm">
            <span data-testid="signed-in-email" className="text-slate-700">
              Signed in as {me.email}
            </span>
            <button
              data-testid="sign-out-button"
              type="button"
              onClick={signOut}
              className="px-3 py-1.5 rounded-md border border-slate-300 hover:bg-slate-100 text-slate-700"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="max-w-3xl mx-auto px-6 py-16" data-testid="app-placeholder">
        <h1 className="text-2xl font-semibold text-slate-900 mb-3">
          You're signed in as {me.email}.
        </h1>
        <p className="text-slate-600 mb-2">
          Onboarding flow coming in Phase 2.
        </p>
        <p className="text-xs text-slate-400">tenant_id: {me.tenant_id}</p>
      </main>
    </div>
  );
}
