import { useState } from "react";

export default function Login() {
  const [loading, setLoading] = useState(false);
  return (
    <div className="min-h-screen bg-slate-50 grid place-items-center px-6">
      <div
        data-testid="login-card"
        className="max-w-md w-full bg-white rounded-lg border border-slate-200 p-8 text-center"
      >
        <h1 className="text-2xl font-semibold text-slate-900 mb-2">
          EdgePosture
        </h1>
        <p className="text-sm text-slate-600 mb-8">
          Sign in to run an audit against your AWS account.
        </p>
        <a
          href="/auth/google/login"
          data-testid="google-login-button"
          onClick={() => setLoading(true)}
          className={`inline-flex items-center justify-center gap-3 w-full
            bg-white border border-slate-300 hover:bg-slate-100
            text-slate-800 font-medium px-5 py-3 rounded-md
            transition ${loading ? "opacity-50 pointer-events-none" : ""}`}
        >
          <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
            <path
              fill="#4285F4"
              d="M21.6 12.227c0-.713-.064-1.4-.182-2.057H12v3.892h5.39a4.611 4.611 0 0 1-2 3.026v2.512h3.235c1.892-1.744 2.985-4.314 2.985-7.373z"
            />
            <path
              fill="#34A853"
              d="M12 22c2.7 0 4.963-.896 6.617-2.4l-3.235-2.512c-.897.6-2.043.957-3.382.957-2.6 0-4.8-1.756-5.585-4.117H3.075v2.59A9.998 9.998 0 0 0 12 22z"
            />
            <path
              fill="#FBBC05"
              d="M6.415 13.928a5.997 5.997 0 0 1 0-3.856V7.482H3.075a10.002 10.002 0 0 0 0 9.036l3.34-2.59z"
            />
            <path
              fill="#EA4335"
              d="M12 5.927c1.467 0 2.785.504 3.822 1.494l2.867-2.867C16.957 2.952 14.694 2 12 2A9.998 9.998 0 0 0 3.075 7.482l3.34 2.59C7.2 7.683 9.4 5.927 12 5.927z"
            />
          </svg>
          <span>Sign in with Google</span>
        </a>
        <p className="text-xs text-slate-500 mt-6">
          Closed beta. Email{" "}
          <a className="underline" href="mailto:hello@edgeposture.io">
            hello@edgeposture.io
          </a>{" "}
          for access.
        </p>
        <p className="text-xs text-slate-400 mt-4">
          Or try the{" "}
          <a className="underline" href="/demo" data-testid="login-demo-link">
            offline demo
          </a>{" "}
          — no sign-in required.
        </p>
      </div>
    </div>
  );
}
