// Feat #22 — `/demo` route renders Results from `/api/demo/audit`.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import App from "../App.jsx";
import Results from "../views/Results.jsx";

const ORIGINAL_LOCATION = window.location;

function setLocationPath(path) {
  // jsdom does not allow `window.location.assign` reassignment; replace.
  delete window.location;
  window.location = { ...ORIGINAL_LOCATION, pathname: path, assign: vi.fn() };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  window.location = ORIGINAL_LOCATION;
});

const DEMO_PAYLOAD = {
  audit: {
    id: "demo",
    account_id: "123456789012",
    region: "us-east-1",
    status: "complete",
    rule_count: 2,
    web_acl_count: 1,
    estimated_waste_usd: 12.5,
    estimated_waste_breakdown: [],
    web_acls: [],
    data_source: "demo",
    created_at: "2026-02-15T10:00:00Z",
  },
  rules: [
    {
      rule_name: "BlockKnownMaliciousIPs",
      web_acl_name: "ruleiq-prod-acl",
      action: "BLOCK",
      hit_count: 18000,
      last_fired: "2026-02-15T09:00:00Z",
      statement_json: {},
      fms_managed: false,
    },
    {
      rule_name: "BlockLegacyAdminPath",
      web_acl_name: "ruleiq-prod-acl",
      action: "BLOCK",
      hit_count: 0,
      last_fired: null,
      statement_json: {},
      fms_managed: false,
    },
  ],
  findings: [
    {
      type: "bypass_candidate",
      severity: "high",
      severity_score: 92,
      confidence: 0.95,
      title: "Possible WAF bypass: SQLi reached origin",
      description: "demo",
      recommendation: "demo",
      affected_rules: ["ruleiq-prod-acl"],
      impact: "Attack-shaped traffic reached origin.",
      suggested_actions: ["Enable AWSManagedRulesSQLiRuleSet."],
      verify_by: "Re-run audit after 24h.",
      disclaimer: "EdgePosture does not generate WAF rules.",
    },
  ],
};

describe("Feat #22 — /demo route", () => {
  it("renders the demo banner when window.location is /demo", async () => {
    setLocationPath("/demo");
    vi.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => DEMO_PAYLOAD,
    });

    render(<App />);

    const banner = await screen.findByTestId("demo-banner");
    expect(banner).toBeInTheDocument();
    expect(banner.textContent).toMatch(/sample audit/i);
    // CTA points users at the real onboarding flow.
    expect(screen.getByTestId("demo-banner-cta")).toBeInTheDocument();
  });

  it("does NOT render the demo banner on the default `/` route", () => {
    setLocationPath("/");
    render(<App />);
    expect(screen.queryByTestId("demo-banner")).not.toBeInTheDocument();
  });

  it("fetches the demo payload from `/api/demo/audit`", async () => {
    setLocationPath("/demo");
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => DEMO_PAYLOAD,
    });
    render(<App />);
    await waitFor(() => {
      expect(fetchSpy).toHaveBeenCalledWith("/api/demo/audit");
    });
    // The real audit endpoints are NEVER hit in demo mode.
    expect(
      fetchSpy.mock.calls.find(([url]) =>
        String(url).includes("/api/audits/"),
      ),
    ).toBeUndefined();
  });
});

describe("Feat #22 — Results in demoMode points download at the demo PDF", () => {
  it("Download Report button targets `/api/demo/report.pdf`", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => DEMO_PAYLOAD,
    });
    // jsdom's location is read-only — proxy assignment instead.
    const hrefSet = vi.fn();
    delete window.location;
    window.location = { ...ORIGINAL_LOCATION, pathname: "/demo" };
    Object.defineProperty(window.location, "href", {
      configurable: true,
      set: hrefSet,
      get: () => "",
    });

    render(<Results auditId="demo" demoMode onGoConnect={() => {}} />);

    const btn = await screen.findByTestId("download-pdf-btn");
    await waitFor(() => expect(btn).not.toBeDisabled());
    btn.click();
    expect(hrefSet).toHaveBeenCalledWith("/api/demo/report.pdf");
  });
});
