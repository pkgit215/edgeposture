// Feat #2 — Flavor B smart remediation rendering.
// Asserts the 🎯 badge + evidence_samples block.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import Results from "../views/Results.jsx";

const _RULE = {
  rule_name: "BlockKnownMaliciousIPs",
  web_acl_name: "prod-cf-edge-acl",
  action: "BLOCK",
  hit_count: 18000,
  last_fired: "2026-02-15T09:00:00Z",
  statement_json: {},
  fms_managed: false,
  ai_explanation: "demo",
};

function _payload(extraFindingFields) {
  return {
    audit: {
      id: "demo", account_id: "123456789012", region: "us-east-1",
      status: "complete", rule_count: 1, web_acl_count: 1,
      estimated_waste_usd: 0, estimated_waste_breakdown: [], web_acls: [],
      data_source: "demo", created_at: "2026-02-15T10:00:00Z",
    },
    rules: [_RULE],
    findings: [{
      type: "bypass_candidate", severity: "high", severity_score: 92,
      confidence: 0.95,
      title: "Possible WAF bypass: SQLi reached origin",
      description: "demo", recommendation: "demo",
      affected_rules: ["prod-cf-edge-acl"],
      impact: "Attack-shaped traffic reached origin.",
      suggested_actions: ["Add AWSManagedRulesSQLiRuleSet at priority 30."],
      verify_by: "Re-run after 24h.",
      disclaimer: "EdgePosture does not generate WAF rules.",
      ...extraFindingFields,
    }],
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("Feat #2 — Flavor B smart remediation UI", () => {
  it("renders the 🎯 Account-specific badge when remediation_kind === 'smart'", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => _payload({
        remediation_kind: "smart",
        evidence_samples: [
          "/products?id=1%27%20UNION",
          "/users?id=1%27%20OR%201",
        ],
      }),
    });
    render(<Results auditId="demo" demoMode onGoConnect={() => {}} />);
    await screen.findByTestId("headline-panel");
    // HIGH-severity findings auto-expand the remediation block — no click
    // needed. Just wait for the body to appear.
    await screen.findByTestId("remediation-body");
    const badge = await screen.findByTestId("smart-remediation-badge");
    expect(badge).toBeInTheDocument();
    expect(badge.textContent).toMatch(/Account-specific/i);
  });

  it("does NOT render the badge when remediation_kind === 'canned'", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => _payload({
        remediation_kind: "canned", evidence_samples: [],
      }),
    });
    render(<Results auditId="demo" demoMode onGoConnect={() => {}} />);
    await screen.findByTestId("headline-panel");
    await screen.findByTestId("remediation-body");
    await screen.findByTestId("suggested-actions");
    expect(
      screen.queryByTestId("smart-remediation-badge"),
    ).not.toBeInTheDocument();
  });

  it("renders evidence_samples in a dedicated block when present", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => _payload({
        remediation_kind: "smart",
        evidence_samples: ["/a?x=1", "/b?y=2"],
      }),
    });
    render(<Results auditId="demo" demoMode onGoConnect={() => {}} />);
    await screen.findByTestId("headline-panel");
    await screen.findByTestId("remediation-body");
    const block = await screen.findByTestId("evidence-samples");
    expect(block).toBeInTheDocument();
    expect(block.textContent).toContain("/a?x=1");
    expect(block.textContent).toContain("/b?y=2");
    expect(block.textContent).toMatch(/Example matched requests/i);
  });

  it("omits the evidence_samples block when the array is empty / missing", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => _payload({
        remediation_kind: "smart", evidence_samples: [],
      }),
    });
    render(<Results auditId="demo" demoMode onGoConnect={() => {}} />);
    await screen.findByTestId("headline-panel");
    await screen.findByTestId("remediation-body");
    await screen.findByTestId("suggested-actions");
    expect(screen.queryByTestId("evidence-samples")).not.toBeInTheDocument();
  });
});
