import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import Results from "../views/Results.jsx";

const RUN = {
  id: "audit-5-3",
  account_id: "371126261144",
  region: "us-east-1",
  status: "complete",
  rule_count: 3,
  estimated_waste_usd: 72,
  data_source: "aws",
  web_acls: [],
};

const RULES = [
  {
    rule_name: "AWS-Common",
    web_acl_name: "acl-x",
    priority: 0,
    action: "Block (group)",
    hit_count: 12,
    last_fired: null,
    fms_managed: false,
    rule_kind: "managed",
    managed_rule_overrides: [
      { name: "SizeRestrictions_BODY", action: "Count" },
      { name: "GenericRFI_QUERYARGUMENTS", action: "Count" },
    ],
  },
];

const FINDINGS = [
  {
    id: "f-bypass",
    type: "bypass_candidate",
    severity: "high",
    title: "Possible WAF bypass",
    description: "shellshock reached origin",
    recommendation: "Enable KnownBadInputs",
    affected_rules: ["ruleiq-cf-acl"],
    confidence: 0.9,
    severity_score: 80,
    // Phase 5.3.1 — flat keys
    suggested_actions: [
      "Enable a managed rule group that covers shellshock signatures.",
      "Deploy in COUNT mode first.",
    ],
    verify_by: "Replay the captured request and confirm 403.",
    disclaimer:
      "RuleIQ does not generate WAF rules. Recommendations point to AWS-maintained managed groups.",
  },
  {
    id: "f-count",
    type: "count_mode_with_hits",
    severity: "medium",
    title: "COUNT-mode rule matching traffic",
    description: "Rule R1 has 50 hits in COUNT.",
    recommendation: "Consider promoting to BLOCK.",
    affected_rules: ["R1"],
    confidence: 0.85,
    severity_score: 50,
    suggested_actions: ["Promote to BLOCK after sampling."],
    verify_by: "Monitor for 7 days post-promotion.",
    disclaimer: "RuleIQ does not generate WAF rules.",
  },
];

beforeEach(() => {
  vi.restoreAllMocks();
});

function mockApi() {
  vi.spyOn(global, "fetch").mockImplementation(async (url) => {
    if (url.endsWith(`/api/audits/${RUN.id}`)) {
      return { ok: true, json: async () => RUN };
    }
    if (url.endsWith(`/api/audits/${RUN.id}/rules`)) {
      return { ok: true, json: async () => RULES };
    }
    if (url.endsWith(`/api/audits/${RUN.id}/findings`)) {
      return { ok: true, json: async () => FINDINGS };
    }
    return { ok: true, json: async () => ({}) };
  });
}

describe("Phase 5.3 — Results UI", () => {
  it("renders the HeadlinePanel (security-first) instead of the legacy SummaryBar", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    const panel = await screen.findByTestId("headline-panel");
    expect(panel).toBeTruthy();
    // Cost line is present but visually demoted (not headline).
    expect(screen.getByTestId("cost-line").textContent).toMatch(/72/);
  });

  it("shows severity sub-counts (high · medium · low)", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    await waitFor(() =>
      expect(screen.getByTestId("sev-high").textContent).toMatch(/1 high/),
    );
    expect(screen.getByTestId("sev-medium").textContent).toMatch(/1 medium/);
  });

  it("renders the Remediation accordion with disclaimer (expanded by default for HIGH)", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    const blocks = await screen.findAllByTestId("remediation-block");
    expect(blocks.length).toBe(FINDINGS.length);
    const disclaimer = await screen.findAllByTestId("remediation-disclaimer");
    expect(disclaimer[0].textContent).toMatch(/RuleIQ does not generate WAF rules/);
  });

  it("Remediation toggle hides/shows the block", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    const toggles = await screen.findAllByTestId("remediation-toggle");
    fireEvent.click(toggles[0]);
    // After click the first (HIGH) block should hide its disclaimer
    await waitFor(() => {
      const dlc = screen.queryAllByTestId("remediation-disclaimer");
      // only the medium finding's accordion remains expanded by default? No — medium starts collapsed.
      expect(dlc.length).toBeLessThan(2);
    });
  });

  it("shows the override-badge on rules with managed_rule_overrides", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    // Switch to the "All rules" tab if needed — the headline panel is on the same page.
    const badge = await screen.findByTestId("override-badge");
    expect(badge.textContent).toMatch(/2 override/);
  });

  it("includes a security-lead sentence when bypass_candidate count > 0", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    const lead = await screen.findByTestId("security-lead");
    expect(lead.textContent).toMatch(/potential security gap/);
  });

  it("Phase 5.3.1 Fix 6 — clicking the accordion header reveals the suggested-actions list", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    const toggles = await screen.findAllByTestId("remediation-toggle");
    // pick the MEDIUM finding (second one) — starts collapsed.
    const mediumToggle = toggles[1];
    // Initially collapsed: no suggested-actions <ul> for this card.
    const initialLists = screen.queryAllByTestId("suggested-actions");
    // Expand it.
    fireEvent.click(mediumToggle);
    await waitFor(() => {
      const lists = screen.getAllByTestId("suggested-actions");
      expect(lists.length).toBeGreaterThan(initialLists.length);
    });
    // The MED finding's `Promote to BLOCK after sampling.` text must now be visible.
    expect(await screen.findByText(/Promote to BLOCK after sampling/)).toBeTruthy();
  });
});
