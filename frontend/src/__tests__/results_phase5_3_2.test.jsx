import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import Results from "../views/Results.jsx";

const RUN = {
  id: "audit-5-3-2",
  account_id: "371126261144",
  region: "us-east-1",
  status: "complete",
  rule_count: 1,
  estimated_waste_usd: 5,
  data_source: "aws",
  web_acls: [],
};

const FINDINGS = [
  {
    id: "f-high",
    type: "bypass_candidate",
    severity: "high",
    title: "High finding",
    description: "x",
    recommendation: "y",
    affected_rules: ["acl-x"],
    confidence: 0.95,
    severity_score: 90,
    impact:
      "Attack-shaped traffic is reaching your origin uninspected. Direct relevance to SOC 2 CC6.6.",
    suggested_actions: ["Enable KnownBadInputs."],
    verify_by: "Replay request.",
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
      return { ok: true, json: async () => [] };
    }
    if (url.endsWith(`/api/audits/${RUN.id}/findings`)) {
      return { ok: true, json: async () => FINDINGS };
    }
    return { ok: true, json: async () => ({}) };
  });
}

describe("Phase 5.3.2 — Impact + Methodology + Tooltips", () => {
  it("renders the impact paragraph inside the accordion (Fix 8)", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    // HIGH severity finding starts expanded — impact should be visible immediately.
    const impact = await screen.findByTestId("impact-block");
    expect(impact.textContent).toMatch(/Attack-shaped traffic/);
    expect(impact.textContent).toMatch(/SOC 2 CC6.6/);
  });

  it("shows the Methodology tab and renders its four subsections (Fix 9)", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    const tab = await screen.findByTestId("tab-methodology");
    fireEvent.click(tab);
    expect(await screen.findByTestId("methodology-content")).toBeTruthy();
    expect(screen.getByTestId("methodology-severity")).toBeTruthy();
    expect(screen.getByTestId("methodology-score")).toBeTruthy();
    expect(screen.getByTestId("methodology-confidence")).toBeTruthy();
    expect(screen.getByTestId("methodology-evidence")).toBeTruthy();
    expect(screen.getByTestId("methodology-not")).toBeTruthy();
  });

  it("surfaces a tooltip on the severity badge referencing Methodology (Fix 10)", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    const badge = await screen.findByTestId("severity-badge");
    // The tooltip is rendered alongside the badge; group-hover reveals it via
    // CSS. We assert the tooltip content is present in the DOM so the
    // hover-driven `display:block` has actual text to surface.
    const sibling = badge.parentElement.querySelector(
      '[data-testid="tooltip-pop"]',
    );
    expect(sibling).toBeTruthy();
    expect(sibling.textContent).toMatch(/HIGH/);
    expect(sibling.textContent).toMatch(/Methodology/);
  });

  it("surfaces a tooltip on the confidence label (Fix 10)", async () => {
    mockApi();
    render(<Results auditId={RUN.id} onGoConnect={() => {}} />);
    const label = await screen.findByTestId("confidence-label");
    const pop = label.parentElement.querySelector('[data-testid="tooltip-pop"]');
    expect(pop).toBeTruthy();
    expect(pop.textContent).toMatch(/structural|log-sample|heuristic/);
    expect(pop.textContent).toMatch(/Methodology/);
  });
});
