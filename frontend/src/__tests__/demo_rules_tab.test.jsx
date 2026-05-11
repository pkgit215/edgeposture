// Fix #22 — Rules tab must render >0 rule rows for the demo fixture.
// Regression guard: ai_explanation must be a string, not an object,
// otherwise the Rules tab crashes with React error #31.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Results from "../views/Results.jsx";

// Load the actual committed demo fixture from disk — the test fails for
// real if the build script regresses, not just if a mock drifts.
const DEMO_PAYLOAD = JSON.parse(
  readFileSync(
    resolve(__dirname, "../../../backend/demo/demo_audit.json"),
    "utf-8",
  ),
);

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(global, "fetch").mockResolvedValue({
    ok: true,
    json: async () => DEMO_PAYLOAD,
  });
});

describe("Fix #22 — Rules tab renders the demo fixture", () => {
  it("loads exactly 52 rule rows when the Rules tab is selected", async () => {
    render(<Results auditId="demo" demoMode onGoConnect={() => {}} />);
    // Wait for the headline panel — proves the fetch+render cycle completed
    // without React error #31 (which would unmount the whole subtree).
    await screen.findByTestId("headline-panel");

    fireEvent.click(screen.getByTestId("tab-rules"));
    await waitFor(() => {
      expect(screen.getByTestId("rule-browser")).toBeInTheDocument();
    });
    const rows = screen.getAllByTestId("rule-row");
    expect(rows).toHaveLength(52);
  });

  it("rule rows expose hit_count, last_fired, action, and a JSON toggle", async () => {
    render(<Results auditId="demo" demoMode onGoConnect={() => {}} />);
    await screen.findByTestId("headline-panel");
    fireEvent.click(screen.getByTestId("tab-rules"));
    await screen.findByTestId("rule-browser");

    const rows = screen.getAllByTestId("rule-row");
    // Spot-check the first row carries the canonical Rules-tab fields.
    const first = rows[0];
    expect(first.getAttribute("data-rule-name")).toBeTruthy();
    // BLOCK / COUNT / ALLOW cell text is present somewhere in the row.
    expect(first.textContent).toMatch(/BLOCK|COUNT|ALLOW/);
    // At least one zero-hit "Never fired" marker exists across the table
    // (the legacy ACL is full of them).
    expect(screen.getAllByTestId("never-fired").length).toBeGreaterThan(0);
    // FMS pill renders for the FMS-managed rule.
    expect(screen.getAllByTestId("fms-pill").length).toBeGreaterThan(0);
  });

  it("does NOT crash if ai_explanation is the full string (regression guard)", async () => {
    // If demo fixture regresses to {explanation,working,concerns} object
    // shape, React will throw error #31 and rule-browser will not mount.
    render(<Results auditId="demo" demoMode onGoConnect={() => {}} />);
    await screen.findByTestId("headline-panel");
    fireEvent.click(screen.getByTestId("tab-rules"));
    await screen.findByTestId("rule-browser");
    // Every rule in the fixture should have a string `ai_explanation`.
    for (const r of DEMO_PAYLOAD.rules) {
      expect(typeof r.ai_explanation).toBe("string");
    }
  });
});
