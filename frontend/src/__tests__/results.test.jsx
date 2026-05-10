import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import Results from "../views/Results.jsx";

const COMPLETE_RUN = {
  id: "audit-test-1",
  account_id: "111122223333",
  region: "us-east-1",
  status: "complete",
  rule_count: 4,
  estimated_waste_usd: 100,
  data_source: "aws",
};

const RUNNING_RUN = { ...COMPLETE_RUN, status: "running" };

beforeEach(() => {
  vi.restoreAllMocks();
});

function mockApiFor(run) {
  vi.spyOn(global, "fetch").mockImplementation(async (url) => {
    if (url.endsWith(`/api/audits/${run.id}`)) {
      return { ok: true, json: async () => run };
    }
    if (url.endsWith(`/api/audits/${run.id}/rules`)) {
      return { ok: true, json: async () => [] };
    }
    if (url.endsWith(`/api/audits/${run.id}/findings`)) {
      return { ok: true, json: async () => [] };
    }
    return { ok: true, json: async () => ({}) };
  });
}

describe("Results — Download Report (PDF) button", () => {
  it("renders enabled when audit status is complete", async () => {
    mockApiFor(COMPLETE_RUN);
    render(<Results auditId={COMPLETE_RUN.id} onGoConnect={() => {}} />);
    const btn = await screen.findByTestId("download-pdf-btn");
    await waitFor(() => expect(btn).not.toBeDisabled());
    expect(btn.getAttribute("title")).toBe("Download PDF report");
  });

  it("renders disabled with the right tooltip when audit is still running", async () => {
    mockApiFor(RUNNING_RUN);
    render(<Results auditId={RUNNING_RUN.id} onGoConnect={() => {}} />);
    const btn = await screen.findByTestId("download-pdf-btn");
    expect(btn).toBeDisabled();
    expect(btn.getAttribute("title")).toBe(
      "Audit must finish before report is available"
    );
  });
});
