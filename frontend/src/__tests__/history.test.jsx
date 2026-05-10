import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import History from "../views/History.jsx";

const COMPLETE_AWS = {
  id: "audit-1",
  account_id: "111122223333",
  region: "us-east-1",
  status: "complete",
  data_source: "aws",
  created_at: "2026-05-10T13:00:00Z",
  rule_count: 8,
  findings_count: 3,
  estimated_waste_usd: 137,
};

const FAILED_AUDIT = { ...COMPLETE_AWS, id: "audit-2", status: "failed" };
const COMPLETE_FIXTURE = { ...COMPLETE_AWS, id: "audit-3", data_source: "fixture" };

beforeEach(() => {
  vi.restoreAllMocks();
});

function mockListAudits(audits) {
  vi.spyOn(global, "fetch").mockImplementation(async (url, init) => {
    if (init && init.method === "POST" && String(url).endsWith("/api/audits/rerun")) {
      return {
        ok: true,
        json: async () => ({ audit_run_id: "new-run", status: "pending" }),
      };
    }
    if (String(url).endsWith("/api/audits")) {
      return { ok: true, json: async () => audits };
    }
    return { ok: true, json: async () => ({}) };
  });
}

describe("History — Re-run button", () => {
  it("renders for a complete AWS audit and POSTs to /api/audits/rerun on click", async () => {
    mockListAudits([COMPLETE_AWS]);
    const user = userEvent.setup();
    render(<History onOpenAudit={() => {}} />);
    const btn = await screen.findByTestId("history-rerun-btn");
    expect(btn).not.toBeDisabled();
    await user.click(btn);
    await waitFor(() => {
      expect(screen.getByTestId("history-rerun-msg")).toBeInTheDocument();
    });
  });

  it("does NOT render for a failed audit", async () => {
    mockListAudits([FAILED_AUDIT]);
    render(<History onOpenAudit={() => {}} />);
    await screen.findAllByTestId("history-row");
    expect(screen.queryByTestId("history-rerun-btn")).toBeNull();
  });

  it("does NOT render for a complete fixture (demo) audit", async () => {
    mockListAudits([COMPLETE_FIXTURE]);
    render(<History onOpenAudit={() => {}} />);
    await screen.findAllByTestId("history-row");
    expect(screen.queryByTestId("history-rerun-btn")).toBeNull();
  });
});
