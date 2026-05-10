import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Connect from "../views/Connect.jsx";

const SETUP = {
  app_runner_account_id: "371126261144",
  external_id: "abc12345abc12345abc12345abc12345",
  cfn_template_url: "https://example.com/customer-role.yaml",
  cfn_quick_create_url: "https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate?templateURL=...",
  inline_iam_json: { Version: "2012-10-17", Statement: [] },
};

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("Connect view", () => {
  it("disables Run audit until the role ARN is well-formed", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: async () => SETUP,
    });
    const user = userEvent.setup();
    render(<Connect onAuditStarted={() => {}} />);
    await screen.findByTestId("role-arn-input");

    const runBtn = screen.getByTestId("run-audit-btn");
    expect(runBtn).toBeDisabled();

    const input = screen.getByTestId("role-arn-input");
    await user.type(input, "not-an-arn");
    expect(runBtn).toBeDisabled();
    expect(screen.getByTestId("role-arn-error")).toBeInTheDocument();

    await user.clear(input);
    await user.type(input, "arn:aws:iam::123456789012:role/RuleIQAuditRole");
    expect(runBtn).not.toBeDisabled();
  });

  it("demo audit link POSTs /api/audits with no role_arn and reports new audit id", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      // First call: setup-info
      .mockResolvedValueOnce({ ok: true, json: async () => SETUP })
      // Second call: createAudit
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ audit_run_id: "abc123", status: "pending" }),
      });
    const onAuditStarted = vi.fn();
    const user = userEvent.setup();
    render(<Connect onAuditStarted={onAuditStarted} />);
    await screen.findByTestId("run-demo-btn");
    await user.click(screen.getByTestId("run-demo-btn"));
    await waitFor(() => expect(onAuditStarted).toHaveBeenCalledWith("abc123"));

    const lastCall = fetchSpy.mock.calls.at(-1);
    expect(lastCall[0]).toContain("/api/audits");
    const body = JSON.parse(lastCall[1].body);
    expect(body.role_arn).toBeUndefined();
    expect(body.account_id).toBe("123456789012");
  });
});
