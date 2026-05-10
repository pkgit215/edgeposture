import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Connect from "../views/Connect.jsx";

// Setup-info response when account_id is NOT supplied (Step 0).
const SETUP_BASE = {
  app_runner_account_id: "371126261144",
  cfn_template_url: "https://example.com/customer-role.yaml",
  inline_iam_json: { Version: "2012-10-17", Statement: [] },
  account_id: null,
  external_id: null,
  cfn_quick_create_url: null,
};

// Setup-info response when account_id IS supplied (Step 1 → derived).
const SETUP_FOR_ACCOUNT = {
  ...SETUP_BASE,
  account_id: "123456789012",
  external_id: "abc12345abc12345abc12345abc12345",
  cfn_quick_create_url:
    "https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate?templateURL=...",
};

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("Connect view — deterministic ExternalId flow", () => {
  it("does not show ExternalId / CFN button until a 12-digit Account ID is entered", async () => {
    vi.spyOn(global, "fetch").mockImplementation(async (url) => ({
      ok: true,
      json: async () =>
        url.includes("account_id=") ? SETUP_FOR_ACCOUNT : SETUP_BASE,
    }));

    const user = userEvent.setup();
    render(<Connect onAuditStarted={() => {}} />);

    // Step 1 input is rendered immediately.
    await screen.findByTestId("account-id-input");

    // No ExternalId / Quick-Create button yet.
    expect(screen.queryByTestId("external-id-input")).toBeNull();
    expect(screen.queryByTestId("quick-create-btn")).toBeNull();

    // Type a partial (non-12-digit) value — still hidden.
    await user.type(screen.getByTestId("account-id-input"), "12345");
    expect(screen.queryByTestId("external-id-input")).toBeNull();

    // Complete to 12 digits — fetch fires, ExternalId + button appear.
    await user.type(screen.getByTestId("account-id-input"), "6789012");
    const eidField = await screen.findByTestId("external-id-input");
    expect(eidField).toHaveValue(SETUP_FOR_ACCOUNT.external_id);
    expect(screen.getByTestId("quick-create-btn")).toBeInTheDocument();
  });

  it("Run audit POST body contains only {account_id, role_arn, region} — no external_id", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockImplementation(async (url, init) => {
      if (init?.method === "POST") {
        return {
          ok: true,
          json: async () => ({ audit_run_id: "run-1", status: "pending" }),
        };
      }
      return {
        ok: true,
        json: async () =>
          url.includes("account_id=") ? SETUP_FOR_ACCOUNT : SETUP_BASE,
      };
    });

    const onAuditStarted = vi.fn();
    const user = userEvent.setup();
    render(<Connect onAuditStarted={onAuditStarted} />);

    await user.type(
      await screen.findByTestId("account-id-input"),
      "123456789012"
    );
    await screen.findByTestId("role-arn-input");
    await user.type(
      screen.getByTestId("role-arn-input"),
      "arn:aws:iam::123456789012:role/RuleIQAuditRole"
    );
    const runBtn = screen.getByTestId("run-audit-btn");
    expect(runBtn).not.toBeDisabled();
    await user.click(runBtn);

    await waitFor(() => expect(onAuditStarted).toHaveBeenCalledWith("run-1"));

    const postCall = fetchSpy.mock.calls.find(
      (c) => c[1] && c[1].method === "POST"
    );
    expect(postCall).toBeDefined();
    const body = JSON.parse(postCall[1].body);
    expect(body).toEqual({
      account_id: "123456789012",
      role_arn: "arn:aws:iam::123456789012:role/RuleIQAuditRole",
      region: "us-east-1",
    });
    // The contract: external_id must NEVER be sent from the client.
    expect("external_id" in body).toBe(false);
  });

  it("demo audit shortcut works without entering an Account ID", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockImplementation(async (url, init) => {
      if (init?.method === "POST") {
        return {
          ok: true,
          json: async () => ({ audit_run_id: "demo-1", status: "pending" }),
        };
      }
      return { ok: true, json: async () => SETUP_BASE };
    });

    const onAuditStarted = vi.fn();
    const user = userEvent.setup();
    render(<Connect onAuditStarted={onAuditStarted} />);

    const demo = await screen.findByTestId("run-demo-shortcut");
    await user.click(demo);
    await waitFor(() => expect(onAuditStarted).toHaveBeenCalledWith("demo-1"));

    const post = fetchSpy.mock.calls.find((c) => c[1] && c[1].method === "POST");
    const body = JSON.parse(post[1].body);
    expect(body.role_arn).toBeUndefined();
    expect(body.account_id).toBe("123456789012");
  });
});
