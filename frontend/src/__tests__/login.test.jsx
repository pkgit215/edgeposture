import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import Login from "../views/Login.jsx";

describe("Login page (Phase 1 #45)", () => {
  it("renders the Sign in with Google button pointing at the backend OAuth route", () => {
    render(<Login />);
    const btn = screen.getByTestId("google-login-button");
    expect(btn).toBeTruthy();
    expect(btn.textContent).toContain("Sign in with Google");
    expect(btn.getAttribute("href")).toBe("/auth/google/login");
  });

  it("offers the offline demo as a no-signin fallback", () => {
    render(<Login />);
    const demo = screen.getByTestId("login-demo-link");
    expect(demo.getAttribute("href")).toBe("/demo");
  });
});
