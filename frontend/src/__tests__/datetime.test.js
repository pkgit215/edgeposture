import { describe, it, expect, vi, afterEach } from "vitest";
import { formatLocalTimestamp } from "../lib/datetime.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("formatLocalTimestamp", () => {
  it("renders 'YYYY-MM-DD HH:MM TZ' with a normalized TZ abbreviation", () => {
    // Force a stable resolved timezone for the test by stubbing
    // Intl.DateTimeFormat to always emit "EDT" (which we normalize to "ET").
    const RealDTF = Intl.DateTimeFormat;
    vi.spyOn(Intl, "DateTimeFormat").mockImplementation(function (
      ..._args
    ) {
      const real = new RealDTF("en-US", { timeZone: "America/New_York" });
      // Produce parts that include a timeZoneName 'short' segment.
      real.formatToParts = () => [
        { type: "timeZoneName", value: "EDT" },
      ];
      return real;
    });

    // 2026-05-10T17:00:00Z is 2026-05-10 13:00 in America/New_York DST → "ET".
    // We don't depend on the test runner's actual TZ — we drive the
    // year/month/day/hour/minute via getFullYear()/getMonth()/etc on a real
    // Date, so any TZ produces SOME well-formed output. We assert format,
    // not specific local hour.
    const out = formatLocalTimestamp("2026-05-10T17:00:00Z");
    expect(out).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} ET$/);
  });

  it("returns the fallback for null / empty / invalid inputs", () => {
    expect(formatLocalTimestamp(null)).toBe("—");
    expect(formatLocalTimestamp("")).toBe("—");
    expect(formatLocalTimestamp(undefined)).toBe("—");
    expect(formatLocalTimestamp("not-a-date")).toBe("—");
    expect(formatLocalTimestamp(null, "n/a")).toBe("n/a");
  });
});
