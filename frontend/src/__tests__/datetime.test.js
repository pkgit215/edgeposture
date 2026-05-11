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

  it("Phase 5.2.1: treats ISO string without TZ suffix as UTC", () => {
    // Backend serialises Mongo BSON Date as ISO without offset, e.g.
    // "2026-05-11T20:00:00.123". JS would otherwise read this as local
    // time, off by the local UTC offset. Output must equal the explicit-Z
    // variant.
    const noTz = formatLocalTimestamp("2026-05-11T20:00:00");
    const withZ = formatLocalTimestamp("2026-05-11T20:00:00Z");
    expect(noTz).toBe(withZ);
    expect(noTz).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} \w+$/);
  });

  it("Phase 5.2.1: respects explicit offset (+/-HH:MM) when present", () => {
    // "+00:00" must NOT be double-shifted.
    const a = formatLocalTimestamp("2026-05-11T20:00:00+00:00");
    const b = formatLocalTimestamp("2026-05-11T20:00:00Z");
    expect(a).toBe(b);
  });
});
