/**
 * Format an ISO-8601 timestamp (or anything `new Date()` accepts) for UI
 * display in the user's local timezone.
 *
 * Output: "YYYY-MM-DD HH:MM TZ" — e.g. "2026-05-10 13:00 ET",
 * "2026-05-10 17:00 UTC".
 *
 * Rules:
 *  - 24-hour time, minute granularity (no seconds).
 *  - Date and time are rendered in the user's resolved local timezone.
 *  - DST-aware abbreviations from `Intl.DateTimeFormat` (`EDT`/`EST`,
 *    `PDT`/`PST`, …) are normalized to the seasonless short form
 *    (`ET` / `PT` / `CT` / `MT`) so the chip doesn't flip in March/November.
 *  - Anything outside the {ET,PT,CT,MT} set falls back to `UTC` when the
 *    abbreviation reads `GMT`/`UTC`/`Z`; otherwise the raw abbreviation
 *    is preserved (e.g. `BST`, `CEST`, `JST`).
 */

const NA_NORMALIZE = {
  EST: "ET",
  EDT: "ET",
  CST: "CT",
  CDT: "CT",
  MST: "MT",
  MDT: "MT",
  PST: "PT",
  PDT: "PT",
};

function _normalizeTzAbbrev(raw) {
  if (!raw) return "UTC";
  const upper = String(raw).toUpperCase();
  if (NA_NORMALIZE[upper]) return NA_NORMALIZE[upper];
  if (upper === "GMT" || upper === "UTC" || upper === "Z") return "UTC";
  // Anything else (BST, CEST, JST, IST, AEDT, …) renders as-is.
  return upper;
}

function _extractTzAbbrev(d) {
  try {
    const parts = new Intl.DateTimeFormat(undefined, {
      timeZoneName: "short",
    }).formatToParts(d);
    const tzPart = parts.find((p) => p.type === "timeZoneName");
    return _normalizeTzAbbrev(tzPart && tzPart.value);
  } catch {
    return "UTC";
  }
}

function _pad2(n) {
  return n < 10 ? "0" + n : "" + n;
}

/**
 * @param {string|number|Date|null|undefined} value
 * @param {string} [fallback="—"]
 * @returns {string}
 */
export function formatLocalTimestamp(value, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  const d = value instanceof Date ? value : new Date(value);
  if (isNaN(d.getTime())) return fallback;

  const yyyy = d.getFullYear();
  const mm = _pad2(d.getMonth() + 1);
  const dd = _pad2(d.getDate());
  const hh = _pad2(d.getHours());
  const min = _pad2(d.getMinutes());
  const tz = _extractTzAbbrev(d);
  return `${yyyy}-${mm}-${dd} ${hh}:${min} ${tz}`;
}
