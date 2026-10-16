const UTC_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?$/u;
const OFFSET_INSTANT = /(?:Z|[+-]\d{2}:\d{2})$/iu;

export function utcInputFromIso(value) {
  if (typeof value !== "string" || !OFFSET_INSTANT.test(value) || !Number.isFinite(Date.parse(value))) return "";
  return new Date(value).toISOString().slice(0, -1);
}

export function isoFromUtcInput(value) {
  const normalized = String(value || "").trim();
  if (!UTC_DATE_TIME.test(normalized)) throw new Error("Enter a valid UTC date and time.");
  const milliseconds = Date.parse(`${normalized}Z`);
  if (!Number.isFinite(milliseconds)) throw new Error("Enter a valid UTC date and time.");
  const result = new Date(milliseconds).toISOString();
  const expected = normalized.length === 16
    ? `${normalized}:00.000`
    : normalized.length === 19
      ? `${normalized}.000`
      : `${normalized.slice(0, 20)}${normalized.slice(20).padEnd(3, "0")}`;
  if (result.slice(0, -1) !== expected) throw new Error("Enter a valid UTC date and time.");
  return result;
}

export const profileUiTimeInternals = Object.freeze({ OFFSET_INSTANT, UTC_DATE_TIME });
