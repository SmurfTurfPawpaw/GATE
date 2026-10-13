const secretPatterns = [
  /\b(?:authorization|cookie|set-cookie)\s*[:=]\s*\S/i,
  /(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd)\s*[:=]\s*\S+/i,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/i,
  /\bxox[a-z]-[A-Za-z0-9-]{10,}\b/i,
  /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}\b/i,
  /\bbearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}(?=$|[\s,;])/i,
  /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/
];

const sensitiveHeader = /\b(?:authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]*/giu;

export function redactSensitiveHeaders(value, replacement = "[secret withheld]") {
  return typeof value === "string" ? value.replace(sensitiveHeader, replacement) : value;
}

export function oneLine(value, { name = "value", max = 600 } = {}) {
  if (typeof value !== "string") throw new Error(`${name} must be text`);
  const normalized = value.trim().replace(/\s+/g, " ");
  if (!normalized) throw new Error(`${name} must not be empty`);
  if (normalized.length > max) throw new Error(`${name} must be ${max} characters or fewer`);
  return normalized;
}

export function assertNoLikelySecret(value, name = "value") {
  if (secretPatterns.some((pattern) => pattern.test(value))) {
    throw new Error(`${name} appears to contain a credential; keep it in private secret storage`);
  }
}

export function slug(value, name = "id") {
  const result = oneLine(value, { name, max: 80 }).toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(result)) {
    throw new Error(`${name} must contain only lowercase letters, numbers, dot, underscore, or dash`);
  }
  return result;
}

export function redactCommand(command) {
  if (!command) return "unknown";
  const base = command.replaceAll("\\", "/").split("/").at(-1);
  return base || "unknown";
}
