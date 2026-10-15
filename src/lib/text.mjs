const secretPatterns = [
  /\b(?:authorization|cookie|set-cookie)\s*[:=]\s*\S/i,
  /(?:api[_-]?key|access[_-]?token|client[_-]?secret|session[_-]?(?:id|key|token)|password|passwd)\s*[:=]\s*\S+/i,
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
const sensitiveQueryName = /(?:^|[_-])(?:api[_-]?key|auth(?:entication|orization)?|bearer|client[_-]?secret|code|credential|key|password|passwd|sas|secret|session(?:[_-]?(?:id|key|token))?|sig(?:nature)?|token)(?:$|[_-])/iu;
const unsafeText = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u061C\u200B\u200E\u200F\u2028-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}]/u;
const unsafeTextGlobal = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u061C\u200B\u200E\u200F\u2028-\u202E\u2060-\u206F\uFEFF\u{E0000}-\u{E007F}]/gu;
const urlCandidate = /\b[a-z][a-z0-9+.-]*:\/\/[^\s<>"'`]+/giu;
const opaqueTokenCandidate = /[A-Za-z0-9+/_=.\-]{24,}/gu;

function tokenEntropy(value) {
  const counts = new Map();
  for (const character of value) counts.set(character, (counts.get(character) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function likelyOpaqueSecret(value, name = "") {
  const token = value.trim();
  if (token.length < 24 || token.length > 2048 || /\s/u.test(token)) return false;
  if (!/^[A-Za-z0-9+/_=.\-]+$/u.test(token)) return false;
  const digestLabel = /(?:sha(?:256|384|512)?|digest|checksum|fingerprint|etag|commit)(?:$|[.\]])/iu.test(name);
  const structuralLabel = /(?:^|[.\]])(?:\$schema|apiVersion|kind)$/u.test(name);
  const sensitiveLabel = /(?:apiKey|accessToken|refreshToken|clientSecret|credential|password|passwd|privateKey|secret|sessionId|sessionKey|sessionToken|token)$/iu.test(name.replace(/[^A-Za-z0-9]/gu, ""));
  const recognizedPublicIdentifier = /^(?:CVE-\d{4}-\d{4,}(?:-[A-Za-z0-9]+)*|OWASP(?:-[A-Za-z0-9]+)+)$/iu.test(token);
  if (digestLabel || structuralLabel || (!sensitiveLabel && (recognizedPublicIdentifier || /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu.test(token)))) return false;
  const coreClasses = [/[a-z]/u, /[A-Z]/u, /[0-9]/u].filter((pattern) => pattern.test(token)).length;
  const strongAlphabetMarker = /[+/=]/u.test(token);
  const distinct = new Set(token).size;
  const entropy = tokenEntropy(token);
  if (sensitiveLabel) return distinct >= 8 && entropy >= 3;
  if (/^[a-f0-9]{32,128}$/iu.test(token)) return distinct >= 12 && entropy >= 3.5;
  if (/^(?=.*[a-z])(?=.*[0-9])[a-z0-9]{32,}$/u.test(token)) return distinct >= 16 && entropy >= 4;
  const mixedCase = /[a-z]/u.test(token) && /[A-Z]/u.test(token);
  const categories = [...token].map((character) => /[a-z]/u.test(character)
    ? "l" : /[A-Z]/u.test(character) ? "u" : /[0-9]/u.test(character) ? "d" : "s");
  const transitions = categories.slice(1).filter((category, index) => category !== categories[index]).length;
  const transitionRate = transitions / Math.max(token.length - 1, 1);
  return (
    (coreClasses >= 3 && transitionRate >= 0.35) ||
    (mixedCase && strongAlphabetMarker && transitionRate >= 0.2)
  ) && distinct >= 12 && entropy >= 3.5;
}

function containsOpaqueCredential(value, name, options = {}) {
  opaqueTokenCandidate.lastIndex = 0;
  for (const match of value.matchAll(opaqueTokenCandidate)) {
    const token = match[0];
    const filesystemPath = (token.startsWith("/") && token.slice(1).includes("/")) || /^[A-Za-z]:[\\/]/u.test(token);
    if (filesystemPath && !options.pathSegments && !options.encodedPathComponent) continue;
    if (options.pathSegments) {
      const parts = token.split(/[\\/]/u).filter(Boolean);
      if (parts.some((part) => likelyOpaqueSecret(part, name))) return true;
      if (filesystemPath) continue;
    }
    if (likelyOpaqueSecret(token, name)) return true;
  }
  return false;
}

function credentialParameters(parsed) {
  const groups = [parsed.searchParams];
  const fragment = parsed.hash.slice(1);
  const parameterText = fragment.includes("?") ? fragment.slice(fragment.indexOf("?") + 1) : fragment;
  if (parameterText.includes("=")) groups.push(new URLSearchParams(parameterText));
  return groups;
}

function decodedUrlVariants(value, name) {
  const variants = [value];
  let current = value;
  for (let round = 0; round < 2; round += 1) {
    if (!current.includes("%")) break;
    if (/%(?![0-9A-Fa-f]{2})/u.test(current)) {
      throw new Error(`${name} contains malformed URL percent encoding`);
    }
    let decoded;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      throw new Error(`${name} contains malformed URL percent encoding`);
    }
    if (decoded === current) break;
    variants.push(decoded);
    current = decoded;
  }
  return variants;
}

function urlComponentContainsOpaqueCredential(value, name, options = {}) {
  return decodedUrlVariants(value, name).some((variant) => containsOpaqueCredential(variant, name, options));
}

function urlPathContainsOpaqueCredential(pathname, name) {
  // Split on literal URL path separators before decoding. An encoded slash
  // can be part of one opaque credential and must not become a trusted path
  // boundary after percent decoding.
  return pathname.split("/").filter(Boolean).some((segment) =>
    decodedUrlVariants(segment, name).some((variant) =>
      containsOpaqueCredential(variant, name, { encodedPathComponent: true })
    )
  );
}

function assertUrlContainsNoCredential(value, name) {
  urlCandidate.lastIndex = 0;
  for (const match of value.matchAll(urlCandidate)) {
    let parsed;
    try {
      parsed = new URL(match[0]);
    } catch {
      continue;
    }
    if (parsed.username || parsed.password) {
      throw new Error(`${name} appears to contain URL user information; keep credentials in private secret storage`);
    }
    for (const parameters of credentialParameters(parsed)) {
      for (const [key, parameter] of parameters) {
        const keys = decodedUrlVariants(key, `${name}.parameter-name`);
        const values = decodedUrlVariants(parameter, `${name}.${key}`);
        if (keys.some((candidate) => likelyOpaqueSecret(candidate, `${name}.parameter-name`)) ||
            (parameter && (keys.some((candidate) => sensitiveQueryName.test(candidate)) ||
              values.some((candidate) => likelyOpaqueSecret(candidate, `${name}.${key}`))))) {
          throw new Error(`${name} appears to contain a credential-bearing URL parameter; keep credentials in private secret storage`);
        }
      }
    }
    const rawFragment = parsed.hash.slice(1);
    const rawQuery = parsed.search.slice(1);
    if (urlPathContainsOpaqueCredential(parsed.pathname, `${name}.path`) ||
        (rawQuery && urlComponentContainsOpaqueCredential(rawQuery, `${name}.query`, { pathSegments: true })) ||
        (rawFragment && urlComponentContainsOpaqueCredential(rawFragment, `${name}.fragment`, { pathSegments: true }))) {
      throw new Error(`${name} appears to contain an opaque credential in a URL; keep credentials in private secret storage`);
    }
  }
}

export function redactSensitiveHeaders(value, replacement = "[secret withheld]") {
  return typeof value === "string" ? value.replace(sensitiveHeader, replacement) : value;
}

export function oneLine(value, { name = "value", max = 600 } = {}) {
  if (typeof value !== "string") throw new Error(`${name} must be text`);
  assertNoUnsafeText(value, name);
  const normalized = value.trim().replace(/\s+/g, " ");
  if (!normalized) throw new Error(`${name} must not be empty`);
  if (normalized.length > max) throw new Error(`${name} must be ${max} characters or fewer`);
  return normalized;
}

export function assertNoLikelySecret(value, name = "value") {
  if (typeof value !== "string") return;
  if (secretPatterns.some((pattern) => pattern.test(value))) {
    throw new Error(`${name} appears to contain a credential; keep it in private secret storage`);
  }
  assertUrlContainsNoCredential(value, name);
  urlCandidate.lastIndex = 0;
  let cursor = 0;
  const nonUrlSegments = [];
  for (const match of value.matchAll(urlCandidate)) {
    nonUrlSegments.push(value.slice(cursor, match.index));
    cursor = match.index + match[0].length;
  }
  nonUrlSegments.push(value.slice(cursor));
  for (const segment of nonUrlSegments) {
    if (containsOpaqueCredential(segment, name)) {
      throw new Error(`${name} appears to contain an opaque credential; keep it in private secret storage`);
    }
  }
}

export function assertNoUnsafeText(value, name = "value") {
  if (typeof value !== "string") throw new Error(`${name} must be text`);
  if (unsafeText.test(value)) {
    throw new Error(`${name} contains a terminal control or invisible direction-formatting character`);
  }
}

export function escapeUnsafeText(value) {
  if (typeof value !== "string") throw new Error("value must be text");
  return value.replace(unsafeTextGlobal, (character) => {
    const codePoint = character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    return `\\u${codePoint}`;
  });
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
