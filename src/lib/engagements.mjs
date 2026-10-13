import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { readJson, readPrivateJson, writeJsonAtomic } from "./config.mjs";
import { recordEvent } from "./events.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { readPrivateFile, writePrivateFileAtomic } from "./private-fs.mjs";
import { assertValidDocument } from "./schema.mjs";
import { oneLine, slug } from "./text.mjs";

const actions = new Set([
  "observe",
  "scan",
  "intercept",
  "authenticate",
  "fuzz",
  "exploit-safe",
  "exploit-stateful",
  "persist",
  "denial-of-service",
  "destructive-test",
  "data-access",
  "data-removal",
  "exfiltration-simulation"
]);

function engagementFile(paths, id) {
  return path.join(paths.engagements, `${slug(id, "engagement id")}.json`);
}

function hashBuffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function unchangedFile(left, right) {
  return sameFile(left, right) && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function readBounded(descriptor, maximumBytes) {
  const chunks = [];
  let total = 0;
  while (total <= maximumBytes) {
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
    const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    chunks.push(buffer.subarray(0, bytesRead));
    total += bytesRead;
  }
  if (total > maximumBytes) return null;
  return Buffer.concat(chunks, total);
}

function readRegularSource(file, label, maximumBytes) {
  const source = path.resolve(file);
  const before = fs.lstatSync(source, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`);
  if (before.size > BigInt(maximumBytes)) throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
  if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
    throw new Error(`${label} cannot be opened without following links on this platform`);
  }
  const flags = fs.constants.O_RDONLY |
    (fs.constants.O_NONBLOCK || 0) |
    (process.platform === "win32" ? 0 : fs.constants.O_NOFOLLOW);
  let descriptor;
  try {
    descriptor = fs.openSync(source, flags);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !unchangedFile(before, opened)) {
      throw new Error(`${label} changed while it was being opened`);
    }
    if (opened.size > BigInt(maximumBytes)) throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
    const content = readBounded(descriptor, maximumBytes);
    if (!content) throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(source, { bigint: true });
    if (
      !afterPath.isFile() || afterPath.isSymbolicLink() ||
      !unchangedFile(opened, afterRead) || !unchangedFile(afterRead, afterPath) ||
      BigInt(content.length) !== afterRead.size
    ) {
      throw new Error(`${label} changed while it was being read`);
    }
    return { source, content };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function writeBufferAtomic(file, content) {
  writePrivateFileAtomic(file, content, { label: `private engagement attachment ${file}` });
}

function approvalEnvelope(value) {
  return {
    engagementId: value.metadata.id,
    owner: value.metadata.owner,
    authorization: value.authorization,
    scope: value.scope,
    plan: {
      reportRef: value.plan.reportRef,
      sha256: value.plan.sha256,
      depth: value.plan.depth,
      hypotheses: value.plan.hypotheses,
      coverage: value.plan.coverage,
      completion: value.plan.completion
    },
    noMistakes: value.review.noMistakes,
    limits: value.limits,
    dataHandling: value.dataHandling,
    stopOn: value.stopOn
  };
}

function envelopeDigest(value) {
  return hashBuffer(Buffer.from(JSON.stringify(approvalEnvelope(value))));
}

function load(paths, id) {
  ensureRuntime(paths);
  const file = engagementFile(paths, id);
  if (!fs.existsSync(file)) throw new Error(`engagement does not exist: ${id}`);
  const value = readPrivateJson(file);
  assertValidDocument(value, "engagement.schema.json", { paths });
  return { file, value };
}

function statusOf(value) {
  return value.metadata?.status || "invalid";
}

function save(paths, file, value) {
  assertValidDocument(value, "engagement.schema.json", { paths });
  writeJsonAtomic(file, value, 0o600);
  recordEvent(
    {
      kind: "engagement.changed",
      summary: `Engagement ${value.metadata.id} is ${statusOf(value)}.`,
      effect: {
        class: "host-write",
        targetRef: `private://engagements/${value.metadata.id}.json`,
        engagementId: value.metadata.id,
        planDigest: value.plan.sha256
      },
      evidenceRefs: [`private://engagements/${value.metadata.id}.json`]
    },
    { paths }
  );
  return value;
}

function inferSelector(target) {
  const value = oneLine(target, { name: "target", max: 500 });
  if (/^https?:\/\//i.test(value)) {
    assertUrlSelector(value);
    return { type: "url", value };
  }
  if (value.includes("/") && net.isIP(value.split("/")[0])) return { type: "cidr", value };
  if (net.isIP(value)) return { type: "ip", value };
  if (/^(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z0-9-]+\.?$/i.test(value)) return { type: "domain", value: value.replace(/\.$/, "") };
  return { type: "application", value };
}

function normalizeSelector(target) {
  if (typeof target === "string") return inferSelector(target);
  if (!target || typeof target !== "object") throw new Error("target selectors must be strings or {type,value} objects");
  const type = oneLine(target.type, { name: "target type", max: 40 });
  const allowed = new Set(["domain", "ip", "cidr", "url", "application", "account", "repository", "device", "path"]);
  if (!allowed.has(type)) throw new Error(`unsupported target selector type: ${type}`);
  const value = oneLine(target.value, { name: "target", max: 500 });
  if (type === "url") assertUrlSelector(value);
  return { type, value };
}

function parseHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return new Set(["http:", "https:"]).has(parsed.protocol) ? parsed : null;
  } catch {
    return null;
  }
}

function hasUrlFragment(value) {
  return Boolean(parseHttpUrl(value)) && String(value).includes("#");
}

function hasUrlQuery(value) {
  const parsed = parseHttpUrl(value);
  return Boolean(parsed) && parsed.href.includes("?");
}

function assertUrlSelector(value) {
  const parsed = parseHttpUrl(value);
  if (!parsed) throw new Error("URL target selectors must be valid HTTP or HTTPS URLs");
  if (hasUrlFragment(value)) throw new Error("URL target selectors must not contain fragments");
}

function positiveInteger(value, fallback, name) {
  const result = Number(value ?? fallback);
  if (!Number.isInteger(result) || result < 1) throw new Error(`${name} must be a positive integer`);
  return result;
}

function positiveNumber(value, fallback, name) {
  const result = Number(value ?? fallback);
  if (!Number.isFinite(result) || result <= 0) throw new Error(`${name} must be positive`);
  return result;
}

export function createEngagement(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  if (Object.hasOwn(input, "evidenceRef")) {
    throw new Error("authorization evidence must be added with attachAuthorization after engagement creation");
  }
  const id = slug(input.id, "engagement id");
  const file = engagementFile(paths, id);
  if (fs.existsSync(file)) throw new Error(`engagement already exists: ${id}`);

  const template = readJson(path.join(paths.repo, "templates", "engagement.json"));
  const include = (input.targets || []).map(normalizeSelector);
  const exclude = (input.exclude || []).map(normalizeSelector);
  const permittedActions = [...new Set((input.actions || []).map((action) => slug(action, "action")))];
  if (!include.length) throw new Error("at least one target is required");
  if (!permittedActions.length) throw new Error("at least one permitted action is required");
  for (const action of permittedActions) {
    if (!actions.has(action)) throw new Error(`unsupported action: ${action}`);
  }

  const now = new Date();
  const validFrom = input.validFrom ? new Date(input.validFrom) : now;
  const validUntil = input.validUntil ? new Date(input.validUntil) : new Date(now.getTime() + 7 * 86_400_000);
  if (!Number.isFinite(validFrom.getTime()) || !Number.isFinite(validUntil.getTime()) || validUntil <= validFrom) {
    throw new Error("authorization validity must contain valid dates with validUntil after validFrom");
  }

  const value = structuredClone(template);
  value.metadata = {
    id,
    title: oneLine(input.title || id, { name: "title", max: 160 }),
    owner: slug(input.owner || "local-operator", "owner"),
    status: "proposed"
  };
  value.authorization = {
    basis: input.basis || "owner",
    evidenceRef: null,
    validFrom: validFrom.toISOString(),
    validUntil: validUntil.toISOString()
  };
  value.scope = {
    include,
    exclude,
    permittedActions,
    environment: input.environment || "host"
  };
  value.plan.reportRef = `private://plans/${id}.md`;
  value.plan.sha256 = null;
  value.plan.depth = input.depth || "exhaustive";
  value.plan.hypotheses = (input.hypotheses || []).map((item) => oneLine(item, { name: "hypothesis", max: 500 }));
  value.review = {
    noMistakes: { status: "pending", runId: null, headSha: null },
    operatorReceipt: { status: "pending", approvedPlanSha256: null, approvedAt: null }
  };
  value.limits = {
    maxMinutes: positiveInteger(input.maxMinutes, 240, "maxMinutes"),
    maxRequests: positiveInteger(input.maxRequests, 20_000, "maxRequests"),
    maxParallel: positiveInteger(input.maxParallel, 8, "maxParallel"),
    maxRatePerSecond: positiveNumber(input.maxRate, 20, "maxRatePerSecond"),
    maxTokens: positiveInteger(input.maxTokens, 1_000_000, "maxTokens")
  };
  value.dataHandling = {
    classification: input.classification || "sensitive",
    allowedDestinations: input.allowedDestinations?.length ? input.allowedDestinations : ["gate-home"],
    retentionDays: Number(input.retentionDays ?? 90),
    secretRefs: input.secretRefs || []
  };
  if (input.stopOn?.length) value.stopOn = [...new Set(input.stopOn.map((item) => slug(item, "stop condition")))];
  return save(paths, file, value);
}

export function attachPlan(id, planFile, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const { file, value } = load(paths, id);
  const { content } = readRegularSource(planFile, "plan source", 2 * 1024 * 1024);
  const destination = path.join(paths.plans, `${value.metadata.id}.md`);
  writeBufferAtomic(destination, content);
  value.plan.reportRef = `private://plans/${value.metadata.id}.md`;
  value.plan.sha256 = hashBuffer(content);
  value.review = {
    noMistakes: { status: "pending", runId: null, headSha: null },
    operatorReceipt: { status: "pending", approvedPlanSha256: null, approvedAt: null }
  };
  value.metadata.status = "proposed";
  return save(paths, file, value);
}

export function recordTechnicalReview(id, input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const { file, value } = load(paths, id);
  if (!value.plan.sha256) throw new Error("attach a plan before recording its technical review");
  if (!["passed", "failed"].includes(input.status)) throw new Error("review status must be passed or failed");
  const headSha = oneLine(input.headSha, { name: "review head SHA", max: 40 }).toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(headSha)) throw new Error("review head SHA must be a full 40-character Git commit SHA");
  value.review.noMistakes = {
    status: input.status,
    runId: oneLine(input.runId || input.run, { name: "review run", max: 160 }),
    headSha
  };
  value.review.operatorReceipt = { status: "pending", approvedPlanSha256: null, approvedAt: null };
  value.metadata.status = "proposed";
  return save(paths, file, value);
}

function planFile(paths, value) {
  const prefix = "private://plans/";
  if (!value.plan.reportRef.startsWith(prefix)) throw new Error("plan reference is invalid");
  const filename = value.plan.reportRef.slice(prefix.length);
  if (path.basename(filename) !== filename) throw new Error("plan reference escapes the private plan directory");
  return path.join(paths.plans, filename);
}

function authorizationFile(paths, reference) {
  const prefix = "private://authorizations/";
  if (typeof reference !== "string" || !reference.startsWith(prefix)) throw new Error("authorization evidence reference is invalid");
  const filename = reference.slice(prefix.length);
  if (path.basename(filename) !== filename) throw new Error("authorization evidence reference escapes the private authorization directory");
  return path.join(paths.authorizations, filename);
}

function authorizationEvidenceRef(value) {
  return `private://authorizations/${value.metadata.id}.evidence`;
}

function requireAttachedAuthorization(value) {
  const expected = authorizationEvidenceRef(value);
  if (!value.authorization.evidenceRef) {
    throw new Error(`${value.authorization.basis} requires private authorization evidence before approval`);
  }
  if (value.authorization.evidenceRef !== expected) {
    throw new Error(`authorization evidence must be attached specifically to engagement ${value.metadata.id}`);
  }
  return expected;
}

export function attachAuthorization(id, authorizationSource, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const { file, value } = load(paths, id);
  const { content } = readRegularSource(authorizationSource, "authorization source", 32 * 1024 * 1024);
  const filename = `${value.metadata.id}.evidence`;
  writeBufferAtomic(path.join(paths.authorizations, filename), content);
  value.authorization.evidenceRef = authorizationEvidenceRef(value);
  value.review = {
    noMistakes: { status: "pending", runId: null, headSha: null },
    operatorReceipt: { status: "pending", approvedPlanSha256: null, approvedAt: null }
  };
  value.metadata.status = "proposed";
  return save(paths, file, value);
}

export function approveEngagement(id, input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const { file, value } = load(paths, id);
  if (!value.plan.sha256) throw new Error("attach a plan before approval");
  const currentHash = hashBuffer(readPrivateFile(planFile(paths, value), null, { label: "approved plan" }));
  if (currentHash !== value.plan.sha256) throw new Error("the plan changed; attach and review it again");
  if (value.review.noMistakes.status !== "passed") throw new Error("a passing No Mistakes review is required");
  if (input.sha256 !== currentHash) throw new Error("the supplied plan digest does not match");
  if (input.confirm !== `APPROVE ${value.metadata.id}`) {
    throw new Error(`operator confirmation must be exactly: APPROVE ${value.metadata.id}`);
  }
  if (Date.now() >= Date.parse(value.authorization.validUntil)) throw new Error("authorization expired before approval");

  const externalAuthorizationRequired = ["client-written-authorization", "contract"].includes(value.authorization.basis);
  let authorizationEvidenceSha256 = null;
  if (externalAuthorizationRequired) {
    const evidenceFile = authorizationFile(paths, requireAttachedAuthorization(value));
    authorizationEvidenceSha256 = hashBuffer(readPrivateFile(evidenceFile, null, { label: "authorization evidence" }));
  }

  fs.mkdirSync(paths.authorizations, { recursive: true, mode: 0o700 });
  const receiptFile = path.join(paths.authorizations, `${value.metadata.id}.receipt.json`);
  const approvedAt = new Date().toISOString();
  value.authorization.evidenceRef ||= `private://authorizations/${value.metadata.id}.receipt.json`;
  const envelopeSha256 = envelopeDigest(value);
  writeJsonAtomic(
    receiptFile,
    {
      apiVersion: "gate.authorization/v1",
      engagementId: value.metadata.id,
      operator: value.metadata.owner,
      confirmation: input.confirm,
      planSha256: currentHash,
      envelopeSha256,
      authorizationEvidenceRef: value.authorization.evidenceRef,
      authorizationEvidenceSha256,
      noMistakesRunId: value.review.noMistakes.runId,
      headSha: value.review.noMistakes.headSha,
      approvedAt
    },
    0o600
  );
  value.review.operatorReceipt = { status: "approved", approvedPlanSha256: currentHash, approvedAt };
  value.metadata.status = "approved";
  return save(paths, file, value);
}

function ipv4Number(address) {
  return address.split(".").reduce((sum, octet) => (sum << 8) + Number(octet), 0) >>> 0;
}

function ipv6Number(address) {
  let normalized = address.toLowerCase().split("%")[0];
  const ipv4Tail = normalized.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (ipv4Tail) {
    const value = ipv4Number(ipv4Tail);
    normalized = normalized.slice(0, -ipv4Tail.length) + `${((value >>> 16) & 0xffff).toString(16)}:${(value & 0xffff).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[a-f0-9]{1,4}$/.test(group))) return null;
  return groups.reduce((sum, group) => (sum << 16n) + BigInt(`0x${group}`), 0n);
}

function cidrContains(cidr, target) {
  const [address, bitsText] = cidr.split("/");
  const bits = Number(bitsText);
  const family = net.isIP(address);
  if (family !== net.isIP(target) || !Number.isInteger(bits)) return false;
  if (family === 4) {
    if (bits < 0 || bits > 32) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ipv4Number(address) & mask) === (ipv4Number(target) & mask);
  }
  if (family === 6) {
    if (bits < 0 || bits > 128) return false;
    const expected = ipv6Number(address);
    const candidate = ipv6Number(target);
    if (expected === null || candidate === null) return false;
    const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
    return (expected & mask) === (candidate & mask);
  }
  return false;
}

function targetHost(target) {
  try {
    return new URL(target).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return String(target).toLowerCase().replace(/\.$/, "");
  }
}

export function targetMatches(selector, target) {
  const rawSelectorValue = typeof selector === "object" && selector ? selector.value : selector;
  if (/^https?:\/\//i.test(String(rawSelectorValue || "")) && hasUrlFragment(rawSelectorValue)) return false;
  const normalized = normalizeSelector(selector);
  const targetValue = typeof target === "object" ? normalizeSelector(target).value : String(target);
  const targetUrl = parseHttpUrl(targetValue);
  if (hasUrlFragment(targetValue)) return false;
  if (normalized.type === "cidr") return cidrContains(normalized.value, targetHost(targetValue));
  if (normalized.type === "domain") {
    const expected = normalized.value.toLowerCase().replace(/\.$/, "");
    const candidate = targetHost(targetValue);
    if (expected.startsWith("*.")) {
      const suffix = expected.slice(1);
      return candidate.endsWith(suffix) && candidate !== suffix.slice(1);
    }
    return candidate === expected;
  }
  if (normalized.type === "ip") return targetHost(targetValue) === normalized.value.toLowerCase();
  if (normalized.type === "url") {
    const expected = parseHttpUrl(normalized.value);
    const candidate = targetUrl;
    if (!expected || !candidate) return false;
    const expectedPath = expected.pathname.replace(/\/$/, "");
    const pathMatches = candidate.pathname === expected.pathname || candidate.pathname.startsWith(`${expectedPath}/`);
    const searchMatches = !hasUrlQuery(normalized.value) ||
      (hasUrlQuery(targetValue) && candidate.search === expected.search);
    return candidate.origin === expected.origin && pathMatches && searchMatches;
  }
  return targetValue === normalized.value;
}

export function checkEngagement(id, input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const { value } = load(paths, id);
  const reasons = [];
  if (!new Set(["approved", "active"]).has(value.metadata.status)) reasons.push("engagement is not approved");
  if (value.review.operatorReceipt.status !== "approved") reasons.push("operator receipt is not approved");
  if (Date.now() < Date.parse(value.authorization.validFrom)) reasons.push("authorization is not active yet");
  if (Date.now() >= Date.parse(value.authorization.validUntil)) reasons.push("authorization expired");
  if (
    input.maxMinutes !== undefined &&
    Number.isFinite(Number(input.maxMinutes)) &&
    Date.now() + Number(input.maxMinutes) * 60_000 > Date.parse(value.authorization.validUntil)
  ) {
    reasons.push("declared duration extends beyond the authorization window");
  }
  if (!value.scope.permittedActions.includes(input.action)) reasons.push(`action is outside scope: ${input.action}`);
  if (!value.scope.include.some((selector) => targetMatches(selector, input.target))) reasons.push(`target is outside scope: ${input.target}`);
  if (value.scope.exclude.some((selector) => targetMatches(selector, input.target))) reasons.push(`target is explicitly excluded: ${input.target}`);
  try {
    const approvedPlanFile = planFile(paths, value);
    if (!value.plan.sha256 || hashBuffer(readPrivateFile(approvedPlanFile, null, { label: "approved plan" })) !== value.plan.sha256) {
      reasons.push("approved plan digest changed");
    }
  } catch {
    reasons.push("approved plan is unavailable");
  }
  if (value.review.operatorReceipt.approvedPlanSha256 !== value.plan.sha256) reasons.push("operator receipt does not match the plan");
  if (value.review.noMistakes.status !== "passed") reasons.push("No Mistakes review has not passed");
  const externalAuthorizationRequired = ["client-written-authorization", "contract"].includes(value.authorization.basis);
  const expectedAuthorizationRef = authorizationEvidenceRef(value);
  const authorizationRefMatches = !externalAuthorizationRequired || value.authorization.evidenceRef === expectedAuthorizationRef;
  if (!authorizationRefMatches) reasons.push("authorization evidence is not attached specifically to this engagement");
  const declaredLimits = [
    ["estimatedRequests", "maxRequests", "requests"],
    ["maxParallel", "maxParallel", "parallelism"],
    ["maxRatePerSecond", "maxRatePerSecond", "request rate"],
    ["maxMinutes", "maxMinutes", "duration"],
    ["maxTokens", "maxTokens", "tokens"]
  ];
  for (const [inputKey, limitKey, label] of declaredLimits) {
    if (input[inputKey] === undefined) continue;
    const amount = Number(input[inputKey]);
    if (!Number.isFinite(amount) || amount <= 0) reasons.push(`declared ${label} must be positive`);
    else if (amount > value.limits[limitKey]) reasons.push(`declared ${label} exceeds the approved limit`);
  }
  try {
    const receiptFile = path.join(paths.authorizations, `${value.metadata.id}.receipt.json`);
    const receipt = readPrivateJson(receiptFile);
    const expectedReceipt = {
      apiVersion: "gate.authorization/v1",
      engagementId: value.metadata.id,
      operator: value.metadata.owner,
      confirmation: `APPROVE ${value.metadata.id}`,
      planSha256: value.plan.sha256,
      authorizationEvidenceRef: externalAuthorizationRequired ? expectedAuthorizationRef : value.authorization.evidenceRef,
      noMistakesRunId: value.review.noMistakes.runId,
      headSha: value.review.noMistakes.headSha,
      approvedAt: value.review.operatorReceipt.approvedAt
    };
    for (const [key, expected] of Object.entries(expectedReceipt)) {
      if (receipt[key] !== expected) reasons.push(`operator authorization receipt ${key} changed`);
    }
    if (receipt.envelopeSha256 !== envelopeDigest(value)) reasons.push("approved engagement envelope changed");
    if (externalAuthorizationRequired && authorizationRefMatches && receipt.authorizationEvidenceRef === expectedAuthorizationRef) {
      const evidenceFile = authorizationFile(paths, expectedAuthorizationRef);
      if (receipt.authorizationEvidenceSha256 !== hashBuffer(readPrivateFile(evidenceFile, null, { label: "authorization evidence" }))) {
        reasons.push("authorization evidence changed");
      }
    }
  } catch {
    reasons.push("operator authorization receipt is unavailable");
  }
  return {
    allowed: reasons.length === 0,
    reasons: [...new Set(reasons)],
    preflightOnly: true,
    executionAvailable: false,
    attestation: {
      operatorProvenance: "local-unverified",
      noMistakesReview: "local-unverified"
    },
    engagement: value
  };
}

export function getEngagement(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  return load(paths, id).value;
}

export function closeEngagement(id, options = {}) {
  const paths = options.paths || runtimePaths(options);
  const { file, value } = load(paths, id);
  value.metadata.status = "closed";
  return save(paths, file, value);
}
