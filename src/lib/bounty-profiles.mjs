import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { ensureRuntime, runtimePaths } from "./paths.mjs";
import {
  readPrivateFileBounded,
  securePrivateDirectory,
  securePrivateFile,
  syncPrivateDirectory,
  writePrivateFileExclusive
} from "./private-fs.mjs";
import { assertNoLikelySecret, assertNoUnsafeText, escapeUnsafeText } from "./text.mjs";
import { validateDocument } from "./schema.mjs";
import {
  PROGRAM_PROFILE_ACTIONS,
  PROGRAM_PROFILE_COVERAGE_DOMAINS,
  PROGRAM_PROFILE_EXECUTION_LIMITS,
  PROGRAM_PROFILE_MODULE_IDS,
  PROGRAM_PROFILE_MODULE_QUESTIONS,
  PROGRAM_PROFILE_QUESTIONS,
  PROGRAM_PROFILE_SECTION_IDS,
  PROGRAM_PROFILE_STOP_CONDITIONS,
  assertValidProgramProfile,
  loadProgramProfileQuestionnaire,
  normalizeProgramProfile,
  programProfileQuestionAnswerIsComplete,
  programProfileRecommendationRequiresObservedSource,
  programProfileQuestionnaireBinding,
  validateProgramProfile,
  validateProgramProfileAnswers,
  validateProgramProfileRecommendations
} from "./program-profile-contract.mjs";

const PROFILE_ID = /^[a-z][a-z0-9-]{1,62}$/u;
const SECRET_REFERENCE = /^(?:env|keychain|file):\/\/[^\s]+$/u;
const PROFILE_FILE = "program-profile.json";
const ANSWERS_FILE = "answers.json";
const STATE_BINDING_FILE = "state-binding.json";
const COMPILED_DIRECTORY = "compiled";
const TRANSACTIONS_DIRECTORY = ".transactions";
const LOCK_FILE = ".profile.lock";
const LOCK_PENDING_FILE = ".profile.lock.pending";
const LOCK_SERIALIZATION_FILE = ".profile.lock.serialization";
const MAX_PROFILE_BYTES = 2 * 1024 * 1024;
const MAX_ANSWERS_BYTES = 2 * 1024 * 1024;
const MAX_RECOMMENDATIONS_BYTES = 2 * 1024 * 1024;
const MAX_PROVIDER_BYTES = 1024 * 1024;
const MAX_STATE_BINDING_BYTES = 16 * 1024;
const MAX_TRANSACTION_INTENT_BYTES = 32 * 1024;
const FRESH_AUTHORITY_CONFIRMATION = Symbol("fresh-authority-confirmation");
const MAX_PROFILE_SETUP_SCAN = 32;
const MAX_PROFILE_SETUP_DISCOVERY = 1024;
const PROFILE_SCHEMA_REF = "https://gate.local/schemas/bug-bounty-program-profile.schema.json";
const COMPILATION_CONTRACT_VERSION = "gate.dev/program-profile-compilation/v3";
const PROVIDER_TEMPLATE_ID = "replace-provider";
const PROVIDER_TEMPLATE_MODEL = "replace-model";
const PROVIDER_TEMPLATE_EFFECTIVE_AT = "2026-10-14T00:00:00Z";
const PROVIDER_TEMPLATE_EXPIRES_AT = "2027-10-14T00:00:00Z";
const CONTENT_BOUND_SOURCE_TYPES = new Set([
  "program-rules",
  "safe-harbor",
  "scope-list",
  "contract",
  "platform-page",
  "architecture",
  "account-instructions"
]);
function cleanProfileId(value) {
  if (typeof value !== "string" || !PROFILE_ID.test(value)) {
    throw new Error("program profile id must start with a letter and contain only lowercase letters, numbers, or dashes");
  }
  return value;
}

function derivedProfileId(id, suffix) {
  const direct = `${id}-${suffix}`;
  if (direct.length <= 63) return cleanProfileId(direct);
  const digest = sha256Bytes(Buffer.from(id, "utf8")).slice(0, 8);
  const maximumBase = 63 - suffix.length - digest.length - 2;
  return cleanProfileId(`${id.slice(0, maximumBase).replace(/-+$/u, "")}-${digest}-${suffix}`);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function canonicalSha256(value) {
  return sha256Bytes(Buffer.from(canonicalText(value), "utf8"));
}

function check(name, ok, detail) {
  return { name, ok: Boolean(ok), detail };
}

function isContained(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function bountyPaths(options = {}) {
  const base = options.paths || runtimePaths(options);
  if (!base?.home) throw new Error("program profiles require GATE_HOME");
  const programs = path.resolve(base.programs || path.join(base.home, "programs"));
  if (!isContained(base.home, programs) || path.resolve(base.home) === programs) {
    throw new Error("program profile storage must be a child of GATE_HOME");
  }
  return { ...base, programs };
}

function ensurePrograms(paths) {
  ensureRuntime(paths);
  securePrivateDirectory(paths.programs, { label: "private program profile root" });
}

function profileDirectory(paths, id) {
  return path.join(paths.programs, cleanProfileId(id));
}

function profileFile(paths, id) {
  return path.join(profileDirectory(paths, id), PROFILE_FILE);
}

function answersFile(paths, id) {
  return path.join(profileDirectory(paths, id), ANSWERS_FILE);
}

function compiledRoot(paths, id) {
  return path.join(profileDirectory(paths, id), COMPILED_DIRECTORY);
}

function stateBindingFile(paths, id) {
  return path.join(profileDirectory(paths, id), STATE_BINDING_FILE);
}

function transactionsRoot(paths, id) {
  return path.join(profileDirectory(paths, id), TRANSACTIONS_DIRECTORY);
}

function privateRef(id, relative = PROFILE_FILE) {
  return `private://programs/${cleanProfileId(id)}/${relative.replaceAll(path.sep, "/")}`;
}

function ensureProfileDirectory(paths, id, options = {}) {
  ensurePrograms(paths);
  const directory = profileDirectory(paths, id);
  securePrivateDirectory(directory, {
    create: options.create !== false,
    label: `private program profile ${id}`
  });
  return directory;
}

function assertProfileEntries(paths, id) {
  const directory = ensureProfileDirectory(paths, id, { create: false });
  const allowed = new Set([
    PROFILE_FILE,
    ANSWERS_FILE,
    STATE_BINDING_FILE,
    COMPILED_DIRECTORY,
    TRANSACTIONS_DIRECTORY,
    LOCK_FILE,
    LOCK_SERIALIZATION_FILE
  ]);
  for (const entry of fs.readdirSync(directory)) {
    if (!allowed.has(entry)) throw new Error(`program profile contains an unexpected entry: ${entry}`);
    const file = path.join(directory, entry);
    if ([COMPILED_DIRECTORY, TRANSACTIONS_DIRECTORY].includes(entry)) {
      securePrivateDirectory(file, { create: false, label: `private program profile directory ${entry} for ${id}` });
    } else {
      securePrivateFile(file, { allowMissing: false, label: `private program profile entry ${entry}` });
    }
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function linuxBootId() {
  if (process.platform !== "linux") return null;
  try {
    const value = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
    return /^[a-f0-9-]{36}$/u.test(value) ? value : null;
  } catch {
    return null;
  }
}

function linuxProcessRecord(pid) {
  if (process.platform !== "linux" || !Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const end = stat.lastIndexOf(")");
    if (end === -1) return null;
    const fields = stat.slice(end + 2).trim().split(/\s+/u);
    const startTicks = fields[19];
    return /^\d+$/u.test(startTicks || "") && /^[A-Z]$/u.test(fields[0] || "")
      ? { state: fields[0], startTicks }
      : null;
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ESRCH") return null;
    throw error;
  }
}

function linuxProcessStartTicks(pid) {
  return linuxProcessRecord(pid)?.startTicks || null;
}

function profileLockOwner() {
  return {
    apiVersion: "gate.dev/program-profile-lock/v1",
    pid: process.pid,
    bootId: linuxBootId(),
    processStartTicks: linuxProcessStartTicks(process.pid),
    nonce: crypto.randomBytes(16).toString("hex"),
    createdAt: new Date().toISOString()
  };
}

function trustedProfileFlock() {
  for (const candidate of ["/usr/bin/flock", "/bin/flock"]) {
    try {
      if (fs.realpathSync(candidate) !== candidate) continue;
      const stat = fs.lstatSync(candidate);
      if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) continue;
      if (typeof process.geteuid === "function" && stat.uid === process.geteuid()) continue;
      return candidate;
    } catch {
      // Try the next fixed protected system path.
    }
  }
  throw new Error("program profile locking requires flock from a protected system path");
}

function withProfileSerialization(directory, id, action, waitForRelease = false) {
  if (process.platform !== "linux") throw new Error("program profile serialization requires Linux/WSL2");
  const file = path.join(directory, LOCK_SERIALIZATION_FILE);
  const descriptor = fs.openSync(
    file,
    fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    0o600
  );
  try {
    const identity = fs.fstatSync(descriptor);
    if (!identity.isFile() || identity.nlink !== 1 || identity.uid !== process.geteuid() ||
        (identity.mode & 0o7777) !== 0o600) {
      throw new Error(`program profile ${id} serialization file is not owner-only`);
    }
    const result = spawnSync(
      trustedProfileFlock(),
      ["--exclusive", ...(waitForRelease ? ["--timeout", "2"] : ["--nonblock"]), "3"],
      {
        stdio: ["ignore", "pipe", "pipe", descriptor],
        env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
        shell: false,
        timeout: 5_000,
        maxBuffer: 16 * 1024
      }
    );
    if (result.error || result.status !== 0) {
      throw new Error(`program profile ${id} lock acquisition is active or indeterminate`);
    }
    const current = fs.lstatSync(file);
    if (!sameIdentity(identity, current)) throw new Error(`program profile ${id} serialization identity changed`);
    return action();
  } finally {
    fs.closeSync(descriptor);
  }
}

function recoverStaleProfileLock(file, directory, id) {
  const observed = fs.lstatSync(file);
  securePrivateFile(file, { allowMissing: false, label: `program profile lock ${id}` });
  const owner = readPrivateJson(file, 8192, `program profile lock ${id}`);
  if (owner?.apiVersion !== "gate.dev/program-profile-lock/v1" ||
      !Number.isSafeInteger(owner.pid) || owner.pid <= 0 ||
      typeof owner.bootId !== "string" || typeof owner.processStartTicks !== "string" ||
      typeof owner.nonce !== "string" || typeof owner.createdAt !== "string") {
    throw new Error(`program profile ${id} has an unverifiable lock; reconcile ${privateRef(id, LOCK_FILE)} manually`);
  }
  const bootId = linuxBootId();
  if (!bootId) {
    throw new Error(`program profile ${id} lock recovery is unavailable without a stable boot identity`);
  }
  const live = owner.bootId === bootId ? linuxProcessRecord(owner.pid) : null;
  if (owner.bootId === bootId && live?.startTicks === owner.processStartTicks &&
      !new Set(["Z", "X"]).has(live.state)) {
    throw new Error(`program profile ${id} is locked by live process ${owner.pid}`);
  }
  const current = fs.lstatSync(file);
  if (!current.isFile() || current.isSymbolicLink() || !sameIdentity(observed, current)) {
    throw new Error(`program profile ${id} lock changed during stale-owner recovery`);
  }
  fs.unlinkSync(file);
  syncPrivateDirectory(directory, { label: `private program profile ${id}` });
}

function withProfileLock(paths, id, action) {
  const directory = ensureProfileDirectory(paths, id);
  const file = path.join(directory, LOCK_FILE);
  const pending = path.join(directory, LOCK_PENDING_FILE);
  const owner = profileLockOwner();
  let identity;
  withProfileSerialization(directory, id, () => {
    if (fs.existsSync(pending)) {
      securePrivateFile(pending, { allowMissing: false, label: `pending program profile lock ${id}` });
      fs.unlinkSync(pending);
      syncPrivateDirectory(directory, { label: `private program profile ${id}` });
    }
    if (fs.existsSync(file)) recoverStaleProfileLock(file, directory, id);
    writePrivateFileExclusive(pending, canonicalText(owner), {
      encoding: "utf8",
      label: `pending program profile lock ${id}`
    });
    fs.renameSync(pending, file);
    syncPrivateDirectory(directory, { label: `private program profile ${id}` });
    identity = fs.lstatSync(file);
    const published = readPrivateJson(file, 8192, `program profile lock ${id}`);
    if (published.nonce !== owner.nonce) throw new Error(`program profile ${id} lock publication changed`);
  });
  try {
    reconcileProfileTransactions(paths, id);
    return action();
  } finally {
    withProfileSerialization(directory, id, () => {
      const current = fs.lstatSync(file);
      if (!current.isFile() || current.isSymbolicLink() || !sameIdentity(identity, current)) {
        throw new Error(`program profile ${id} lock changed while held`);
      }
      const published = readPrivateJson(file, 8192, `program profile lock ${id}`);
      if (published.nonce !== owner.nonce) throw new Error(`program profile ${id} lock owner changed while held`);
      fs.unlinkSync(file);
      syncPrivateDirectory(directory, { label: `private program profile ${id}` });
    }, true);
  }
}

function readPrivateJson(file, maximumBytes, label) {
  let value;
  try {
    value = JSON.parse(readPrivateFileBounded(file, maximumBytes, "utf8", { label }));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`, { cause: error });
    throw error;
  }
  return value;
}

function statIdentity(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs
  };
}

function sameStableStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

/** Safely read a bounded external JSON input without following a leaf link. */
function readExternalJson(file, maximumBytes, label) {
  const resolved = path.resolve(file);
  const before = fs.lstatSync(resolved, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new Error(`${label} must be a single-link regular non-symlink file`);
  }
  if (before.size > BigInt(maximumBytes)) throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
  if (process.platform !== "win32" && !fs.constants.O_NOFOLLOW) {
    throw new Error(`${label} cannot be opened without following links on this platform`);
  }
  const descriptor = fs.openSync(
    resolved,
    fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0) |
      (process.platform === "win32" ? 0 : fs.constants.O_NOFOLLOW)
  );
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameIdentity(before, opened)) {
      throw new Error(`${label} changed while it was opened`);
    }
    const chunks = [];
    let total = 0;
    while (total <= maximumBytes) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      chunks.push(buffer.subarray(0, count));
      total += count;
    }
    if (total > maximumBytes) throw new Error(`${label} exceeds the ${maximumBytes}-byte limit`);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameStableStat(statIdentity(opened), statIdentity(after)) || after.size !== BigInt(total)) {
      throw new Error(`${label} changed while it was read`);
    }
    const final = fs.lstatSync(resolved, { bigint: true });
    if (!sameStableStat(statIdentity(after), statIdentity(final))) {
      throw new Error(`${label} changed while it was verified`);
    }
    try {
      return JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
    } catch (error) {
      throw new Error(`${label} is not valid JSON`, { cause: error });
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function deepMerge(base, overlay) {
  if (Array.isArray(overlay)) return structuredClone(overlay);
  if (!overlay || typeof overlay !== "object") return structuredClone(overlay);
  const source = base && typeof base === "object" && !Array.isArray(base) ? base : {};
  const result = structuredClone(source);
  for (const [key, value] of Object.entries(overlay)) {
    if (["__proto__", "prototype", "constructor"].includes(key)) {
      throw new Error("unsafe program profile answer key");
    }
    if (value === undefined) continue;
    result[key] = value && typeof value === "object" && !Array.isArray(value)
      ? deepMerge(result[key], value)
      : structuredClone(value);
  }
  return result;
}

function decision(disposition = "unknown", options = {}) {
  return {
    disposition,
    claimState: options.claimState || "unverified",
    sourceRefs: options.sourceRefs || [],
    rationale: options.rationale || null,
    conditions: options.conditions || []
  };
}

function initialProfile(id, options = {}) {
  const at = options.now || new Date().toISOString();
  const title = options.title || id;
  const owner = options.owner || "local-operator";
  return {
    $schema: PROFILE_SCHEMA_REF,
    apiVersion: "gate.dev/program-profile/v1",
    kind: "BugBountyProgramProfile",
    metadata: {
      id,
      title,
      owner,
      status: "draft",
      revision: 1,
      createdAt: at,
      updatedAt: at
    },
    questionnaire: {
      sectionStatus: Object.fromEntries(PROGRAM_PROFILE_SECTION_IDS.map((section) => [section, "not-started"])),
      applicableModules: [],
      activeSection: PROGRAM_PROFILE_SECTION_IDS[0] || null
    },
    identity: {
      programName: title,
      objective: "Operator input required.",
      depth: "thorough",
      deliverables: [],
      successCriteria: []
    },
    sources: [],
    authorization: {
      basis: "owner",
      programUrl: null,
      safeHarbor: decision(),
      validFrom: null,
      validUntil: null,
      lastVerifiedAt: at,
      sourceRefs: [],
      operatorConfirmed: false,
      contacts: []
    },
    scope: {
      assets: [],
      thirdPartyHandling: decision(),
      redirectHandling: decision(),
      discoveredAssetHandling: decision()
    },
    techniquePolicy: {
      actions: Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((action) => [action, decision()])),
      techniques: []
    },
    limits: {
      timezone: "Etc/UTC",
      windows: [],
      maxMinutes: 240,
      maxRequests: 20000,
      maxParallel: 8,
      maxRatePerSecond: 20,
      maxTokens: 1000000,
      maxSpendUsd: null,
      sourceRefs: []
    },
    access: { accounts: [], identityProviderNotes: null },
    architecture: { components: [], trustBoundaries: [], dataFlows: [], unknowns: [], sourceRefs: [] },
    coverage: Object.fromEntries(PROGRAM_PROFILE_COVERAGE_DOMAINS.map((domain) => [domain, decision()])),
    dataEvidence: {
      classification: "internal",
      allowedDestinations: ["gate-home"],
      retentionDays: 90,
      redactionRules: [],
      minimumProof: "Use the least target data needed to establish the finding.",
      secretRefs: [],
      sourceRefs: []
    },
    stops: {
      conditions: Object.fromEntries(PROGRAM_PROFILE_STOP_CONDITIONS.map((condition) => [condition, {
        enabled: true,
        response: "Stop affected work, preserve evidence, and escalate to the operator.",
        claimState: "unverified",
        sourceRefs: []
      }])),
      escalationContacts: [],
      cleanup: { required: true, steps: [], verification: "Operator verification required.", sourceRefs: [] }
    },
    reporting: {
      severityStandard: "program-defined",
      submissionChannel: "Operator input required.",
      disclosurePolicy: "Operator input required.",
      retestPolicy: "Operator input required.",
      requiredSections: [],
      sourceRefs: []
    },
    executionPolicy: {
      requestedAssistanceModes: [],
      phases: []
    },
    modules: Object.fromEntries(PROGRAM_PROFILE_MODULE_IDS.map((moduleId) => [moduleId, {
      disposition: "unknown",
      claimState: "unverified",
      sourceRefs: [],
      rationale: null,
      conditions: [],
      answers: {}
    }])),
    ambiguities: [],
    attestation: {
      operator: owner,
      answersComplete: false,
      sourceClaimsReviewed: false,
      exactScopeReviewed: false,
      attestedAt: null,
      attestedRevision: null
    }
  };
}

function questionnaireRecords(options = {}) {
  const questionnaire = loadProgramProfileQuestionnaire(options);
  const configured = [
    ...(questionnaire.sections || []).flatMap((section) =>
      (section.questions || []).map((question) => ({ ...question, sectionId: section.id, moduleId: null }))
    ),
    ...(questionnaire.conditionalModules || []).flatMap((module) =>
      (module.questions || []).map((question) => ({ ...question, sectionId: null, moduleId: module.id }))
    )
  ];
  const exported = [
    ...(Array.isArray(PROGRAM_PROFILE_QUESTIONS) ? PROGRAM_PROFILE_QUESTIONS : []),
    ...(Array.isArray(PROGRAM_PROFILE_MODULE_QUESTIONS) ? PROGRAM_PROFILE_MODULE_QUESTIONS : [])
  ];
  const records = new Map(configured.map((item) => [item.id, item]));
  for (const item of exported) records.set(item.id, { ...records.get(item.id), ...item });
  return { questionnaire, questions: [...records.values()] };
}

function questionMap(options = {}) {
  return new Map(questionnaireRecords(options).questions.map((item) => [item.id, item]));
}

function recommendationSourceRefs(value, found = new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) recommendationSourceRefs(item, found);
    return found;
  }
  if (!value || typeof value !== "object") return found;
  for (const [key, child] of Object.entries(value)) {
    if (key === "sourceRefs" && Array.isArray(child)) {
      for (const sourceRef of child) if (typeof sourceRef === "string") found.add(sourceRef);
    } else {
      recommendationSourceRefs(child, found);
    }
  }
  return found;
}

function availableRecommendationSources(profile) {
  return new Map((profile?.sources || []).filter((source) => source?.id).map((source) => [source.id, source]));
}

function recommendationDisplaySummary(question, summary) {
  return question.sensitive
    ? "A private local recommendation is available; its value remains hidden."
    : String(summary || "A supported recommendation is available.");
}

/**
 * Resolve one recommendation without mutating profile state. The exact value
 * is returned only for trusted local callers; terminal and browser surfaces
 * must render `summary`, never serialize this result wholesale.
 */
export function programProfileRecommendation(questionId, options = {}) {
  const question = (options.questions || PROGRAM_PROFILE_QUESTIONS).find((item) => item.id === questionId);
  if (!question) return { available: false, questionId, reason: "unknown-question" };
  const policy = question.recommendationPolicy;
  if (policy.class === "manual-only") {
    return {
      available: false,
      questionId,
      reason: "manual-only",
      summary: "Direct local operator review is required; GATE will not recommend this answer."
    };
  }

  const supplied = policy.class === "evidence-proposal"
    ? options.recommendations?.proposals?.[questionId]
    : undefined;
  if (supplied) {
    if (!new Set(["source-derived", "local-derived"]).has(supplied.provenance) ||
        !new Set(["observed", "inferred", "unverified"]).has(supplied.basis?.claimState) ||
        !Array.isArray(supplied.basis?.sourceRefs) ||
        (supplied.provenance === "source-derived" && supplied.basis.sourceRefs.length === 0)) {
      return {
        available: false,
        questionId,
        reason: "proposal-invalid",
        summary: "The private proposal is not a valid provenance-bound recommendation."
      };
    }
    if (supplied.basis?.claimState === "unverified") {
      return {
        available: false,
        questionId,
        reason: "proposal-unverified",
        summary: "The private proposal remains unresolved because its basis is unverified."
      };
    }
    const observedSourceRequired = programProfileRecommendationRequiresObservedSource(question);
    if (observedSourceRequired &&
        (supplied.provenance !== "source-derived" || supplied.basis?.claimState !== "observed" ||
          !supplied.basis?.sourceRefs?.length)) {
      return {
        available: false,
        questionId,
        reason: "observed-source-required",
        summary: "This question requires an observed, source-derived proposal with cited current sources."
      };
    }
    // Evidence eligibility is bound to the profile revision supplied to the
    // recommendation operation. Earlier proposals in the same bulk update may
    // change applicability, but they cannot bootstrap sources for later
    // proposals in that update.
    const availableSources = availableRecommendationSources(options.sourceProfile || options.profile);
    const requiredSources = new Set([
      ...(supplied.basis?.sourceRefs || []),
      ...recommendationSourceRefs(supplied.value),
      ...(String(question.path || "").endsWith(".sourceRefs") && Array.isArray(supplied.value)
        ? supplied.value.filter((sourceRef) => typeof sourceRef === "string")
        : [])
    ]);
    if ([...requiredSources].some((sourceRef) => !availableSources.has(sourceRef))) {
      return {
        available: false,
        questionId,
        reason: "source-missing",
        summary: "The private proposal remains unresolved because a referenced source is absent."
      };
    }
    if (observedSourceRequired && [...requiredSources].some((sourceRef) =>
      availableSources.get(sourceRef)?.claimState !== "observed"
    )) {
      return {
        available: false,
        questionId,
        reason: "source-not-observed",
        summary: "The private proposal remains unresolved because a cited source is not observed."
      };
    }
    const decisionTime = Date.parse(options.now || new Date().toISOString());
    if (observedSourceRequired && [...requiredSources].some((sourceRef) => {
      const source = availableSources.get(sourceRef);
      const observedAt = Date.parse(source?.observedAt);
      return !Number.isFinite(observedAt) || observedAt > decisionTime ||
        (CONTENT_BOUND_SOURCE_TYPES.has(source?.type) && !/^[a-f0-9]{64}$/u.test(source?.contentSha256 || ""));
    })) {
      return {
        available: false,
        questionId,
        reason: "source-not-current",
        summary: "The private proposal remains unresolved because a cited observed source is not current and content-bound."
      };
    }
    return {
      available: true,
      questionId,
      value: structuredClone(supplied.value),
      provenance: supplied.provenance,
      summary: recommendationDisplaySummary(question, supplied.basis.summary),
      basis: {
        claimState: supplied.basis.claimState,
        sourceCount: supplied.basis.sourceRefs.length
      }
    };
  }

  if (policy.class === "operator-preference") {
    return {
      available: true,
      questionId,
      value: structuredClone(policy.value),
      provenance: "operator-preference",
      summary: recommendationDisplaySummary(question, policy.summary),
      basis: { policy: policy.basis }
    };
  }
  return {
    available: false,
    questionId,
    reason: "proposal-required",
    summary: programProfileRecommendationRequiresObservedSource(question)
      ? "An observed source-derived proposal with cited current sources is required."
      : "A validated source-derived or local-derived proposal is required."
  };
}

function attestationQuestionIds(options = {}) {
  return questionnaireRecords(options).questions
    .filter((item) => String(item.path || "").startsWith("attestation."))
    .map((item) => item.id);
}

function substantiveProfileSha256(profile) {
  const value = normalizeProgramProfile(structuredClone(profile));
  value.metadata = {
    id: value.metadata?.id,
    title: value.metadata?.title,
    owner: value.metadata?.owner
  };
  value.questionnaire = {
    applicableModules: value.questionnaire?.applicableModules || []
  };
  delete value.attestation;
  return canonicalSha256(value);
}

function substantiveAnswersSha256(envelope, options = {}) {
  const attestationIds = new Set(attestationQuestionIds(options));
  return canonicalSha256(Object.fromEntries(
    Object.entries(envelope?.answers || {}).filter(([id]) => !attestationIds.has(id))
  ));
}

function attestationClaimsComplete(attestation) {
  return Boolean(
    attestation?.operator &&
    attestation.answersComplete === true &&
    attestation.sourceClaimsReviewed === true &&
    attestation.exactScopeReviewed === true &&
    attestation.attestedAt
  );
}

function clearAttestation(profile) {
  profile.attestation = {
    operator: profile.metadata?.owner || "local-operator",
    answersComplete: false,
    sourceClaimsReviewed: false,
    exactScopeReviewed: false,
    attestedAt: null,
    attestedRevision: null
  };
}

function clearAttestationAnswers(envelope, options = {}) {
  for (const id of attestationQuestionIds(options)) delete envelope.answers[id];
}

function attestationClaims(attestation) {
  const claims = structuredClone(attestation || {});
  delete claims.attestedRevision;
  return claims;
}

function authorityReviewBasis(profile) {
  const normalized = normalizeProgramProfile(structuredClone(profile || {}));
  const authorization = normalized.authorization || {};
  const contacts = [...(authorization.contacts || [])].sort((left, right) =>
    canonicalText(left).localeCompare(canonicalText(right))
  );
  return {
    sources: structuredClone(normalized.sources || []),
    authorization: {
      basis: authorization.basis,
      programUrl: authorization.programUrl,
      safeHarbor: structuredClone(authorization.safeHarbor),
      validFrom: authorization.validFrom,
      validUntil: authorization.validUntil,
      lastVerifiedAt: authorization.lastVerifiedAt,
      sourceRefs: structuredClone(authorization.sourceRefs || []),
      contacts: structuredClone(contacts)
    }
  };
}

function inputExplicitlyConfirmsAuthority(value, overlay, suppliedEnvelope) {
  const supplied = suppliedEnvelope
    ? Object.hasOwn(suppliedEnvelope.answers || {}, "authority-operator-confirmed")
    : pathPresent(overlay, "authorization.operatorConfirmed");
  return supplied && value.authorization?.operatorConfirmed === true;
}

function invalidateChangedAuthorityConfirmation(current, value, overlay, suppliedEnvelope, answerEnvelope, options = {}) {
  const explicitTrue = inputExplicitlyConfirmsAuthority(value, overlay, suppliedEnvelope);
  const freshConfirmation = options[FRESH_AUTHORITY_CONFIRMATION] === true;
  if (freshConfirmation && !explicitTrue) {
    throw new Error("fresh authority confirmation requires an explicit true authority-operator-confirmed answer");
  }
  const changed = canonicalSha256(authorityReviewBasis(current)) !== canonicalSha256(authorityReviewBasis(value));
  const establishesConfirmation = current.authorization?.operatorConfirmed !== true &&
    value.authorization?.operatorConfirmed === true;
  if (freshConfirmation && explicitTrue) return;
  if (!changed && !establishesConfirmation) return;
  value.authorization.operatorConfirmed = false;
  delete answerEnvelope.answers["authority-operator-confirmed"];
}

function suppliedAttestationIsFresh(value, overlay, suppliedEnvelope, currentProfile, options = {}) {
  if (!attestationClaimsComplete(value.attestation)) return false;
  const questions = questionnaireRecords(options).questions
    .filter((item) => String(item.path || "").startsWith("attestation."));
  if (suppliedEnvelope) {
    const ids = questions.map((item) => item.id);
    if (!ids.every((id) => Object.hasOwn(suppliedEnvelope.answers || {}, id))) return false;
  } else if (!questions.every((item) => pathPresent(overlay, item.path))) {
    return false;
  }
  if (!currentProfile) return true;
  if (canonicalSha256(attestationClaims(value.attestation)) ===
      canonicalSha256(attestationClaims(currentProfile.attestation))) return false;
  const suppliedAt = Date.parse(value.attestation.attestedAt);
  const floors = [currentProfile.metadata?.updatedAt, currentProfile.attestation?.attestedAt]
    .map((item) => Date.parse(item))
    .filter(Number.isFinite);
  return Number.isFinite(suppliedAt) && floors.every((floor) => suppliedAt > floor);
}

function setAtPath(value, dottedPath, replacement) {
  const parts = dottedPath.split(".");
  if (!parts.length || parts.some((part) => part === "__proto__" || part === "prototype" || part === "constructor")) {
    throw new Error(`invalid program profile answer path: ${dottedPath}`);
  }
  let cursor = value;
  for (const part of parts.slice(0, -1)) {
    if (!cursor[part] || typeof cursor[part] !== "object" || Array.isArray(cursor[part])) cursor[part] = {};
    cursor = cursor[part];
  }
  cursor[parts.at(-1)] = structuredClone(replacement);
}

function overlayFromAnswerEnvelope(envelope, options = {}) {
  const validation = validateProgramProfileAnswers(envelope, options);
  if (!validation.ok) throw new Error(`program profile answers validation failed: ${validation.errors.join("; ")}`);
  const questions = questionMap(options);
  const overlay = {};
  const entries = Object.entries(envelope.answers || {}).map(([questionId, value]) => {
    const question = questions.get(questionId);
    if (!question) throw new Error(`unknown program profile question: ${questionId}`);
    const target = question.path;
    if (!target) throw new Error(`program profile question has no target path: ${questionId}`);
    return { questionId, target, value };
  }).sort((left, right) => {
    const depth = left.target.split(".").length - right.target.split(".").length;
    return depth || left.target.localeCompare(right.target) || left.questionId.localeCompare(right.questionId);
  });
  for (const { target, value } of entries) {
    setAtPath(overlay, target, value);
  }
  return overlay;
}

function normalizedAnswersInput(id, input, options = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("program profile answers must be an object");
  assertRawAnswersSafe(input);
  if (input.kind === "BugBountyProgramProfileAnswers" ||
      ["gate.dev/program-profile-answers/v1", "gate.dev/program-profile-answers/v2"].includes(input.apiVersion)) {
    if (input.metadata?.programId !== id) throw new Error("program profile answer envelope does not match the requested program id");
    return { overlay: overlayFromAnswerEnvelope(input, options), envelope: structuredClone(input) };
  }
  if (input.kind === "BugBountyProgramProfile" || input.apiVersion === "gate.dev/program-profile/v1") {
    return { overlay: structuredClone(input), envelope: null };
  }
  return { overlay: structuredClone(input), envelope: null };
}

function valueAtPath(value, dottedPath) {
  let cursor = value;
  for (const part of String(dottedPath).split(".").filter(Boolean)) {
    if (!cursor || typeof cursor !== "object" || !Object.hasOwn(cursor, part)) return undefined;
    cursor = cursor[part];
  }
  return cursor;
}

function pathPresent(value, dottedPath) {
  let cursor = value;
  for (const part of String(dottedPath).split(".").filter(Boolean)) {
    if (!cursor || typeof cursor !== "object" || !Object.hasOwn(cursor, part)) return false;
    cursor = cursor[part];
  }
  return true;
}

function conditionMatches(condition, profile) {
  if (!condition) return true;
  const actual = valueAtPath(profile, condition.path);
  if (Object.hasOwn(condition, "equals")) return actual === condition.equals;
  if (Object.hasOwn(condition, "includes")) {
    return Array.isArray(actual)
      ? actual.includes(condition.includes)
      : typeof actual === "string" && actual.includes(condition.includes);
  }
  return false;
}

function mergedAnswerEnvelope(id, profile, inputOverlay, suppliedEnvelope, existingEnvelope, options = {}) {
  const at = suppliedEnvelope?.metadata?.updatedAt || options.now || new Date().toISOString();
  const answers = {
    ...(existingEnvelope?.answers || {}),
    ...(suppliedEnvelope?.answers || {})
  };
  if (!suppliedEnvelope) {
    for (const question of questionnaireRecords(options).questions) {
      if (pathPresent(inputOverlay, question.path)) answers[question.id] = valueAtPath(profile, question.path);
    }
  }
  return {
    $schema: "https://gate.local/schemas/bug-bounty-program-profile-answers.schema.json",
    apiVersion: "gate.dev/program-profile-answers/v2",
    kind: "BugBountyProgramProfileAnswers",
    metadata: {
      programId: id,
      title: profile.metadata.title,
      updatedAt: at,
      baseRevision: null,
      baseProfileSha256: null
    },
    answers
  };
}

function bindAnswerEnvelope(envelope, profile, profileSha256 = canonicalSha256(profile)) {
  const bound = structuredClone(envelope);
  bound.apiVersion = "gate.dev/program-profile-answers/v2";
  bound.metadata = {
    ...bound.metadata,
    programId: profile.metadata.id,
    title: profile.metadata.title,
    baseRevision: profile.metadata.revision,
    baseProfileSha256: profileSha256
  };
  return bound;
}

function assertAnswerMutationBase(stored, envelope, options = {}) {
  let expectedRevision;
  let expectedProfileSha256;
  if (envelope) {
    if (envelope.apiVersion !== "gate.dev/program-profile-answers/v2" ||
        envelope.metadata.baseRevision === null || envelope.metadata.baseProfileSha256 === null) {
      throw new Error(
        "program profile answer envelope is not bound to a base profile; reload current answers and use gate.dev/program-profile-answers/v2"
      );
    }
    expectedRevision = envelope.metadata.baseRevision;
    expectedProfileSha256 = envelope.metadata.baseProfileSha256;
  } else {
    expectedRevision = options.expectedRevision;
    expectedProfileSha256 = options.expectedProfileSha256;
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1 ||
        !/^[a-f0-9]{64}$/u.test(expectedProfileSha256 || "")) {
      throw new Error("raw program profile updates require expectedRevision and expectedProfileSha256 from the current profile");
    }
  }
  if (options.expectedRevision !== undefined && options.expectedRevision !== expectedRevision) {
    throw new Error("program profile update has conflicting expected revisions");
  }
  if (options.expectedProfileSha256 !== undefined && options.expectedProfileSha256 !== expectedProfileSha256) {
    throw new Error("program profile update has conflicting expected profile digests");
  }
  if (stored.profile.metadata.revision !== expectedRevision) {
    throw new Error(`program profile revision changed: expected ${expectedRevision}, observed ${stored.profile.metadata.revision}`);
  }
  if (stored.binding.profileSha256 !== expectedProfileSha256) {
    throw new Error(
      `program profile digest changed: expected ${expectedProfileSha256}, observed ${stored.binding.profileSha256}`
    );
  }
}

function normalizeProfileProgress(profile, envelope, options = {}) {
  const normalized = structuredClone(profile);
  const { questionnaire, questions } = questionnaireRecords(options);
  const questionsById = new Map(questions.map((question) => [question.id, question]));
  const answered = new Set(Object.entries(envelope?.answers || {})
    .filter(([id, answer]) => {
      const question = questionsById.get(id);
      return question && programProfileQuestionAnswerIsComplete(question, answer);
    })
    .map(([id]) => id));
  if (answered.has("identity-program-name") && typeof normalized.identity?.programName === "string") {
    normalized.metadata.title = normalized.identity.programName;
  }
  const explicitlySelected = new Set(normalized.questionnaire?.applicableModules || []);
  const applicableModules = new Set();
  for (const module of questionnaire.conditionalModules || []) {
    // The required applicableModules answer is authoritative. Imported or
    // stale module answer objects must never expand the selected technology
    // surface implicitly.
    if (explicitlySelected.has(module.id) || conditionMatches(module.activation, normalized)) {
      applicableModules.add(module.id);
    }
  }
  normalized.questionnaire.applicableModules = PROGRAM_PROFILE_MODULE_IDS.filter((id) => applicableModules.has(id));

  const applicableQuestion = (question) =>
    (!question.moduleId || applicableModules.has(question.moduleId)) && conditionMatches(question.condition, normalized);
  const status = {};
  for (const sectionId of PROGRAM_PROFILE_SECTION_IDS) {
    const sectionQuestions = questions.filter((question) => question.sectionId === sectionId && applicableQuestion(question));
    const required = sectionQuestions.filter((question) => question.required);
    const answeredCount = sectionQuestions.filter((question) => answered.has(question.id)).length;
    status[sectionId] = required.every((question) => answered.has(question.id))
      ? "complete"
      : answeredCount ? "in-progress" : "not-started";
  }
  normalized.questionnaire.sectionStatus = status;
  normalized.questionnaire.activeSection = PROGRAM_PROFILE_SECTION_IDS.find((id) => status[id] !== "complete") || null;

  const moduleQuestionsComplete = questions
    .filter((question) => question.moduleId && applicableQuestion(question) && question.required)
    .every((question) => answered.has(question.id));
  const coreComplete = PROGRAM_PROFILE_SECTION_IDS.every((id) => status[id] === "complete");
  if (normalized.metadata.status !== "superseded") {
    normalized.metadata.status = coreComplete && moduleQuestionsComplete ? "needs-operator-review" : "draft";
    if (normalized.metadata.status === "needs-operator-review") {
      const candidate = structuredClone(normalized);
      candidate.metadata.status = "ready-to-materialize";
      const semantic = semanticProfileChecks(candidate, candidate.metadata.id, options);
      if (semantic.blockers.length === 0) normalized.metadata.status = "ready-to-materialize";
    }
  }
  return normalizeProgramProfile(normalized);
}

function inspectSecretReferences(profile) {
  const errors = [];
  const normalizedField = (key) => String(key).replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
  const sensitivePath = (parts) => {
    const fields = parts.map(normalizedField);
    if (fields.some((field) => /(?:passwords?|passwd|apikeys?|accesstokens?|refreshtokens?|clientsecrets?|privatekeys?|credentials?|credentialvalues?|secrets?|sessionid|sessionkey|sessiontoken|tokens?)$/u.test(field))) {
      return true;
    }
    if (fields.some((field) => field === "auth" || field === "bearer")) return true;
    return fields.some((field, index) =>
      index > 0 && fields[index - 1] === "headers" && /^(?:authorization|cookie|setcookie)$/u.test(field)
    );
  };
  const refs = [
    ...(profile.dataEvidence?.secretRefs || []),
    ...(profile.access?.accounts || []).flatMap((account) => account.secretRefs || [])
  ];
  for (const reference of refs) {
    if (typeof reference !== "string" || !SECRET_REFERENCE.test(reference)) {
      errors.push("credential references must use env://, keychain://, or file:// and contain no whitespace");
    }
  }
  const visit = (value, pathParts = []) => {
    if (typeof value === "string") {
      try {
        assertNoUnsafeText(value, pathParts.join(".") || "program profile value");
      } catch (error) {
        errors.push(error.message);
      }
      try {
        assertNoLikelySecret(value, pathParts.join(".") || "program profile value");
      } catch (error) {
        errors.push(error.message);
      }
      if (
        sensitivePath(pathParts) &&
        !SECRET_REFERENCE.test(value)
      ) {
        errors.push(`${pathParts.join(".")} must be a symbolic secret reference`);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, [...pathParts, String(index)]));
      return;
    }
    if (value && typeof value === "object") {
      for (const [key, item] of Object.entries(value)) {
        const propertyLocation = `${pathParts.join(".") || "program profile value"} property name`;
        let safeKey = key;
        for (const inspect of [assertNoUnsafeText, assertNoLikelySecret]) {
          try {
            inspect(key, propertyLocation);
          } catch (error) {
            errors.push(error.message);
            safeKey = "[rejected-property-name]";
          }
        }
        visit(item, [...pathParts, safeKey]);
      }
    }
  };
  visit(profile);
  return [...new Set(errors)];
}

function assertProfileSafe(profile) {
  const errors = inspectSecretReferences(profile);
  if (errors.length) throw new Error(`program profile rejected: ${errors.join("; ")}`);
}

function literalSecretScan() {
  return {
    status: "pass",
    finding: "no-likely-secret-detected",
    method: "gate-heuristic-v1"
  };
}

function assertRawAnswersSafe(input) {
  const errors = inspectSecretReferences(input);
  if (errors.length) throw new Error(`program profile answers rejected: ${errors.join("; ")}`);
}

function readyContractErrorPath(detail) {
  const pointer = detail.match(/^\/([A-Za-z0-9_/-]+)/u)?.[1];
  if (pointer) return pointer.split("/").filter(Boolean).join(".");
  if (detail.startsWith("sources ")) return "sources";
  return detail.match(/^([A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+)\s/u)?.[1] || null;
}

function semanticProfileChecks(profile, id, options = {}) {
  const now = new Date(options.now || new Date().toISOString());
  const assessedAtMs = now.getTime();
  const sourceIds = new Set((profile.sources || []).map((source) => source.id));
  const sourceObservedAt = new Map((profile.sources || []).map((source) => [source.id, Date.parse(source.observedAt)]));
  const checks = [];
  const blockers = [];
  const warnings = [];
  const addBlocker = (code, detail, profilePath = null) => blockers.push({ code, detail, path: profilePath });
  const addWarning = (code, detail, profilePath = null) => warnings.push({ code, detail, path: profilePath });

  checks.push(check("profile-id", profile.metadata?.id === id, profile.metadata?.id === id
    ? "profile id matches its private directory"
    : "profile metadata id does not match its private directory"));

  const secretErrors = inspectSecretReferences(profile);
  checks.push(check("symbolic-secrets", secretErrors.length === 0, secretErrors.length
    ? secretErrors.join("; ")
    : "profile contains only symbolic secret references"));
  for (const detail of secretErrors) addBlocker("secret-value-or-invalid-reference", detail);

  const references = [];
  const collectReferences = (value, currentPath = []) => {
    if (value && typeof value === "object") {
      if (Array.isArray(value.sourceRefs)) {
        for (const ref of value.sourceRefs) references.push({ ref, path: [...currentPath, "sourceRefs"].join(".") });
      }
      if (Array.isArray(value)) value.forEach((item, index) => collectReferences(item, [...currentPath, String(index)]));
      else for (const [key, item] of Object.entries(value)) collectReferences(item, [...currentPath, key]);
    }
  };
  collectReferences(profile);
  const missingRefs = references.filter(({ ref }) => !sourceIds.has(ref));
  checks.push(check("source-references", missingRefs.length === 0, missingRefs.length
    ? `${missingRefs.length} source reference(s) do not resolve to the source ledger`
    : "all source references resolve to the source ledger"));
  for (const item of missingRefs) addBlocker("missing-source", `source ${item.ref} is not present`, item.path);

  for (const source of profile.sources || []) {
    if (CONTENT_BOUND_SOURCE_TYPES.has(source.type) && !source.contentSha256) {
      addBlocker(
        "source-content-digest-missing",
        `source ${source.id} of type ${source.type} requires a captured content SHA-256 before the profile is ready`,
        `sources.${source.id}.contentSha256`
      );
    }
    const observedAt = sourceObservedAt.get(source.id);
    if (Number.isFinite(observedAt) && observedAt > assessedAtMs) {
      addBlocker(
        "source-observation-in-future",
        `source ${source.id} was recorded after the verification time`,
        `sources.${source.id}.observedAt`
      );
    }
  }

  if (!profile.authorization?.operatorConfirmed) {
    addBlocker("authorization-unconfirmed", "operator has not confirmed the authorization basis", "authorization.operatorConfirmed");
  }
  const validFrom = profile.authorization?.validFrom ? new Date(profile.authorization.validFrom) : null;
  const validUntil = profile.authorization?.validUntil ? new Date(profile.authorization.validUntil) : null;
  const authorizationVerifiedAt = Date.parse(profile.authorization?.lastVerifiedAt);
  if (Number.isFinite(authorizationVerifiedAt) && authorizationVerifiedAt > assessedAtMs) {
    addBlocker(
      "authorization-verification-in-future",
      "authorization terms were marked verified after the verification time",
      "authorization.lastVerifiedAt"
    );
  }
  for (const sourceRef of profile.authorization?.sourceRefs || []) {
    const observedAt = sourceObservedAt.get(sourceRef);
    if (Number.isFinite(authorizationVerifiedAt) && Number.isFinite(observedAt) && authorizationVerifiedAt < observedAt) {
      addBlocker(
        "authorization-verification-predates-source",
        `authorization verification predates cited source ${sourceRef}`,
        "authorization.lastVerifiedAt"
      );
    }
  }
  if (validFrom && validUntil && !(validFrom < validUntil)) {
    addBlocker("authorization-window-invalid", "authorization end must be later than its start", "authorization");
  }
  if (validUntil && (Number.isNaN(now.getTime()) || Number.isNaN(validUntil.getTime()) || now >= validUntil)) {
    addBlocker("authorization-expired", "authorization is expired at the verification time", "authorization.validUntil");
  }
  if (validFrom && !Number.isNaN(validFrom.getTime()) && now < validFrom) {
    addBlocker("authorization-not-active", "authorization has not started at the verification time", "authorization.validFrom");
  }
  if (!validFrom || !validUntil) {
    addWarning(
      "authorization-window-open-ended",
      "the reusable program source has no complete validity window; a fresh finite window is required before a downstream engagement can receive execution authority",
      "authorization"
    );
  }
  if (["public-bug-bounty-program", "client-written-authorization", "contract"].includes(profile.authorization?.basis) &&
      !(profile.authorization?.sourceRefs || []).length) {
    addBlocker("authorization-source-missing", "third-party authorization requires a cited source", "authorization.sourceRefs");
  }
  if (profile.authorization?.basis === "public-bug-bounty-program" && !profile.authorization?.programUrl) {
    addBlocker("program-url-missing", "a public bug bounty authorization requires its program URL", "authorization.programUrl");
  }
  if (["public-bug-bounty-program", "client-written-authorization", "contract"].includes(profile.authorization?.basis) &&
      profile.authorization?.safeHarbor?.disposition === "unknown") {
    addBlocker("safe-harbor-unresolved", "safe-harbor terms remain unresolved", "authorization.safeHarbor");
  }

  const included = (profile.scope?.assets || []).filter((asset) => asset.disposition === "allowed");
  if (!included.length) addBlocker("scope-empty", "at least one exact allowed asset selector is required", "scope.assets");
  for (const asset of profile.scope?.assets || []) {
    if (asset.disposition === "unknown") {
      addBlocker("scope-disposition-unresolved", `asset ${asset.id} is ${asset.disposition}`, `scope.assets.${asset.id}`);
    }
    if (asset.disposition === "allowed" && asset.claimState === "unverified") {
      addBlocker("scope-unverified", `allowed asset ${asset.id} is unverified`, `scope.assets.${asset.id}`);
    }
    if (asset.disposition === "allowed" && !(asset.sourceRefs || []).length && !profile.authorization?.operatorConfirmed) {
      addBlocker("scope-source-missing", `allowed asset ${asset.id} lacks provenance`, `scope.assets.${asset.id}.sourceRefs`);
    }
  }
  for (const field of ["thirdPartyHandling", "redirectHandling", "discoveredAssetHandling"]) {
    const item = profile.scope?.[field];
    if (!item || item.disposition === "unknown") {
      addBlocker("scope-boundary-unresolved", `${field} has no resolved decision`, `scope.${field}`);
    }
  }

  const allowedActions = [];
  for (const action of PROGRAM_PROFILE_ACTIONS) {
    const item = profile.techniquePolicy?.actions?.[action];
    if (!item || item.disposition === "unknown") {
      addBlocker("action-unknown", `action ${action} has no resolved disposition`, `techniquePolicy.actions.${action}`);
    } else if (item.disposition === "allowed") {
      allowedActions.push(action);
      if (item.claimState === "unverified") {
        addBlocker("action-unverified", `allowed action ${action} is unverified`, `techniquePolicy.actions.${action}`);
      }
    }
  }
  if (!allowedActions.length) addBlocker("no-allowed-actions", "no action has an unconditional allowed disposition", "techniquePolicy.actions");
  for (const technique of profile.techniquePolicy?.techniques || []) {
    const action = profile.techniquePolicy?.actions?.[technique.action];
    if (technique.disposition === "allowed" && action?.disposition !== "allowed") {
      addBlocker("technique-action-conflict", `technique ${technique.id} is allowed while action ${technique.action} is ${action?.disposition || "missing"}`, `techniquePolicy.techniques.${technique.id}`);
    }
    if (technique.disposition === "unknown") {
      addBlocker("technique-unresolved", `technique ${technique.id} is ${technique.disposition}`, `techniquePolicy.techniques.${technique.id}`);
    }
  }

  for (const domain of PROGRAM_PROFILE_COVERAGE_DOMAINS) {
    const item = profile.coverage?.[domain];
    if (!item || item.disposition === "unknown") {
      addBlocker("coverage-unresolved", `coverage domain ${domain} is ${item?.disposition || "missing"}`, `coverage.${domain}`);
    }
  }
  const classificationRank = new Map([
    ["public", 0],
    ["internal", 1],
    ["confidential", 2],
    ["restricted", 3]
  ]);
  const releaseClassification = classificationRank.get(profile.dataEvidence?.classification);
  for (const flow of profile.architecture?.dataFlows || []) {
    const flowClassification = classificationRank.get(flow.dataClassification);
    if (flow.dataClassification === "unknown") {
      addBlocker(
        "data-flow-classification-unknown",
        `data flow ${flow.id} has an unknown classification`,
        `architecture.dataFlows.${flow.id}.dataClassification`
      );
    } else if (flowClassification > releaseClassification) {
      addBlocker(
        "data-release-classification-too-low",
        `data flow ${flow.id} is ${flow.dataClassification}, above the ${profile.dataEvidence.classification} release classification`,
        "dataEvidence.classification"
      );
    }
  }
  for (const moduleId of profile.questionnaire?.applicableModules || []) {
    const module = profile.modules?.[moduleId];
    if (!module || module.disposition === "unknown") {
      addBlocker("module-unresolved", `applicable module ${moduleId} is ${module?.disposition || "missing"}`, `modules.${moduleId}`);
    }
  }
  for (const ambiguity of profile.ambiguities || []) {
    if (ambiguity.status === "unresolved") addBlocker("ambiguity-unresolved", ambiguity.question, `ambiguities.${ambiguity.id}`);
  }
  for (const [section, status] of Object.entries(profile.questionnaire?.sectionStatus || {})) {
    if (status !== "complete") addBlocker("questionnaire-incomplete", `section ${section} is ${status}`, `questionnaire.sectionStatus.${section}`);
  }
  if (!profile.attestation?.answersComplete || !profile.attestation?.sourceClaimsReviewed ||
      !profile.attestation?.exactScopeReviewed || !profile.attestation?.attestedAt) {
    addBlocker("operator-attestation-incomplete", "operator attestation is incomplete", "attestation");
  } else if (profile.attestation.attestedRevision !== profile.metadata.revision) {
    addBlocker(
      "operator-attestation-stale",
      `operator attestation binds revision ${profile.attestation.attestedRevision ?? "none"}, not current revision ${profile.metadata.revision}`,
      "attestation.attestedRevision"
    );
  }
  const attestedAt = Date.parse(profile.attestation?.attestedAt);
  if (Number.isFinite(attestedAt) && attestedAt > assessedAtMs) {
    addBlocker(
      "operator-attestation-in-future",
      "operator attestation was recorded after the verification time",
      "attestation.attestedAt"
    );
  }
  if (Number.isFinite(attestedAt) && Number.isFinite(authorizationVerifiedAt) && attestedAt < authorizationVerifiedAt) {
    addBlocker(
      "operator-attestation-predates-authorization-verification",
      "operator attestation predates the recorded authorization verification",
      "attestation.attestedAt"
    );
  }
  for (const [sourceId, observedAt] of sourceObservedAt) {
    if (Number.isFinite(attestedAt) && Number.isFinite(observedAt) && attestedAt < observedAt) {
      addBlocker(
        "operator-attestation-predates-source",
        `operator attestation predates source ${sourceId}`,
        "attestation.attestedAt"
      );
    }
  }
  if (profile.metadata?.status !== "ready-to-materialize") {
    addBlocker("profile-status-not-ready", `profile status is ${profile.metadata?.status || "missing"}`, "metadata.status");
  }
  for (const [id, stop] of Object.entries(profile.stops?.conditions || {})) {
    if (!stop.enabled) addWarning("stop-disabled", `stop condition ${id} is disabled`, `stops.conditions.${id}`);
  }

  // The canonical validator intentionally permits incomplete drafts. Re-run
  // it against a ready candidate so every missing ready-state requirement is
  // visible before the runtime considers promotion.
  const readyCandidate = structuredClone(profile);
  readyCandidate.metadata.status = "ready-to-materialize";
  const readyContract = validateProgramProfile(readyCandidate, options);
  for (const detail of readyContract.errors) {
    if (!blockers.some((item) => item.detail === detail)) {
      addBlocker("ready-contract-incomplete", detail, readyContractErrorPath(detail));
    }
  }

  checks.push(check("compile-readiness", blockers.length === 0, blockers.length
    ? `${blockers.length} blocking issue(s) remain`
    : "profile is ready for no-contact compilation"));
  const effectiveActionDispositions = effectiveGlobalActionDispositions(profile);
  return {
    checks,
    blockers,
    warnings,
    allowedActions: allowedActions.filter((action) => effectiveActionDispositions[action] === "allowed")
  };
}

function loadStoredProfileState(paths, id, options = {}) {
  const snapshot = readProfileStateSnapshot(paths, id, options);
  const validation = validateProgramProfile(snapshot.profile, { paths });
  if (!validation.ok) throw new Error(`program profile validation failed: ${validation.errors.join("; ")}`);
  const answerValidation = validateProgramProfileAnswers(snapshot.answers, { paths });
  if (!answerValidation.ok) throw new Error(`program profile answers validation failed: ${answerValidation.errors.join("; ")}`);
  return snapshot;
}

function loadStoredProfile(paths, id, options = {}) {
  return loadStoredProfileState(paths, id, options).profile;
}

function stateBindingValue(id, revision, profileBytes, answerBytes) {
  return {
    apiVersion: "gate.dev/program-profile-state-binding/v1",
    kind: "ProgramProfileStateBinding",
    profileId: id,
    revision,
    profileSha256: sha256Bytes(profileBytes),
    answersSha256: sha256Bytes(answerBytes)
  };
}

function validateStateBinding(binding, id) {
  if (binding?.apiVersion !== "gate.dev/program-profile-state-binding/v1" ||
      binding.kind !== "ProgramProfileStateBinding" || binding.profileId !== id ||
      !Number.isSafeInteger(binding.revision) || binding.revision < 1 ||
      !/^[a-f0-9]{64}$/u.test(binding.profileSha256 || "") ||
      !/^[a-f0-9]{64}$/u.test(binding.answersSha256 || "")) {
    throw new Error(`program profile ${id} has an invalid state binding`);
  }
}

function readStateBindingRecord(paths, id) {
  const bytes = readPrivateFileBounded(
    stateBindingFile(paths, id),
    MAX_STATE_BINDING_BYTES,
    null,
    { label: `program profile state binding ${id}` }
  );
  let binding;
  try {
    binding = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`program profile state binding ${id} is not valid JSON`, { cause: error });
  }
  validateStateBinding(binding, id);
  return { binding, bytes };
}

function readProfileStateSnapshot(paths, id, options = {}) {
  assertProfileEntries(paths, id);
  const root = transactionsRoot(paths, id);
  if (!options.allowPending && fs.existsSync(root)) {
    securePrivateDirectory(root, { create: false, label: `program profile transaction root ${id}` });
    if (fs.readdirSync(root).length) throw new Error(`program profile ${id} has an interrupted state transaction requiring locked recovery`);
  }
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const before = readStateBindingRecord(paths, id);
    const profileBytes = readPrivateFileBounded(profileFile(paths, id), MAX_PROFILE_BYTES, null, { label: `program profile ${id}` });
    const answerBytes = readPrivateFileBounded(answersFile(paths, id), MAX_ANSWERS_BYTES, null, { label: `program profile answers ${id}` });
    const after = readStateBindingRecord(paths, id);
    if (!before.bytes.equals(after.bytes)) {
      if (attempt === 0) continue;
      throw new Error(`program profile ${id} changed while its bound state was read`);
    }
    const binding = before.binding;
    if (sha256Bytes(profileBytes) !== binding.profileSha256 || sha256Bytes(answerBytes) !== binding.answersSha256) {
      throw new Error(`program profile ${id} profile/answers state binding does not match`);
    }
    let profile;
    let answers;
    try {
      profile = JSON.parse(profileBytes.toString("utf8"));
      answers = JSON.parse(answerBytes.toString("utf8"));
    } catch (error) {
      throw new Error(`program profile ${id} bound state is not valid JSON`, { cause: error });
    }
    if (profile.metadata?.revision !== binding.revision) {
      throw new Error(`program profile ${id} revision does not match its state binding`);
    }
    return { binding, profile, answers, profileBytes, answerBytes };
  }
  throw new Error(`program profile ${id} changed while its bound state was read`);
}

function verifyProfileStateBinding(paths, id, options = {}) {
  return readProfileStateSnapshot(paths, id, options).binding;
}

function transactionFileDigest(file, maximumBytes, label) {
  if (!fs.existsSync(file)) return null;
  return sha256Bytes(readPrivateFileBounded(file, maximumBytes, null, { label }));
}

function validateTransactionIntent(intent, id, transactionId) {
  const digests = [
    intent?.next?.profileSha256,
    intent?.next?.answersSha256,
    intent?.next?.bindingSha256
  ];
  if (intent?.apiVersion !== "gate.dev/program-profile-state-transaction/v1" ||
      intent.kind !== "ProgramProfileStateTransaction" || intent.id !== transactionId ||
      intent.profileId !== id || !Number.isSafeInteger(intent.revision) || intent.revision < 1 ||
      !digests.every((value) => /^[a-f0-9]{64}$/u.test(value || ""))) {
    throw new Error(`program profile ${id} contains an invalid state transaction intent`);
  }
}

function publishTransactionComponent(transactionDirectory, stageName, destination, expectedSha256, maximumBytes, label) {
  const staged = path.join(transactionDirectory, stageName);
  if (fs.existsSync(staged)) {
    const stagedSha256 = transactionFileDigest(staged, maximumBytes, `${label} staged state`);
    if (stagedSha256 !== expectedSha256) throw new Error(`${label} staged digest does not match its transaction intent`);
    fs.renameSync(staged, destination);
    securePrivateFile(destination, { allowMissing: false, label });
    // A cross-directory rename changes both directory entries. Flush both so
    // recovery observes either the staged component or its published target,
    // never a durability gap between them.
    syncPrivateDirectory(transactionDirectory, { label: `program profile state transaction ${path.basename(transactionDirectory)}` });
    syncPrivateDirectory(path.dirname(destination), { label: `parent directory for ${label}` });
    return;
  }
  const publishedSha256 = transactionFileDigest(destination, maximumBytes, label);
  if (publishedSha256 !== expectedSha256) throw new Error(`${label} is neither staged nor durably published`);
}

function reconcileProfileTransactions(paths, id) {
  const root = transactionsRoot(paths, id);
  securePrivateDirectory(root, { label: `program profile transaction root ${id}` });
  for (const transactionId of fs.readdirSync(root).sort()) {
    if (!/^txn-[a-f0-9]{24}$/u.test(transactionId)) {
      throw new Error(`program profile ${id} transaction root contains an unexpected entry: ${transactionId}`);
    }
    const directory = path.join(root, transactionId);
    securePrivateDirectory(directory, { create: false, label: `program profile state transaction ${transactionId}` });
    const intentFile = path.join(directory, "intent.json");
    if (!fs.existsSync(intentFile)) {
      // Publication never starts before the final intent rename. This also
      // clears partial exclusive stages, intent.pending, and temporary names
      // left by older staging implementations after an abrupt process death.
      fs.rmSync(directory, { recursive: true, force: false });
      syncPrivateDirectory(root, { label: `program profile transaction root ${id}` });
      continue;
    }
    const allowed = new Set(["profile.next", "answers.next", "binding.next", "intent.json"]);
    for (const entry of fs.readdirSync(directory)) {
      if (!allowed.has(entry)) throw new Error(`program profile state transaction contains an unexpected entry: ${entry}`);
      securePrivateFile(path.join(directory, entry), { allowMissing: false, label: `program profile transaction entry ${entry}` });
    }
    const intent = readPrivateJson(intentFile, MAX_TRANSACTION_INTENT_BYTES, `program profile transaction intent ${transactionId}`);
    validateTransactionIntent(intent, id, transactionId);
    publishTransactionComponent(directory, "profile.next", profileFile(paths, id), intent.next.profileSha256, MAX_PROFILE_BYTES, `program profile ${id}`);
    publishTransactionComponent(directory, "answers.next", answersFile(paths, id), intent.next.answersSha256, MAX_ANSWERS_BYTES, `program profile answers ${id}`);
    publishTransactionComponent(directory, "binding.next", stateBindingFile(paths, id), intent.next.bindingSha256, MAX_STATE_BINDING_BYTES, `program profile state binding ${id}`);
    verifyProfileStateBinding(paths, id, { allowPending: true });
    fs.rmSync(directory, { recursive: true, force: false });
    syncPrivateDirectory(root, { label: `program profile transaction root ${id}` });
  }
}

function serializeProfileState(paths, id, profile, envelope) {
  assertValidProgramProfile(profile, { paths });
  const answerValidation = validateProgramProfileAnswers(envelope, { paths });
  if (!answerValidation.ok) throw new Error(`program profile answers validation failed: ${answerValidation.errors.join("; ")}`);
  const profileBytes = Buffer.from(canonicalText(profile), "utf8");
  const answerBytes = Buffer.from(canonicalText(envelope), "utf8");
  if (profileBytes.length > MAX_PROFILE_BYTES) {
    throw new Error(`program profile exceeds the ${MAX_PROFILE_BYTES}-byte limit`);
  }
  if (answerBytes.length > MAX_ANSWERS_BYTES) throw new Error("program profile answers exceed the private storage limit");
  const binding = stateBindingValue(id, profile.metadata.revision, profileBytes, answerBytes);
  const bindingBytes = Buffer.from(canonicalText(binding), "utf8");
  return { profileBytes, answerBytes, bindingBytes, binding };
}

function writeProfileState(paths, id, profile, envelope) {
  const state = serializeProfileState(paths, id, profile, envelope);
  const root = transactionsRoot(paths, id);
  securePrivateDirectory(root, { label: `program profile transaction root ${id}` });
  if (fs.readdirSync(root).length) throw new Error(`program profile ${id} has an unreconciled state transaction`);
  const transactionId = `txn-${crypto.randomBytes(12).toString("hex")}`;
  const directory = path.join(root, transactionId);
  securePrivateDirectory(directory, { label: `program profile state transaction ${transactionId}` });
  syncPrivateDirectory(root, { label: `program profile transaction root ${id}` });
  const intent = {
    apiVersion: "gate.dev/program-profile-state-transaction/v1",
    kind: "ProgramProfileStateTransaction",
    id: transactionId,
    profileId: id,
    revision: profile.metadata.revision,
    createdAt: profile.metadata.updatedAt,
    next: {
      profileSha256: sha256Bytes(state.profileBytes),
      answersSha256: sha256Bytes(state.answerBytes),
      bindingSha256: sha256Bytes(state.bindingBytes)
    }
  };
  try {
    // Every transaction directory is new and private, so exclusive writes are
    // preferable to atomic replacement here. A process death during an
    // exclusive stage write can leave only a known partial filename, which
    // reconciliation safely removes while no intent exists. Atomic helpers
    // may leave implementation-specific temporary names after SIGKILL.
    writePrivateFileExclusive(path.join(directory, "profile.next"), state.profileBytes, { label: `staged program profile ${id}` });
    writePrivateFileExclusive(path.join(directory, "answers.next"), state.answerBytes, { label: `staged program profile answers ${id}` });
    writePrivateFileExclusive(path.join(directory, "binding.next"), state.bindingBytes, { label: `staged program profile state binding ${id}` });
    const pendingIntent = path.join(directory, "intent.pending");
    writePrivateFileExclusive(pendingIntent, canonicalText(intent), {
      encoding: "utf8",
      label: `pending program profile transaction intent ${transactionId}`
    });
    fs.renameSync(pendingIntent, path.join(directory, "intent.json"));
    syncPrivateDirectory(directory, { label: `program profile state transaction ${transactionId}` });
    reconcileProfileTransactions(paths, id);
  } finally {
    if (fs.existsSync(directory) && !fs.existsSync(path.join(directory, "intent.json"))) {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
  return {
    profile: { sha256: state.binding.profileSha256, bytes: state.profileBytes.length },
    answers: { sha256: state.binding.answersSha256, bytes: state.answerBytes.length },
    binding: state.binding
  };
}

function profileSummary(profile, verification = null) {
  return {
    id: profile.metadata.id,
    title: profile.metadata.title,
    status: profile.metadata.status,
    revision: profile.metadata.revision,
    updatedAt: profile.metadata.updatedAt,
    profileRef: privateRef(profile.metadata.id),
    profileSha256: canonicalSha256(profile),
    ready: verification ? verification.ready : undefined,
    blockerCount: verification ? verification.blockers.length : undefined
  };
}

export function loadProgramProfileAnswers(file, options = {}) {
  const paths = bountyPaths(options);
  const value = readExternalJson(file, MAX_ANSWERS_BYTES, "program profile answers source");
  assertRawAnswersSafe(value);
  const validation = validateProgramProfileAnswers(value, { paths });
  if (!validation.ok) throw new Error(`program profile answers validation failed: ${validation.errors.join("; ")}`);
  return value;
}

export function loadProgramProfileRecommendations(file, options = {}) {
  const paths = bountyPaths(options);
  const value = readExternalJson(file, MAX_RECOMMENDATIONS_BYTES, "program profile recommendations source");
  const validation = validateProgramProfileRecommendations(value, { paths });
  if (!validation.ok) {
    throw new Error(`program profile recommendations validation failed: ${validation.errors.join("; ")}`);
  }
  const secretErrors = inspectSecretReferences(value);
  if (secretErrors.length) {
    throw new Error(`program profile recommendations rejected: ${secretErrors.join("; ")}`);
  }
  return value;
}

function recommendationMutationBase(profile, recommendations, options = {}) {
  const currentSha256 = canonicalSha256(profile);
  if (options.expectedRevision !== undefined && options.expectedRevision !== profile.metadata.revision) {
    throw new Error(
      `program profile revision changed: expected ${options.expectedRevision}, observed ${profile.metadata.revision}`
    );
  }
  if (options.expectedProfileSha256 !== undefined && options.expectedProfileSha256 !== currentSha256) {
    throw new Error(
      `program profile digest changed: expected ${options.expectedProfileSha256}, observed ${currentSha256}`
    );
  }
  if (!recommendations) return currentSha256;
  if (recommendations.metadata.programId !== profile.metadata.id) {
    throw new Error("program profile recommendations do not match the requested program id");
  }
  const unbound = recommendations.metadata.baseRevision === null &&
    recommendations.metadata.baseProfileSha256 === null;
  if (unbound) {
    throw new Error("program profile recommendations are not bound to the current base profile");
  }
  if (recommendations.metadata.baseRevision !== profile.metadata.revision) {
    throw new Error(
      `program profile recommendation revision changed: expected ${recommendations.metadata.baseRevision}, ` +
      `observed ${profile.metadata.revision}`
    );
  }
  if (recommendations.metadata.baseProfileSha256 !== currentSha256) {
    throw new Error("program profile recommendation digest does not match the current profile");
  }
  return currentSha256;
}

function recommendationMode(selected, recommendations) {
  const provenances = new Set(selected.map((item) => item.provenance));
  if (provenances.has("operator-preference") && provenances.size > 1) return "mixed";
  if (provenances.has("operator-preference")) return "policy";
  if (provenances.size > 0 || recommendations) return "proposal";
  return "policy";
}

function assertRecommendationEnvelope(recommendations, paths) {
  if (!recommendations) return;
  const validation = validateProgramProfileRecommendations(recommendations, { paths });
  if (!validation.ok) {
    throw new Error(`program profile recommendations validation failed: ${validation.errors.join("; ")}`);
  }
  const secretErrors = inspectSecretReferences(recommendations);
  if (secretErrors.length) {
    throw new Error(`program profile recommendations rejected: ${secretErrors.join("; ")}`);
  }
}

function selectProgramProfileRecommendations(profile, currentAnswers, recommendations, options = {}) {
  const workingProfile = structuredClone(profile);
  const selected = [];
  let skippedExplicitCount = 0;
  let skippedNotApplicableCount = 0;
  let unavailableCount = 0;
  let manualOnlyCount = 0;

  for (const question of PROGRAM_PROFILE_QUESTIONS) {
    if (Object.hasOwn(currentAnswers.answers, question.id)) {
      skippedExplicitCount += 1;
      continue;
    }
    if (!conditionMatches(question.condition, workingProfile)) {
      skippedNotApplicableCount += 1;
      continue;
    }
    const resolved = programProfileRecommendation(question.id, {
      profile: workingProfile,
      sourceProfile: profile,
      recommendations,
      now: options.now
    });
    if (!resolved.available) {
      if (resolved.reason === "manual-only") manualOnlyCount += 1;
      else unavailableCount += 1;
      continue;
    }
    if (!programProfileQuestionAnswerIsComplete(question, resolved.value)) {
      unavailableCount += 1;
      continue;
    }
    selected.push({
      questionId: question.id,
      provenance: resolved.provenance,
      value: structuredClone(resolved.value)
    });
    setAtPath(workingProfile, question.path, resolved.value);
  }

  return {
    selected,
    mode: recommendationMode(selected, recommendations),
    skippedExplicitCount,
    skippedNotApplicableCount,
    unavailableCount,
    manualOnlyCount
  };
}

function emptyProgramProfileAnswers(id, at) {
  return {
    $schema: "https://gate.local/schemas/bug-bounty-program-profile-answers.schema.json",
    apiVersion: "gate.dev/program-profile-answers/v2",
    kind: "BugBountyProgramProfileAnswers",
    metadata: {
      programId: id,
      title: id,
      updatedAt: at,
      baseRevision: null,
      baseProfileSha256: null
    },
    answers: {}
  };
}

export function createProgramProfileWithRecommendations(id, recommendations = null, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  assertRecommendationEnvelope(recommendations, paths);
  if (recommendations) {
    if (recommendations.metadata.programId !== cleanId) {
      throw new Error("program profile recommendations do not match the requested program id");
    }
    if (recommendations.metadata.baseRevision !== null || recommendations.metadata.baseProfileSha256 !== null) {
      throw new Error("program profile create requires unbound recommendations with null base fields");
    }
  }
  const at = options.now || new Date().toISOString();
  const answers = emptyProgramProfileAnswers(cleanId, at);
  const profile = initialProfile(cleanId, { now: at });
  const selection = selectProgramProfileRecommendations(profile, answers, recommendations, { now: at });
  for (const item of selection.selected) answers.answers[item.questionId] = item.value;
  const result = createProgramProfile(cleanId, answers, { paths, now: at });
  return {
    ...result,
    updated: selection.selected.length > 0,
    recommendationMode: selection.mode,
    appliedCount: selection.selected.length,
    appliedQuestionIds: selection.selected.map((item) => item.questionId),
    skippedExplicitCount: selection.skippedExplicitCount,
    skippedNotApplicableCount: selection.skippedNotApplicableCount,
    unavailableCount: selection.unavailableCount,
    manualOnlyCount: selection.manualOnlyCount
  };
}

export function applyProgramProfileRecommendations(id, recommendations = null, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  assertRecommendationEnvelope(recommendations, paths);

  const resumed = resumeProgramProfile(cleanId, { paths });
  const profile = resumed.profile;
  const currentAnswers = resumed.answers;
  const currentProfileSha256 = recommendationMutationBase(profile, recommendations, options);
  const selection = selectProgramProfileRecommendations(profile, currentAnswers, recommendations, { now: options.now });
  const { selected } = selection;
  const mode = selection.mode;
  if (selected.length === 0) {
    return {
      updated: false,
      id: cleanId,
      revision: profile.metadata.revision,
      profileSha256: currentProfileSha256,
      recommendationMode: mode,
      appliedCount: 0,
      appliedQuestionIds: [],
      skippedExplicitCount: selection.skippedExplicitCount,
      skippedNotApplicableCount: selection.skippedNotApplicableCount,
      unavailableCount: selection.unavailableCount,
      manualOnlyCount: selection.manualOnlyCount
    };
  }

  const nextAnswers = structuredClone(currentAnswers);
  nextAnswers.metadata.updatedAt = options.now || new Date().toISOString();
  for (const item of selected) nextAnswers.answers[item.questionId] = item.value;
  const result = applyProgramProfileAnswers(cleanId, nextAnswers, { paths, now: nextAnswers.metadata.updatedAt });
  return {
    ...result,
    recommendationMode: mode,
    appliedCount: selected.length,
    appliedQuestionIds: selected.map((item) => item.questionId),
    skippedExplicitCount: selection.skippedExplicitCount,
    skippedNotApplicableCount: selection.skippedNotApplicableCount,
    unavailableCount: selection.unavailableCount,
    manualOnlyCount: selection.manualOnlyCount
  };
}

export function applyProgramProfileRecommendation(id, questionId, recommendations = null, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  assertRecommendationEnvelope(recommendations, paths);
  const question = questionMap({ paths }).get(questionId);
  if (!question) throw new Error(`unknown program profile question: ${String(questionId)}`);

  const resumed = resumeProgramProfile(cleanId, { paths });
  const profile = resumed.profile;
  const currentAnswers = resumed.answers;
  const currentProfileSha256 = recommendationMutationBase(profile, recommendations, options);
  if (Object.hasOwn(currentAnswers.answers || {}, questionId)) {
    return {
      updated: false,
      id: cleanId,
      revision: profile.metadata.revision,
      profileSha256: currentProfileSha256,
      questionId,
      reason: "explicit-answer"
    };
  }
  if (!conditionMatches(question.condition, profile)) {
    throw new Error(`program profile recommendation is not applicable: ${questionId}`);
  }
  const at = options.now || new Date().toISOString();
  const resolved = programProfileRecommendation(questionId, {
    profile,
    sourceProfile: profile,
    recommendations,
    now: at
  });
  if (!resolved.available || !programProfileQuestionAnswerIsComplete(question, resolved.value)) {
    throw new Error(
      `program profile recommendation is unavailable for ${questionId}: ` +
      `${resolved.summary || resolved.reason || "unsupported recommendation"}`
    );
  }

  const nextAnswers = structuredClone(currentAnswers);
  nextAnswers.metadata.updatedAt = at;
  nextAnswers.answers[questionId] = structuredClone(resolved.value);
  const result = applyProgramProfileAnswers(cleanId, nextAnswers, { paths, now: at });
  return {
    ...result,
    questionId,
    recommendationMode: resolved.provenance === "operator-preference" ? "policy" : "proposal",
    provenance: resolved.provenance
  };
}

export function createProgramProfile(id, answers = {}, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  const { overlay, envelope } = normalizedAnswersInput(cleanId, answers, { paths });
  if (envelope?.apiVersion === "gate.dev/program-profile-answers/v2" &&
      (envelope.metadata.baseRevision !== null || envelope.metadata.baseProfileSha256 !== null)) {
    throw new Error("program profile create requires an unbound v2 answer envelope with null base fields");
  }
  const at = options.now || new Date().toISOString();
  let value = deepMerge(initialProfile(cleanId, {
    now: at,
    title: envelope?.metadata?.title || overlay.metadata?.title,
    owner: overlay.metadata?.owner
  }), overlay);
  value.$schema = PROFILE_SCHEMA_REF;
  value.apiVersion = "gate.dev/program-profile/v1";
  value.kind = "BugBountyProgramProfile";
  value.metadata = {
    ...value.metadata,
    id: cleanId,
    revision: 1,
    createdAt: at,
    updatedAt: at
  };
  let answerEnvelope = mergedAnswerEnvelope(cleanId, value, overlay, envelope, null, { paths, now: at });
  const explicitAuthorityConfirmation = inputExplicitlyConfirmsAuthority(value, overlay, envelope);
  if (explicitAuthorityConfirmation && options[FRESH_AUTHORITY_CONFIRMATION] !== true) {
    value.authorization.operatorConfirmed = false;
    delete answerEnvelope.answers["authority-operator-confirmed"];
    clearAttestation(value);
    clearAttestationAnswers(answerEnvelope, { paths });
  }
  value.attestation.attestedRevision = suppliedAttestationIsFresh(value, overlay, envelope, null, { paths })
    ? value.metadata.revision
    : null;
  value = normalizeProfileProgress(value, answerEnvelope, { paths, now: at });
  assertValidProgramProfile(value, { paths });
  assertProfileSafe(value);
  answerEnvelope = bindAnswerEnvelope(answerEnvelope, value);
  const answerValidation = validateProgramProfileAnswers(answerEnvelope, { paths });
  if (!answerValidation.ok) throw new Error(`program profile answers validation failed: ${answerValidation.errors.join("; ")}`);
  ensureProfileDirectory(paths, cleanId);
  return withProfileLock(paths, cleanId, () => {
    if (fs.existsSync(profileFile(paths, cleanId))) throw new Error(`program profile already exists: ${cleanId}`);
    const state = writeProfileState(paths, cleanId, value, answerEnvelope);
    const verification = verifyProfileValue(value, cleanId, { paths, now: at });
    return {
      created: true,
      ...profileSummary(value, verification),
      profileBytes: state.profile.bytes,
      answersSha256: state.answers.sha256
    };
  });
}

export function applyProgramProfileAnswers(id, answers, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  ensureProfileDirectory(paths, cleanId, { create: false });
  return withProfileLock(paths, cleanId, () => {
    const stored = loadStoredProfileState(paths, cleanId);
    const current = stored.profile;
    const existingEnvelope = stored.answers;
    const { overlay, envelope } = normalizedAnswersInput(cleanId, answers, { paths });
    assertAnswerMutationBase(stored, envelope, options);
    const at = options.now || new Date().toISOString();
    let value = deepMerge(current, overlay);
    value.$schema = PROFILE_SCHEMA_REF;
    value.apiVersion = "gate.dev/program-profile/v1";
    value.kind = "BugBountyProgramProfile";
    value.metadata = {
      ...value.metadata,
      id: cleanId,
      revision: current.metadata.revision + 1,
      createdAt: current.metadata.createdAt,
      updatedAt: at
    };
    let answerEnvelope = mergedAnswerEnvelope(cleanId, value, overlay, envelope, existingEnvelope, { paths, now: at });
    invalidateChangedAuthorityConfirmation(current, value, overlay, envelope, answerEnvelope, options);
    const substantiveChange = substantiveProfileSha256(current) !== substantiveProfileSha256(value) ||
      substantiveAnswersSha256(existingEnvelope, { paths }) !== substantiveAnswersSha256(answerEnvelope, { paths });
    const attestationChanged = canonicalSha256(attestationClaims(current.attestation)) !==
      canonicalSha256(attestationClaims(value.attestation));
    const freshAttestation = suppliedAttestationIsFresh(value, overlay, envelope, current, { paths });
    if (substantiveChange && !freshAttestation) {
      clearAttestation(value);
      clearAttestationAnswers(answerEnvelope, { paths });
    } else if (attestationClaimsComplete(value.attestation) &&
        (freshAttestation || (!attestationChanged && current.attestation?.attestedRevision === current.metadata.revision))) {
      value.attestation.attestedRevision = value.metadata.revision;
    } else {
      value.attestation.attestedRevision = null;
    }
    value = normalizeProfileProgress(value, answerEnvelope, { paths, now: at });
    assertValidProgramProfile(value, { paths });
    assertProfileSafe(value);
    answerEnvelope = bindAnswerEnvelope(answerEnvelope, value);
    const answerValidation = validateProgramProfileAnswers(answerEnvelope, { paths });
    if (!answerValidation.ok) throw new Error(`program profile answers validation failed: ${answerValidation.errors.join("; ")}`);
    const state = writeProfileState(paths, cleanId, value, answerEnvelope);
    const verification = verifyProfileValue(value, cleanId, { paths, now: at });
    return {
      updated: true,
      ...profileSummary(value, verification),
      profileBytes: state.profile.bytes,
      answersSha256: state.answers.sha256
    };
  });
}

export function applyProgramProfileAuthorityConfirmation(id, answers, options = {}) {
  return applyProgramProfileAnswers(id, answers, {
    ...options,
    [FRESH_AUTHORITY_CONFIRMATION]: true
  });
}

export function clearProgramProfileAnswer(id, questionId, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  const question = questionMap({ paths }).get(questionId);
  if (!question) throw new Error(`unknown program profile question: ${String(questionId)}`);
  ensureProfileDirectory(paths, cleanId, { create: false });
  return withProfileLock(paths, cleanId, () => {
    const stored = loadStoredProfileState(paths, cleanId);
    assertAnswerMutationBase(stored, null, options);
    const current = stored.profile;
    const existingEnvelope = stored.answers;
    if (!Object.hasOwn(existingEnvelope.answers || {}, questionId)) {
      return {
        updated: false,
        cleared: false,
        questionId,
        ...profileSummary(current, verifyProfileValue(current, cleanId, { paths, now: options.now }))
      };
    }

    const at = options.now || new Date().toISOString();
    let answerEnvelope = structuredClone(existingEnvelope);
    answerEnvelope.metadata.updatedAt = at;
    delete answerEnvelope.answers[questionId];
    const remainingOverlay = overlayFromAnswerEnvelope(answerEnvelope, { paths });
    let value = deepMerge(initialProfile(cleanId, {
      now: current.metadata.createdAt,
      owner: current.metadata.owner
    }), remainingOverlay);
    value.$schema = PROFILE_SCHEMA_REF;
    value.apiVersion = "gate.dev/program-profile/v1";
    value.kind = "BugBountyProgramProfile";
    value.metadata = {
      ...value.metadata,
      id: cleanId,
      owner: current.metadata.owner,
      status: current.metadata.status === "superseded" ? "superseded" : "draft",
      revision: current.metadata.revision + 1,
      createdAt: current.metadata.createdAt,
      updatedAt: at
    };

    invalidateChangedAuthorityConfirmation(current, value, {}, null, answerEnvelope);
    const substantiveChange = substantiveProfileSha256(current) !== substantiveProfileSha256(value) ||
      substantiveAnswersSha256(existingEnvelope, { paths }) !== substantiveAnswersSha256(answerEnvelope, { paths });
    if (substantiveChange) {
      clearAttestation(value);
      clearAttestationAnswers(answerEnvelope, { paths });
    } else {
      value.attestation.attestedRevision = null;
    }
    value = normalizeProfileProgress(value, answerEnvelope, { paths, now: at });
    assertValidProgramProfile(value, { paths });
    assertProfileSafe(value);
    answerEnvelope = bindAnswerEnvelope(answerEnvelope, value);
    const answerValidation = validateProgramProfileAnswers(answerEnvelope, { paths });
    if (!answerValidation.ok) {
      throw new Error(`program profile answers validation failed: ${answerValidation.errors.join("; ")}`);
    }
    const state = writeProfileState(paths, cleanId, value, answerEnvelope);
    const verification = verifyProfileValue(value, cleanId, { paths, now: at });
    return {
      updated: true,
      cleared: true,
      questionId,
      ...profileSummary(value, verification),
      profileBytes: state.profile.bytes,
      answersSha256: state.answers.sha256
    };
  });
}

export function resumeProgramProfile(id, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  ensureProfileDirectory(paths, cleanId, { create: false });
  return withProfileLock(paths, cleanId, () => {
    const stored = loadStoredProfileState(paths, cleanId);
    const profile = stored.profile;
    const envelope = bindAnswerEnvelope(stored.answers, profile, stored.binding.profileSha256);
    return {
      profile,
      answers: envelope,
      nextSection: PROGRAM_PROFILE_SECTION_IDS.find((section) => profile.questionnaire.sectionStatus[section] !== "complete") || null,
      activeSection: profile.questionnaire.activeSection,
      summary: profileSummary(profile)
    };
  });
}

function verifyProfileValue(profile, id, options = {}) {
  const assessedAt = new Date(options.now || Date.now()).toISOString();
  const verificationOptions = { ...options, now: assessedAt };
  const schema = validateProgramProfile(profile, verificationOptions);
  const checks = [check("schema", schema.ok, schema.ok ? "profile matches the canonical schema" : schema.errors.join("; "))];
  if (!schema.ok) return { ok: false, structuralValid: false, ready: false, id, assessedAt, status: "invalid", profileSha256: canonicalSha256(profile), checks, blockers: schema.errors.map((detail) => ({ code: "schema-invalid", detail, path: null })), warnings: [] };
  const semantic = semanticProfileChecks(profile, id, verificationOptions);
  checks.push(...semantic.checks);
  const structuralValid = checks.filter((item) => item.name !== "compile-readiness").every((item) => item.ok);
  const ready = structuralValid && semantic.blockers.length === 0;
  return {
    ok: ready,
    structuralValid,
    ready,
    id,
    assessedAt,
    status: structuralValid ? (ready ? "ready-to-materialize" : profile.metadata.status) : "invalid",
    profileSha256: canonicalSha256(profile),
    checks,
    blockers: semantic.blockers,
    warnings: semantic.warnings,
    allowedActions: semantic.allowedActions
  };
}

export function verifyProgramProfile(id, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  ensurePrograms(paths);
  try {
    const stored = loadStoredProfileState(paths, cleanId);
    return verifyProfileValue(stored.profile, cleanId, { ...options, paths });
  } catch (error) {
    return {
      ok: false,
      structuralValid: false,
      ready: false,
      id: cleanId,
      assessedAt: new Date(options.now || Date.now()).toISOString(),
      status: "invalid",
      profileSha256: null,
      checks: [check("private-profile", false, error.code === "ENOENT" ? "program profile does not exist" : error.message)],
      blockers: [{ code: "profile-unavailable", detail: error.message, path: null }],
      warnings: []
    };
  }
}

function listProfileDirectories(paths) {
  ensurePrograms(paths);
  const entries = [];
  for (const name of fs.readdirSync(paths.programs)) {
    if (!PROFILE_ID.test(name)) {
      entries.push({ id: null, entry: name, ok: false, ready: false, status: "invalid", blockerCount: 1 });
      continue;
    }
    try {
      securePrivateDirectory(path.join(paths.programs, name), { create: false, label: `private program profile ${name}` });
      const verification = verifyProgramProfile(name, { paths });
      entries.push({
        id: name,
        ok: verification.ok,
        ready: verification.ready,
        status: verification.status,
        blockerCount: verification.blockers.length,
        profileSha256: verification.profileSha256
      });
    } catch {
      entries.push({ id: name, ok: false, ready: false, status: "invalid", blockerCount: 1, profileSha256: null });
    }
  }
  return entries.sort((left, right) => String(left.id || left.entry).localeCompare(String(right.id || right.entry)));
}

function programSetupPathsOverlap(left, right) {
  return isContained(left, right) || isContained(right, left);
}

function programSetupProspectiveRealPath(candidate) {
  let current = path.resolve(candidate);
  const missing = [];
  while (true) {
    try {
      const real = fs.realpathSync.native ? fs.realpathSync.native(current) : fs.realpathSync(current);
      return path.resolve(real, ...missing.reverse());
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const parent = path.dirname(current);
      if (parent === current) throw error;
      missing.push(path.basename(current));
      current = parent;
    }
  }
}

function assertProgramSetupUnscopedRoot(home, canonicalHome) {
  const visited = new Set();
  for (const candidate of [home, canonicalHome]) {
    let current = path.resolve(candidate);
    while (!visited.has(current)) {
      visited.add(current);
      try {
        fs.lstatSync(path.join(current, ".case-binding.json"));
        throw new Error("program profile setup root must not be a case state root or its descendant");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
}

function ensureProgramProfileSetupRoot(options = {}) {
  const supplied = bountyPaths(options);
  if (supplied.caseId !== null && supplied.caseId !== undefined) {
    throw new Error("program profile setup scan requires the shared runtime root");
  }
  const expected = runtimePaths({ home: supplied.home, repo: supplied.repo, env: options.env });
  const home = path.resolve(expected.home);
  const repo = path.resolve(expected.repo);
  const programs = path.resolve(expected.programs);
  if (path.resolve(supplied.programs) !== programs || path.resolve(supplied.stateHome || supplied.home) !== home) {
    throw new Error("program profile setup paths do not match the shared runtime root");
  }
  if (home === path.parse(home).root) throw new Error("GATE_HOME cannot be a filesystem root");
  if (programSetupPathsOverlap(home, repo)) throw new Error("GATE_HOME and the GATE repository must not overlap");
  const canonicalHome = programSetupProspectiveRealPath(home);
  const canonicalRepo = programSetupProspectiveRealPath(repo);
  if (programSetupPathsOverlap(canonicalHome, canonicalRepo)) {
    throw new Error("GATE_HOME and the GATE repository must not overlap after resolving parent links");
  }
  assertProgramSetupUnscopedRoot(home, canonicalHome);
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  securePrivateDirectory(home, { create: false, label: "GATE_HOME" });
  securePrivateDirectory(programs, { label: "private program profile root" });
  const canonicalPrograms = programSetupProspectiveRealPath(programs);
  if (canonicalPrograms === canonicalHome || !isContained(canonicalHome, canonicalPrograms)) {
    throw new Error("program profile storage must remain below GATE_HOME after resolving parent links");
  }
  return { ...expected, programs };
}

function boundedProgramSetupEntries(directory, maximum, label) {
  const entries = [];
  const handle = fs.opendirSync(directory);
  try {
    while (entries.length <= maximum) {
      const entry = handle.readSync();
      if (!entry) break;
      entries.push(entry.name);
    }
  } finally {
    handle.closeSync();
  }
  if (entries.length > maximum) throw new Error(`${label} exceeds its ${maximum}-entry bound`);
  return entries;
}

function auditProgramProfileSetupEntries(paths, id) {
  const directory = profileDirectory(paths, id);
  securePrivateDirectory(directory, { create: false, label: `private program profile ${id}` });
  const allowed = new Set([
    PROFILE_FILE,
    ANSWERS_FILE,
    STATE_BINDING_FILE,
    COMPILED_DIRECTORY,
    TRANSACTIONS_DIRECTORY,
    LOCK_FILE,
    LOCK_SERIALIZATION_FILE
  ]);
  const entries = boundedProgramSetupEntries(directory, allowed.size, `program profile ${id}`);
  for (const entry of entries) {
    if (!allowed.has(entry)) throw new Error(`program profile contains an unexpected entry: ${entry}`);
    const file = path.join(directory, entry);
    if ([COMPILED_DIRECTORY, TRANSACTIONS_DIRECTORY].includes(entry)) {
      securePrivateDirectory(file, { create: false, label: `private program profile directory ${entry} for ${id}` });
    } else {
      securePrivateFile(file, { allowMissing: false, label: `private program profile entry ${entry}` });
    }
  }
  if (entries.includes(TRANSACTIONS_DIRECTORY) &&
      boundedProgramSetupEntries(transactionsRoot(paths, id), 0, `program profile transaction root ${id}`).length) {
    throw new Error(`program profile ${id} has an interrupted state transaction requiring locked recovery`);
  }
}

function loadProgramProfileSetupState(paths, id) {
  auditProgramProfileSetupEntries(paths, id);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const before = readStateBindingRecord(paths, id);
    const profileBytes = readPrivateFileBounded(
      profileFile(paths, id),
      MAX_PROFILE_BYTES,
      null,
      { label: `program profile ${id}` }
    );
    const answerBytes = readPrivateFileBounded(
      answersFile(paths, id),
      MAX_ANSWERS_BYTES,
      null,
      { label: `program profile answers ${id}` }
    );
    const after = readStateBindingRecord(paths, id);
    if (!before.bytes.equals(after.bytes)) {
      if (attempt === 0) continue;
      throw new Error(`program profile ${id} changed while its bound state was read`);
    }
    const binding = before.binding;
    if (sha256Bytes(profileBytes) !== binding.profileSha256 || sha256Bytes(answerBytes) !== binding.answersSha256) {
      throw new Error(`program profile ${id} profile/answers state binding does not match`);
    }
    let profile;
    let answers;
    try {
      profile = JSON.parse(profileBytes.toString("utf8"));
      answers = JSON.parse(answerBytes.toString("utf8"));
    } catch (error) {
      throw new Error(`program profile ${id} bound state is not valid JSON`, { cause: error });
    }
    if (profile.metadata?.revision !== binding.revision || profile.metadata?.id !== id ||
        answers.metadata?.programId !== id) {
      throw new Error(`program profile ${id} bound state identity does not match`);
    }
    const profileValidation = validateProgramProfile(profile, { paths });
    if (!profileValidation.ok) {
      throw new Error(`program profile validation failed: ${profileValidation.errors.join("; ")}`);
    }
    const answerValidation = validateProgramProfileAnswers(answers, { paths });
    if (!answerValidation.ok) {
      throw new Error(`program profile answers validation failed: ${answerValidation.errors.join("; ")}`);
    }
    return { binding, profile, answers };
  }
  throw new Error(`program profile ${id} changed while its bound state was read`);
}

function scanProgramProfileSetupNames(paths) {
  const names = [];
  const directory = fs.opendirSync(paths.programs);
  try {
    while (names.length <= MAX_PROFILE_SETUP_DISCOVERY) {
      const entry = directory.readSync();
      if (!entry) break;
      names.push(entry.name);
    }
  } finally {
    directory.closeSync();
  }
  const discoveryTruncated = names.length > MAX_PROFILE_SETUP_DISCOVERY;
  const discoveredNames = names.slice(0, MAX_PROFILE_SETUP_DISCOVERY).sort();
  const selected = discoveredNames.slice(0, MAX_PROFILE_SETUP_SCAN);
  const discovered = discoveryTruncated ? MAX_PROFILE_SETUP_DISCOVERY + 1 : discoveredNames.length;
  const omitted = Math.max(0, discovered - selected.length);
  return {
    names: selected,
    scan: {
      limit: MAX_PROFILE_SETUP_SCAN,
      discoveryLimit: MAX_PROFILE_SETUP_DISCOVERY,
      discovered,
      scanned: selected.length,
      omitted,
      discoveredAtLeast: discoveryTruncated,
      omittedAtLeast: discoveryTruncated,
      complete: !discoveryTruncated && omitted === 0,
      truncated: discoveryTruncated || omitted > 0,
      invalid: 0
    }
  };
}

function programProfileSetupProgress(profile, envelope, options = {}) {
  const applicableModules = new Set(profile.questionnaire?.applicableModules || []);
  const applicable = questionnaireRecords(options).questions.filter((question) =>
    (!question.moduleId || applicableModules.has(question.moduleId)) && conditionMatches(question.condition, profile)
  );
  const answers = envelope?.answers || {};
  const answered = applicable.reduce(
    (total, question) => total + (Object.hasOwn(answers, question.id) && programProfileQuestionAnswerIsComplete(question, answers[question.id]) ? 1 : 0),
    0
  );
  const next = applicable.find((question) => !Object.hasOwn(answers, question.id) || !programProfileQuestionAnswerIsComplete(question, answers[question.id]));
  return {
    answered,
    total: applicable.length,
    nextSection: next?.sectionId || (next?.moduleId ? "conditional-modules" : null)
  };
}

function programProfileSetupStage(profile, verification, progress) {
  if (profile.metadata.status === "superseded") return "superseded";
  if (progress.answered < progress.total) return "questionnaire";
  return verification.ready === true ? "ready" : "operator-review";
}

// This read-only fleet view exposes the profile title only so the observer can
// derive a bounded private cockpit label. It deliberately contains no
// target, objective, source, answer, digest, path, authorization, or blocker
// detail. The observer applies its process-local opaque identifier and rejects
// unsafe titles after this bounded, binding-checked read.
export function programProfileSetupFleetStatus(options = {}) {
  const paths = ensureProgramProfileSetupRoot(options);
  const result = scanProgramProfileSetupNames(paths);
  const profiles = [];
  let invalid = 0;
  for (const name of result.names) {
    if (!PROFILE_ID.test(name)) {
      invalid += 1;
      continue;
    }
    try {
      const stored = loadProgramProfileSetupState(paths, name);
      const verification = verifyProfileValue(stored.profile, name, { ...options, paths });
      if (!verification.structuralValid || stored.profile.metadata.id !== name) {
        invalid += 1;
        continue;
      }
      const progress = programProfileSetupProgress(stored.profile, stored.answers, { paths });
      const stage = programProfileSetupStage(stored.profile, verification, progress);
      profiles.push({
        id: name,
        title: stored.profile.metadata.title,
        stage,
        readiness: stage === "ready" ? "ready" : "not-ready",
        progress: { answered: progress.answered, total: progress.total },
        blockerCount: stage === "questionnaire" ? Math.max(1, verification.blockers.length) : verification.blockers.length,
        nextSection: stage === "questionnaire" ? progress.nextSection : null,
        recommendationMode: null,
        updatedAt: stored.profile.metadata.updatedAt
      });
    } catch {
      invalid += 1;
    }
  }
  return {
    profiles,
    scan: {
      ...result.scan,
      invalid,
      complete: result.scan.complete && invalid === 0
    }
  };
}

export function programProfileStatus(id = null, options = {}) {
  const paths = bountyPaths(options);
  if (id === null || id === undefined) return listProfileDirectories(paths);
  const cleanId = cleanProfileId(id);
  try {
    const stored = loadStoredProfileState(paths, cleanId);
    const verification = verifyProfileValue(stored.profile, cleanId, { ...options, paths });
    if (!verification.structuralValid) return verification;
    return { ...verification, profile: profileSummary(stored.profile, verification) };
  } catch (error) {
    return verifyProgramProfile(cleanId, { ...options, paths });
  }
}

function decisionLine(label, item) {
  const sources = item.sourceRefs?.length ? `; sources: ${item.sourceRefs.join(", ")}` : "";
  const conditions = item.conditions?.length ? `; conditions: ${item.conditions.join(" | ")}` : "";
  return `- ${label}: **${item.disposition}** (${item.claimState})${sources}${conditions}`;
}

function explorationInstructions(depth) {
  const depthDirective = {
    targeted: "Pursue promising signals deeply when they bear on the narrow objective; record relevant deferred branches instead of treating them as covered.",
    thorough: "Complete the baseline map, then prioritize and test promising signals and applicable high-friction scenarios across the selected coverage.",
    exhaustive: "Systematically enumerate, test, and disposition relevant hypotheses and high-friction scenarios across every applicable coverage domain."
  }[depth] || "Apply the recorded depth and preserve every untested branch as an explicit limitation.";
  return {
    depthDirective,
    surfaceRole: "Use surface checks to build the map and generate leads; scanner or baseline completion alone is not assessment completion.",
    onPromisingSignal: "Treat anomalous, differential, state-dependent, boundary-crossing, or internally inconsistent observations as candidate signals. Record the evidence, form a testable hypothesis, and choose a discriminating follow-up within the compiled task bounds.",
    automationPriority: "Prefer repeatable automation when state, sequencing, timing, concurrency, callbacks or webhooks, role or tenant matrices, or large differential sets make a permitted test costly or error-prone to perform manually.",
    completionRule: "Before claiming completion, give every promising signal a recorded hypothesis and observed, inferred, or unverified conclusion, and every applicable workstream a tested, not-applicable, blocked, or untested disposition."
  };
}

function operatorReview(profile, verification) {
  const executionPolicy = exactExecutionPolicy(profile);
  const modulePolicy = executionPolicy.modulePolicy;
  const effectiveActionDispositions = executionPolicy.globalCeilings.effectiveActionDispositions;
  const executableActions = conservativeExecutableActions(profile, executionPolicy);
  const exploration = explorationInstructions(profile.identity.depth);
  const lines = [
    `# ${profile.metadata.title}`,
    "",
    `Program profile: \`${profile.metadata.id}\``,
    `Revision: ${profile.metadata.revision}`,
    `Profile status: ${profile.metadata.status}`,
    `Profile compilation readiness: ${verification.ready ? "ready" : "blocked"} (report generation only)`,
    "",
    "## Objective",
    "",
    profile.identity.objective,
    "",
    `Depth: ${profile.identity.depth}`,
    "",
    "## Assessment strategy",
    "",
    `- Depth directive: ${exploration.depthDirective}`,
    `- Surface role: ${exploration.surfaceRole}`,
    `- Signal follow-up: ${exploration.onPromisingSignal}`,
    `- Automation priority: ${exploration.automationPriority}`,
    `- Completion rule: ${exploration.completionRule}`,
    "",
    "### Deliverables",
    "",
    ...(profile.identity.deliverables.length
      ? profile.identity.deliverables.map((item) => `- ${item}`)
      : ["- None recorded."]),
    "",
    "### Success criteria",
    "",
    ...(profile.identity.successCriteria.length
      ? profile.identity.successCriteria.map((item) => `- ${item}`)
      : ["- None recorded."]),
    "",
    "### Named technique rules",
    "",
    ...(profile.techniquePolicy.techniques.length
      ? profile.techniquePolicy.techniques.map((item) => decisionLine(`\`${item.id}\` — ${item.name} [${item.action}]`, item))
      : ["- None recorded."]),
    "",
    "## Authorization",
    "",
    `- Basis: ${profile.authorization.basis}`,
    `- Valid from: ${profile.authorization.validFrom || "not specified by source"}`,
    `- Valid until: ${profile.authorization.validUntil || "not specified by source"}`,
    `- Operator confirmed: ${profile.authorization.operatorConfirmed ? "yes" : "no"}`,
    `- Source references: ${profile.authorization.sourceRefs.join(", ") || "none"}`,
    "",
    "## Scope",
    "",
    ...(profile.scope.assets.length ? profile.scope.assets.map((asset) =>
      `- ${asset.id}: ${asset.selector.type} \`${asset.selector.value}\` — **${asset.disposition}** (${asset.claimState})`
    ) : ["- No asset selectors recorded."]),
    "",
    "## Applicable module policy",
    "",
    `- Combination: ${modulePolicy.combination}`,
    `- Application: ${modulePolicy.application}`,
    `- Effective module disposition: **${modulePolicy.effectiveDisposition}**`,
    ...(modulePolicy.modules.length
      ? modulePolicy.modules.map((module) => decisionLine(module.id, module))
      : ["- Selected modules: none (neutral allowed ceiling)."]),
    "",
    "## Action policy",
    "",
    ...PROGRAM_PROFILE_ACTIONS.map((action) =>
      `${decisionLine(action, profile.techniquePolicy.actions[action])}; effective after module ceiling: **${effectiveActionDispositions[action]}**`
    ),
    "",
    `Effectively allowed after module ceilings: ${verification.allowedActions.length ? verification.allowedActions.join(", ") : "none"}.`,
    `Conservatively executable across every configured phase/asset slice: ${executableActions.length ? executableActions.join(", ") : "none"}.`,
    "",
    "## Coverage",
    "",
    ...PROGRAM_PROFILE_COVERAGE_DOMAINS.map((domain) => decisionLine(domain, profile.coverage[domain])),
    "",
    "## Limits",
    "",
    `- Duration: ${profile.limits.maxMinutes} minutes`,
    `- Requests: ${profile.limits.maxRequests}`,
    `- Parallel operations: ${profile.limits.maxParallel}`,
    `- Rate: ${profile.limits.maxRatePerSecond}/second`,
    `- Token budget: ${profile.limits.maxTokens}`,
    `- Spend ceiling: ${profile.limits.maxSpendUsd === null ? "none recorded" : `$${profile.limits.maxSpendUsd}`}`,
    "",
    "## Data and evidence",
    "",
    `- Classification: ${profile.dataEvidence.classification}`,
    `- Destinations: ${profile.dataEvidence.allowedDestinations.join(", ")}`,
    `- Retention: ${profile.dataEvidence.retentionDays} days`,
    `- Minimum proof: ${profile.dataEvidence.minimumProof}`,
    "",
    "## Stops and cleanup",
    "",
    ...PROGRAM_PROFILE_STOP_CONDITIONS.map((id) => `- ${id}: ${profile.stops.conditions[id].enabled ? "enabled" : "disabled"} — ${profile.stops.conditions[id].response}`),
    "",
    `Cleanup required: ${profile.stops.cleanup.required ? "yes" : "no"}. ${profile.stops.cleanup.verification}`,
    "",
    "## Blocking issues",
    "",
    ...(verification.blockers.length
      ? verification.blockers.map((item) => `- \`${item.code}\`${item.path ? ` at \`${item.path}\`` : ""}: ${item.detail}`)
      : ["- None."]),
    ""
  ];
  return escapeUnsafeText(lines.join("\n"));
}

function ambiguityReport(profile, verification) {
  const explicit = profile.ambiguities.map((item) => ({
    id: item.id,
    status: item.status,
    question: item.question,
    resolution: item.resolution,
    sourceRefs: item.sourceRefs
  }));
  return {
    apiVersion: "gate.dev/program-profile-ambiguities/v1",
    kind: "ProgramProfileAmbiguityReport",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    resolved: explicit.filter((item) => item.status === "resolved"),
    unresolved: [
      ...explicit.filter((item) => item.status === "unresolved"),
      ...verification.blockers.map((item, index) => ({
        id: `generated-${String(index + 1).padStart(3, "0")}`,
        status: "unresolved",
        question: item.detail,
        resolution: null,
        sourceRefs: [],
        code: item.code,
        path: item.path
      }))
    ]
  };
}

function scopeMatrix(profile, verification) {
  const conditional = profile.scope.assets.filter((item) => item.disposition === "conditional");
  const unknown = profile.scope.assets.filter((item) => item.disposition === "unknown");
  return {
    apiVersion: "gate.dev/program-scope-matrix/v1",
    kind: "ProgramScopeMatrix",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    includes: profile.scope.assets.filter((item) => item.disposition === "allowed"),
    excludes: profile.scope.assets.filter((item) => item.disposition === "denied"),
    conditional,
    unknown,
    unresolved: unknown,
    boundaries: {
      thirdParty: profile.scope.thirdPartyHandling,
      redirects: profile.scope.redirectHandling,
      discoveredAssets: profile.scope.discoveredAssetHandling
    }
  };
}

function techniqueMatrix(profile, verification) {
  const policy = exactExecutionPolicy(profile);
  const executableAllowedActions = conservativeExecutableActions(profile, policy);
  return {
    apiVersion: "gate.dev/program-technique-matrix/v1",
    kind: "ProgramTechniqueMatrix",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    actions: profile.techniquePolicy.actions,
    effectiveActionDispositions: policy.globalCeilings.effectiveActionDispositions,
    modulePolicy: policy.modulePolicy,
    techniques: profile.techniquePolicy.techniques,
    globalAllowedActionCeilings: verification.allowedActions || [],
    executableAllowedActions,
    phaseScopedExecutableActions: executionActionSlices(profile, policy),
    note: "An action is executable only when a phase requests it for an allowed asset and its global, applicable-module, and per-asset decisions are unconditional allowed dispositions."
  };
}

function coveragePlan(profile, verification) {
  return {
    apiVersion: "gate.dev/program-coverage-plan/v1",
    kind: "ProgramCoveragePlan",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    domains: PROGRAM_PROFILE_COVERAGE_DOMAINS.map((id) => ({ id, ...profile.coverage[id] }))
  };
}

function effectiveLimitEnvelope(profile, asset, phase = null) {
  return Object.fromEntries(PROGRAM_PROFILE_EXECUTION_LIMITS.map((key) => {
    const values = [profile.limits[key], asset?.limitOverrides?.[key], phase?.limits?.[key]]
      .filter((value) => typeof value === "number" && Number.isFinite(value));
    return [key, values.length ? Math.min(...values) : null];
  }));
}

function combinedActionDisposition(...decisions) {
  const dispositions = decisions.map((decision) => decision?.disposition || "unknown");
  if (dispositions.includes("denied")) return "denied";
  if (dispositions.includes("unknown")) return "unknown";
  if (dispositions.includes("conditional")) return "conditional";
  return "allowed";
}

function applicableModulePolicy(profile) {
  const modules = (profile.questionnaire?.applicableModules || []).map((id) => {
    const module = profile.modules?.[id] || {};
    return {
      id,
      disposition: module.disposition || "unknown",
      claimState: module.claimState || "unverified",
      sourceRefs: module.sourceRefs || [],
      rationale: module.rationale ?? null,
      conditions: module.conditions || []
    };
  });
  return {
    combination: "intersection",
    application: "global-ceiling-until-assets-have-explicit-module-bindings",
    effectiveDisposition: modules.length ? combinedActionDisposition(...modules) : "allowed",
    modules
  };
}

function effectiveGlobalActionDispositions(profile, modulePolicy = applicableModulePolicy(profile)) {
  return Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((id) => [
    id,
    combinedActionDisposition(profile.techniquePolicy.actions[id], ...modulePolicy.modules)
  ]));
}

function effectiveAssetPolicy(profile, asset, modulePolicy = applicableModulePolicy(profile)) {
  const assignedPhases = (profile.executionPolicy?.phases || [])
    .filter((phase) => phase.assetRefs.includes(asset.id));
  const phaseActions = new Set(assignedPhases.flatMap((phase) => phase.actions));
  const actions = Object.fromEntries(PROGRAM_PROFILE_ACTIONS.map((id) => {
    const globalDecision = profile.techniquePolicy.actions[id];
    const assetDecision = asset.actionOverrides?.[id] || null;
    const disposition = combinedActionDisposition(globalDecision, assetDecision, ...modulePolicy.modules);
    return [id, {
      disposition,
      permittedUnderCeilings: asset.disposition === "allowed" && disposition === "allowed",
      executable: asset.disposition === "allowed" && disposition === "allowed" && phaseActions.has(id),
      globalDecision,
      assetDecision,
      moduleDisposition: modulePolicy.effectiveDisposition
    }];
  }));
  const phases = assignedPhases
    .map((phase) => ({
      id: phase.id,
      phaseId: phase.phaseId,
      actions: phase.actions.map((id) => ({
        id,
        executable: actions[id]?.executable === true,
        effectiveDisposition: actions[id]?.disposition || "unknown"
      })),
      allowedToolIds: phase.allowedToolIds,
      deniedToolIds: phase.deniedToolIds,
      conditions: phase.conditions,
      claimState: phase.claimState,
      sourceRefs: phase.sourceRefs,
      limits: effectiveLimitEnvelope(profile, asset, phase)
    }));
  return {
    id: asset.id,
    selector: asset.selector,
    disposition: asset.disposition,
    claimState: asset.claimState,
    sourceRefs: asset.sourceRefs,
    rationale: asset.rationale,
    conditions: asset.conditions,
    actions,
    allowedActionCeilings: PROGRAM_PROFILE_ACTIONS.filter((id) => actions[id].permittedUnderCeilings),
    executableAllowedActions: PROGRAM_PROFILE_ACTIONS.filter((id) => actions[id].executable),
    limits: effectiveLimitEnvelope(profile, asset),
    phases
  };
}

function exactExecutionPolicy(profile) {
  const modulePolicy = applicableModulePolicy(profile);
  const effectiveActionDispositions = effectiveGlobalActionDispositions(profile, modulePolicy);
  const assets = profile.scope.assets.map((asset) => effectiveAssetPolicy(profile, asset, modulePolicy));
  return {
    requestedAssistanceModes: profile.executionPolicy?.requestedAssistanceModes || [],
    modulePolicy,
    globalCeilings: {
      actions: profile.techniquePolicy.actions,
      effectiveActionDispositions,
      limits: Object.fromEntries(PROGRAM_PROFILE_EXECUTION_LIMITS.map((key) => [key, profile.limits[key]]))
    },
    assets,
    phases: (profile.executionPolicy?.phases || []).map((phase) => ({
      ...phase,
      assets: phase.assetRefs.map((id) => assets.find((asset) => asset.id === id)).filter(Boolean).map((asset) => ({
        id: asset.id,
        executableAllowedActions: phase.actions.filter((action) => asset.actions[action]?.executable),
        limits: effectiveLimitEnvelope(profile, profile.scope.assets.find((item) => item.id === asset.id), phase)
      }))
    }))
  };
}

function executionActionSlices(profile, policy = exactExecutionPolicy(profile)) {
  return policy.phases.flatMap((phase) => phase.assets.map((asset) => ({
    phasePolicyId: phase.id,
    phaseId: phase.phaseId,
    assetId: asset.id,
    executableAllowedActions: asset.executableAllowedActions
  })));
}

function requestedExecutionActions(profile) {
  const requested = new Set((profile.executionPolicy?.phases || []).flatMap((phase) => phase.actions));
  return PROGRAM_PROFILE_ACTIONS.filter((action) => requested.has(action));
}

function conservativeExecutableActions(profile, policy = exactExecutionPolicy(profile)) {
  const slices = executionActionSlices(profile, policy);
  if (!slices.length) return [];
  return PROGRAM_PROFILE_ACTIONS.filter((action) =>
    slices.every((slice) => slice.executableAllowedActions.includes(action))
  );
}

function runTokenEnvelope(profile, policy = exactExecutionPolicy(profile)) {
  const assetCeilings = policy.assets
    .filter((asset) => asset.disposition === "allowed")
    .map((asset) => ({ assetId: asset.id, maxTokens: asset.limits.maxTokens }));
  const phaseAssetCeilings = policy.phases.flatMap((phase) => phase.assets.map((asset) => ({
    phasePolicyId: phase.id,
    phaseId: phase.phaseId,
    assetId: asset.id,
    maxTokens: asset.limits.maxTokens
  })));
  const candidates = [
    profile.limits.maxTokens,
    ...assetCeilings.map((item) => item.maxTokens),
    ...phaseAssetCeilings.map((item) => item.maxTokens)
  ].filter((value) => typeof value === "number" && Number.isFinite(value));
  return {
    globalMaxTokens: profile.limits.maxTokens,
    assetCeilings,
    phaseAssetCeilings,
    effectiveMaxTokens: Math.min(...candidates)
  };
}

function executionPolicyPlan(profile, verification) {
  return {
    apiVersion: "gate.dev/program-execution-policy/v1",
    kind: "ProgramExecutionPolicy",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    ...exactExecutionPolicy(profile)
  };
}

function modelContext(profile, verification, input) {
  const allowedAssets = profile.scope.assets.filter((asset) => asset.disposition === "allowed");
  const exclusions = profile.scope.assets.filter((asset) => asset.disposition === "denied");
  const executionPolicy = exactExecutionPolicy(profile);
  const effectiveActionDispositions = executionPolicy.globalCeilings.effectiveActionDispositions;
  const conditionalPolicy = {
    safeHarbor: profile.authorization.safeHarbor.disposition === "conditional"
      ? profile.authorization.safeHarbor
      : null,
    scopeAssets: profile.scope.assets.filter((item) => item.disposition === "conditional"),
    scopeBoundaries: Object.fromEntries(
      ["thirdPartyHandling", "redirectHandling", "discoveredAssetHandling"]
        .filter((id) => profile.scope[id].disposition === "conditional")
        .map((id) => [id, profile.scope[id]])
    ),
    actions: PROGRAM_PROFILE_ACTIONS
      .filter((id) => profile.techniquePolicy.actions[id].disposition === "conditional")
      .map((id) => ({ id, ...profile.techniquePolicy.actions[id] })),
    techniques: profile.techniquePolicy.techniques.filter((item) => item.disposition === "conditional"),
    coverage: PROGRAM_PROFILE_COVERAGE_DOMAINS
      .filter((id) => profile.coverage[id].disposition === "conditional")
      .map((id) => ({ id, ...profile.coverage[id] })),
    modules: profile.questionnaire.applicableModules
      .filter((id) => profile.modules[id].disposition === "conditional")
      .map((id) => ({ id, ...profile.modules[id] }))
  };
  return {
    apiVersion: "gate.dev/model-context/v3",
    kind: "ModelContextPacket",
    metadata: {
      id: `context-${input.compilationId.slice(0, 24)}`,
      profileId: profile.metadata.id,
      profileRevision: profile.metadata.revision,
      profileSha256: verification.profileSha256,
      classification: profile.dataEvidence.classification,
      compilationContract: input.artifactContractVersion,
      issuedAt: input.assessedAt,
      expiresAt: profile.authorization.validUntil
    },
    task: {
      objective: profile.identity.objective,
      depth: profile.identity.depth,
      deliverables: profile.identity.deliverables,
      successCriteria: profile.identity.successCriteria,
      engagementId: input.engagementId,
      workflowId: input.workflowId
    },
    authorization: {
      basis: profile.authorization.basis,
      programUrl: profile.authorization.programUrl,
      validFrom: profile.authorization.validFrom,
      validUntil: profile.authorization.validUntil,
      lastVerifiedAt: profile.authorization.lastVerifiedAt,
      requiresFreshEngagementWindow: profile.authorization.validFrom === null || profile.authorization.validUntil === null,
      operatorConfirmed: profile.authorization.operatorConfirmed,
      sourceRefs: profile.authorization.sourceRefs,
      contacts: profile.authorization.contacts,
      safeHarbor: profile.authorization.safeHarbor,
      sourceClaims: profile.sources.map((source) => ({
        id: source.id,
        type: source.type,
        reference: source.reference,
        contentSha256: source.contentSha256,
        observedAt: source.observedAt,
        claimState: source.claimState
      }))
    },
    scope: {
      includes: allowedAssets,
      excludes: exclusions,
      conditional: conditionalPolicy.scopeAssets,
      unknown: profile.scope.assets.filter((asset) => asset.disposition === "unknown"),
      boundaries: scopeMatrix(profile, verification).boundaries
    },
    rules: {
      globalAllowedActionCeilings: verification.allowedActions || [],
      permittedActions: conservativeExecutableActions(profile, executionPolicy),
      deniedActions: PROGRAM_PROFILE_ACTIONS.filter((id) => effectiveActionDispositions[id] === "denied"),
      conditionalActions: PROGRAM_PROFILE_ACTIONS.filter((id) => effectiveActionDispositions[id] === "conditional"),
      unresolvedActions: PROGRAM_PROFILE_ACTIONS.filter((id) => effectiveActionDispositions[id] === "unknown"),
      actionDecisions: profile.techniquePolicy.actions,
      effectiveActionDispositions,
      modulePolicy: executionPolicy.modulePolicy,
      namedTechniques: profile.techniquePolicy.techniques,
      limits: profile.limits,
      stops: PROGRAM_PROFILE_STOP_CONDITIONS.filter((id) => profile.stops.conditions[id].enabled),
      stopConditions: profile.stops.conditions,
      escalationContacts: profile.stops.escalationContacts,
      cleanup: profile.stops.cleanup
    },
    executionPolicy,
    access: profile.access,
    architecture: profile.architecture,
    coverage: profile.coverage,
    modules: Object.fromEntries(profile.questionnaire.applicableModules.map((id) => [id, profile.modules[id]])),
    reporting: profile.reporting,
    conditionalPolicy,
    dataHandling: {
      ...profile.dataEvidence,
      literalSecretScan: literalSecretScan()
    },
    unresolved: verification.blockers.map(({ code, detail, path: profilePath }) => ({ code, detail, path: profilePath })),
    modelInstructions: {
      noAssumptions: true,
      onMissingContext: "Return one structured list of missing facts and do not broaden scope.",
      onIncompatibleCapability: "Name the unavailable capability and stop that route.",
      authorizationStatement: "Use only the exact authorization, selectors, actions, limits, destinations, stops, and cleanup rules in this packet.",
      ...explorationInstructions(profile.identity.depth)
    }
  };
}

function providerProfileInput(input, paths, options = {}) {
  if (!input) return null;
  const profile = typeof input === "string"
    ? readExternalJson(input, MAX_PROVIDER_BYTES, "provider capability profile")
    : structuredClone(input);
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new Error("provider capability profile must be an object");
  const validation = validateDocument(profile, "provider-capability-profile.schema.json", { paths });
  if (!validation.ok) throw new Error(`provider capability profile validation failed: ${validation.errors.join("; ")}`);
  if (profile.metadata.id === PROVIDER_TEMPLATE_ID) {
    throw new Error("provider capability profile still uses the template metadata.id; replace it with the reviewed provider identity");
  }
  if (profile.metadata.model === PROVIDER_TEMPLATE_MODEL) {
    throw new Error("provider capability profile still uses the template metadata.model; replace it with the exact reviewed model identity");
  }
  if (
    profile.apiVersion === "gate.dev/provider-capability-profile/v2" &&
    profile.metadata.effectiveAt === PROVIDER_TEMPLATE_EFFECTIVE_AT &&
    profile.metadata.expiresAt === PROVIDER_TEMPLATE_EXPIRES_AT
  ) {
    throw new Error("provider capability profile still uses the legacy template freshness interval; replace it with reviewed effectiveAt and expiresAt values");
  }
  const effective = profile.metadata.effectiveAt ? Date.parse(profile.metadata.effectiveAt) : null;
  const expires = profile.metadata.expiresAt ? Date.parse(profile.metadata.expiresAt) : null;
  if (effective !== null && Number.isNaN(effective)) throw new Error("provider capability effectiveAt must be a date-time");
  if (expires !== null && Number.isNaN(expires)) throw new Error("provider capability expiresAt must be a date-time");
  if (effective !== null && expires !== null && expires <= effective) {
    throw new Error("provider capability expiresAt must be later than effectiveAt");
  }
  const assessedAt = Date.parse(options.now || new Date().toISOString());
  const freshness = effective === null || expires === null
    ? "unknown"
    : assessedAt < effective || assessedAt >= expires ? "stale" : "current";
  return { value: profile, sha256: canonicalSha256(profile), freshness };
}

function compatibilityReport(profile, verification, packet, provider) {
  const packetBytes = artifactBytes(packet, "model-context.json");
  const runEnvelope = runTokenEnvelope(profile);
  const declaredContext = provider?.freshness === "current" ? provider.value.contextWindow : null;
  const contextAccountingAvailable = Boolean(declaredContext);
  // A provider may opt into this conservative, tokenizer-independent bound
  // only when its tokenizer is known not to emit more than one token per
  // input UTF-8 byte. Provider framing, system text, tools, and all other
  // request input are covered separately by the declared overhead bound.
  const inputTokensUpperBound = contextAccountingAvailable ? packetBytes.length : null;
  const requestOverheadTokensUpperBound = contextAccountingAvailable
    ? declaredContext.requestOverheadTokensUpperBound
    : null;
  const reservedOutputTokens = contextAccountingAvailable ? declaredContext.reservedOutputTokens : null;
  const totalRequestTokensUpperBound = contextAccountingAvailable
    ? inputTokensUpperBound + requestOverheadTokensUpperBound + reservedOutputTokens
    : null;
  const providerContextWindowStatus = !contextAccountingAvailable
    ? "unknown"
    : totalRequestTokensUpperBound <= declaredContext.maxTokens ? "pass" : "block";
  const runTokenBudgetStatus = !contextAccountingAvailable
    ? "unknown"
    : totalRequestTokensUpperBound <= runEnvelope.effectiveMaxTokens ? "pass" : "block";
  const requestedAssistanceModes = profile.executionPolicy?.requestedAssistanceModes || [];
  const destination = provider?.value.metadata.destination || "unknown";
  const destinationStatus = destination === "unknown" || provider?.freshness !== "current"
    ? "unknown"
    : profile.dataEvidence.allowedDestinations.includes(destination === "local" ? "gate-home" : "configured-cloud-model")
      ? "pass" : "block";
  const dimensions = [
    { id: "profile-schema", status: verification.structuralValid ? "pass" : "block" },
    { id: "authorization-binding", status: verification.blockers.some((item) => item.code.startsWith("authorization") || item.code === "program-url-missing") ? "block" : "pass" },
    { id: "scope-match", status: verification.blockers.some((item) => item.code.startsWith("scope")) ? "block" : "pass" },
    { id: "technique-policy", status: verification.blockers.some((item) => item.code.startsWith("action") || item.code.startsWith("technique") || item.code === "no-allowed-actions") ? "block" : "pass" },
    { id: "data-release", status: destinationStatus },
    { id: "provider-capability", status: "unknown" },
    { id: "provider-context-window", status: providerContextWindowStatus },
    { id: "run-token-budget", status: runTokenBudgetStatus }
  ];
  let providerPrediction = "unknown";
  let providerBlockers = [];
  const requestedActions = requestedExecutionActions(profile);
  if (provider?.freshness === "current") {
    const dispositions = [];
    for (const action of requestedActions) {
      const modes = provider.value.capabilities[action] || {};
      for (const mode of requestedAssistanceModes) {
        const disposition = modes[mode] || "unknown";
        dispositions.push(disposition);
        if (disposition === "deny") providerBlockers.push({ action, assistanceMode: mode });
      }
    }
    providerPrediction = providerBlockers.length
      ? "incompatible"
      : dispositions.length && dispositions.every((item) => item === "allow") ? "compatible" : "unknown";
    dimensions.find((item) => item.id === "provider-capability").status =
      providerPrediction === "compatible" ? "pass" : providerPrediction === "incompatible" ? "block" : "unknown";
  }
  const routeAccountingBlockers = [];
  if (providerContextWindowStatus === "unknown" || runTokenBudgetStatus === "unknown") {
    routeAccountingBlockers.push({
      code: "context-accounting-unavailable",
      detail: "A current, finite, model-bound provider context-window declaration is required to establish the initial request bound.",
      path: "provider.contextWindow"
    });
  } else {
    if (providerContextWindowStatus === "block") {
      routeAccountingBlockers.push({
        code: "provider-context-window-exceeded",
        detail: `The initial request upper bound of ${totalRequestTokensUpperBound} tokens exceeds the provider context window of ${declaredContext.maxTokens}.`,
        path: "provider.contextWindow.maxTokens"
      });
    }
    if (runTokenBudgetStatus === "block") {
      routeAccountingBlockers.push({
        code: "run-token-budget-exceeded",
        detail: `The initial request upper bound of ${totalRequestTokensUpperBound} tokens exceeds the reviewed cumulative run ceiling of ${runEnvelope.effectiveMaxTokens}.`,
        path: "executionPolicy"
      });
    }
  }
  const gateBlockers = [...verification.blockers, ...routeAccountingBlockers];
  let routingStrategy;
  let routingReason;
  if (!verification.ready) {
    routingStrategy = "operator";
    routingReason = "Resolve the listed GATE profile blockers before selecting an execution route.";
  } else if (destinationStatus !== "pass") {
    routingStrategy = "operator";
    routingReason = "Review provider destination metadata and recorded data destinations before model routing.";
  } else if (providerContextWindowStatus === "unknown" || runTokenBudgetStatus === "unknown") {
    routingStrategy = "operator";
    routingReason = "Record current provider context-window accounting before model routing.";
  } else if (providerContextWindowStatus === "block") {
    routingStrategy = "operator";
    routingReason = "Reduce the compact request payload or select a provider with a larger declared context window.";
  } else if (runTokenBudgetStatus === "block") {
    routingStrategy = "operator";
    routingReason = "Reduce the initial request bound or raise the reviewed cumulative run-token ceiling.";
  } else if (providerPrediction === "compatible") {
    routingStrategy = "provider-model";
    routingReason = "The supplied provider profile permits every compiled action and assistance mode.";
  } else if (providerPrediction === "incompatible") {
    routingStrategy = "reviewed-adapter";
    routingReason = "Use an admitted reviewed adapter or a compatible local route for denied capabilities.";
  } else {
    routingStrategy = "provider-adjudicated";
    routingReason = "Provider support is incomplete; make one truthful capability request without disguising intent.";
  }
  const routeReady = routingStrategy === "provider-model";
  const routeBlockers = [...verification.blockers, ...routeAccountingBlockers];
  if (destinationStatus !== "pass") {
    routeBlockers.push({
      code: destinationStatus === "block" ? "provider-destination-blocked" : "provider-destination-unverified",
      detail: "The provider destination is not a current allowed data destination for this profile.",
      path: "provider.metadata.destination"
    });
  }
  if (providerPrediction !== "compatible") {
    routeBlockers.push({
      code: providerPrediction === "incompatible" ? "provider-capability-incompatible" : "provider-capability-unverified",
      detail: "The provider profile does not currently allow every requested action and assistance mode.",
      path: "provider.capabilities"
    });
  }
  return {
    apiVersion: "gate.dev/model-preflight/v2",
    kind: "ModelCompatibilityReport",
    packetId: packet.metadata.id,
    packetSha256: sha256Bytes(packetBytes),
    assessedAt: packet.metadata.issuedAt,
    gateDecision: gateBlockers.length === 0 ? "pass" : "block",
    providerPrediction,
    dataReleaseStatus: destinationStatus,
    routeReady,
    requestedActions,
    requestedAssistanceModes,
    provider: provider ? {
      apiVersion: provider.value.apiVersion,
      id: provider.value.metadata.id,
      model: provider.value.metadata.model || null,
      destination,
      policyProfileSha256: provider.sha256,
      policyEffectiveAt: provider.value.metadata.effectiveAt || null,
      policyExpiresAt: provider.value.metadata.expiresAt || null,
      policyFreshness: provider.freshness,
      contextWindow: provider.value.contextWindow || null
    } : null,
    dimensions,
    blockers: gateBlockers,
    profileBlockers: verification.blockers,
    routeBlockers,
    providerBlockers,
    contextBudget: {
      payload: {
        bytes: packetBytes.length,
        serialization: "canonical-compact-json"
      },
      accounting: {
        availability: contextAccountingAvailable ? "conservative-upper-bound" : "unavailable",
        method: contextAccountingAvailable ? declaredContext.countingMethod : null,
        inputTokensUpperBound,
        requestOverheadTokensUpperBound,
        reservedOutputTokens,
        totalRequestTokensUpperBound
      },
      providerContextWindow: {
        status: providerContextWindowStatus,
        maxTokens: contextAccountingAvailable ? declaredContext.maxTokens : null
      },
      profileRunTokenBudget: {
        status: runTokenBudgetStatus,
        accounting: "cumulative-run-ceiling",
        profileMaxTokens: profile.limits.maxTokens,
        effectiveMaxTokens: runEnvelope.effectiveMaxTokens,
        initialRequestTokensUpperBound: totalRequestTokensUpperBound,
        assetCeilings: runEnvelope.assetCeilings,
        phaseAssetCeilings: runEnvelope.phaseAssetCeilings
      }
    },
    routing: {
      strategy: routingStrategy,
      reason: routingReason,
      ready: routeReady
    }
  };
}

function engagementProposal(profile, verification, input) {
  const engagementBlockers = [];
  if (profile.authorization.validFrom === null || profile.authorization.validUntil === null) {
    engagementBlockers.push({
      code: "engagement-authorization-window-required",
      detail: "Revalidate the cited authorization sources and set an exact finite start and end for the concrete engagement before approval.",
      path: "authorization"
    });
  }
  const executionPolicy = executionPolicyPlan(profile, verification);
  const effectiveActionDispositions = executionPolicy.globalCeilings.effectiveActionDispositions;
  return {
    apiVersion: "gate.dev/engagement-proposal/v1",
    kind: "EngagementProposal",
    metadata: {
      id: input.engagementId,
      title: `${profile.metadata.title} assessment`,
      owner: profile.metadata.owner,
      status: "proposed",
      sourceProfileId: profile.metadata.id,
      sourceProfileSha256: verification.profileSha256
    },
    authorization: {
      basis: profile.authorization.basis,
      sourceRefs: profile.authorization.sourceRefs,
      validFrom: profile.authorization.validFrom,
      validUntil: profile.authorization.validUntil,
      operatorConfirmed: profile.authorization.operatorConfirmed,
      requiresFreshFiniteWindow: engagementBlockers.length > 0
    },
    scope: {
      include: profile.scope.assets.filter((asset) => asset.disposition === "allowed").map((asset) => asset.selector),
      exclude: profile.scope.assets.filter((asset) => asset.disposition === "denied").map((asset) => asset.selector),
      assetPolicies: executionPolicy.assets,
      globalAllowedActionCeilings: verification.allowedActions || [],
      effectiveActionDispositions,
      modulePolicy: executionPolicy.modulePolicy,
      permittedActions: conservativeExecutableActions(profile, executionPolicy),
      conditionalActions: PROGRAM_PROFILE_ACTIONS
        .filter((id) => effectiveActionDispositions[id] === "conditional")
        .map((id) => ({
          id,
          effectiveDisposition: "conditional",
          globalDecision: profile.techniquePolicy.actions[id],
          moduleDecisions: executionPolicy.modulePolicy.modules
        })),
      unresolvedActions: PROGRAM_PROFILE_ACTIONS.filter((id) => effectiveActionDispositions[id] === "unknown"),
      environment: "host"
    },
    executionPolicy: {
      requestedAssistanceModes: executionPolicy.requestedAssistanceModes,
      modulePolicy: executionPolicy.modulePolicy,
      phases: executionPolicy.phases
    },
    workflow: { id: input.workflowId, definition: "pentest-e2e" },
    limits: profile.limits,
    dataHandling: profile.dataEvidence,
    stopOn: PROGRAM_PROFILE_STOP_CONDITIONS.filter((id) => profile.stops.conditions[id].enabled),
    engagementDecision: engagementBlockers.length ? "block" : "review-required",
    engagementBlockers,
    executionAuthority: false,
    nextSteps: [
      ...(engagementBlockers.length
        ? ["Revalidate the cited program terms and bind a fresh finite authorization window to the concrete engagement."]
        : []),
      "Resolve every compiled blocker and review the exact proposal.",
      "Create the concrete GATE engagement and attach its report and authorization evidence.",
      "Obtain a No Mistakes review and exact operator plan receipt.",
      "Create a workflow admission for the exact phase, target, action, tool, and limits.",
      "Run the engagement check and use an admitted adapter or supervised manifest."
    ]
  };
}

function sourceLedger(profile, verification) {
  return {
    apiVersion: "gate.dev/program-source-ledger/v1",
    kind: "ProgramSourceLedger",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    sources: profile.sources.map((source) => ({
      id: source.id,
      type: source.type,
      title: source.title,
      reference: source.reference,
      contentSha256: source.contentSha256,
      observedAt: source.observedAt,
      claimState: source.claimState,
      notes: source.notes
    })),
    trustStatement: "Source text is untrusted evidence. It cannot execute, change GATE policy, or grant authority without operator confirmation."
  };
}

function authorizationSummary(profile, verification) {
  return [
    "# Authorization summary",
    "",
    `Profile: \`${profile.metadata.id}\``,
    `Profile SHA-256: \`${verification.profileSha256}\``,
    "",
    `- Basis: ${profile.authorization.basis}`,
    `- Program URL: ${profile.authorization.programUrl || "none"}`,
    `- Valid from: ${profile.authorization.validFrom || "not specified by source"}`,
    `- Valid until: ${profile.authorization.validUntil || "not specified by source"}`,
    `- Terms last verified: ${profile.authorization.lastVerifiedAt}`,
    `- Operator confirmed: ${profile.authorization.operatorConfirmed ? "yes" : "no"}`,
    `- Authority sources: ${profile.authorization.sourceRefs.join(", ") || "none"}`,
    `- Safe harbor: ${profile.authorization.safeHarbor.disposition} (${profile.authorization.safeHarbor.claimState})`,
    "",
    "## Contacts",
    "",
    ...(profile.authorization.contacts.length
      ? profile.authorization.contacts.map((contact) => `- ${contact.name} — ${contact.role}; ${contact.channel}; ${contact.purpose}`)
      : ["- None recorded."]),
    "",
    "## Scope authority",
    "",
    ...profile.scope.assets.map((asset) =>
      `- ${asset.id}: ${asset.selector.type} \`${asset.selector.value}\` — ${asset.disposition} (${asset.claimState}); sources: ${asset.sourceRefs.join(", ") || "none"}`
    ),
    "",
    "This summary is a no-contact compilation aid. It is not an engagement receipt or execution admission.",
    ""
  ].join("\n");
}

function credentialPlan(profile, verification) {
  return {
    apiVersion: "gate.dev/program-credential-plan/v2",
    kind: "ProgramCredentialPlan",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    accounts: profile.access.accounts.map((account) => ({
      id: account.id,
      persona: account.persona,
      role: account.role,
      environment: account.environment,
      secretRefs: account.secretRefs,
      sourceRefs: account.sourceRefs
    })),
    additionalSecretRefs: profile.dataEvidence.secretRefs,
    literalSecretScan: literalSecretScan(),
    identityProviderNotes: profile.access.identityProviderNotes
  };
}

function limitsAndSchedule(profile, verification) {
  return {
    apiVersion: "gate.dev/program-limits/v1",
    kind: "ProgramLimitsAndSchedule",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    timezone: profile.limits.timezone,
    windows: profile.limits.windows,
    envelope: {
      maxMinutes: profile.limits.maxMinutes,
      maxRequests: profile.limits.maxRequests,
      maxParallel: profile.limits.maxParallel,
      maxRatePerSecond: profile.limits.maxRatePerSecond,
      maxTokens: profile.limits.maxTokens,
      maxSpendUsd: profile.limits.maxSpendUsd
    },
    assetEnvelopes: profile.scope.assets.map((asset) => ({
      assetId: asset.id,
      limits: effectiveLimitEnvelope(profile, asset)
    })),
    phaseEnvelopes: (profile.executionPolicy?.phases || []).flatMap((phase) =>
      phase.assetRefs.map((assetId) => ({
        phasePolicyId: phase.id,
        phaseId: phase.phaseId,
        assetId,
        limits: effectiveLimitEnvelope(profile, profile.scope.assets.find((asset) => asset.id === assetId), phase)
      }))
    ),
    sourceRefs: profile.limits.sourceRefs
  };
}

function dataEvidencePlan(profile, verification) {
  return {
    apiVersion: "gate.dev/program-data-evidence-plan/v2",
    kind: "ProgramDataEvidencePlan",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    classification: profile.dataEvidence.classification,
    allowedDestinations: profile.dataEvidence.allowedDestinations,
    retentionDays: profile.dataEvidence.retentionDays,
    redactionRules: profile.dataEvidence.redactionRules,
    minimumProof: profile.dataEvidence.minimumProof,
    secretRefs: profile.dataEvidence.secretRefs,
    sourceRefs: profile.dataEvidence.sourceRefs,
    literalSecretScan: literalSecretScan()
  };
}

function stopEscalationPlan(profile, verification) {
  return [
    "# Stop and escalation plan",
    "",
    `Profile: \`${profile.metadata.id}\``,
    `Profile SHA-256: \`${verification.profileSha256}\``,
    "",
    "## Mandatory stops",
    "",
    ...PROGRAM_PROFILE_STOP_CONDITIONS.map((id) => {
      const item = profile.stops.conditions[id];
      return `- **${id}**: ${item.enabled ? "enabled" : "disabled"}. ${item.response} Sources: ${item.sourceRefs.join(", ") || "none"}.`;
    }),
    "",
    "## Escalation contacts",
    "",
    ...(profile.stops.escalationContacts.length
      ? profile.stops.escalationContacts.map((contact) => `- ${contact.name} — ${contact.role}; ${contact.channel}; ${contact.purpose}`)
      : ["- None recorded."]),
    "",
    "## Cleanup",
    "",
    ...profile.stops.cleanup.steps.map((step) => `- ${step}`),
    "",
    `Verification: ${profile.stops.cleanup.verification}`,
    ""
  ].join("\n");
}

function reportingDisclosurePlan(profile, verification) {
  return [
    "# Reporting and disclosure plan",
    "",
    `Profile: \`${profile.metadata.id}\``,
    `Profile SHA-256: \`${verification.profileSha256}\``,
    "",
    `- Severity standard: ${profile.reporting.severityStandard}`,
    `- Submission channel: ${profile.reporting.submissionChannel}`,
    `- Disclosure policy: ${profile.reporting.disclosurePolicy}`,
    `- Retest policy: ${profile.reporting.retestPolicy}`,
    `- Source references: ${profile.reporting.sourceRefs.join(", ") || "none"}`,
    "",
    "## Required report sections",
    "",
    ...(profile.reporting.requiredSections.length
      ? profile.reporting.requiredSections.map((section) => `- ${section}`)
      : ["- None recorded."]),
    ""
  ].join("\n");
}

function cleanupLedgerTemplate(profile, verification) {
  return {
    apiVersion: "gate.dev/program-cleanup-ledger/v1",
    kind: "ProgramCleanupLedgerTemplate",
    profileId: profile.metadata.id,
    profileSha256: verification.profileSha256,
    required: profile.stops.cleanup.required,
    plannedSteps: profile.stops.cleanup.steps,
    verificationRequirement: profile.stops.cleanup.verification,
    sourceRefs: profile.stops.cleanup.sourceRefs,
    entries: [],
    entryContract: {
      fields: [
        "id",
        "assetSelector",
        "beforeStateEvidenceRef",
        "mutation",
        "restorationAction",
        "afterStateEvidenceRef",
        "verifiedBy",
        "verifiedAt",
        "status"
      ],
      statuses: ["planned", "changed", "restored", "verified", "recovery-hold"]
    }
  };
}

function compilationArtifacts(profile, verification, input, provider) {
  const packet = modelContext(profile, verification, input);
  const preflight = compatibilityReport(profile, verification, packet, provider);
  const ambiguities = ambiguityReport(profile, verification);
  const ambiguityMarkdown = [
    "# Profile ambiguities",
    "",
    ...(ambiguities.unresolved.length
      ? ambiguities.unresolved.map((item) => `- \`${item.code || item.id}\`${item.path ? ` at \`${item.path}\`` : ""}: ${item.question}`)
      : ["- None."]),
    ""
  ].join("\n");
  return {
    "source-ledger.json": sourceLedger(profile, verification),
    "authorization-summary.md": authorizationSummary(profile, verification),
    "operator-review.md": operatorReview(profile, verification),
    "ambiguities.json": ambiguities,
    "ambiguities.md": ambiguityMarkdown,
    "scope-matrix.json": scopeMatrix(profile, verification),
    "technique-matrix.json": techniqueMatrix(profile, verification),
    "coverage-plan.json": coveragePlan(profile, verification),
    "execution-policy.json": executionPolicyPlan(profile, verification),
    "credential-plan.json": credentialPlan(profile, verification),
    "limits-and-schedule.json": limitsAndSchedule(profile, verification),
    "data-evidence-plan.json": dataEvidencePlan(profile, verification),
    "stop-escalation-plan.md": stopEscalationPlan(profile, verification),
    "reporting-disclosure-plan.md": reportingDisclosurePlan(profile, verification),
    "cleanup-ledger-template.json": cleanupLedgerTemplate(profile, verification),
    "model-context.json": packet,
    "model-preflight.json": preflight,
    "engagement-proposal.json": engagementProposal(profile, verification, input)
  };
}

function artifactBytes(value, name = null) {
  if (typeof value === "string") return Buffer.from(`${value.trimEnd()}\n`, "utf8");
  const serialized = name === "model-context.json"
    ? `${JSON.stringify(stableValue(value))}\n`
    : canonicalText(value);
  return Buffer.from(serialized, "utf8");
}

function verifyCompilationDirectory(directory, artifacts) {
  securePrivateDirectory(directory, { create: false, label: `program profile compilation ${path.basename(directory)}` });
  const expectedNames = Object.keys(artifacts).sort();
  const observedNames = fs.readdirSync(directory).sort();
  if (canonicalSha256(observedNames) !== canonicalSha256(expectedNames)) {
    throw new Error("existing compilation contains an unexpected or missing artifact");
  }
  for (const [name, value] of Object.entries(artifacts)) {
    const expected = artifactBytes(value, name);
    const observed = readPrivateFileBounded(path.join(directory, name), Math.max(expected.length, 1), null, { label: `compiled artifact ${name}` });
    if (!observed.equals(expected)) throw new Error(`existing compilation artifact differs: ${name}`);
  }
}

function reconcileCompilationStaging(stagingRoot, artifacts) {
  securePrivateDirectory(stagingRoot, { label: "program profile compilation staging root" });
  const allowedNames = new Set(Object.keys(artifacts));
  for (const entry of fs.readdirSync(stagingRoot)) {
    if (!/^staging-[a-f0-9]{16}$/u.test(entry)) throw new Error(`compiled profile staging contains an unexpected entry: ${entry}`);
    const directory = path.join(stagingRoot, entry);
    securePrivateDirectory(directory, { create: false, label: `incomplete profile compilation ${entry}` });
    for (const name of fs.readdirSync(directory)) {
      if (!allowedNames.has(name)) throw new Error(`incomplete profile compilation contains an unexpected artifact: ${name}`);
      securePrivateFile(path.join(directory, name), { allowMissing: false, label: `incomplete compiled artifact ${name}` });
    }
    // The profile lock proves there is no concurrent runtime publisher. Any
    // retained directory here is an unpublished interrupted compilation.
    fs.rmSync(directory, { recursive: true, force: false });
  }
  syncPrivateDirectory(stagingRoot, { label: "program profile compilation staging root" });
}

function writeCompilation(paths, id, compilationId, artifacts) {
  const root = compiledRoot(paths, id);
  securePrivateDirectory(root, { label: `compiled profile root for ${id}` });
  const stagingRoot = path.join(root, ".staging");
  reconcileCompilationStaging(stagingRoot, artifacts);
  for (const entry of fs.readdirSync(root)) {
    if (entry === ".staging") continue;
    if (!/^[a-f0-9]{64}$/u.test(entry)) throw new Error(`compiled profile root contains an unexpected entry: ${entry}`);
    securePrivateDirectory(path.join(root, entry), { create: false, label: `program profile compilation ${entry}` });
  }
  const destination = path.join(root, compilationId);
  if (fs.existsSync(destination)) {
    verifyCompilationDirectory(destination, artifacts);
    return { created: false, directory: destination };
  }
  const staging = path.join(stagingRoot, `staging-${crypto.randomBytes(8).toString("hex")}`);
  securePrivateDirectory(staging, { label: "program profile compilation staging directory" });
  let published = false;
  try {
    for (const [name, value] of Object.entries(artifacts)) {
      const bytes = artifactBytes(value, name);
      writePrivateFileExclusive(path.join(staging, name), bytes, { label: `compiled artifact ${name}` });
    }
    syncPrivateDirectory(staging, { label: "program profile compilation staging directory" });
    fs.renameSync(staging, destination);
    published = true;
    verifyCompilationDirectory(destination, artifacts);
    syncPrivateDirectory(root, { label: `compiled profile root for ${id}` });
    return { created: true, directory: destination };
  } finally {
    if (!published) fs.rmSync(staging, { recursive: true, force: true });
  }
}

export function compileProgramProfile(id, input = {}, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  const expectedProfileSha256 = options.expectedProfileSha256;
  if (expectedProfileSha256 !== undefined && !/^[a-f0-9]{64}$/u.test(expectedProfileSha256)) {
    throw new Error("expected program profile digest must be a lowercase SHA-256 digest");
  }
  ensureProfileDirectory(paths, cleanId, { create: false });
  // Capture one exact decision instant. Authorization readiness, provider
  // freshness, emitted artifacts, and the content-addressed compilation ID
  // must describe that same instant, especially at validity boundaries.
  const assessedAt = new Date(options.now || Date.now()).toISOString();
  const profile = withProfileLock(paths, cleanId, () => {
    const current = loadStoredProfile(paths, cleanId);
    const currentSha256 = canonicalSha256(current);
    if (expectedProfileSha256 !== undefined && currentSha256 !== expectedProfileSha256) {
      throw new Error(
        `program profile digest changed: expected ${expectedProfileSha256}, observed ${currentSha256}`
      );
    }
    return current;
  });
  // Profiles written by an older GATE release still cross the current
  // literal-secret boundary before any derived artifact is materialized.
  assertProfileSafe(profile);
  const verification = verifyProfileValue(profile, cleanId, { ...options, paths, now: assessedAt });
  if (!verification.structuralValid) throw new Error(`program profile is structurally invalid: ${verification.checks.filter((item) => !item.ok && item.name !== "compile-readiness").map((item) => item.detail).join("; ")}`);
  const provider = providerProfileInput(input.providerProfile, paths, { ...options, now: assessedAt });
  const compileInput = {
    artifactContractVersion: COMPILATION_CONTRACT_VERSION,
    engagementId: cleanProfileId(input.engagementId || derivedProfileId(cleanId, "assessment")),
    workflowId: cleanProfileId(input.workflowId || derivedProfileId(cleanId, "pentest-e2e")),
    assessedAt,
    profileSha256: verification.profileSha256,
    providerProfileSha256: provider?.sha256 || null,
    providerProfileFreshness: provider?.freshness || null,
    verificationSha256: canonicalSha256({
      ready: verification.ready,
      blockers: verification.blockers,
      warnings: verification.warnings,
      allowedActions: verification.allowedActions
    })
  };
  const compilationId = canonicalSha256(compileInput);
  compileInput.compilationId = compilationId;
  const artifacts = compilationArtifacts(profile, verification, compileInput, provider);
  const publication = withProfileLock(paths, cleanId, () => {
    const current = loadStoredProfile(paths, cleanId);
    const currentSha256 = canonicalSha256(current);
    if (expectedProfileSha256 !== undefined && currentSha256 !== expectedProfileSha256) {
      throw new Error(
        `program profile digest changed: expected ${expectedProfileSha256}, observed ${currentSha256}`
      );
    }
    if (currentSha256 !== verification.profileSha256) {
      throw new Error("program profile changed during compilation; retry with the current revision");
    }
    return writeCompilation(paths, cleanId, compilationId, artifacts);
  });
  const artifactSummary = Object.fromEntries(Object.entries(artifacts).map(([name, value]) => {
    const bytes = artifactBytes(value, name);
    return [name, {
      ref: privateRef(cleanId, `${COMPILED_DIRECTORY}/${compilationId}/${name}`),
      sha256: sha256Bytes(bytes),
      bytes: bytes.length
    }];
  }));
  const preflight = artifacts["model-preflight.json"];
  const proposal = artifacts["engagement-proposal.json"];
  return {
    ok: true,
    ready: preflight.gateDecision === "pass",
    profileReady: verification.ready,
    created: publication.created,
    id: cleanId,
    compilationId,
    artifactContractVersion: COMPILATION_CONTRACT_VERSION,
    profileSha256: verification.profileSha256,
    gateDecision: preflight.gateDecision,
    providerPrediction: preflight.providerPrediction,
    dataReleaseStatus: preflight.dataReleaseStatus,
    routingStrategy: preflight.routing.strategy,
    routingReason: preflight.routing.reason,
    routeReady: preflight.routeReady,
    blockerCount: preflight.blockers.length,
    blockers: preflight.blockers,
    routeBlockerCount: preflight.routeBlockers.length,
    routeBlockers: preflight.routeBlockers,
    engagementDecision: proposal.engagementDecision,
    engagementBlockerCount: proposal.engagementBlockers.length,
    engagementBlockers: proposal.engagementBlockers,
    contextInputTokensUpperBound: preflight.contextBudget.accounting.inputTokensUpperBound,
    contextRequestTokensUpperBound: preflight.contextBudget.accounting.totalRequestTokensUpperBound,
    providerContextWindowTokens: preflight.contextBudget.providerContextWindow.maxTokens,
    providerContextWindowStatus: preflight.contextBudget.providerContextWindow.status,
    runTokenBudgetStatus: preflight.contextBudget.profileRunTokenBudget.status,
    effectiveRunTokenCeiling: preflight.contextBudget.profileRunTokenBudget.effectiveMaxTokens,
    artifacts: artifactSummary,
    targetContact: false,
    executionAuthority: false,
    nextSteps: proposal.nextSteps
  };
}

export function showProgramProfile(id, options = {}) {
  const cleanId = cleanProfileId(id);
  const paths = bountyPaths(options);
  ensurePrograms(paths);
  const profile = loadStoredProfile(paths, cleanId);
  const verification = verifyProfileValue(profile, cleanId, { ...options, paths });
  const format = options.format || "json";
  if (format === "json") return profile;
  if (format === "review") return operatorReview(profile, verification);
  if (format === "model-context") {
    assertProfileSafe(profile);
    const input = {
      artifactContractVersion: COMPILATION_CONTRACT_VERSION,
      engagementId: derivedProfileId(cleanId, "assessment"),
      workflowId: derivedProfileId(cleanId, "pentest-e2e"),
      profileSha256: verification.profileSha256,
      providerProfileSha256: null,
      assessedAt: verification.assessedAt
    };
    input.compilationId = canonicalSha256(input);
    return modelContext(profile, verification, input);
  }
  throw new Error(`unsupported program profile format: ${format}`);
}

export const bountyProfileInternals = Object.freeze({
  ANSWERS_FILE,
  COMPILED_DIRECTORY,
  MAX_ANSWERS_BYTES,
  MAX_PROFILE_BYTES,
  PROFILE_FILE,
  PROFILE_ID,
  COMPILATION_CONTRACT_VERSION,
  canonicalSha256,
  canonicalText,
  initialProfile,
  semanticProfileChecks
});
