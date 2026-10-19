#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { createOidcVerifier } from "./auth.mjs";
import { startRemoteCockpitServer } from "./server.mjs";
import { RemoteBridgeStore } from "./store.mjs";

const CONFIG_VERSION = "gate.remote-server-config/v1";
const MAX_CONFIG_BYTES = 32 * 1024;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;

function usage() {
  return `Usage: node cockpit/remote/server-cli.mjs --config ABSOLUTE_PATH

The config path may instead be supplied through GATE_REMOTE_CONFIG. The config
and runner public-key files must either be current-user owner-only files for local
use or protected root-owned files readable but not writable by this
service. Their path ancestors must not be writable by other users except for an
owner-protecting sticky directory. The database remains current-user owner-only.
`;
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, required, optional = []) {
  if (!record(value)) return false;
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

function parseArguments(argv, environment = process.env) {
  let configured = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help") return Object.freeze({ help: true });
    if (argument !== "--config" || configured !== null) throw new Error("Use exactly one --config option.");
    configured = argv[++index];
    if (!configured) throw new Error("--config requires an absolute path.");
  }
  const fromEnvironment = typeof environment.GATE_REMOTE_CONFIG === "string"
    ? environment.GATE_REMOTE_CONFIG.trim() : "";
  if (configured && fromEnvironment && configured !== fromEnvironment) {
    throw new Error("--config and GATE_REMOTE_CONFIG must not disagree.");
  }
  const selected = configured || fromEnvironment;
  if (!selected || !path.isAbsolute(selected) || path.normalize(selected) !== selected || selected.includes("\0")) {
    throw new Error("An absolute normalized remote config path is required.");
  }
  return Object.freeze({ help: false, configPath: selected });
}

function currentIdentity() {
  if (typeof process.getuid !== "function") return Object.freeze({ uid: null, gids: new Set(), actual: true });
  const gids = new Set((typeof process.getgroups === "function" ? process.getgroups() : []).map(BigInt));
  if (typeof process.getgid === "function") gids.add(BigInt(process.getgid()));
  return Object.freeze({ uid: BigInt(process.getuid()), gids, actual: true });
}

function identityCanWrite(stat, identity) {
  if (identity.uid === null) return false;
  if (identity.uid === 0n) return true;
  if (stat.uid === identity.uid) return (stat.mode & 0o200n) !== 0n;
  if (identity.gids.has(stat.gid)) return (stat.mode & 0o020n) !== 0n;
  return (stat.mode & 0o002n) !== 0n;
}

function assertProtectedStaticFile(stat, label, identity) {
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a protected regular file.`);
  }
  if (identity.uid === null || stat.uid === identity.uid) {
    if ((stat.mode & 0o077n) !== 0n) throw new Error(`${label} must be an owner-only regular file.`);
    return "current-user";
  }
  const groupReadable = identity.gids.has(stat.gid) && (stat.mode & 0o040n) !== 0n;
  if (stat.uid !== 0n || !groupReadable || (stat.mode & 0o037n) !== 0n || identityCanWrite(stat, identity)) {
    throw new Error(`${label} must be root-owned, group-readable, and not writable by the current user.`);
  }
  return "administrator";
}

function assertProtectedAncestors(filename, label, options = {}) {
  let child = filename;
  let directory = path.dirname(filename);
  const identity = options.identity || currentIdentity();
  while (true) {
    const stat = fs.lstatSync(directory, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} path ancestors must be real directories.`);
    if ((stat.mode & 0o022n) !== 0n) {
      const childStat = fs.lstatSync(child, { bigint: true });
      const stickyProtectsChild = (stat.mode & 0o1000n) !== 0n
        && identity.uid !== null && childStat.uid === identity.uid;
      if (!stickyProtectsChild) throw new Error(`${label} path ancestors must not be writable by other users.`);
    }
    if (options.denyCurrentIdentityWrites && identityCanWrite(stat, identity)) {
      throw new Error(`${label} path ancestors must not be writable by the current user.`);
    }
    if (options.denyCurrentIdentityWrites && identity.actual) {
      let writable = false;
      try {
        fs.accessSync(directory, fs.constants.W_OK);
        writable = true;
      } catch (error) {
        if (error?.code !== "EACCES" && error?.code !== "EPERM") throw error;
      }
      if (writable) throw new Error(`${label} path ancestors must not be writable by the current user.`);
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    child = directory;
    directory = parent;
  }
}

function readStableOwnerFile(filename, maximumBytes, label, options = {}) {
  const identity = options.identity || currentIdentity();
  assertProtectedAncestors(filename, label, { identity });
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error(`${label} requires no-follow file opens.`);
  let descriptor;
  try {
    descriptor = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor, { bigint: true });
    const ownership = assertProtectedStaticFile(before, label, identity);
    if (options.expectedOwnership !== undefined && ownership !== options.expectedOwnership) {
      throw new Error(`${label} must use the same protected ownership class as the remote config.`);
    }
    if (ownership === "administrator") {
      assertProtectedAncestors(filename, label, { identity, denyCurrentIdentityWrites: true });
      if (identity.actual) {
        let writable = false;
        try {
          fs.accessSync(filename, fs.constants.W_OK);
          writable = true;
        } catch (error) {
          if (error?.code !== "EACCES" && error?.code !== "EPERM") throw error;
        }
        if (writable) throw new Error(`${label} must not be writable by the current user.`);
      }
    }
    if (before.size < 1n || before.size > BigInt(maximumBytes)) throw new Error(`${label} has an invalid size.`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const afterOwnership = assertProtectedStaticFile(after, label, identity);
    const pathAfter = fs.lstatSync(filename, { bigint: true });
    const pathAfterOwnership = assertProtectedStaticFile(pathAfter, label, identity);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mode !== after.mode || before.uid !== after.uid || before.gid !== after.gid
        || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
        || after.size !== BigInt(bytes.length) || ownership !== afterOwnership
        || ownership !== pathAfterOwnership
        || pathAfter.dev !== after.dev || pathAfter.ino !== after.ino || pathAfter.size !== after.size
        || pathAfter.mode !== after.mode || pathAfter.uid !== after.uid || pathAfter.gid !== after.gid
        || pathAfter.mtimeNs !== after.mtimeNs || pathAfter.ctimeNs !== after.ctimeNs) {
      throw new Error(`${label} changed while it was read.`);
    }
    return options.includeOwnership ? Object.freeze({ bytes, ownership }) : bytes;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function absolutePath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || path.normalize(value) !== value || value.includes("\0")) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  return value;
}

function readConfiguration(filename, options = {}) {
  let value;
  let ownership;
  try {
    const loaded = readStableOwnerFile(filename, MAX_CONFIG_BYTES, "Remote config", {
      ...options,
      includeOwnership: true
    });
    ownership = loaded.ownership;
    value = JSON.parse(loaded.bytes.toString("utf8"));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("Remote config must contain valid JSON.");
    throw error;
  }
  if (!exactKeys(value, [
    "apiVersion", "origin", "host", "port", "operatorId", "caseId", "sessionRevision", "databasePath", "oidc", "runner"
  ], ["identityAssertionHeader"]) || value.apiVersion !== CONFIG_VERSION
      || !exactKeys(value.runner, ["id", "publicKeyPath"])
      || !exactKeys(value.oidc, ["issuer", "audience", "operatorSubject", "jwksUrl"],
        ["clockSkewSeconds", "maxTokenLifetimeSeconds", "jwksCacheMs", "jwksTimeoutMs"])) {
    throw new Error("Remote config does not match the reviewed configuration shape.");
  }
  if (value.host !== "127.0.0.1" && value.host !== "::1") {
    throw new Error("Remote server host must be an explicit loopback address.");
  }
  if (!Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65_535) {
    throw new Error("Remote server port must be an integer from 1 through 65535.");
  }
  if (value.oidc.operatorSubject !== value.operatorId) {
    throw new Error("OIDC operator subject must equal the configured operator identity.");
  }
  if (typeof value.runner.id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u.test(value.runner.id)) {
    throw new Error("Runner identity is invalid.");
  }
  absolutePath(value.databasePath, "Remote database path");
  absolutePath(value.runner.publicKeyPath, "Runner public-key path");
  const configuration = Object.freeze(value);
  return options.includeOwnership
    ? Object.freeze({ configuration, ownership })
    : configuration;
}

function loadRunnerPublicKey(filename, options = {}) {
  const pem = readStableOwnerFile(filename, MAX_PUBLIC_KEY_BYTES, "Runner public key", options).toString("utf8");
  let key;
  try {
    key = crypto.createPublicKey(pem);
  } catch {
    throw new Error("Runner public key is invalid.");
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new Error("Runner public key must be Ed25519.");
  }
  return key;
}

function startupDiagnostic(error) {
  if (typeof error?.publicMessage === "string") return error.publicMessage;
  if (typeof error?.code === "string") return "A required protected file, owner-only database, or listener is unavailable.";
  if (error instanceof TypeError) return error.message;
  const message = typeof error?.message === "string" ? error.message : "Remote service startup failed.";
  return message.includes("/") || message.includes("\\") ? "Remote service startup failed." : message;
}

async function main() {
  let selected;
  try {
    selected = parseArguments(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${usage()}`);
    process.exitCode = 2;
    return;
  }
  if (selected.help) {
    process.stdout.write(usage());
    return;
  }

  let store;
  let server;
  try {
    const loadedConfig = readConfiguration(selected.configPath, { includeOwnership: true });
    const config = loadedConfig.configuration;
    const runnerPublicKey = loadRunnerPublicKey(config.runner.publicKeyPath, {
      expectedOwnership: loadedConfig.ownership
    });
    store = new RemoteBridgeStore({ databasePath: config.databasePath });
    if (typeof store.runnerNonceStore !== "function") {
      throw new Error("The durable runner nonce store is unavailable.");
    }
    const oidcVerifier = createOidcVerifier(config.oidc);
    server = await startRemoteCockpitServer({
      origin: config.origin,
      host: config.host,
      port: config.port,
      operatorId: config.operatorId,
      caseId: config.caseId,
      sessionRevision: config.sessionRevision,
      store,
      oidcVerifier,
      runnerPublicKeys: new Map([[config.runner.id, runnerPublicKey]]),
      runnerNonceStore: store.runnerNonceStore(),
      ...(config.identityAssertionHeader === undefined ? {} : { identityAssertionHeader: config.identityAssertionHeader }),
      closeStore: true
    });
  } catch (error) {
    try { store?.close(); } catch {}
    process.stderr.write(`GATE remote cockpit did not start: ${startupDiagnostic(error)}\n`);
    process.exitCode = 1;
    return;
  }

  process.stdout.write(`GATE remote cockpit ready on ${server.host}:${server.port} behind the configured HTTPS identity gateway.\n`);
  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    await server.close().catch(() => {});
  };
  process.once("SIGINT", () => close().then(() => process.exit(0)));
  process.once("SIGTERM", () => close().then(() => process.exit(0)));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();

export const serverCliInternals = Object.freeze({
  CONFIG_VERSION,
  assertProtectedAncestors,
  assertProtectedStaticFile,
  loadRunnerPublicKey,
  parseArguments,
  readConfiguration,
  readStableOwnerFile,
  startupDiagnostic,
  usage
});
