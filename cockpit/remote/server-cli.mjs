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

The config path may instead be supplied through GATE_REMOTE_CONFIG. The file,
runner public-key file, and database must be owner-only. Their path ancestors
must not be writable by other users except for an owner-protecting sticky directory.
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

function assertOwnerOnly(stat, label) {
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077n) !== 0n) {
    throw new Error(`${label} must be an owner-only regular file.`);
  }
  if (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())) {
    throw new Error(`${label} must be owned by the current user.`);
  }
}

function assertProtectedAncestors(filename, label) {
  let child = filename;
  let directory = path.dirname(filename);
  const currentUid = typeof process.getuid === "function" ? BigInt(process.getuid()) : null;
  while (true) {
    const stat = fs.lstatSync(directory, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} path ancestors must be real directories.`);
    if ((stat.mode & 0o022n) !== 0n) {
      const childStat = fs.lstatSync(child, { bigint: true });
      const stickyProtectsChild = (stat.mode & 0o1000n) !== 0n
        && currentUid !== null && childStat.uid === currentUid;
      if (!stickyProtectsChild) throw new Error(`${label} path ancestors must not be writable by other users.`);
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    child = directory;
    directory = parent;
  }
}

function readStableOwnerFile(filename, maximumBytes, label) {
  assertProtectedAncestors(filename, label);
  if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error(`${label} requires no-follow file opens.`);
  let descriptor;
  try {
    descriptor = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor, { bigint: true });
    assertOwnerOnly(before, label);
    if (before.size < 1n || before.size > BigInt(maximumBytes)) throw new Error(`${label} has an invalid size.`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    assertOwnerOnly(after, label);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mtimeNs !== after.mtimeNs || after.size !== BigInt(bytes.length)) {
      throw new Error(`${label} changed while it was read.`);
    }
    return bytes;
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

function readConfiguration(filename) {
  let value;
  try {
    value = JSON.parse(readStableOwnerFile(filename, MAX_CONFIG_BYTES, "Remote config").toString("utf8"));
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
  return Object.freeze(value);
}

function loadRunnerPublicKey(filename) {
  const pem = readStableOwnerFile(filename, MAX_PUBLIC_KEY_BYTES, "Runner public key").toString("utf8");
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
  if (typeof error?.code === "string") return "A required owner-only file, database, or listener is unavailable.";
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
    const config = readConfiguration(selected.configPath);
    const runnerPublicKey = loadRunnerPublicKey(config.runner.publicKeyPath);
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
  loadRunnerPublicKey,
  parseArguments,
  readConfiguration,
  readStableOwnerFile,
  startupDiagnostic,
  usage
});
