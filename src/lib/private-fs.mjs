import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const PRIVATE_DIRECTORY_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;

const usesPosixPermissions = process.platform !== "win32";
const noFollow = fs.constants.O_NOFOLLOW || 0;
const nonBlocking = fs.constants.O_NONBLOCK || 0;
const directoryOnly = fs.constants.O_DIRECTORY || 0;

function lstatIfPresent(file) {
  try {
    return fs.lstatSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function privateFlags(flags) {
  if (usesPosixPermissions && !fs.constants.O_NOFOLLOW) {
    throw new Error("this platform cannot enforce no-follow private file access");
  }
  return flags | noFollow;
}

function assertCurrentOwner(stat, label) {
  if (usesPosixPermissions && typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
    throw new Error(`${label} is not owned by the current user`);
  }
}

function assertDirectoryStat(stat, label) {
  if (stat.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
  if (!stat.isDirectory()) throw new Error(`${label} must be a directory`);
  assertCurrentOwner(stat, label);
}

function assertFileStat(stat, label) {
  if (stat.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
  if (!stat.isFile()) throw new Error(`${label} must be a regular file`);
  if (stat.nlink !== 1) throw new Error(`${label} must not have multiple hard links`);
  assertCurrentOwner(stat, label);
}

function verifyPathStillNames(file, openedStat, validator, label) {
  const finalStat = fs.lstatSync(file);
  validator(finalStat, label);
  if (!sameFile(finalStat, openedStat)) throw new Error(`${label} changed while it was being verified`);
}

/**
 * Create or validate one private directory without following a leaf symlink.
 * POSIX mode bits have no ACL-equivalent meaning on Windows, so Windows still
 * verifies type and stable identity while leaving access control to the user's
 * profile ACL. POSIX directories are owned by the caller and exactly 0700.
 */
export function securePrivateDirectory(directory, options = {}) {
  const resolved = path.resolve(directory);
  const label = options.label || `private directory ${resolved}`;
  let before = lstatIfPresent(resolved);
  if (!before) {
    if (options.create === false) throw new Error(`${label} does not exist`);
    try {
      fs.mkdirSync(resolved, { mode: PRIVATE_DIRECTORY_MODE });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    before = fs.lstatSync(resolved);
  }
  assertDirectoryStat(before, label);

  if (!usesPosixPermissions) {
    verifyPathStillNames(resolved, before, assertDirectoryStat, label);
    return resolved;
  }

  let descriptor;
  try {
    descriptor = fs.openSync(resolved, privateFlags(fs.constants.O_RDONLY | directoryOnly));
  } catch (error) {
    throw new Error(`${label} could not be opened without following links: ${error.message}`, { cause: error });
  }
  try {
    let opened = fs.fstatSync(descriptor);
    assertDirectoryStat(opened, label);
    if (!sameFile(before, opened)) throw new Error(`${label} changed while it was being opened`);
    if ((opened.mode & 0o7777) !== PRIVATE_DIRECTORY_MODE) fs.fchmodSync(descriptor, PRIVATE_DIRECTORY_MODE);
    opened = fs.fstatSync(descriptor);
    assertDirectoryStat(opened, label);
    if ((opened.mode & 0o7777) !== PRIVATE_DIRECTORY_MODE) {
      throw new Error(`${label} permissions are not owner-only (expected 0700)`);
    }
    verifyPathStillNames(resolved, opened, assertDirectoryStat, label);
  } finally {
    fs.closeSync(descriptor);
  }
  return resolved;
}

function openExistingPrivateFile(file, operation, label) {
  const before = fs.lstatSync(file);
  assertFileStat(before, label);
  const access = operation === "append"
    ? fs.constants.O_WRONLY | fs.constants.O_APPEND
    : fs.constants.O_RDONLY;
  const descriptor = fs.openSync(file, privateFlags(access | nonBlocking));
  try {
    let opened = fs.fstatSync(descriptor);
    assertFileStat(opened, label);
    if (!sameFile(before, opened)) throw new Error(`${label} changed while it was being opened`);
    if (usesPosixPermissions && (opened.mode & 0o7777) !== PRIVATE_FILE_MODE) {
      fs.fchmodSync(descriptor, PRIVATE_FILE_MODE);
      opened = fs.fstatSync(descriptor);
    }
    if (usesPosixPermissions && (opened.mode & 0o7777) !== PRIVATE_FILE_MODE) {
      throw new Error(`${label} permissions are not owner-only (expected 0600)`);
    }
    verifyPathStillNames(file, opened, assertFileStat, label);
    return descriptor;
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

/** Open a stable, regular, single-link private file and remediate it to 0600. */
export function openPrivateFile(file, options = {}) {
  const resolved = path.resolve(file);
  const operation = options.operation || "read";
  const label = options.label || `private file ${resolved}`;
  if (!new Set(["read", "append"]).has(operation)) throw new Error(`unsupported private file operation: ${operation}`);

  while (true) {
    const present = lstatIfPresent(resolved);
    if (present) return openExistingPrivateFile(resolved, operation, label);
    if (!options.create) throw Object.assign(new Error(`${label} does not exist`), { code: "ENOENT" });
    if (operation !== "append") throw new Error(`${label} can only be created for append`);
    let descriptor;
    try {
      descriptor = fs.openSync(
        resolved,
        privateFlags(fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_EXCL | nonBlocking),
        PRIVATE_FILE_MODE
      );
    } catch (error) {
      if (error.code === "EEXIST") continue;
      throw error;
    }
    try {
      const opened = fs.fstatSync(descriptor);
      assertFileStat(opened, label);
      if (usesPosixPermissions && (opened.mode & 0o7777) !== PRIVATE_FILE_MODE) {
        fs.fchmodSync(descriptor, PRIVATE_FILE_MODE);
      }
      const secured = fs.fstatSync(descriptor);
      if (usesPosixPermissions && (secured.mode & 0o7777) !== PRIVATE_FILE_MODE) {
        throw new Error(`${label} permissions are not owner-only (expected 0600)`);
      }
      verifyPathStillNames(resolved, secured, assertFileStat, label);
      return descriptor;
    } catch (error) {
      fs.closeSync(descriptor);
      throw error;
    }
  }
}

export function securePrivateFile(file, options = {}) {
  const resolved = path.resolve(file);
  if (!lstatIfPresent(resolved)) {
    if (options.allowMissing !== false) return false;
    throw Object.assign(new Error(`${options.label || `private file ${resolved}`} does not exist`), { code: "ENOENT" });
  }
  const descriptor = openPrivateFile(resolved, { operation: "read", label: options.label });
  fs.closeSync(descriptor);
  return true;
}

export function readPrivateFile(file, encoding = null, options = {}) {
  const descriptor = openPrivateFile(file, { operation: "read", label: options.label });
  try {
    return fs.readFileSync(descriptor, encoding === null ? undefined : encoding);
  } finally {
    fs.closeSync(descriptor);
  }
}

export function appendPrivateFile(file, content, options = {}) {
  securePrivateDirectory(path.dirname(file), { create: false, label: `parent directory for ${file}` });
  const descriptor = openPrivateFile(file, { operation: "append", create: true, label: options.label });
  try {
    fs.writeFileSync(descriptor, content, options.encoding || "utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

export function writePrivateFileAtomic(file, content, options = {}) {
  const resolved = path.resolve(file);
  const parent = path.dirname(resolved);
  securePrivateDirectory(parent, { create: false, label: `parent directory for ${resolved}` });
  securePrivateFile(resolved, { label: options.label });
  const temporary = path.join(
    parent,
    `.${path.basename(resolved)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      privateFlags(fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL),
      PRIVATE_FILE_MODE
    );
    fs.writeFileSync(descriptor, content, options.encoding);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, resolved);
    securePrivateFile(resolved, { allowMissing: false, label: options.label });
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
  }
}
