import fs from "node:fs";
import path from "node:path";

import { readJson } from "./config.mjs";
import {
  objectiveRouteCatalogSemanticErrors,
  resolveObjectiveRecommendation
} from "./objective-router.mjs";
import { runtimePaths } from "./paths.mjs";
import { validateDocument } from "./schema.mjs";

export const MAX_OBJECTIVE_PROPOSAL_BYTES = 64 * 1024;

const usesPosixPermissions = process.platform !== "win32";
const noFollow = fs.constants.O_NOFOLLOW || 0;
const nonBlocking = fs.constants.O_NONBLOCK || 0;

function samePrivateFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mode === right.mode && left.nlink === right.nlink && left.uid === right.uid &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function assertPrivateProposalStat(stat) {
  if (stat.isSymbolicLink()) throw new Error("objective proposal must not be a symbolic link");
  if (!stat.isFile() || stat.nlink !== 1n) {
    throw new Error("objective proposal must be a single-link regular file");
  }
  if (usesPosixPermissions) {
    if (typeof process.geteuid === "function" && stat.uid !== BigInt(process.geteuid())) {
      throw new Error("objective proposal is not owned by the current user");
    }
    if ((stat.mode & 0o7777n) !== 0o600n) {
      throw new Error("objective proposal permissions are not owner-only (expected 0600)");
    }
  }
}

export function readPrivateObjectiveProposal(file) {
  const resolved = path.resolve(String(file || ""));
  let before;
  try {
    before = fs.lstatSync(resolved, { bigint: true });
  } catch {
    throw new Error("objective proposal is unavailable");
  }
  assertPrivateProposalStat(before);
  if (before.size > BigInt(MAX_OBJECTIVE_PROPOSAL_BYTES)) {
    throw new Error(`objective proposal exceeds the ${MAX_OBJECTIVE_PROPOSAL_BYTES}-byte limit`);
  }
  if (usesPosixPermissions && !fs.constants.O_NOFOLLOW) {
    throw new Error("this platform cannot enforce no-follow objective proposal access");
  }

  let descriptor;
  try {
    descriptor = fs.openSync(
      resolved,
      fs.constants.O_RDONLY | nonBlocking | (usesPosixPermissions ? noFollow : 0)
    );
  } catch {
    throw new Error("objective proposal could not be opened without following links");
  }

  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    assertPrivateProposalStat(opened);
    if (!samePrivateFile(before, opened)) throw new Error("objective proposal changed while it was opened");

    const chunks = [];
    let total = 0;
    while (total <= MAX_OBJECTIVE_PROPOSAL_BYTES) {
      const buffer = Buffer.allocUnsafe(Math.min(
        64 * 1024,
        MAX_OBJECTIVE_PROPOSAL_BYTES + 1 - total
      ));
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      chunks.push(buffer.subarray(0, count));
      total += count;
    }
    if (total > MAX_OBJECTIVE_PROPOSAL_BYTES) {
      throw new Error(`objective proposal exceeds the ${MAX_OBJECTIVE_PROPOSAL_BYTES}-byte limit`);
    }

    const after = fs.fstatSync(descriptor, { bigint: true });
    assertPrivateProposalStat(after);
    if (!samePrivateFile(opened, after) || after.size !== BigInt(total)) {
      throw new Error("objective proposal changed while it was read");
    }

    let final;
    try {
      final = fs.lstatSync(resolved, { bigint: true });
    } catch {
      throw new Error("objective proposal changed while it was verified");
    }
    assertPrivateProposalStat(final);
    if (!samePrivateFile(after, final)) throw new Error("objective proposal changed while it was verified");

    try {
      return JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
    } catch {
      throw new Error("objective proposal is malformed JSON");
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

export function loadObjectiveRoutingContext(options = {}) {
  const paths = options.paths || runtimePaths(options);
  let routeCatalog;
  let toolCatalog;
  try {
    routeCatalog = readJson(path.join(paths.repo, "config", "objective-routes.json"));
  } catch {
    throw new Error("checked-in objective route catalog is unavailable or malformed");
  }
  try {
    toolCatalog = readJson(path.join(paths.repo, "catalog", "security-tools.json"));
  } catch {
    throw new Error("checked-in security tool catalog is unavailable or malformed");
  }

  const toolValidation = validateDocument(toolCatalog, "tool-catalog.schema.json", { paths });
  if (!toolValidation.ok) throw new Error("checked-in security tool catalog failed validation");
  const toolIds = toolCatalog.tools.map((tool) => tool.id);
  if (new Set(toolIds).size !== toolIds.length) {
    throw new Error("checked-in security tool catalog contains duplicate tool ids");
  }

  const catalogErrors = objectiveRouteCatalogSemanticErrors(routeCatalog, { paths, toolIds });
  if (catalogErrors.length > 0) throw new Error("checked-in objective route catalog failed validation");
  return { paths, routeCatalog, toolCatalog, toolIds };
}

export function recommendObjectiveFromPrivateFile(file, options = {}) {
  const context = loadObjectiveRoutingContext(options);
  const proposal = readPrivateObjectiveProposal(file);
  try {
    return resolveObjectiveRecommendation(context.routeCatalog, proposal, {
      paths: context.paths,
      toolIds: context.toolIds
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes("not bound to the current route catalog digest")) {
      throw new Error("objective proposal is stale for the checked-in route catalog");
    }
    throw new Error("objective proposal failed categorical validation");
  }
}
