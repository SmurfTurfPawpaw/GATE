import fs from "node:fs";
import path from "node:path";
import { readPrivateJson } from "./config.mjs";
import { readJsonLines } from "./jsonl.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { projectRegistryStatus } from "./projects.mjs";
import { validateDocument } from "./schema.mjs";
import { scanCodexUsage } from "./tokens.mjs";
import { upstreamStatus } from "./upstreams.mjs";

function canonicalUsageRecords(values, paths, partial = false) {
  const records = new Map();
  for (const value of values) {
    if (!validateDocument(value, "token-usage.schema.json", { paths }).ok) continue;
    // Repeated reads or retries can append the same canonical record. Its ID is
    // the idempotency boundary, so retain one copy rather than counting it twice.
    records.set(
      value.id,
      partial && value.availability !== "unavailable" ? { ...value, availability: "estimated" } : value
    );
  }
  return [...records.values()];
}

export async function buildStatus(options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const tokenRead = {};
  const [events, publicLearnings, privateLearnings, tokenLog] = await Promise.all([
    readJsonLines(paths.events, { limit: 100, privateFile: true }),
    readJsonLines(paths.publicLearningRecords, { limit: 100 }),
    readJsonLines(paths.privateLearnings, { limit: 100, privateFile: true }),
    readJsonLines(paths.tokens, { limit: 500, metadata: tokenRead, privateFile: true })
  ]);
  const tokenLogPartial = tokenRead.byteTruncated || tokenRead.limitTruncated ||
    tokenLog.some((value) => value?.kind === "invalid-jsonl");
  const recordedTokens = canonicalUsageRecords(tokenLog, paths, tokenLogPartial);
  // A canonical feed can contain usage derived from these same Codex session
  // files. Prefer it wholesale when present; summing both sources would claim
  // usage twice. The host/session-root scan remains the discovery fallback.
  const tokens = recordedTokens.length ? recordedTokens : await scanCodexUsage(options.tokens || {});
  const engagements = fs.existsSync(paths.engagements)
    ? fs.readdirSync(paths.engagements).filter((file) => file.endsWith(".json")).map((file) => {
        try {
          return readPrivateJson(path.join(paths.engagements, file));
        } catch {
          return { id: file, status: "invalid" };
        }
      })
    : [];
  return {
    at: new Date().toISOString(),
    repository: paths.repo,
    gate_home: paths.home,
    events: events.slice(-30).reverse(),
    learnings: [...publicLearnings, ...privateLearnings]
      .sort((left, right) => Date.parse(left.at || 0) - Date.parse(right.at || 0))
      .slice(-30)
      .reverse(),
    engagements,
    projects: projectRegistryStatus({ paths }),
    tokens,
    upstreams: upstreamStatus({ paths, verifyIntegrity: false })
  };
}
