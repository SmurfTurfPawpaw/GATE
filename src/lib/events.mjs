import crypto from "node:crypto";
import { appendJsonLine } from "./jsonl.mjs";
import { ensureRuntime, runtimePaths } from "./paths.mjs";
import { assertValidDocument } from "./schema.mjs";
import { assertNoLikelySecret, oneLine } from "./text.mjs";

export function newId(prefix) {
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  return `${prefix}_${stamp}_${crypto.randomBytes(4).toString("hex")}`;
}

export function recordEvent(input, options = {}) {
  const paths = options.paths || runtimePaths(options);
  ensureRuntime(paths);
  const summary = oneLine(input.summary, { name: "summary" });
  assertNoLikelySecret(summary, "summary");
  const id = input.id || newId("evt");
  const statusAliases = {
    observed: "succeeded",
    passed: "succeeded",
    complete: "succeeded",
    approved: "succeeded"
  };
  const status = statusAliases[input.status] || input.status || "succeeded";
  const allowedStatuses = new Set(["queued", "running", "waiting", "blocked", "succeeded", "failed", "cancelled", "unknown"]);
  const event = {
    apiVersion: "gate.event/v1",
    id,
    at: input.at || new Date().toISOString(),
    runId: input.runId || input.run_id || `run_${id.slice(4)}`,
    taskId: input.taskId || null,
    component: input.component || "gate",
    agent: input.agent === null ? null : input.agent || "gate",
    kind: oneLine(input.kind, { name: "kind", max: 100 }),
    status: allowedStatuses.has(status) ? status : "unknown",
    summary,
    effect: {
      class: input.effect?.class || "none",
      targetRef: input.effect?.targetRef || null,
      engagementId: input.effect?.engagementId || null,
      planDigest: input.effect?.planDigest || null
    },
    evidenceRefs: input.evidenceRefs || [],
    usageRef: input.usageRef || null
  };
  assertValidDocument(event, "event.schema.json", { paths });
  appendJsonLine(paths.events, event);
  return event;
}
