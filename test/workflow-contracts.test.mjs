import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PENTEST_COVERAGE_DOMAINS,
  pentestWorkflowSemanticErrors
} from "../src/lib/pentest-workflow.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (relative) => JSON.parse(fs.readFileSync(path.join(repo, relative), "utf8"));
const workflow = readJson("config/workflows/pentest-e2e.json");
const catalog = readJson("catalog/security-tools.json");
const engagementPolicy = readJson("policies/engagements.json");
const clone = (value) => structuredClone(value);
const semanticErrors = (candidate) => pentestWorkflowSemanticErrors(candidate, { catalog, engagementPolicy });

test("the workflow uses the exact ordered 18-domain contract", () => {
  assert.equal(PENTEST_COVERAGE_DOMAINS.length, 18);
  assert.deepEqual(workflow.coverageDomains, PENTEST_COVERAGE_DOMAINS);

  const reordered = clone(workflow);
  [reordered.coverageDomains[0], reordered.coverageDomains[1]] =
    [reordered.coverageDomains[1], reordered.coverageDomains[0]];
  assert.ok(semanticErrors(reordered).includes(
    "workflow coverage domains differ from the exact ordered 18-domain contract"
  ));
});

test("defined stops equal the default-plus-phase mandatory stop union", () => {
  const mandatory = new Set([
    ...workflow.defaultStopConditions,
    ...workflow.phases.flatMap((phase) => phase.stopPolicy.additional)
  ]);
  assert.deepEqual(
    [...mandatory].sort(),
    workflow.stopConditions.map((condition) => condition.id).sort()
  );
  assert.equal(mandatory.size, 13);

  const unusedDefinition = clone(workflow);
  unusedDefinition.stopConditions.push({
    id: "unused-stop",
    trigger: "A structurally valid stop exists without a phase or default-policy requirement.",
    response: "Reject the contract because defined stops must equal the effective mandatory union."
  });
  assert.ok(semanticErrors(unusedDefinition).includes(
    "workflow stop definitions differ from the mandatory stop-condition union"
  ));

  const missingUse = clone(workflow);
  for (const phase of missingUse.phases) {
    phase.stopPolicy.additional = phase.stopPolicy.additional.filter((id) => id !== "cleanup-incomplete");
  }
  assert.ok(semanticErrors(missingUse).includes(
    "workflow stop definitions differ from the mandatory stop-condition union"
  ));
});

test("every non-offline target-contact mapping has a reviewed adapter constraint", () => {
  const activeMappings = workflow.phases.flatMap((phase) =>
    phase.targetContact
      ? phase.toolMappings.filter((mapping) => mapping.mode !== "offline-only")
        .map((mapping) => ({ phase, mapping }))
      : []
  );
  assert.ok(activeMappings.length > 0);
  assert.ok(activeMappings.every(({ mapping }) =>
    typeof mapping.adapterConstraint === "string" && mapping.adapterConstraint.trim()
  ));

  const weakened = clone(workflow);
  const phase = weakened.phases.find((candidate) =>
    candidate.targetContact &&
    candidate.toolMappings.some((mapping) => mapping.mode !== "offline-only")
  );
  const mapping = phase.toolMappings.find((candidate) => candidate.mode !== "offline-only");
  delete mapping.adapterConstraint;
  assert.ok(semanticErrors(weakened).some((error) =>
    error.includes(`${phase.id} target-contact mapping ${mapping.toolId} lacks an adapter constraint`)
  ));
});

test("network enumeration can promote one bounded hypothesis to controlled exploitation", () => {
  const network = workflow.phases.find((phase) => phase.id === "network-service-enumeration");
  const controlled = workflow.phases.find((phase) => phase.id === "controlled-exploitation");
  const routes = network.transitions.filter((transition) =>
    transition.kind === "normal" && transition.to === controlled.id
  );
  assert.equal(routes.length, 1);
  assert.equal(routes[0].guard.authorization, "new-engagement");
  assert.ok(routes[0].handoffId);
  assert.ok(controlled.dependsOn.anyOf.includes(network.id));
});

test("42 definitions cover every normal, stop, and failure entry into target-contact A3 phases", () => {
  const phases = new Map(workflow.phases.map((phase) => [phase.id, phase]));
  const handoffs = new Map(workflow.handoffs.map((handoff) => [handoff.id, handoff]));
  const allEntries = workflow.phases.flatMap((phase) => phase.transitions.map((transition) => ({
    phase,
    transition,
    destination: phases.get(transition.to)
  }))).filter(({ destination }) =>
    destination.targetContact && destination.effectClass === "A3"
  );
  const normalEntries = allEntries.filter(({ transition }) => transition.kind === "normal");

  assert.equal(allEntries.length, 74);
  assert.ok(allEntries.every(({ transition }) => transition.handoffId));
  assert.equal(normalEntries.length, 42);
  assert.equal(new Set(normalEntries.map(({ transition }) => transition.handoffId)).size, 42);
  for (const { phase, transition, destination } of normalEntries) {
    const handoff = handoffs.get(transition.handoffId);
    assert.ok(handoff, `missing handoff for ${phase.id} -> ${destination.id}`);
    assert.equal(handoff.fromPhase, phase.id);
    assert.equal(handoff.toPhase, destination.id);
    assert.equal(handoff.automaticPromotion, false);
    const teardown = transition.guard.authorization === "preauthorized-teardown";
    assert.equal(handoff.type, teardown ? "operational-transfer" : "approval-boundary");
    assert.equal(handoff.policyId, teardown ? "teardown-structured-v1" : "a3-structured-v1");
  }
  for (const handoff of workflow.handoffs.filter(({ type }) => type === "operational-transfer")) {
    const matching = allEntries.filter(({ phase, transition }) =>
      phase.id === handoff.fromPhase &&
      transition.to === handoff.toPhase &&
      transition.handoffId === handoff.id
    );
    assert.deepEqual(
      [...new Set(matching.map(({ transition }) => transition.kind))].sort(),
      ["failure", "normal", "stop"]
    );
    assert.ok(matching.every(({ transition }) =>
      transition.guard.authorization === "preauthorized-teardown"
    ));
  }

  const missing = clone(workflow);
  delete missing.phases.find((phase) => phase.id === "network-service-enumeration")
    .transitions.find((transition) => transition.to === "controlled-exploitation").handoffId;
  assert.ok(semanticErrors(missing).some((error) =>
    /transition to A3 phase controlled-exploitation lacks a structured handoff/u.test(error)
  ));

  const missingStopHandoff = clone(workflow);
  delete missingStopHandoff.phases.find((phase) => phase.id === "network-service-enumeration")
    .transitions.find((transition) =>
      transition.kind === "stop" && transition.to === "cleanup-and-restoration"
    ).handoffId;
  assert.ok(semanticErrors(missingStopHandoff).some((error) =>
    /transition to A3 phase cleanup-and-restoration lacks a structured handoff/u.test(error)
  ));

  const wrongPolicy = clone(workflow);
  wrongPolicy.handoffs.find((handoff) => handoff.id === "high-impact-handoff-07").policyId =
    "teardown-structured-v1";
  assert.ok(semanticErrors(wrongPolicy).some((error) =>
    /high-impact-handoff-07 A3 handoff policy .* instead of a3-structured-v1/u.test(error)
  ));
});

test("the reusable A3 and teardown policies remain type-separated", () => {
  assert.deepEqual(
    workflow.handoffPolicies.map(({ id, type }) => ({ id, type })),
    [
      { id: "a3-structured-v1", type: "approval-boundary" },
      { id: "teardown-structured-v1", type: "operational-transfer" }
    ]
  );
  assert.deepEqual(semanticErrors(workflow), []);

  const weakened = clone(workflow);
  weakened.handoffPolicies.find((policy) => policy.id === "teardown-structured-v1").type =
    "approval-boundary";
  assert.ok(semanticErrors(weakened).some((error) =>
    /handoff policy teardown-structured-v1 has type approval-boundary instead of operational-transfer/u.test(error)
  ));
});
