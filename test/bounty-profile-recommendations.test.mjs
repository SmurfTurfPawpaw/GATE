import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  applyProgramProfileAnswers,
  applyProgramProfileRecommendation,
  applyProgramProfileRecommendations,
  createProgramProfile,
  createProgramProfileWithRecommendations,
  programProfileRecommendation,
  resumeProgramProfile
} from "../src/lib/bounty-profiles.mjs";
import {
  PROGRAM_PROFILE_MANUAL_ONLY_QUESTION_IDS,
  programProfileQuestionnaireBinding
} from "../src/lib/program-profile-contract.mjs";
import { runtimePaths } from "../src/lib/paths.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gate = path.join(repo, "bin", "gate.mjs");

function invoke(args, home) {
  return spawnSync(process.execPath, [gate, ...args], {
    cwd: repo,
    env: { ...process.env, GATE_HOME: home },
    encoding: "utf8",
    timeout: 10_000
  });
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-profile-recommendations-"));
  const paths = runtimePaths({ repo, home: path.join(root, "home") });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return paths;
}

function proposal(value, { provenance = "local-derived", sourceRefs = [], claimState = "observed" } = {}) {
  return {
    value,
    provenance,
    basis: {
      summary: "Use the private reviewed proposal for this question.",
      claimState,
      sourceRefs
    }
  };
}

function envelope(id, profile, proposals) {
  const binding = programProfileQuestionnaireBinding({ repo });
  return {
    $schema: "https://gate.local/schemas/bug-bounty-program-profile-recommendations.schema.json",
    apiVersion: "gate.dev/program-profile-recommendations/v1",
    kind: "BugBountyProgramProfileRecommendations",
    metadata: {
      programId: id,
      createdAt: "2026-10-16T10:02:00.000Z",
      questionnaireId: binding.id,
      questionnaireVersion: binding.version,
      questionnaireSha256: binding.sha256,
      baseRevision: profile.summary.revision,
      baseProfileSha256: profile.summary.profileSha256
    },
    proposals
  };
}

function decision(disposition = "allowed") {
  return {
    disposition,
    claimState: "observed",
    sourceRefs: ["program-rules"],
    rationale: "The cited program source supports this decision.",
    conditions: [],
    answers: {}
  };
}

test("bulk recommendations preserve explicit answers, activate module proposals, and write one revision", (t) => {
  const paths = fixture(t);
  const id = "recommendation-bulk";
  createProgramProfile(id, {}, { paths, now: "2026-10-16T10:00:00.000Z" });
  const programSource = {
    id: "program-rules",
    type: "program-rules",
    title: "Published program rules",
    reference: "https://example.test/rules",
    contentSha256: "a".repeat(64),
    observedAt: "2026-10-16T09:00:00.000Z",
    claimState: "observed",
    notes: "Captured in operator-controlled private storage."
  };
  const explicit = resumeProgramProfile(id, { paths }).answers;
  explicit.metadata.updatedAt = "2026-10-16T10:01:00.000Z";
  explicit.answers["identity-depth"] = "exhaustive";
  explicit.answers["authority-sources"] = [programSource];
  applyProgramProfileAnswers(id, explicit, { paths, now: explicit.metadata.updatedAt });

  const current = resumeProgramProfile(id, { paths });
  const recommendations = envelope(id, current, {
    "identity-program-name": proposal("Recommendation fixture"),
    "authority-sources": proposal([programSource]),
    "authority-basis": proposal("public-bug-bounty-program", {
      provenance: "source-derived",
      sourceRefs: ["program-rules"]
    }),
    "coverage-applicable-modules": proposal(["web-api"], {
      provenance: "source-derived",
      sourceRefs: ["program-rules"]
    }),
    "web-api-assessment": proposal(decision(), {
      provenance: "source-derived",
      sourceRefs: ["program-rules"]
    }),
    "web-api-entry-points": proposal(["Private reviewed web entry point."], {
      provenance: "source-derived",
      sourceRefs: ["program-rules"]
    }),
    "web-api-auth-flows": proposal(["Private reviewed authentication flow."], {
      provenance: "source-derived",
      sourceRefs: ["program-rules"]
    }),
    "web-api-automation-rules": proposal("Use only the source-backed automation limits.", {
      provenance: "source-derived",
      sourceRefs: ["program-rules"]
    }),
    "limits-max-minutes": proposal(30, {
      provenance: "source-derived",
      sourceRefs: ["missing-source"]
    })
  });

  const result = applyProgramProfileRecommendations(id, recommendations, {
    paths,
    now: "2026-10-16T10:03:00.000Z",
    expectedRevision: current.profile.metadata.revision,
    expectedProfileSha256: current.summary.profileSha256
  });
  assert.equal(result.updated, true);
  assert.equal(result.revision, current.profile.metadata.revision + 1);
  assert.equal(result.recommendationMode, "mixed");
  assert.ok(result.appliedQuestionIds.includes("web-api-automation-rules"));
  assert.equal(result.appliedQuestionIds.includes("limits-max-minutes"), false);
  assert.ok(result.unavailableCount > 0);
  for (const questionId of PROGRAM_PROFILE_MANUAL_ONLY_QUESTION_IDS) {
    assert.equal(result.appliedQuestionIds.includes(questionId), false, questionId);
  }

  const stored = resumeProgramProfile(id, { paths });
  assert.equal(stored.profile.identity.depth, "exhaustive");
  assert.deepEqual(stored.profile.sources, [programSource]);
  assert.deepEqual(stored.profile.questionnaire.applicableModules, ["web-api"]);
  assert.equal(stored.profile.modules["web-api"].answers.automationRules, "Use only the source-backed automation limits.");
  assert.equal(Object.hasOwn(stored.answers.answers, "limits-max-minutes"), false);

  assert.throws(() => applyProgramProfileRecommendations(id, recommendations, { paths }), /revision changed/u);
  const before = stored.profile.metadata.revision;
  const idempotent = applyProgramProfileRecommendations(id, null, {
    paths,
    now: "2026-10-16T10:04:00.000Z"
  });
  assert.equal(idempotent.updated, false);
  assert.equal(idempotent.appliedCount, 0);
  assert.equal(resumeProgramProfile(id, { paths }).profile.metadata.revision, before);
});

test("manual-only and sensitive recommendation summaries never expose a proposed value", () => {
  const manual = programProfileRecommendation("authority-operator-confirmed");
  assert.equal(manual.available, false);
  assert.equal(manual.reason, "manual-only");

  const sensitiveValue = "PRIVATE_CONTACT_CANARY";
  const sensitive = programProfileRecommendation("accounts-personas", {
    profile: { sources: [] },
    recommendations: {
      proposals: {
        "accounts-personas": proposal([{ name: sensitiveValue }])
      }
    }
  });
  assert.equal(sensitive.available, true);
  assert.doesNotMatch(sensitive.summary, new RegExp(sensitiveValue, "u"));
  assert.match(sensitive.summary, /value remains hidden/u);

  const unverified = programProfileRecommendation("accounts-personas", {
    profile: { sources: [] },
    recommendations: {
      proposals: {
        "accounts-personas": proposal([{ name: "Private account" }], { claimState: "unverified" })
      }
    }
  });
  assert.equal(unverified.available, false);
  assert.equal(unverified.reason, "proposal-unverified");

  const localTimezone = programProfileRecommendation("limits-timezone", {
    profile: { sources: [] },
    recommendations: {
      proposals: {
        "limits-timezone": proposal("Europe/Brussels", {
          provenance: "local-derived",
          claimState: "observed"
        })
      }
    }
  });
  assert.equal(localTimezone.available, true);
  assert.equal(localTimezone.basis.claimState, "observed");

  const permissionWithoutSource = programProfileRecommendation("actions-all", {
    profile: { sources: [] },
    recommendations: {
      proposals: {
        "actions-all": proposal({ observe: { disposition: "allowed" } })
      }
    }
  });
  assert.equal(permissionWithoutSource.available, false);
  assert.equal(permissionWithoutSource.reason, "observed-source-required");

  const selfBootstrappedSource = programProfileRecommendation("authority-sources", {
    profile: { sources: [] },
    recommendations: {
      proposals: {
        "authority-sources": proposal([{
          id: "program-rules",
          type: "program-rules",
          title: "Published program rules",
          reference: "https://example.test/rules",
          contentSha256: "a".repeat(64),
          observedAt: "2026-10-16T09:00:00.000Z",
          claimState: "observed",
          notes: null
        }], { provenance: "source-derived", sourceRefs: ["program-rules"] })
      }
    }
  });
  assert.equal(selfBootstrappedSource.available, false);
  assert.equal(selfBootstrappedSource.reason, "source-missing");

  const inferredPermission = programProfileRecommendation("actions-all", {
    profile: { sources: [{ id: "program-rules" }] },
    recommendations: {
      proposals: {
        "actions-all": proposal({ observe: { disposition: "allowed" } }, {
          provenance: "source-derived",
          sourceRefs: ["program-rules"],
          claimState: "inferred"
        })
      }
    }
  });
  assert.equal(inferredPermission.available, false);
  assert.equal(inferredPermission.reason, "observed-source-required");

  const unobservedSource = programProfileRecommendation("actions-all", {
    profile: { sources: [{ id: "program-rules", claimState: "inferred" }] },
    recommendations: {
      proposals: {
        "actions-all": proposal({ observe: { disposition: "allowed" } }, {
          provenance: "source-derived",
          sourceRefs: ["program-rules"]
        })
      }
    }
  });
  assert.equal(unobservedSource.available, false);
  assert.equal(unobservedSource.reason, "source-not-observed");

  const futureSource = programProfileRecommendation("limits-max-minutes", {
    profile: {
      sources: [{
        id: "program-rules",
        type: "program-rules",
        claimState: "observed",
        observedAt: "2099-01-01T00:00:00.000Z",
        contentSha256: "a".repeat(64)
      }]
    },
    recommendations: {
      proposals: {
        "limits-max-minutes": proposal(30, {
          provenance: "source-derived",
          sourceRefs: ["program-rules"]
        })
      }
    },
    now: "2026-10-16T10:00:00.000Z"
  });
  assert.equal(futureSource.available, false);
  assert.equal(futureSource.reason, "source-not-current");

  for (const [questionId, profile, candidate] of [
    [
      "architecture-source-refs",
      { sources: [] },
      proposal(["missing-source"])
    ],
    [
      "limits-source-refs",
      { sources: [{ id: "program-rules", claimState: "observed" }] },
      proposal(["missing-source"], { provenance: "source-derived", sourceRefs: ["program-rules"] })
    ]
  ]) {
    const missingTopLevelSource = programProfileRecommendation(questionId, {
      profile,
      recommendations: { proposals: { [questionId]: candidate } }
    });
    assert.equal(missingTopLevelSource.available, false, questionId);
    assert.equal(missingTopLevelSource.reason, "source-missing", questionId);
  }
});

test("invalid recommendation values fail before any profile revision is written", (t) => {
  const paths = fixture(t);
  const id = "recommendation-invalid";
  createProgramProfile(id, {}, { paths, now: "2026-10-16T11:00:00.000Z" });
  const current = resumeProgramProfile(id, { paths });
  const recommendations = envelope(id, current, {
    "limits-max-minutes": proposal("not-an-integer", {
      provenance: "source-derived",
      sourceRefs: ["program-rules"]
    })
  });
  assert.throws(
    () => applyProgramProfileRecommendations(id, recommendations, { paths }),
    /must be a safe integer/u
  );
  assert.equal(resumeProgramProfile(id, { paths }).profile.metadata.revision, 1);
});

test("one evidence recommendation applies through an exact base-bound mutation", (t) => {
  const paths = fixture(t);
  const id = "recommendation-single";
  createProgramProfile(id, {}, { paths, now: "2026-10-16T11:00:00.000Z" });
  const current = resumeProgramProfile(id, { paths });
  const recommendations = envelope(id, current, {
    "limits-timezone": proposal("Europe/Brussels", {
      provenance: "local-derived",
      claimState: "observed"
    })
  });

  const applied = applyProgramProfileRecommendation(id, "limits-timezone", recommendations, {
    paths,
    now: "2026-10-16T11:01:00.000Z",
    expectedRevision: current.summary.revision,
    expectedProfileSha256: current.summary.profileSha256
  });
  assert.equal(applied.updated, true);
  assert.equal(applied.provenance, "local-derived");
  assert.equal(resumeProgramProfile(id, { paths }).profile.limits.timezone, "Europe/Brussels");
  assert.throws(
    () => applyProgramProfileRecommendation(id, "identity-objective", recommendations, { paths }),
    /revision changed/u
  );
});

test("an unbound create-time proposal cannot introduce and self-cite its authority source", (t) => {
  const paths = fixture(t);
  const id = "recommendation-source-bootstrap";
  const current = {
    summary: { revision: null, profileSha256: null }
  };
  const recommendations = envelope(id, current, {
    "authority-sources": proposal([{
      id: "program-rules",
      type: "program-rules",
      title: "Published program rules",
      reference: "https://example.test/rules",
      contentSha256: "a".repeat(64),
      observedAt: "2026-10-16T09:00:00.000Z",
      claimState: "observed",
      notes: null
    }], { provenance: "source-derived", sourceRefs: ["program-rules"] })
  });
  recommendations.metadata.baseRevision = null;
  recommendations.metadata.baseProfileSha256 = null;

  const result = createProgramProfileWithRecommendations(id, recommendations, {
    paths,
    now: "2026-10-16T11:31:00.000Z"
  });
  assert.equal(result.appliedQuestionIds.includes("authority-sources"), false);
  assert.deepEqual(resumeProgramProfile(id, { paths }).profile.sources, []);
});

test("bulk proposal eligibility uses the source ledger from the bound base", () => {
  const seedSource = {
    id: "seed-source",
    type: "operator-statement",
    title: "Reviewed operator source",
    reference: "private://programs/recommendation-two-step-sources/seed-source",
    contentSha256: null,
    observedAt: "2026-10-16T10:00:00.000Z",
    claimState: "observed",
    notes: "Reviewed before the recommendation operation."
  };
  const addedSource = {
    id: "added-source",
    type: "program-rules",
    title: "Newly proposed rules source",
    reference: "https://example.test/new-rules",
    contentSha256: "b".repeat(64),
    observedAt: "2026-10-16T10:30:00.000Z",
    claimState: "observed",
    notes: "Proposed for a later explicit review."
  };
  const resolved = programProfileRecommendation("authority-basis", {
    profile: { sources: [seedSource, addedSource] },
    sourceProfile: { sources: [seedSource] },
    recommendations: {
      proposals: {
        "authority-basis": proposal("public-bug-bounty-program", {
          provenance: "source-derived",
          sourceRefs: ["added-source"]
        })
      }
    }
  });
  assert.equal(resolved.available, false);
  assert.equal(resolved.reason, "source-missing");
});

test("create-time recommendation binding is validated before any profile state exists", (t) => {
  const paths = fixture(t);
  const recommendations = envelope("different-program", {
    summary: { revision: null, profileSha256: null }
  }, {});

  assert.throws(
    () => createProgramProfileWithRecommendations("requested-program", recommendations, { paths }),
    /do not match the requested program id/u
  );
  assert.equal(fs.existsSync(path.join(paths.programs, "requested-program")), false);
});

test("CLI bulk recommendation mode is headless, bounded, and idempotent", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gate-profile-recommendations-cli-"));
  const home = path.join(root, "home");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const created = invoke([
    "bounty", "profile", "create", "recommendation-cli", "--apply-recommended", "--json"
  ], home);
  assert.equal(created.status, 0, created.stderr);
  const first = JSON.parse(created.stdout);
  assert.equal(first.recommendationMode, "policy");
  assert.ok(first.appliedCount > 0);
  assert.equal(first.revision, 1);

  const resumed = invoke([
    "bounty", "profile", "resume", "recommendation-cli", "--apply-recommended", "--json"
  ], home);
  assert.equal(resumed.status, 0, resumed.stderr);
  const second = JSON.parse(resumed.stdout);
  assert.equal(second.updated, false);
  assert.equal(second.appliedCount, 0);
  assert.equal(second.revision, first.revision);
});
