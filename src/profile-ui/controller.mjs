import * as bountyProfiles from "../lib/bounty-profiles.mjs";
import {
  loadProgramProfileQuestionnaire,
  PROGRAM_PROFILE_ACTIONS,
  PROGRAM_PROFILE_COVERAGE_DOMAINS,
  PROGRAM_PROFILE_STOP_CONDITIONS
} from "../lib/program-profile-contract.mjs";

const MANUAL_REVIEW_QUESTIONS = new Set([
  "authority-operator-confirmed",
  "attestation-operator",
  "attestation-answers-complete",
  "attestation-sources-reviewed",
  "attestation-scope-reviewed",
  "attestation-at"
]);

export class ProfileUiError extends Error {
  constructor(status, code, publicMessage) {
    super(publicMessage);
    this.name = "ProfileUiError";
    this.status = status;
    this.code = code;
    this.publicMessage = publicMessage;
  }
}

function valueAtPath(value, dottedPath) {
  let cursor = value;
  for (const part of String(dottedPath || "").split(".").filter(Boolean)) {
    if (!cursor || typeof cursor !== "object" || !Object.hasOwn(cursor, part)) return undefined;
    cursor = cursor[part];
  }
  return cursor;
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

function questionnaireLayout(questionnaire) {
  const attestation = questionnaire.sections.find((section) => section.id === "ambiguities-attestation");
  const ordinary = questionnaire.sections.filter((section) => section.id !== "ambiguities-attestation");
  return [
    ...ordinary.map((section) => ({
      id: section.id,
      title: section.title,
      purpose: section.purpose,
      kind: "section",
      questions: section.questions.map((question) => ({ ...question, sectionId: section.id, moduleId: null }))
    })),
    ...questionnaire.conditionalModules.map((module) => ({
      id: `module-${module.id}`,
      title: module.title,
      purpose: module.purpose,
      kind: "module",
      moduleId: module.id,
      questions: module.questions.map((question) => ({
        ...question,
        sectionId: null,
        moduleId: module.id,
        condition: question.condition || module.activation
      }))
    })),
    ...(attestation ? [{
      id: attestation.id,
      title: attestation.title,
      purpose: attestation.purpose,
      kind: "section",
      questions: attestation.questions.map((question) => ({
        ...question,
        sectionId: attestation.id,
        moduleId: null
      }))
    }] : [])
  ];
}

function recommendationFor(question, profile) {
  if (MANUAL_REVIEW_QUESTIONS.has(question.id) || question.recommendationPolicy?.class === "manual-only") {
    return {
      available: false,
      summary: question.recommendationPolicy?.summary || "This answer requires the operator.",
      reason: "manual-only"
    };
  }
  if (typeof bountyProfiles.programProfileRecommendation === "function") {
    const result = bountyProfiles.programProfileRecommendation(question.id, { profile });
    return result?.available
      ? {
          available: true,
          value: structuredClone(result.value),
          provenance: result.provenance || null,
          summary: result.summary || question.recommendationPolicy?.summary || "Recommended by the reviewed profile policy.",
          reason: result.reason || null,
          basis: result.basis || question.recommendationPolicy?.basis || null
        }
      : {
          available: false,
          summary: result?.summary || question.recommendationPolicy?.summary || "No supported recommendation is available.",
          reason: result?.reason || "unavailable"
        };
  }
  if (question.recommendationPolicy?.class === "operator-preference" &&
      Object.hasOwn(question.recommendationPolicy, "value")) {
    return {
      available: true,
      value: structuredClone(question.recommendationPolicy.value),
      provenance: "reviewed-policy",
      summary: question.recommendationPolicy.summary,
      reason: "reviewed-operator-preference",
      basis: question.recommendationPolicy.basis || null
    };
  }
  return {
    available: false,
    summary: question.recommendationPolicy?.summary || "No supported recommendation is available.",
    reason: "source-evidence-required"
  };
}

function sourceReview(profile) {
  return (profile.sources || []).map((source) => ({
    id: source.id,
    title: source.title,
    type: source.type,
    observedAt: source.observedAt,
    claimState: source.claimState,
    contentDigestRecorded: typeof source.contentSha256 === "string"
  }));
}

function publicRecommendation(recommendation) {
  const basis = typeof recommendation?.basis === "string"
    ? recommendation.basis
    : typeof recommendation?.basis?.policy === "string"
      ? recommendation.basis.policy
      : Number.isSafeInteger(recommendation?.basis?.sourceCount)
        ? `${recommendation.basis.sourceCount} cited local source${recommendation.basis.sourceCount === 1 ? "" : "s"}`
        : null;
  return {
    available: recommendation?.available === true,
    provenance: recommendation?.provenance || null,
    summary: recommendation?.summary || "No supported recommendation is available.",
    reason: recommendation?.reason || null,
    basis
  };
}

function serializeState(profileId, resumed, questionnaire) {
  const { profile, answers } = resumed;
  const answeredIds = new Set(Object.keys(answers.answers || {}));
  const selectedModules = new Set(profile.questionnaire?.applicableModules || []);
  const sections = questionnaireLayout(questionnaire).map((section) => {
    const sectionApplicable = section.kind !== "module" || selectedModules.has(section.moduleId);
    const questions = section.questions.map((question) => {
      const applicable = sectionApplicable && conditionMatches(question.condition, profile);
      return {
        id: question.id,
        path: question.path,
        prompt: question.prompt,
        why: question.why,
        type: question.type,
        required: question.required === true,
        sensitive: question.sensitive === true,
        allowNull: question.allowNull === true,
        choices: question.choices || [],
        sectionId: question.sectionId,
        moduleId: question.moduleId,
        applicable,
        answered: answeredIds.has(question.id),
        value: answeredIds.has(question.id) ? structuredClone(answers.answers[question.id]) : undefined,
        manualOnly: MANUAL_REVIEW_QUESTIONS.has(question.id) ||
          question.recommendationPolicy?.class === "manual-only",
        // Exact recommendation values stay inside the trusted local
        // controller. The browser receives only display-safe metadata and
        // invokes a server-side resolution when the operator accepts one.
        recommendation: publicRecommendation(recommendationFor(question, profile))
      };
    });
    const applicableQuestions = questions.filter((question) => question.applicable);
    return {
      id: section.id,
      title: section.title,
      purpose: section.purpose,
      kind: section.kind,
      applicable: sectionApplicable,
      progress: {
        answered: applicableQuestions.filter((question) => question.answered).length,
        total: applicableQuestions.length
      },
      questions
    };
  });
  const applicableQuestions = sections.flatMap((section) => section.questions).filter((question) => question.applicable);
  const recommendationCount = applicableQuestions.filter((question) =>
    !question.answered && question.recommendation.available && !question.manualOnly).length;
  return {
    apiVersion: "gate.dev/profile-ui-state/v1",
    profile: {
      id: profileId,
      title: profile.metadata.title,
      status: profile.metadata.status,
      revision: profile.metadata.revision,
      profileSha256: resumed.summary.profileSha256,
      updatedAt: profile.metadata.updatedAt
    },
    progress: {
      answered: applicableQuestions.filter((question) => question.answered).length,
      total: applicableQuestions.length,
      requiredRemaining: applicableQuestions.filter((question) => question.required && !question.answered).length
    },
    recommendationCount,
    semantics: {
      dispositions: [...(questionnaire.semantics?.dispositions || [])],
      claimStates: [...(questionnaire.semantics?.claimStates || [])],
      actions: [...(questionnaire.semantics?.actions || [])],
      coverageDomains: [...(questionnaire.semantics?.coverageDomains || [])],
      stopConditions: [...(questionnaire.semantics?.stopConditions || [])]
    },
    sources: sourceReview(profile),
    authorizationSourceRefs: [...(profile.authorization?.sourceRefs || [])],
    sections
  };
}

function assertMutationBase(request, current) {
  if (!Number.isSafeInteger(request?.baseRevision) || request.baseRevision < 1 ||
      !/^[a-f0-9]{64}$/u.test(request?.baseProfileSha256 || "")) {
    throw new ProfileUiError(400, "base-required", "Reload the profile before saving this answer.");
  }
  if (request.baseRevision !== current.profile.metadata.revision ||
      request.baseProfileSha256 !== current.summary.profileSha256) {
    throw new ProfileUiError(409, "stale-profile", "This profile changed in another window. Reload it before saving.");
  }
}

function typeLooksValid(question, value) {
  if (value === null) return question.allowNull === true;
  if (["text", "multiline", "datetime"].includes(question.type)) {
    return typeof value === "string" && value.trim().length > 0 &&
      (question.type !== "datetime" || Number.isFinite(Date.parse(value)));
  }
  if (question.type === "boolean") return typeof value === "boolean";
  if (question.type === "integer") return Number.isSafeInteger(value);
  if (question.type === "number") return typeof value === "number" && Number.isFinite(value);
  if (question.type === "enum") return typeof value === "string" && question.choices?.includes(value);
  if (question.type === "multi-enum") {
    return Array.isArray(value) && value.every((item) => question.choices?.includes(item)) &&
      new Set(value).size === value.length;
  }
  if (["decision", "action-decisions", "coverage-decisions", "stop-responses"].includes(question.type)) {
    return Boolean(value && typeof value === "object" && !Array.isArray(value));
  }
  return Array.isArray(value);
}

function questionIndex(questionnaire) {
  return new Map(questionnaireLayout(questionnaire).flatMap((section) => section.questions)
    .map((question) => [question.id, question]));
}

function publicMutationFailure(error) {
  if (error instanceof ProfileUiError) return error;
  if (/revision changed|digest changed|base profile|changed during/u.test(error?.message || "")) {
    return new ProfileUiError(409, "stale-profile", "This profile changed in another window. Reload it before saving.");
  }
  return new ProfileUiError(
    422,
    "answer-not-accepted",
    "GATE could not save this answer. Review the fields and referenced IDs, then try again."
  );
}

export function createProfileWizardController(options = {}) {
  const { profileId, paths } = options;
  if (typeof profileId !== "string") throw new Error("profile wizard requires one selected profile id");
  const questionnaire = loadProgramProfileQuestionnaire({ paths });
  const questions = questionIndex(questionnaire);

  const current = () => bountyProfiles.resumeProgramProfile(profileId, { paths });
  const state = () => serializeState(profileId, current(), questionnaire);

  const saveAnswer = (request, mode = "answer") => {
    const resumed = current();
    assertMutationBase(request, resumed);
    const question = questions.get(request?.questionId);
    if (!question) throw new ProfileUiError(404, "question-not-found", "That profile question is no longer available.");
    const selectedModules = new Set(resumed.profile.questionnaire?.applicableModules || []);
    if ((question.moduleId && !selectedModules.has(question.moduleId)) ||
        !conditionMatches(question.condition, resumed.profile)) {
      throw new ProfileUiError(409, "question-not-applicable", "That question no longer applies to this profile.");
    }

    let value = request.value;
    if (mode === "recommendation") {
      const recommendation = recommendationFor(question, resumed.profile);
      if (!recommendation.available || question.recommendationPolicy?.class === "manual-only") {
        throw new ProfileUiError(409, "recommendation-unavailable", "This question needs your answer or source evidence.");
      }
      value = recommendation.value;
    }
    if (!typeLooksValid(question, value)) {
      throw new ProfileUiError(422, "answer-shape-invalid", "Complete the visible fields using the expected answer format.");
    }
    if (question.id === "authority-operator-confirmed" && value === true && request.reviewAcknowledged !== true) {
      throw new ProfileUiError(422, "source-review-required", "Review the local source summary before confirming authority.");
    }

    const envelope = structuredClone(resumed.answers);
    envelope.metadata.updatedAt = new Date(options.now?.() || Date.now()).toISOString();
    envelope.answers[question.id] = structuredClone(value);
    try {
      bountyProfiles.applyProgramProfileAnswers(profileId, envelope, { paths });
      return state();
    } catch (error) {
      throw publicMutationFailure(error);
    }
  };

  return Object.freeze({
    profileId,
    state,
    saveAnswer: (request) => saveAnswer(request, "answer"),
    applyRecommendation: (request) => saveAnswer(request, "recommendation"),
    applySupportedRecommendations(request) {
      const resumed = current();
      assertMutationBase(request, resumed);
      if (typeof bountyProfiles.applyProgramProfileRecommendations !== "function") {
        throw new ProfileUiError(501, "bulk-recommendations-unavailable", "Bulk recommendations are not available in this GATE build.");
      }
      try {
        bountyProfiles.applyProgramProfileRecommendations(profileId, null, {
          paths,
          expectedRevision: resumed.profile.metadata.revision,
          expectedProfileSha256: resumed.summary.profileSha256
        });
        return state();
      } catch (error) {
        throw publicMutationFailure(error);
      }
    }
  });
}

export const profileUiControllerInternals = Object.freeze({
  MANUAL_REVIEW_QUESTIONS,
  PROGRAM_PROFILE_ACTIONS,
  PROGRAM_PROFILE_COVERAGE_DOMAINS,
  PROGRAM_PROFILE_STOP_CONDITIONS,
  questionnaireLayout,
  serializeState
});
