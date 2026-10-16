import * as bountyProfiles from "../lib/bounty-profiles.mjs";
import {
  loadProgramProfileQuestionnaire,
  PROGRAM_PROFILE_ACTIONS,
  PROGRAM_PROFILE_COVERAGE_DOMAINS,
  programProfileQuestionAnswerIsComplete,
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
  constructor(status, code, publicMessage, fields = []) {
    super(publicMessage);
    this.name = "ProfileUiError";
    this.status = status;
    this.code = code;
    this.publicMessage = publicMessage;
    this.fields = fields;
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
        module: module.id,
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

function recommendationFor(question, profile, recommendations = null, now = undefined) {
  if (MANUAL_REVIEW_QUESTIONS.has(question.id) || question.recommendationPolicy?.class === "manual-only") {
    return {
      available: false,
      summary: question.recommendationPolicy?.summary || "This answer requires the operator.",
      reason: "manual-only"
    };
  }
  if (typeof bountyProfiles.programProfileRecommendation === "function") {
    const result = bountyProfiles.programProfileRecommendation(question.id, { profile, recommendations, now });
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

function authorizationSourceResolved(source, decisionTimeMs) {
  const observedAtMs = Date.parse(source?.observedAt);
  return source?.claimState === "observed" && Number.isFinite(observedAtMs) && observedAtMs <= decisionTimeMs;
}

function authorizationSourceReview(profile, decisionTimeMs) {
  const sources = new Map((profile.sources || []).map((source) => [source.id, source]));
  return (profile.authorization?.sourceRefs || []).map((sourceRef) => {
    const source = sources.get(sourceRef);
    if (!source) {
      return {
        id: sourceRef,
        title: "Referenced source is missing",
        type: null,
        observedAt: null,
        claimState: null,
        contentDigestRecorded: false,
        resolved: false,
        missing: true
      };
    }
    return {
      id: source.id,
      title: source.title,
      type: source.type,
      observedAt: source.observedAt,
      claimState: source.claimState,
      contentDigestRecorded: typeof source.contentSha256 === "string",
      resolved: authorizationSourceResolved(source, decisionTimeMs),
      missing: false
    };
  });
}

function publicRecommendation(recommendation, question) {
  const sensitive = question?.sensitive === true;
  const basis = sensitive
    ? null
    : typeof recommendation?.basis === "string"
      ? recommendation.basis
      : typeof recommendation?.basis?.policy === "string"
        ? recommendation.basis.policy
        : Number.isSafeInteger(recommendation?.basis?.sourceCount)
          ? `${recommendation.basis.sourceCount} cited local source${recommendation.basis.sourceCount === 1 ? "" : "s"}`
          : null;
  const claimState = ["observed", "inferred"].includes(recommendation?.basis?.claimState)
    ? recommendation.basis.claimState
    : null;
  const provenance = ["operator-preference", "source-derived", "local-derived"].includes(recommendation?.provenance)
    ? recommendation.provenance
    : null;
  return {
    available: recommendation?.available === true,
    provenance,
    summary: sensitive
      ? recommendation?.available === true
        ? "A private local recommendation is available; its value and supporting details remain hidden."
        : "No supported private recommendation is available yet."
      : recommendation?.summary || "No supported recommendation is available.",
    reason: sensitive ? null : recommendation?.reason || null,
    basis,
    claimState
  };
}

function serializeState(
  profileId,
  resumed,
  questionnaire,
  resolveRecommendation = recommendationFor,
  decisionTimeMs = Date.now()
) {
  const { profile, answers } = resumed;
  const answeredIds = new Set(Object.keys(answers.answers || {}));
  const selectedModules = new Set(profile.questionnaire?.applicableModules || []);
  const sections = questionnaireLayout(questionnaire).map((section) => {
    const sectionApplicable = section.kind !== "module" || selectedModules.has(section.moduleId);
    const questions = section.questions.map((question) => {
      const applicable = sectionApplicable && conditionMatches(question.condition, profile);
      const present = answeredIds.has(question.id);
      const value = present ? answers.answers[question.id] : undefined;
      const answered = present && (!applicable || !question.required ||
        programProfileQuestionAnswerIsComplete(question, value));
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
        answered,
        answerPresent: present,
        value: present ? structuredClone(value) : undefined,
        manualOnly: MANUAL_REVIEW_QUESTIONS.has(question.id) ||
          question.recommendationPolicy?.class === "manual-only",
        // Exact recommendation values stay inside the trusted local
        // controller. The browser receives only display-safe metadata and
        // invokes a server-side resolution when the operator accepts one.
        recommendation: publicRecommendation(resolveRecommendation(question, profile), question)
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
    !question.answerPresent && question.recommendation.available && !question.manualOnly).length;
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
    authorizationSources: authorizationSourceReview(profile, decisionTimeMs),
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

function fieldIssue(path, message) {
  return { path, message };
}

function validateRequiredFields(question, value, profile) {
  const issues = [];
  if (["text", "multiline", "datetime"].includes(question.type) && typeof value === "string" && !value.trim()) {
    issues.push(fieldIssue(question.path, "Enter a value or leave this question unresolved."));
  }
  if (question.type === "contact-list" && Array.isArray(value)) {
    if (value.length === 0) issues.push(fieldIssue(question.path, "Add at least one contact, or leave this question unresolved."));
    const sourceIds = new Set((profile.sources || []).map((source) => source.id));
    value.forEach((contact, index) => {
      if (!contact || typeof contact !== "object" || Array.isArray(contact)) {
        issues.push(fieldIssue(`${question.path}.${index}`, "Complete this contact with the guided fields."));
        return;
      }
      for (const key of ["name", "role", "channel", "purpose"]) {
        if (typeof contact[key] !== "string" || !contact[key].trim()) {
          issues.push(fieldIssue(`${question.path}.${index}.${key}`, `${key === "channel" ? "Published channel" : titleForField(key)} is required.`));
        }
      }
      if (!Array.isArray(contact.sourceRefs)) {
        issues.push(fieldIssue(`${question.path}.${index}.sourceRefs`, "Choose supporting sources from the local source ledger."));
      } else {
        contact.sourceRefs.forEach((sourceRef) => {
          if (!sourceIds.has(sourceRef)) {
            issues.push(fieldIssue(`${question.path}.${index}.sourceRefs`, "A selected supporting source is no longer available."));
          }
        });
      }
    });
  }
  if (question.type === "source-list" && Array.isArray(value)) {
    if (value.length === 0) issues.push(fieldIssue(question.path, "Add at least one source, or leave this question unresolved."));
    value.forEach((source, index) => {
      if (!source || typeof source !== "object" || Array.isArray(source)) {
        issues.push(fieldIssue(`${question.path}.${index}`, "Complete this source with the guided fields."));
        return;
      }
      for (const key of ["id", "type", "title", "reference", "observedAt", "claimState"]) {
        if (typeof source[key] !== "string" || !source[key].trim()) {
          issues.push(fieldIssue(`${question.path}.${index}.${key}`, `${titleForField(key)} is required.`));
        }
      }
    });
  }
  return issues;
}

function titleForField(value) {
  return String(value).replace(/([a-z])([A-Z])/gu, "$1 $2").replace(/^./u, (letter) => letter.toUpperCase());
}

function authorityReviewIssues(profile, request, decisionTimeMs) {
  const currentRefs = [...(profile.authorization?.sourceRefs || [])];
  const reviewedRefs = Array.isArray(request.reviewedSourceRefs) ? request.reviewedSourceRefs : [];
  const issues = [];
  if (currentRefs.length === 0) {
    issues.push(fieldIssue("authorization.sourceRefs", "Add the sources that establish authority before confirming."));
    return issues;
  }
  if (new Set(reviewedRefs).size !== reviewedRefs.length || reviewedRefs.length !== currentRefs.length ||
      currentRefs.some((sourceRef) => !reviewedRefs.includes(sourceRef))) {
    issues.push(fieldIssue("authorization.sourceRefs", "Review the complete current authority source set before confirming."));
  }
  const sources = new Map((profile.sources || []).map((source) => [source.id, source]));
  for (const sourceRef of currentRefs) {
    const source = sources.get(sourceRef);
    if (!source) {
      issues.push(fieldIssue("authorization.sourceRefs", "A referenced authority source is missing from the local ledger."));
    } else if (source.claimState !== "observed") {
      issues.push(fieldIssue("authorization.sourceRefs", "Every authority source must be observed before confirmation."));
    } else if (!authorizationSourceResolved(source, decisionTimeMs)) {
      issues.push(fieldIssue(
        "authorization.sourceRefs",
        "Every authority source must have a valid observation time at or before this review."
      ));
    }
  }
  return issues;
}

function questionIndex(questionnaire) {
  return new Map(questionnaireLayout(questionnaire).flatMap((section) => section.questions)
    .map((question) => [question.id, question]));
}

function publicMutationFailure(error, safeFieldPath = null) {
  if (error instanceof ProfileUiError) return error;
  if (/revision changed|digest changed|base profile|changed during/u.test(error?.message || "")) {
    return new ProfileUiError(409, "stale-profile", "This profile changed in another window. Reload it before saving.");
  }
  // Library errors can contain rejected values. Never derive browser-visible
  // field names from those strings; use only the questionnaire path already
  // selected by this trusted controller.
  const safeFields = typeof safeFieldPath === "string"
    ? [fieldIssue(safeFieldPath, "This answer did not match its required structure.")]
    : [];
  return new ProfileUiError(
    422,
    "answer-not-accepted",
    "GATE could not save this answer. Review the listed fields and try again.",
    safeFields
  );
}

export function createProfileWizardController(options = {}) {
  const { profileId, paths } = options;
  if (typeof profileId !== "string") throw new Error("profile wizard requires one selected profile id");
  const questionnaire = loadProgramProfileQuestionnaire({ paths });
  const questions = questionIndex(questionnaire);
  const recommendations = options.recommendations || null;

  const decisionTime = () => {
    const supplied = typeof options.now === "function" ? options.now() : options.now ?? Date.now();
    const milliseconds = new Date(supplied).getTime();
    if (!Number.isFinite(milliseconds)) throw new Error("profile wizard decision time is invalid");
    return { milliseconds, iso: new Date(milliseconds).toISOString() };
  };

  const current = () => bountyProfiles.resumeProgramProfile(profileId, { paths });
  const boundRecommendations = (resumed) => {
    if (!recommendations) return null;
    return recommendations.metadata?.programId === profileId &&
      recommendations.metadata?.baseRevision === resumed.profile.metadata.revision &&
      recommendations.metadata?.baseProfileSha256 === resumed.summary.profileSha256
      ? recommendations
      : null;
  };
  const stateAt = (at) => {
    const resumed = current();
    const activeRecommendations = boundRecommendations(resumed);
    return serializeState(
      profileId,
      resumed,
      questionnaire,
      (question, profile) => recommendationFor(question, profile, activeRecommendations, at.iso),
      at.milliseconds
    );
  };
  const state = () => stateAt(decisionTime());

  const saveAnswer = (request, mode = "answer") => {
    const at = decisionTime();
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
      const recommendation = recommendationFor(
        question,
        resumed.profile,
        boundRecommendations(resumed),
        at.iso
      );
      if (!recommendation.available || question.recommendationPolicy?.class === "manual-only") {
        throw new ProfileUiError(409, "recommendation-unavailable", "This question needs your answer or source evidence.");
      }
      value = recommendation.value;
    }
    if (!typeLooksValid(question, value)) {
      throw new ProfileUiError(422, "answer-shape-invalid", "Complete the visible fields using the expected answer format.", [
        fieldIssue(question.path, "Use the guided control or the documented advanced structure.")
      ]);
    }
    if (question.required && !programProfileQuestionAnswerIsComplete(question, value)) {
      throw new ProfileUiError(422, "answer-incomplete", "Complete this required answer before saving.", [
        fieldIssue(question.path, "Add at least one meaningful item or leave this question unresolved for now.")
      ]);
    }
    const fieldIssues = validateRequiredFields(question, value, resumed.profile);
    if (fieldIssues.length) {
      throw new ProfileUiError(422, "required-fields-missing", "Complete the required fields before saving.", fieldIssues);
    }
    if (question.id === "authority-operator-confirmed" && value === true) {
      const reviewIssues = authorityReviewIssues(resumed.profile, request, at.milliseconds);
      if (request.reviewAcknowledged !== true || reviewIssues.length) {
        throw new ProfileUiError(
          422,
          "source-review-required",
          "Review the complete current authority source set before confirming authority.",
          reviewIssues.length ? reviewIssues : [fieldIssue("authorization.sourceRefs", "Acknowledge the displayed current sources.")]
        );
      }
    }

    if (mode === "recommendation") {
      if (typeof bountyProfiles.applyProgramProfileRecommendation !== "function") {
        throw new ProfileUiError(501, "recommendation-unavailable", "This GATE build cannot apply one reviewed recommendation.");
      }
      try {
        bountyProfiles.applyProgramProfileRecommendation(profileId, question.id, question.recommendationPolicy?.class === "operator-preference" ? boundRecommendations(resumed) : recommendations, {
          paths,
          expectedRevision: resumed.profile.metadata.revision,
          expectedProfileSha256: resumed.summary.profileSha256,
          now: at.iso
        });
        return stateAt(at);
      } catch (error) {
        throw publicMutationFailure(error, question.path);
      }
    }

    const envelope = structuredClone(resumed.answers);
    envelope.metadata.updatedAt = at.iso;
    envelope.answers[question.id] = structuredClone(value);
    try {
      const applyAnswers = question.id === "authority-operator-confirmed" && value === true
        ? bountyProfiles.applyProgramProfileAuthorityConfirmation
        : bountyProfiles.applyProgramProfileAnswers;
      if (typeof applyAnswers !== "function") {
        throw new ProfileUiError(501, "authority-confirmation-unavailable", "This GATE build cannot record a reviewed authority confirmation.");
      }
      applyAnswers(profileId, envelope, { paths, now: at.iso });
      return stateAt(at);
    } catch (error) {
      throw publicMutationFailure(error, question.path);
    }
  };

  return Object.freeze({
    profileId,
    state,
    saveAnswer: (request) => saveAnswer(request, "answer"),
    applyRecommendation: (request) => saveAnswer(request, "recommendation"),
    clearAnswer(request) {
      const at = decisionTime();
      const resumed = current();
      assertMutationBase(request, resumed);
      const question = questions.get(request?.questionId);
      if (!question) throw new ProfileUiError(404, "question-not-found", "That profile question is no longer available.");
      if (!Object.hasOwn(resumed.answers.answers || {}, question.id)) return stateAt(at);
      if (typeof bountyProfiles.clearProgramProfileAnswer !== "function") {
        throw new ProfileUiError(501, "answer-clear-unavailable", "Clearing saved answers is not available in this GATE build.");
      }
      try {
        bountyProfiles.clearProgramProfileAnswer(profileId, question.id, {
          paths,
          expectedRevision: resumed.profile.metadata.revision,
          expectedProfileSha256: resumed.summary.profileSha256,
          now: at.iso
        });
        return stateAt(at);
      } catch (error) {
        throw publicMutationFailure(error, question.path);
      }
    },
    applySupportedRecommendations(request) {
      const at = decisionTime();
      const resumed = current();
      assertMutationBase(request, resumed);
      if (typeof bountyProfiles.applyProgramProfileRecommendations !== "function") {
        throw new ProfileUiError(501, "bulk-recommendations-unavailable", "Bulk recommendations are not available in this GATE build.");
      }
      try {
        bountyProfiles.applyProgramProfileRecommendations(profileId, boundRecommendations(resumed), {
          paths,
          expectedRevision: resumed.profile.metadata.revision,
          expectedProfileSha256: resumed.summary.profileSha256,
          now: at.iso
        });
        return stateAt(at);
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
