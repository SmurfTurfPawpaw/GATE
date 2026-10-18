import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import path from "node:path";

import { ActivityStore } from "./activity.mjs";
import { CompanionContractError, containsLikelyCredential, questionToken } from "./contracts.mjs";

const MAX_PROTOCOL_LINE_BYTES = 4 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const MAX_CONVERSATION_ENTRIES = 48;
const MAX_VISIBLE_MESSAGE_CHARACTERS = 4_000;

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function tokenCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function unavailableCost() {
  return Object.freeze({ availability: "unavailable", amountMicros: null, unit: null });
}

function estimatedThreadCost(value, threadId) {
  const usage = record(value?.threadUsage) ? value.threadUsage : null;
  if (!usage || usage.threadId !== threadId) return unavailableCost();
  const usd = tokenCount(usage.estimatedUsageUsdMicros);
  if (usd !== null) return Object.freeze({ availability: "estimated", amountMicros: usd, unit: "USD" });
  const credits = tokenCount(usage.estimatedUsageCreditsMicros);
  return credits === null
    ? unavailableCost()
    : Object.freeze({ availability: "estimated", amountMicros: credits, unit: "credits" });
}

function boundedText(value, maximum) {
  if (typeof value !== "string") return null;
  const normalized = value.normalize("NFC").replace(/\r\n?/gu, "\n").trim();
  const characters = [...normalized];
  if (characters.length < 1 || characters.length > maximum
      || /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u.test(normalized)) return null;
  return normalized;
}

function itemCategory(type) {
  if (type === "commandExecution" || type === "mcpToolCall" || type === "dynamicToolCall") return "tool";
  if (type === "fileChange") return "file-change";
  if (type === "webSearch") return "research";
  if (type === "collabAgentToolCall" || type === "subAgentActivity") return "agent";
  return null;
}

function completedState(item) {
  const status = typeof item?.status === "string" ? item.status.toLowerCase() : "";
  if (["failed", "declined", "error", "cancelled"].includes(status)) return "failed";
  return "completed";
}

function visibleAssistantMessage(item) {
  if (item?.type !== "agentMessage") return null;
  const text = boundedText(item.text, MAX_VISIBLE_MESSAGE_CHARACTERS);
  if (!text) return null;
  return containsLikelyCredential(text)
    ? "A Codex message was withheld because it may contain a credential. Review it in the local Codex session."
    : text;
}

function sanitizeQuestionRequest(params) {
  if (!record(params) || !Array.isArray(params.questions)
      || params.questions.length < 1 || params.questions.length > 3) return null;
  const questions = [];
  const ids = new Set();
  for (const question of params.questions) {
    if (!record(question) || question.isSecret === true || question.isOther === true
        || typeof question.id !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/u.test(question.id)
        || ids.has(question.id)) return null;
    const header = boundedText(question.header, 24);
    const prompt = boundedText(question.question, 500);
    if (!header || !prompt || !Array.isArray(question.options)
        || question.options.length < 2 || question.options.length > 3) return null;
    const options = [];
    const labels = new Set();
    for (const [optionIndex, option] of question.options.entries()) {
      if (!record(option)) return null;
      const label = boundedText(option.label, 100);
      const description = boundedText(option.description, 300);
      if (!label || !description || labels.has(label) || containsLikelyCredential(`${label} ${description}`)) return null;
      labels.add(label);
      const recommended = /\(Recommended\)$/u.test(label);
      if ((optionIndex === 0) !== recommended) return null;
      options.push(Object.freeze({ label, description, recommended }));
    }
    if (containsLikelyCredential(`${header} ${prompt}`)) return null;
    ids.add(question.id);
    questions.push(Object.freeze({ id: question.id, header, question: prompt, options: Object.freeze(options) }));
  }
  return Object.freeze(questions);
}

export class JsonLineAppServer extends EventEmitter {
  #child;
  #buffer = "";
  #nextId = 1;
  #pending = new Map();
  #closed = false;
  #requestTimeoutMs;
  #spawnProcess;

  constructor(options = {}) {
    super();
    this.#requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (!Number.isSafeInteger(this.#requestTimeoutMs) || this.#requestTimeoutMs < 1_000 || this.#requestTimeoutMs > 300_000) {
      throw new Error("app-server request timeout must be between 1000 and 300000 milliseconds");
    }
    this.#spawnProcess = options.spawnProcess || ((command, args, spawnOptions) => spawn(command, args, spawnOptions));
    this.command = options.command || "codex";
    this.args = Object.freeze(options.args || ["app-server", "--stdio"]);
    this.cwd = path.resolve(options.cwd || process.cwd());
  }

  async start() {
    if (this.#child) return;
    if (this.#closed) throw new Error("app-server transport is closed");
    const child = this.#spawnProcess(this.command, [...this.args], {
      cwd: this.cwd,
      env: process.env,
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"]
    });
    this.#child = child;
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => this.#read(chunk));
    // stderr can contain local diagnostics and paths. Drain it, but never place
    // it in a browser-visible event or an exception body.
    child.stderr.on("data", () => {});
    child.once("error", () => this.#shutdown(new Error("Codex app-server could not start")));
    child.once("exit", () => this.#shutdown(new Error("Codex app-server stopped")));
    await new Promise((resolve, reject) => {
      const onSpawn = () => { child.off("error", onError); resolve(); };
      const onError = () => { child.off("spawn", onSpawn); reject(new Error("Codex app-server could not start")); };
      child.once("spawn", onSpawn);
      child.once("error", onError);
    });
  }

  request(method, params = {}) {
    if (!this.#child || this.#closed || !this.#child.stdin.writable) {
      return Promise.reject(new Error("Codex app-server is unavailable"));
    }
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error("Codex app-server request timed out"));
      }, this.#requestTimeoutMs);
      timer.unref?.();
      this.#pending.set(id, { resolve, reject, timer });
      this.#write({ id, method, params });
    });
  }

  notify(method, params = {}) {
    if (!this.#child || this.#closed || !this.#child.stdin.writable) throw new Error("Codex app-server is unavailable");
    this.#write({ method, params });
  }

  respond(id, result) {
    this.#write({ id, result });
  }

  respondError(id, code = -32601, message = "This request is not supported by the local cockpit companion.") {
    this.#write({ id, error: { code, message } });
  }

  async close() {
    if (this.#closed) return;
    this.#closed = true;
    const child = this.#child;
    this.#child = undefined;
    this.#shutdown(new Error("Codex app-server closed"));
    if (!child || child.exitCode !== null) return;
    child.kill("SIGTERM");
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
        resolve();
      }, 2_000);
      timer.unref?.();
      child.once("exit", () => { clearTimeout(timer); resolve(); });
    });
  }

  #write(value) {
    if (!this.#child || this.#closed || !this.#child.stdin.writable) throw new Error("Codex app-server is unavailable");
    this.#child.stdin.write(`${JSON.stringify(value)}\n`);
  }

  #read(chunk) {
    this.#buffer += chunk;
    if (Buffer.byteLength(this.#buffer, "utf8") > MAX_PROTOCOL_LINE_BYTES) {
      this.#child?.kill("SIGKILL");
      this.#shutdown(new Error("Codex app-server protocol limit exceeded"));
      return;
    }
    while (true) {
      const newline = this.#buffer.indexOf("\n");
      if (newline < 0) return;
      const line = this.#buffer.slice(0, newline).trim();
      this.#buffer = this.#buffer.slice(newline + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      if (!record(message)) continue;
      if ((typeof message.id === "number" || typeof message.id === "string")
          && (Object.hasOwn(message, "result") || Object.hasOwn(message, "error"))) {
        const pending = this.#pending.get(message.id);
        if (!pending) continue;
        this.#pending.delete(message.id);
        clearTimeout(pending.timer);
        if (Object.hasOwn(message, "error")) pending.reject(new Error("Codex app-server rejected the request"));
        else pending.resolve(message.result);
        continue;
      }
      if ((typeof message.id === "number" || typeof message.id === "string") && typeof message.method === "string") {
        this.emit("request", message);
      } else if (typeof message.method === "string") {
        this.emit("notification", message.method, message.params);
      }
    }
  }

  #shutdown(error) {
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.#pending.clear();
    this.emit("closed");
  }
}

export class CodexCompanionAdapter extends EventEmitter {
  #transport;
  #activity;
  #threadId = null;
  #activeTurnId = null;
  #connected = false;
  #conversation = [];
  #tokens = null;
  #cost = unavailableCost();
  #costRefresh = null;
  #questions = new Map();
  #submission = Promise.resolve();
  #sessionRevision = crypto.randomInt(1, 2_147_483_648);
  #stateRevision = 0;
  #busyWithoutTurnId = false;

  constructor(options = {}) {
    super();
    this.cwd = path.resolve(options.cwd || process.cwd());
    this.ephemeral = options.ephemeral !== false;
    this.resumeThreadId = options.threadId || null;
    this.#activity = options.activityStore || new ActivityStore();
    this.#transport = options.transport || new JsonLineAppServer({
      cwd: this.cwd,
      command: options.command,
      args: options.args,
      spawnProcess: options.spawnProcess,
      requestTimeoutMs: options.requestTimeoutMs
    });
    this.#transport.on("notification", (method, params) => this.#notification(method, params));
    this.#transport.on("request", (request) => this.#serverRequest(request));
    this.#transport.on("closed", () => {
      if (this.#connected) this.#activity.append({ category: "waiting", state: "blocked" });
      this.#connected = false;
      this.#changed();
    });
  }

  get activityStore() {
    return this.#activity;
  }

  async connect() {
    if (this.#connected) return;
    await this.#transport.start();
    await this.#transport.request("initialize", {
      clientInfo: { name: "gate-cockpit", title: "GATE Local Cockpit", version: "0.3.0" },
      capabilities: { experimentalApi: true }
    });
    this.#transport.notify("initialized", {});
    const result = this.resumeThreadId
      ? await this.#transport.request("thread/resume", { threadId: this.resumeThreadId, cwd: this.cwd })
      : await this.#transport.request("thread/start", {
        cwd: this.cwd,
        ephemeral: this.ephemeral,
        threadSource: "gate-cockpit"
      });
    const threadId = result?.thread?.id;
    if (typeof threadId !== "string" || threadId.length < 8) throw new Error("Codex app-server did not return a thread");
    this.#threadId = threadId;
    const status = result.thread.status;
    const activeTurn = Array.isArray(result.thread.turns)
      ? result.thread.turns.findLast((turn) => turn?.status === "inProgress" && typeof turn.id === "string")
      : null;
    this.#activeTurnId = activeTurn?.id || null;
    this.#busyWithoutTurnId = status?.type === "active" && !this.#activeTurnId;
    this.#connected = true;
    this.#activity.append({ category: "waiting", state: "completed" });
    this.#changed();
    void this.#refreshCost();
  }

  sendMessage(request) {
    return this.#serialize(async () => {
      if (!this.#connected || !this.#threadId) throw new Error("Codex is not connected");
      if (this.#busyWithoutTurnId) throw new Error("The resumed Codex thread is busy in another client");
      const input = [{ type: "text", text: request.message }];
      let result;
      if (this.#activeTurnId) {
        result = await this.#transport.request("turn/steer", {
          threadId: this.#threadId,
          expectedTurnId: this.#activeTurnId,
          clientUserMessageId: request.requestId,
          input
        });
      } else {
        result = await this.#transport.request("turn/start", {
          threadId: this.#threadId,
          clientUserMessageId: request.requestId,
          input
        });
        if (typeof result?.turn?.id === "string") this.#activeTurnId = result.turn.id;
      }
      this.#pushConversation("operator", request.message);
      this.#changed();
      return result;
    });
  }


  answerQuestion(response) {
    return this.#serialize(async () => {
      const pending = this.#questions.get(response.questionToken);
      if (!pending) throw new CompanionContractError(409, "question-expired", "That question is no longer active. Reload the cockpit.");
      const answerKeys = Object.keys(response.answers).sort();
      const questionKeys = pending.questions.map((question) => question.id).sort();
      if (answerKeys.length !== questionKeys.length || answerKeys.some((key, index) => key !== questionKeys[index])) {
        throw new CompanionContractError(400, "question-response-invalid", "Answer every displayed question before continuing.");
      }
      const answers = {};
      for (const question of pending.questions) {
        const selected = response.answers[question.id];
        if (!question.options.some((option) => option.label === selected)) {
          throw new CompanionContractError(400, "question-response-invalid", "Choose one of the displayed answers.");
        }
        answers[question.id] = { answers: [selected] };
      }
      this.#questions.delete(response.questionToken);
      this.#transport.respond(pending.requestId, { answers });
      this.#activity.append({ category: "waiting", state: "completed" });
      this.#changed();
    });
  }

  privateState() {
    const questions = [...this.#questions.entries()].map(([token, pending]) => Object.freeze({
      token,
      questions: pending.questions
    }));
    return Object.freeze({
      apiVersion: "gate.local-companion-state/v1",
      sessionRevision: this.#sessionRevision,
      stateRevision: this.#stateRevision,
      observedAt: new Date().toISOString(),
      connected: this.#connected,
      turn: this.#questions.size > 0 || this.#busyWithoutTurnId ? "waiting" : this.#activeTurnId ? "working" : "idle",
      tokens: this.#tokens,
      conversation: Object.freeze(this.#conversation.map((entry) => Object.freeze({ ...entry }))),
      pendingQuestions: Object.freeze(questions)
    });
  }

  async close() {
    this.#connected = false;
    await this.#transport.close();
  }

  #serialize(action) {
    const next = this.#submission.then(action, action);
    this.#submission = next.catch(() => {});
    return next;
  }

  #changed() {
    this.#stateRevision += 1;
    this.emit("state");
  }

  async #refreshCost() {
    if (!this.#connected || !this.#threadId || this.#costRefresh) return this.#costRefresh;
    const threadId = this.#threadId;
    this.#costRefresh = this.#transport.request("account/usage/read", { threadId })
      .then((result) => {
        if (this.#threadId !== threadId) return;
        const next = estimatedThreadCost(result, threadId);
        const changed = JSON.stringify(next) !== JSON.stringify(this.#cost);
        this.#cost = next;
        if (this.#tokens) this.#tokens = Object.freeze({ ...this.#tokens, cost: this.#cost });
        if (changed) this.#changed();
      })
      .catch(() => {})
      .finally(() => { this.#costRefresh = null; });
    return this.#costRefresh;
  }

  #pushConversation(role, text) {
    this.#conversation.push(Object.freeze({ role, text, at: new Date().toISOString() }));
    if (this.#conversation.length > MAX_CONVERSATION_ENTRIES) {
      this.#conversation.splice(0, this.#conversation.length - MAX_CONVERSATION_ENTRIES);
    }
  }

  #serverRequest(request) {
    if (request.method !== "item/tool/requestUserInput" || request.params?.threadId !== this.#threadId
        || request.params?.isBlocking !== true || typeof this.#activeTurnId !== "string"
        || request.params?.turnId !== this.#activeTurnId || typeof request.params?.itemId !== "string") {
      this.#transport.respondError(request.id);
      this.#activity.append({ category: "waiting", state: "blocked" });
      return;
    }
    const questions = sanitizeQuestionRequest(request.params);
    if (!questions || this.#questions.size >= 8) {
      this.#transport.respondError(request.id, -32602, "This question must be answered in the local Codex interface.");
      this.#activity.append({ category: "waiting", state: "blocked" });
      return;
    }
    const token = questionToken();
    this.#questions.set(token, { requestId: request.id, turnId: request.params.turnId, questions });
    this.#activity.append({ category: "waiting", state: "started" });
    this.#changed();
  }

  #notification(method, params) {
    if (["turn/started", "turn/completed", "thread/tokenUsage/updated", "item/started", "item/completed"].includes(method)
        && params?.threadId !== this.#threadId) return;
    if (method === "turn/started") {
      if (typeof params?.turn?.id !== "string"
          || (this.#activeTurnId !== null && params.turn.id !== this.#activeTurnId)) return;
      this.#activeTurnId = params.turn.id;
      this.#busyWithoutTurnId = false;
      this.#activity.append({ category: "thinking", state: "started" });
      this.#changed();
      return;
    }
    if (method === "turn/completed") {
      if (typeof this.#activeTurnId !== "string" || params?.turn?.id !== this.#activeTurnId) return;
      this.#activeTurnId = null;
      this.#busyWithoutTurnId = false;
      for (const [token, pending] of this.#questions) {
        if (pending.turnId === params?.turn?.id) this.#questions.delete(token);
      }
      const state = params?.turn?.status === "completed" ? "completed" : "failed";
      this.#activity.append({ category: "thinking", state });
      this.#changed();
      return;
    }
    if (method === "thread/tokenUsage/updated") {
      if (typeof this.#activeTurnId !== "string" || params?.turnId !== this.#activeTurnId) return;
      const usage = params?.tokenUsage?.total;
      const input = tokenCount(usage?.inputTokens);
      const cachedInput = tokenCount(usage?.cachedInputTokens);
      const output = tokenCount(usage?.outputTokens);
      const reasoningOutput = tokenCount(usage?.reasoningOutputTokens);
      const total = tokenCount(usage?.totalTokens);
      const contextWindow = params?.tokenUsage?.modelContextWindow ?? null;
      if ([input, cachedInput, output, reasoningOutput, total].every((value) => value !== null)
          && (contextWindow === null || (Number.isSafeInteger(contextWindow) && contextWindow > 0))) {
        this.#tokens = Object.freeze({
          availability: "exact",
          source: "codex-notification",
          input,
          cachedInput,
          output,
          reasoningOutput,
          total,
          contextWindow,
          cost: this.#cost
        });
        this.#activity.append({ category: "thinking", state: "progress", tokens: { total, contextWindow } });
        this.#changed();
        void this.#refreshCost();
      }
      return;
    }
    if (method !== "item/started" && method !== "item/completed") return;
    if (typeof this.#activeTurnId !== "string" || params?.turnId !== this.#activeTurnId) return;
    const item = params?.item;
    const assistantMessage = method === "item/completed" ? visibleAssistantMessage(item) : null;
    if (assistantMessage) {
      this.#pushConversation("codex", assistantMessage);
      this.#changed();
    }
    const category = itemCategory(item?.type);
    if (!category) return;
    this.#activity.append({
      category,
      state: method === "item/started" ? "started" : completedState(item)
    });
  }
}

export const appServerInternals = Object.freeze({
  DEFAULT_REQUEST_TIMEOUT_MS,
  MAX_CONVERSATION_ENTRIES,
  MAX_PROTOCOL_LINE_BYTES,
  boundedText,
  completedState,
  estimatedThreadCost,
  itemCategory,
  sanitizeQuestionRequest,
  visibleAssistantMessage
});
