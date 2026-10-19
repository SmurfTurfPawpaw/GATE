import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, lstat, readFile, readdir, mkdtemp, cp, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import vm from "node:vm";
import * as model from "../assets/model.js";
import { createFileSnapshotProvider, startCompanionServer } from "../companion/server.mjs";

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");
const execute = promisify(execFile);

async function artifactFiles(root, directory = root) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = new URL(entry.name, directory);
    const stat = await lstat(absolute);
    assert.equal(stat.isSymbolicLink(), false, `public artifact must not contain symlink ${absolute.pathname}`);
    if (entry.isDirectory()) files.push(...await artifactFiles(root, new URL(`${entry.name}/`, directory)));
    else if (entry.isFile()) files.push(path.posix.relative(root.pathname, absolute.pathname));
    else assert.fail(`public artifact must contain regular files only: ${absolute.pathname}`);
  }
  return files.sort();
}

function documentModel(html) {
  const root = { tag: "document", attributes: {}, children: [], text: "" };
  const stack = [root];
  const voids = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
  for (const token of html.matchAll(/<!--[\s\S]*?-->|<![^>]*>|<\/[^>]+>|<[a-z][^>]*>|[^<]+/gi)) {
    const value = token[0];
    if (value.startsWith("<!")) continue;
    if (value.startsWith("</")) { stack.pop(); continue; }
    if (!value.startsWith("<")) { stack.at(-1).text += value; continue; }
    const tag = /^<([^\s/>]+)/.exec(value)[1].toLowerCase();
    const attributes = {};
    for (const attribute of value.slice(tag.length + 1, -1).matchAll(/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
      const name = attribute[1].toLowerCase();
      if (!(name in attributes)) attributes[name] = attribute[2] ?? attribute[3] ?? attribute[4] ?? "";
    }
    const element = { tag, attributes, children: [], text: "" };
    stack.at(-1).children.push(element);
    if (!voids.has(tag)) stack.push(element);
  }
  const all = [];
  const visit = element => { all.push(element); element.children.forEach(visit); };
  visit(root);
  return { all, byId: id => all.find(element => element.attributes.id === id) };
}

test("active document assets resolve within a Pages subpath", async () => {
  const { all } = documentModel(await read("index.html"));
  const base = new URL("https://preview.invalid/GATE/");
  const references = all.flatMap(element => ["src", "href"].filter(key => key in element.attributes).map(key => element.attributes[key]));
  assert.ok(references.length >= 5);
  for (const reference of references) {
    const resolved = new URL(reference, base);
    assert.equal(resolved.origin, base.origin);
    assert.ok(resolved.pathname.startsWith(base.pathname));
  }
  assert.equal(all.some(element => element.tag === "base"), false);
});

test("active document declares restrictive CSP and robots directives", async () => {
  const { all } = documentModel(await read("index.html"));
  const policy = all.find(element => element.tag === "meta" && element.attributes["http-equiv"]?.toLowerCase() === "content-security-policy");
  assert.ok(policy);
  const directives = new Map(policy.attributes.content.split(";").map(part => part.trim().split(/\s+/)).filter(parts => parts[0]).map(([name, ...values]) => [name, values]));
  for (const [name, values] of [["default-src", ["'none'"]], ["script-src", ["'self'"]], ["connect-src", ["'self'"]], ["base-uri", ["'none'"]]]) {
    assert.deepEqual(directives.get(name), values);
  }
  const robots = all.find(element => element.tag === "meta" && element.attributes.name === "robots");
  assert.deepEqual(new Set(robots.attributes.content.split(/,\s*/)), new Set(["noindex", "nofollow", "noarchive", "nosnippet"]));
  assert.equal(all.some(element => element.tag === "style" || element.tag === "script" && !element.attributes.src), false);
});

test("Pages build excludes every private companion and observer module", async () => {
  await execute(process.execPath, ["scripts/build-site.mjs"], { cwd: new URL("..", import.meta.url) });
  const output = new URL("../_site/", import.meta.url);
  assert.deepEqual(await artifactFiles(output), [
    ".nojekyll",
    "assets/app.js",
    "assets/favicon.svg",
    "assets/model.js",
    "assets/styles.css",
    "data/status.json",
    "index.html",
    "robots.txt"
  ]);
  await assert.rejects(access(new URL("companion/client.js", output)));
  await assert.rejects(access(new URL("remote/client.js", output)));
  const html = await readFile(new URL("index.html", output), "utf8");
  assert.doesNotMatch(html, /api\/fleet|api\/cockpit|remote\/client|session=|csrf=/u);
});

test("public snapshot names the exact repository version", async () => {
  const snapshot = JSON.parse(await read("data/status.json"));
  const repositoryPackage = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
  assert.equal(snapshot.gate.version, repositoryPackage.version);
});

test("preview puts the pilot scorecard first, keeps four fleet metrics, and makes steering secondary", async () => {
  const { all, byId } = documentModel(await read("index.html"));
  assert.equal(byId("mode-banner").children.some(element => element.tag === "strong" && element.text === "PREVIEW · NOT LIVE"), true);
  for (const id of ["message-input", "message-send"]) assert.ok("disabled" in byId(id).attributes);
  assert.equal("hidden" in byId("decision-panel").attributes, false);
  const visible = element => !("hidden" in element.attributes) && element.attributes["aria-hidden"] !== "true";
  const text = element => visible(element)
    ? [element.text, ...element.children.map(text)].join(" ").replace(/\s+/g, " ").trim()
    : "";
  const main = all.find(element => element.tag === "main");
  const sections = [];
  const visit = element => {
    if (!visible(element)) return;
    if (element.tag === "section") sections.push(element);
    element.children.forEach(visit);
  };
  visit(main);
  const name = element => element.attributes["aria-label"] || text(byId(element.attributes["aria-labelledby"]));
  assert.deepEqual(sections.map(name), ["Pilot status", "Current status", "Fleet", "Live activity", "Steer the dedicated runner"]);
  const metrics = sections[1].children.filter(visible);
  assert.deepEqual(metrics.map(metric => text(metric.children.find(element => element.tag === "small"))),
    ["ACTIVE WORK", "NEEDS YOU", "BLOCKERS", "TOKENS"]);
  assert.deepEqual(all.filter(element => /^h[1-6]$/.test(element.tag) && visible(element)).map(text),
    ["Pilot status", "Fleet", "Live activity", "Steer the dedicated runner"]);
  assert.deepEqual(byId("pilot-panel").children.find(element => element.attributes.class === "pilot-primary")
    .children.map(element => text(element.children.find(child => child.tag === "small"))),
    ["SOLVING", "LEARNING", "COCKPIT"]);
  assert.deepEqual(byId("pilot-panel").children.find(element => element.attributes.class === "pilot-plan")
    .children.map(element => text(element.children.find(child => child.tag === "small"))),
    ["NOW · PLAN STEP", "ACTION NEEDED", "LATEST VERIFIED EVENT"]);
  assert.match(text(byId("pilot-alert")), /Pilot feed unavailable/u);
  assert.match(text(byId("pilot-alert")), /observer and dedicated runner/u);
  assert.ok(byId("pilot-case-select"));
});

test("robots policy requests no crawling", async () => {
  const robots = await read("robots.txt");
  assert.match(robots, /^User-agent: \*\nDisallow: \/\n$/);
});


class Element {
  constructor(tag = "div") {
    this.tagName = tag;
    this.children = [];
    this.listeners = {};
    this.value = "";
    this.parentElement = { querySelector: () => null };
    this.style = { setProperty() {} };
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text || "") + this.children.map(child => child.textContent).join(""); }
  get firstChild() { return this.children[0]; }
  append(...children) { this.children.push(...children); }
  appendChild(child) { this.append(child); }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  removeAttribute(name) { delete this[name]; }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  querySelector(tag) { return this.children.find(child => child.tagName === tag); }
}

async function browser(snapshot, options = {}) {
  const elements = new Map();
  const events = {};
  const requests = [];
  const context = {
    ...model, console, Intl, Date, TextEncoder, crypto: globalThis.crypto,
    sessionStorage: options.sessionStorage,
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, new Element());
        return elements.get(id);
      },
      createTextNode: text => { const element = new Element(); element.textContent = text; return element; },
      createElement: tag => new Element(tag)
    },
    fetch: async url => {
      requests.push(url);
      return new Response(JSON.stringify(snapshot), { headers: { "content-type": "application/json" } });
    },
    addEventListener: (name, callback) => { events[name] = callback; },
    setTimeout: () => 1, clearTimeout() {}, setInterval() {}
  };
  context.window = context;
  vm.createContext(context);
  const source = await read("assets/app.js");
  vm.runInContext(source.slice(source.indexOf('const byId')), context);
  await new Promise(resolve => setImmediate(resolve));
  return { elements, events, requests, context };
}

function memorySessionStorage(initial = []) {
  const values = new Map(initial);
  return {
    getItem(key) { return values.has(key) ? values.get(key) : null; },
    setItem(key, value) { values.set(key, String(value)); },
    removeItem(key) { values.delete(key); }
  };
}

test("public preview renders campaigns and token budget without enabling writes", async () => {
  const snapshot = JSON.parse(await read("data/status.json"));
  const { elements, requests } = await browser(snapshot);
  assert.deepEqual(requests, ["./data/status.json"]);
  assert.equal(elements.get("campaign-list").children.length, snapshot.campaigns.length);
  assert.match(elements.get("mode-banner").textContent, /PREVIEW/);
  assert.match(elements.get("token-usage").textContent, /18\.4K \/ 50K/);
  assert.equal(elements.get("running-count").textContent, "1");
  assert.equal(elements.get("message-input").disabled, true);
  assert.equal(elements.get("message-send").disabled, true);
});

test("invalid public data renders unavailable without throwing", async () => {
  const { elements } = await browser({ privateCanary: "must not render" });
  assert.equal(elements.get("token-usage").textContent, "Unavailable");
  assert.equal(elements.get("running-count").textContent, "Unavailable");
  assert.equal(elements.get("message-send").disabled, true);
});

test("local startup without fleet telemetry renders native choices and submits selected answers", async () => {
  const page = await browser(JSON.parse(await read("data/status.json")));
  let submitted;
  page.context.GATE_PUBLIC_COCKPIT_BRIDGE = {
    apiVersion: "gate.local-cockpit-bridge/v1",
    submitMessage() {},
    async submitQuestion(request) {
      submitted = request;
      return { apiVersion: "gate.local-cockpit-receipt/v1", requestId: request.requestId, status: "accepted" };
    }
  };
  const at = new Date().toISOString();
  page.events["gate:companion-private-state"]({ detail: {
    apiVersion: "gate.local-companion-state/v1", sessionRevision: 1, stateRevision: 1,
    observedAt: at, connected: true, turn: "idle", tokens: null,
    conversation: [{ role: "codex", text: "Ready to continue", at }],
    pendingQuestions: [{ token: "q_" + "a".repeat(43), questions: [{
      id: "depth", header: "Depth", question: "Choose depth",
      options: [
        { label: "Deep", description: "Explore", recommended: true },
        { label: "Focused", description: "Limit", recommended: false }
      ]
    }] }]
  } });
  assert.match(page.elements.get("conversation").textContent, /Ready to continue/);
  assert.equal(page.elements.get("token-usage").textContent, "Unavailable");
  assert.match(page.elements.get("token-summary").textContent, /unavailable/i);
  const group = page.elements.get("choice-list").children[0];
  group.children[1].children[1].listeners.click();
  await page.elements.get("choice-list").children.at(-1).listeners.click();
  assert.equal(submitted.answers.depth, "Focused");
  assert.match(submitted.requestId, /^req-[0-9a-f-]{36}$/u);
  assert.equal(submitted.sessionRevision, 1);
  const status = page.elements.get("message-status");
  assert.match(status.textContent, /accepted the choices/);
  const retriedRequestIds = [];
  for (const accepted of [false, true]) {
    let finish;
    page.context.GATE_PUBLIC_COCKPIT_BRIDGE.submitMessage = request => new Promise(resolve => {
      retriedRequestIds.push(request.requestId);
      finish = () => resolve(accepted
        ? { apiVersion: "gate.local-cockpit-receipt/v1", requestId: request.requestId, status: "accepted" }
        : null);
    });
    page.elements.get("message-input").value = "Continue please";
    const submission = page.elements.get("message-composer").listeners.submit({ preventDefault() {} });
    page.events["gate:companion-connection"]({ detail: { connected: true } });
    assert.match(status.textContent, /Requesting local companion acceptance/);
    finish();
    await submission;
    const result = status.textContent;
    assert.match(result, accepted ? /accepted the message/ : /No valid local receipt/);
    page.events["gate:companion-connection"]({ detail: { connected: true } });
    assert.equal(status.textContent, result);
    assert.equal(page.elements.get("message-input").value, accepted ? "" : "Continue please");
  }
  assert.equal(retriedRequestIds[0], retriedRequestIds[1], "a preserved draft must replay its original idempotency key");
});

test("publication boundaries reject private canaries and preserve validated snapshot bytes", async () => {
  const temporary = await mkdtemp(new URL("../../snapshot-fixture-", import.meta.url));
  try {
    const root = path.join(temporary, "cockpit");
    await cp(new URL("../", import.meta.url), root, {
      recursive: true, filter: source => !source.includes("_site") && !source.includes("snapshot-fixture-") && !source.endsWith("/test")
    });
    await writeFile(path.join(temporary, "package.json"), await readFile(new URL("../../package.json", import.meta.url)));
    const file = path.join(root, "data/status.json");
    const bytes = await readFile(new URL("../data/status.json", import.meta.url));
    await writeFile(file, bytes);
    const provider = createFileSnapshotProvider(file);
    assert.deepEqual(await provider.readBytes(), bytes);
    await execute(process.execPath, [path.join(root, "scripts/build-site.mjs")]);
    assert.deepEqual(await readFile(path.join(root, "_site/data/status.json")), bytes);
    const invalid = JSON.parse(bytes);
    invalid.privateCanary = "PRIVATE_CANARY";
    const companion = await startCompanionServer({
      snapshotProvider: provider,
      adapter: { sendMessage() {}, answerQuestion() {}, privateState() {}, activityStore: {} }
    });
    try {
      const endpoint = new URL("/data/status.json", companion.url);
      const validResponse = await fetch(endpoint);
      assert.equal(validResponse.status, 200);
      assert.deepEqual(Buffer.from(await validResponse.arrayBuffer()), bytes);
      await writeFile(file, JSON.stringify(invalid));
      const rejected = await fetch(endpoint);
      assert.equal(rejected.status, 503);
      assert.doesNotMatch(await rejected.text(), /PRIVATE_CANARY/);
    } finally {
      await companion.close();
    }
    await assert.rejects(provider(), /invalid/);
    await assert.rejects(provider.readBytes(), /invalid/);
    await assert.rejects(execute(process.execPath, [path.join(root, "scripts/build-site.mjs")]), /invalid/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("private drafts survive invalid, missing, and expired preview refreshes", async () => {
  for (const response of [
    async () => { throw new Error("missing"); },
    async () => new Response("{", { headers: { "content-type": "application/json" } }),
    async () => {
      const expired = JSON.parse(await read("data/status.json"));
      expired.snapshot.validUntil = "2020-01-01T00:00:00Z";
      return new Response(JSON.stringify(expired), { headers: { "content-type": "application/json" } });
    }
  ]) {
    const page = await browser(JSON.parse(await read("data/status.json")));
    page.context.GATE_PUBLIC_COCKPIT_BRIDGE = {
      apiVersion: "gate.local-cockpit-bridge/v1",
      submitMessage() {}, submitQuestion() {}
    };
    page.events["gate:companion-private-state"]({ detail: {
      apiVersion: "gate.local-companion-state/v1", sessionRevision: 1, stateRevision: 1,
      observedAt: new Date().toISOString(), connected: true, turn: "idle", tokens: null,
      conversation: [], pendingQuestions: []
    } });
    page.elements.get("message-input").value = "Keep my unsent draft";
    page.context.fetch = response;
    await page.events["gate:companion-snapshot"]();
    assert.equal(page.elements.get("message-input").value, "Keep my unsent draft");
    assert.equal(page.elements.get("message-input").disabled, false);
    page.events["gate:companion-connection"]({ detail: { connected: false } });
    await page.events["gate:companion-snapshot"]();
    assert.equal(page.elements.get("message-input").value, "Keep my unsent draft");
  }
});

function remoteState(at, overrides = {}) {
  const validUntil = new Date(Date.parse(at) + 300_000).toISOString();
  return {
    apiVersion: "gate.remote-cockpit-state/v1", sessionRevision: 5, stateRevision: 1,
    observedAt: at, validUntil,
    runner: { state: "connected", observedAt: at }, codex: { state: "idle" }, tokens: null,
    conversation: [{ role: "codex", text: "Remote session ready", at }], pendingQuestions: [],
    ...overrides
  };
}

function remoteFleet(at, overrides = {}) {
  const unavailable = () => ({ value: null, precision: "unavailable" });
  const scan = (profile = false) => ({
    availability: "unavailable", discovered: null, scanned: null, omitted: null, invalid: null,
    discoveredAtLeast: false, omittedAtLeast: false, complete: false, truncated: true,
    ...(profile ? { visible: null, representedByCases: null } : {})
  });
  return {
    apiVersion: "gate.remote-fleet/v2", sessionRevision: 5, revision: 1, selectionEpoch: "0".repeat(32),
    observedAt: null, receivedAt: at, validUntil: new Date(Date.parse(at) + 15_000).toISOString(), connection: "unavailable", sourceFreshness: "unavailable",
    coverage: { state: "unavailable", cases: scan(), profiles: scan(true) },
    summary: {
      campaigns: unavailable(), active: unavailable(), waiting: unavailable(), attention: unavailable(),
      profileAnswers: { answered: null, total: null, precision: "unavailable" },
      runningExecutions: unavailable(), activeWorkflows: unavailable(), runningAnalyses: unavailable(),
      setupBlockers: unavailable(), blockers: unavailable(), campaignTokens: { availability: "unavailable", total: null },
      hostTokens: {
        availability: "unavailable", input: null, cachedInput: null, output: null, total: null,
        cost: { availability: "unavailable", amountMicros: null, unit: null }
      }
    },
    campaigns: [],
    ...overrides
  };
}

const pilotMetric = value => ({ availability: "available", value });

function remotePilot(at) {
  return {
    availability: "available", reason: null, observedAt: at,
    validUntil: new Date(Date.parse(at) + 180_000).toISOString(),
    solving: {
      availability: "available", verdict: "pass", now: "complete", actionNeeded: "none", updatedAt: at,
      completion: { state: "complete", reproduction: "confirmed", externalAcceptance: "accepted" },
      objectives: { availability: "available", completed: 1, total: 1 },
      depth: {
        level: "systematic", branchesExplored: pilotMetric(7), techniquesAttempted: pilotMetric(5),
        deadEndsRetired: pilotMetric(2)
      },
      efficiency: {
        elapsedSeconds: pilotMetric(900), activeSeconds: pilotMetric(600), tokens: pilotMetric(12_000),
        toolRuns: pilotMetric(8), requests: pilotMetric(31), retries: pilotMetric(1)
      }
    },
    learning: {
      availability: "available", verdict: "provisional", now: "checking", actionNeeded: "review", updatedAt: at,
      stages: {
        observations: pilotMetric(6), candidates: pilotMetric(4), validated: pilotMetric(3),
        applied: pilotMetric(2), transferred: pilotMetric(0), regressed: pilotMetric(0)
      }
    },
    cockpit: {
      availability: "available", verdict: "pass", now: "current", actionNeeded: "none", updatedAt: at,
      signals: { availability: "available", available: 10, total: 10 },
      updatesPublished: pilotMetric(12), updatesMissed: pilotMetric(0)
    },
    integrity: {
      availability: "available", status: "consistent",
      checks: { availability: "available", available: 6, total: 6 },
      issues: pilotMetric(0), checkedAt: at
    }
  };
}

function connectedRemoteFleet(at) {
  const exact = value => ({ value, precision: "exact" });
  const caseScan = {
    availability: "available", discovered: 1, scanned: 1, omitted: 0, invalid: 0,
    discoveredAtLeast: false, omittedAtLeast: false, complete: true, truncated: false
  };
  const profileScan = {
    availability: "available", discovered: 0, scanned: 0, omitted: 0, invalid: 0,
    discoveredAtLeast: false, omittedAtLeast: false, complete: true, truncated: false,
    visible: 0, representedByCases: 0
  };
  const work = {
    runningExecutions: exact(0), activeWorkflows: exact(0), runningAnalyses: exact(0), setupBlockers: exact(0)
  };
  return remoteFleet(at, {
    observedAt: at, connection: "connected", sourceFreshness: "current",
    coverage: { state: "exact", cases: caseScan, profiles: profileScan },
    summary: {
      campaigns: exact(1), active: exact(1), waiting: exact(0), attention: exact(0),
      profileAnswers: { answered: 0, total: 0, precision: "exact" }, blockers: exact(0),
      ...work,
      campaignTokens: { availability: "exact", total: 12_000 },
      hostTokens: {
        availability: "unavailable", input: null, cachedInput: null, output: null, total: null,
        cost: { availability: "unavailable", amountMicros: null, unit: null }
      }
    },
    campaigns: [{
      alias: "Campaign 1", kind: "case", stage: "active-testing", state: "running", progress: null,
      attention: "steady", freshness: "current", work,
      tokens: { availability: "exact", total: 12_000 }, pilot: remotePilot(at),
      latestEvent: { availability: "available", category: "campaign", status: "running", at }
    }]
  });
}

test("remote case-worker pilot events become the primary live scorecard", async () => {
  const page = await browser(JSON.parse(await read("data/status.json")));
  const at = new Date().toISOString();
  page.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands() { return null; },
    async submitMessage() { return null; }, async submitQuestion() { return null; }
  };
  page.events["gate:remote-private-state"]({ detail: remoteState(at) });
  page.events["gate:remote-fleet"]({ detail: connectedRemoteFleet(at) });
  page.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  assert.equal(page.elements.get("pilot-alert").hidden, true);
  assert.equal(page.elements.get("running-count").textContent, "1", "a running case counts even without an active workflow");
  assert.equal(page.elements.get("pilot-case-alias").textContent, "Campaign 1");
  assert.equal(page.elements.get("pilot-heartbeat").textContent, "Observer heartbeat current");
  assert.equal(page.elements.get("pilot-solving-verdict").textContent, "Pass");
  assert.equal(page.elements.get("pilot-learning-verdict").textContent, "Provisional");
  assert.equal(page.elements.get("pilot-cockpit-verdict").textContent, "Pass");
  assert.equal(page.elements.get("pilot-now").textContent, "Complete");
  assert.equal(page.elements.get("pilot-action").textContent, "Review");
  assert.equal(page.elements.get("pilot-depth").textContent, "Systematic");
  assert.equal(page.elements.get("pilot-learning").textContent, "Checking");
  assert.equal(page.elements.get("pilot-cockpit").textContent, "Current");
  assert.equal(page.elements.get("pilot-integrity").textContent, "Consistent");
  assert.equal(page.elements.get("pilot-event").textContent, "Campaign Running");
  assert.match(page.elements.get("pilot-learning-verdict-detail").textContent, /0 transferred/u);

  const transitionAt = new Date(Date.parse(at) + 1_000).toISOString();
  const transitioned = connectedRemoteFleet(transitionAt);
  transitioned.revision = 2;
  transitioned.campaigns[0].latestEvent.status = "succeeded";
  page.events["gate:remote-fleet"]({ detail: transitioned });
  assert.equal(page.elements.get("pilot-event").textContent, "Campaign Succeeded");
  assert.match(page.elements.get("pilot-event-detail").textContent, /Updated/u);

  const partialRuntime = structuredClone(connectedRemoteFleet(transitionAt));
  partialRuntime.revision = 3;
  partialRuntime.campaigns[0].latestEvent.status = "succeeded";
  partialRuntime.campaigns[0].pilot.solving.efficiency.elapsedSeconds = { availability: "unavailable", value: null };
  partialRuntime.campaigns[0].pilot.solving.efficiency.activeSeconds = { availability: "unavailable", value: null };
  page.events["gate:remote-fleet"]({ detail: partialRuntime });
  assert.equal(page.elements.get("pilot-efficiency").textContent, "12K tokens");
  assert.match(page.elements.get("pilot-efficiency-detail").textContent, /Duration unavailable/u);
  assert.match(page.elements.get("pilot-efficiency-detail").textContent, /31 requests/u);
  assert.match(page.elements.get("pilot-timeline").textContent, /complete/u);

  const blocked = structuredClone(partialRuntime);
  blocked.revision = 4;
  blocked.campaigns[0].state = "blocked";
  blocked.summary.blockers = { value: 1, precision: "exact" };
  page.events["gate:remote-fleet"]({ detail: blocked });
  assert.equal(page.elements.get("blocker-count").textContent, "1");
  assert.match(page.elements.get("blocker-summary").textContent, /Blocked cases/u);
});

test("multiple case scorecards retain an explicit safe alias selection across reload", async () => {
  const sessionStorage = memorySessionStorage();
  const at = new Date().toISOString();
  const fleet = connectedRemoteFleet(at);
  const second = structuredClone(fleet.campaigns[0]);
  second.alias = "Campaign 2";
  fleet.campaigns.push(second);
  fleet.coverage.cases.discovered = 2;
  fleet.coverage.cases.scanned = 2;
  fleet.summary.campaigns.value = 2;
  fleet.summary.active.value = 2;

  const connect = page => {
    page.context.GATE_REMOTE_COCKPIT_BRIDGE = {
      apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
      async reconcileCommands() { return null; }, async submitMessage() { return null; }, async submitQuestion() { return null; }
    };
    page.events["gate:remote-private-state"]({ detail: remoteState(at) });
    page.events["gate:remote-fleet"]({ detail: structuredClone(fleet) });
    page.events["gate:remote-connection"]({ detail: { apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at } });
  };

  const first = await browser(JSON.parse(await read("data/status.json")), { sessionStorage });
  connect(first);
  assert.equal(first.elements.get("pilot-case-alias").textContent, "No case selected");
  first.elements.get("pilot-case-select").value = "Campaign 2";
  first.elements.get("pilot-case-select").listeners.change();
  assert.equal(first.elements.get("pilot-case-alias").textContent, "Campaign 2");
  assert.deepEqual(JSON.parse(sessionStorage.getItem("gate.pilot-case-selection/v2")), {
    apiVersion: "gate.pilot-case-selection/v2", selectionEpoch: "0".repeat(32), alias: "Campaign 2"
  });

  const reloaded = await browser(JSON.parse(await read("data/status.json")), { sessionStorage });
  connect(reloaded);
  assert.equal(reloaded.elements.get("pilot-case-alias").textContent, "Campaign 2");

  const restartedFleet = structuredClone(fleet);
  restartedFleet.revision = 2;
  restartedFleet.selectionEpoch = "1".repeat(32);
  reloaded.events["gate:remote-fleet"]({ detail: restartedFleet });
  assert.equal(reloaded.elements.get("pilot-case-alias").textContent, "No case selected");
  assert.equal(sessionStorage.getItem("gate.pilot-case-selection/v2"), null);
});

test("authenticated remote mode queues commands and preserves drafts while disconnected", async () => {
  const page = await browser(JSON.parse(await read("data/status.json")));
  const at = new Date().toISOString();
  let submitted;
  page.events["gate:remote-private-state"]({ detail: remoteState(at) });
  page.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connecting", at
  } });
  assert.equal(page.elements.get("message-input").disabled, true, "state alone must remain read-only");
  page.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands() { return null; },
    async submitMessage(request) {
      submitted = request;
      return {
        apiVersion: "gate.remote-cockpit-receipt/v1", requestId: request.requestId, sessionRevision: 5,
        commandId: `cmd_${"a".repeat(36)}`, sequence: 1, status: "queued", acceptedAt: at
      };
    },
    async submitQuestion() { return null; }
  };
  page.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  assert.match(page.elements.get("mode-banner").textContent, /LIVE · REMOTE/);
  assert.equal(page.elements.get("message-input").disabled, false);
  page.events["gate:remote-private-state"]({ detail: remoteState(at, {
    stateRevision: 2, codex: { state: "waiting" }, pendingQuestions: []
  }) });
  assert.equal(page.elements.get("question-count").textContent, "1+");
  assert.match(page.elements.get("question-summary").textContent, /Open laptop/);
  page.elements.get("message-input").value = "Continue the remote run";
  await page.elements.get("message-composer").listeners.submit({ preventDefault() {} });
  assert.equal(submitted.apiVersion, "gate.remote-message-request/v1");
  assert.match(submitted.requestId, /^req-[0-9a-f-]{36}$/u);
  assert.equal(submitted.sessionRevision, 5);
  assert.equal(page.elements.get("message-input").value, "");
  assert.match(page.elements.get("message-status").textContent, /Queued for Codex/);

  page.events["gate:remote-command"]({ detail: {
    apiVersion: "gate.remote-command-event/v1", sequence: 2,
    at: new Date(Date.parse(at) + 1_000).toISOString(), requestId: submitted.requestId,
    commandId: `cmd_${"a".repeat(36)}`, state: "running"
  } });
  assert.match(page.elements.get("activity-feed").textContent, /running/i);

  page.elements.get("message-input").value = "Keep this draft";
  page.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "offline", at
  } });
  assert.equal(page.elements.get("message-input").disabled, true);
  assert.equal(page.elements.get("message-input").value, "Keep this draft");
  assert.match(page.elements.get("message-input").placeholder, /Live connection required/);

  page.events["gate:remote-revoked"]();
  assert.equal(page.elements.get("message-input").value, "");
  assert.equal(page.elements.get("message-input").disabled, true);
});

test("remote fleet remains visibly live while the Codex conversation is offline and recovers independently", async () => {
  const page = await browser(JSON.parse(await read("data/status.json")));
  const at = new Date().toISOString();
  page.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands() { return null; },
    async submitMessage() { throw new Error("offline conversation must not submit"); },
    async submitQuestion() { throw new Error("offline conversation must not submit"); }
  };
  page.events["gate:remote-private-state"]({ detail: remoteState(at, {
    codex: { state: "offline" }, pendingQuestions: []
  }) });
  page.events["gate:remote-fleet"]({ detail: connectedRemoteFleet(at) });
  page.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });

  assert.match(page.elements.get("mode-banner").textContent, /LIVE · FLEET · CODEX OFFLINE/u);
  assert.match(page.elements.get("connection-state").textContent, /Fleet live · Codex offline/u);
  assert.equal(page.elements.get("running-count").textContent, "1");
  assert.equal(page.elements.get("pilot-case-alias").textContent, "Campaign 1");
  assert.equal(page.elements.get("message-input").disabled, true);
  assert.match(page.elements.get("message-input").placeholder, /Codex conversation offline/u);
  assert.match(page.elements.get("message-status").textContent, /Fleet telemetry is live/u);

  const recoveredAt = new Date(Date.parse(at) + 1_000).toISOString();
  page.events["gate:remote-private-state"]({ detail: remoteState(recoveredAt, { stateRevision: 2 }) });
  assert.match(page.elements.get("mode-banner").textContent, /LIVE · REMOTE/u);
  assert.equal(page.elements.get("message-input").disabled, false);
});

test("remote projection loss clears state and fleet while preserving the connected transport", async () => {
  const page = await browser(JSON.parse(await read("data/status.json")));
  const at = new Date().toISOString();
  page.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands() { return null; },
    async submitMessage() { return null; }, async submitQuestion() { return null; }
  };
  page.events["gate:remote-private-state"]({ detail: remoteState(at) });
  page.events["gate:remote-fleet"]({ detail: remoteFleet(at) });
  page.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  page.elements.get("message-input").value = "Keep this draft";
  assert.match(page.elements.get("mode-banner").textContent, /LIVE · REMOTE/);
  assert.equal(page.elements.get("message-input").disabled, false);

  page.events["gate:remote-projection-unavailable"]({ detail: {
    apiVersion: "gate.remote-projection-unavailable/v1", projection: "state"
  } });
  assert.equal(vm.runInContext("remoteState", page.context), undefined);
  assert.equal(vm.runInContext("remoteFleet", page.context), undefined);
  assert.equal(vm.runInContext("remoteConnection.state", page.context), "connected");
  assert.match(page.elements.get("mode-banner").textContent, /REMOTE · OFFLINE/);
  assert.match(page.elements.get("conversation").textContent, /Live connection required/);
  assert.equal(page.elements.get("message-input").disabled, true);
  assert.equal(page.elements.get("message-input").value, "Keep this draft");

  const recoveredAt = new Date().toISOString();
  page.events["gate:remote-private-state"]({ detail: remoteState(recoveredAt, { stateRevision: 2 }) });
  assert.match(page.elements.get("mode-banner").textContent, /LIVE · REMOTE/);
  assert.equal(page.elements.get("message-input").disabled, false);
  assert.equal(page.elements.get("message-input").value, "Keep this draft");
});

test("remote reload retries reuse scoped request ids without persisting message or answer text", async () => {
  const snapshot = JSON.parse(await read("data/status.json"));
  const sessionStorage = memorySessionStorage();
  const at = new Date().toISOString();
  const pendingQuestion = {
    token: `q_${"r".repeat(43)}`,
    questions: [{
      id: "approach", header: "Approach", question: "How should Codex continue?",
      options: [
        { label: "Recommended route", description: "Use the reviewed path", recommended: true },
        { label: "Narrow route", description: "Reduce the work", recommended: false }
      ]
    }]
  };
  const failed = { messages: [], questions: [] };
  const first = await browser(snapshot, { sessionStorage });
  first.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands() { return null; },
    async submitMessage(request) { failed.messages.push(request); return null; },
    async submitQuestion(request) { failed.questions.push(request); return null; }
  };
  first.events["gate:remote-private-state"]({ detail: remoteState(at, {
    codex: { state: "waiting" }, pendingQuestions: [pendingQuestion]
  }) });
  first.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  first.elements.get("message-input").value = "Retry this private instruction after reload";
  await first.elements.get("message-composer").listeners.submit({ preventDefault() {} });
  await first.elements.get("choice-list").children.at(-1).listeners.click();
  assert.equal(failed.messages.length, 1);
  assert.equal(failed.questions.length, 1);

  const persisted = sessionStorage.getItem("gate.remote-cockpit-retry/v1");
  assert.ok(persisted);
  assert.doesNotMatch(persisted, /Retry this private instruction|Recommended route|Use the reviewed path/u);
  const metadata = JSON.parse(persisted);
  assert.equal(metadata.caseId, "alpha-case");
  assert.equal(metadata.sessionRevision, 5);
  assert.equal(metadata.entries.length, 2);
  assert.equal(metadata.entries.every(entry => /^[0-9a-f]{64}$/u.test(entry.digest)), true);

  const retried = { messages: [], questions: [] };
  const second = await browser(snapshot, { sessionStorage });
  second.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands() { return null; },
    async submitMessage(request) {
      retried.messages.push(request);
      return {
        apiVersion: "gate.remote-cockpit-receipt/v1", requestId: request.requestId, sessionRevision: 5,
        commandId: `cmd_${"m".repeat(36)}`, sequence: 1, status: "queued", acceptedAt: at
      };
    },
    async submitQuestion(request) {
      retried.questions.push(request);
      return {
        apiVersion: "gate.remote-cockpit-receipt/v1", requestId: request.requestId, sessionRevision: 5,
        commandId: `cmd_${"q".repeat(36)}`, sequence: 2, status: "queued", acceptedAt: at
      };
    }
  };
  second.events["gate:remote-private-state"]({ detail: remoteState(at, {
    codex: { state: "waiting" }, pendingQuestions: [pendingQuestion]
  }) });
  second.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  second.elements.get("message-input").value = "Retry this private instruction after reload";
  await second.elements.get("message-composer").listeners.submit({ preventDefault() {} });
  await second.elements.get("choice-list").children.at(-1).listeners.click();

  assert.equal(retried.messages[0].requestId, failed.messages[0].requestId);
  assert.equal(retried.questions[0].requestId, failed.questions[0].requestId);
  const queued = JSON.parse(sessionStorage.getItem("gate.remote-cockpit-retry/v1")).entries;
  assert.equal(queued.length, 2);
  assert.deepEqual(new Set(queued.map(entry => entry.commandId)), new Set([
    `cmd_${"m".repeat(36)}`, `cmd_${"q".repeat(36)}`
  ]));
  assert.doesNotMatch(JSON.stringify(queued), /Retry this private instruction|Recommended route|Use the reviewed path/u);

  for (const [sequence, request, commandId] of [
    [3, retried.messages[0], `cmd_${"m".repeat(36)}`],
    [4, retried.questions[0], `cmd_${"q".repeat(36)}`]
  ]) {
    second.events["gate:remote-command"]({ detail: {
      apiVersion: "gate.remote-command-event/v1", sequence, at,
      requestId: request.requestId, commandId, state: "completed"
    } });
  }
  assert.deepEqual(JSON.parse(sessionStorage.getItem("gate.remote-cockpit-retry/v1")).entries, []);

  const isolatedStorage = memorySessionStorage([["gate.remote-cockpit-retry/v1", persisted]]);
  const differentCase = await browser(snapshot, { sessionStorage: isolatedStorage });
  let isolatedRequest;
  differentCase.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "beta-case", sessionRevision: 5,
    async reconcileCommands() { return null; },
    async submitMessage(request) { isolatedRequest = request; return null; },
    async submitQuestion() { return null; }
  };
  differentCase.events["gate:remote-private-state"]({ detail: remoteState(at) });
  differentCase.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  differentCase.elements.get("message-input").value = "Retry this private instruction after reload";
  await differentCase.elements.get("message-composer").listeners.submit({ preventDefault() {} });
  assert.notEqual(isolatedRequest.requestId, failed.messages[0].requestId);
});

test("a queued question survives reload without duplicating its command", async () => {
  const snapshot = JSON.parse(await read("data/status.json"));
  const sessionStorage = memorySessionStorage();
  const at = new Date().toISOString();
  const pendingQuestion = {
    token: `q_${"s".repeat(43)}`,
    questions: [{
      id: "route", header: "Route", question: "Which route should Codex use?",
      options: [
        { label: "Recommended route", description: "Use the reviewed path", recommended: true },
        { label: "Narrow route", description: "Reduce the work", recommended: false }
      ]
    }]
  };
  let firstSubmission;
  const first = await browser(snapshot, { sessionStorage });
  first.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands() { return null; },
    async submitMessage() { return null; },
    async submitQuestion(request) {
      firstSubmission = request;
      return {
        apiVersion: "gate.remote-cockpit-receipt/v1", requestId: request.requestId, sessionRevision: 5,
        commandId: `cmd_${"s".repeat(36)}`, sequence: 1, status: "queued", acceptedAt: at
      };
    }
  };
  first.events["gate:remote-private-state"]({ detail: remoteState(at, {
    codex: { state: "waiting" }, pendingQuestions: [pendingQuestion]
  }) });
  first.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  await first.elements.get("choice-list").children.at(-1).listeners.click();
  assert.ok(firstSubmission);
  const persisted = sessionStorage.getItem("gate.remote-cockpit-retry/v1");
  assert.doesNotMatch(persisted, /Recommended route|Use the reviewed path/u);
  assert.equal(JSON.parse(persisted).entries[0].commandId, `cmd_${"s".repeat(36)}`);

  let duplicateSubmissions = 0;
  let statusRequest;
  let resolveStatus;
  const statusResult = new Promise((resolve) => { resolveStatus = resolve; });
  const reloaded = await browser(snapshot, { sessionStorage });
  reloaded.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands(request) { statusRequest = request; return statusResult; },
    async submitMessage() { return null; },
    async submitQuestion() { duplicateSubmissions += 1; return null; }
  };
  reloaded.events["gate:remote-private-state"]({ detail: remoteState(at, {
    codex: { state: "waiting" }, pendingQuestions: [pendingQuestion]
  }) });
  reloaded.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  const group = reloaded.elements.get("choice-list").children[0];
  const options = group.children[1].children;
  const submit = reloaded.elements.get("choice-list").children.at(-1);
  assert.equal(submit.textContent, "Queued");
  assert.equal(submit.disabled, true);
  assert.equal(options.every(option => option.disabled && option["aria-pressed"] === "false"), true);
  await submit.listeners.click();
  assert.equal(duplicateSubmissions, 0);

  assert.deepEqual(JSON.parse(JSON.stringify(statusRequest)), {
    apiVersion: "gate.remote-command-status-request/v1",
    caseId: "alpha-case",
    sessionRevision: 5,
    commands: [{ requestId: firstSubmission.requestId, commandId: `cmd_${"s".repeat(36)}` }]
  });
  resolveStatus({
    apiVersion: "gate.remote-command-status-response/v1",
    caseId: "alpha-case",
    sessionRevision: 5,
    commands: [{ requestId: firstSubmission.requestId, commandId: `cmd_${"s".repeat(36)}`, state: "completed" }]
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(JSON.parse(sessionStorage.getItem("gate.remote-cockpit-retry/v1")).entries, []);
  assert.equal(reloaded.elements.get("choice-list").children.length, 0,
    "authenticated status reconciliation must close a question whose terminal SSE event was pruned");
  reloaded.events["gate:remote-private-state"]({ detail: remoteState(at, {
    stateRevision: 2, codex: { state: "idle" }, pendingQuestions: []
  }) });
  assert.equal(reloaded.elements.get("choice-list").children.length, 0);
});

test("a pruned queued command releases its retained question for a new answer", async () => {
  const snapshot = JSON.parse(await read("data/status.json"));
  const at = new Date().toISOString();
  const questionToken = `q_${"p".repeat(43)}`;
  const requestId = "req-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const commandId = `cmd_${"p".repeat(36)}`;
  const sessionStorage = memorySessionStorage([["gate.remote-cockpit-retry/v1", JSON.stringify({
    apiVersion: "gate.remote-cockpit-retry/v1",
    caseId: "alpha-case",
    sessionRevision: 5,
    entries: [{
      kind: "question",
      requestId,
      digest: "a".repeat(64),
      questionToken,
      commandId
    }]
  })]]);
  const page = await browser(snapshot, { sessionStorage });
  let statusRequest;
  page.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    async reconcileCommands(request) {
      statusRequest = request;
      return {
        apiVersion: "gate.remote-command-status-response/v1",
        caseId: "alpha-case",
        sessionRevision: 5,
        commands: []
      };
    },
    async submitMessage() { return null; },
    async submitQuestion() { return null; }
  };
  page.events["gate:remote-private-state"]({ detail: remoteState(at, {
    codex: { state: "waiting" },
    pendingQuestions: [{
      token: questionToken,
      questions: [{
        id: "route", header: "Route", question: "Which route should Codex use?",
        options: [
          { label: "Recommended route", description: "Use the reviewed path", recommended: true },
          { label: "Narrow route", description: "Reduce the work", recommended: false }
        ]
      }]
    }]
  }) });
  page.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  await new Promise(resolve => setImmediate(resolve));

  assert.deepEqual(JSON.parse(JSON.stringify(statusRequest.commands)), [{ requestId, commandId }]);
  assert.deepEqual(JSON.parse(sessionStorage.getItem("gate.remote-cockpit-retry/v1")).entries, []);
  const submit = page.elements.get("choice-list").children.at(-1);
  assert.equal(submit.textContent, "Continue with selected answers");
  assert.equal(submit.disabled, false);
});

test("cockpit fails closed when local and remote bridges are both present", async () => {
  const page = await browser(JSON.parse(await read("data/status.json")));
  page.context.GATE_PUBLIC_COCKPIT_BRIDGE = {
    apiVersion: "gate.local-cockpit-bridge/v1", submitMessage() {}, submitQuestion() {}
  };
  page.context.GATE_REMOTE_COCKPIT_BRIDGE = {
    apiVersion: "gate.remote-cockpit-bridge/v1", caseId: "alpha-case", sessionRevision: 5,
    reconcileCommands() {}, submitMessage() {}, submitQuestion() {}
  };
  const at = new Date().toISOString();
  page.events["gate:remote-connection"]({ detail: {
    apiVersion: "gate.remote-cockpit-connection/v1", state: "connected", at
  } });
  page.events["gate:remote-private-state"]({ detail: remoteState(at) });
  assert.equal(page.elements.get("message-input").disabled, true);
  assert.match(page.elements.get("message-status").textContent, /Live connection required/);
  assert.doesNotMatch(page.elements.get("mode-banner").textContent, /LIVE · REMOTE/);
});

test("remote client withdraws live state on departure and reloads cached restorations", async () => {
  const source = await read("remote/client.js");
  const listeners = new Map();
  const signals = [];
  let reloads = 0;
  const context = {
    ...model,
    AbortController, CustomEvent, Date, Event, Intl, Promise, Response, TextDecoder, TextEncoder,
    console, crypto: globalThis.crypto,
    document: { readyState: "loading", addEventListener() {} },
    location: { reload() { reloads += 1; } },
    queueMicrotask, setTimeout, clearTimeout,
    setInterval: () => 1, clearInterval() {},
    addEventListener(name, callback) { listeners.set(name, callback); },
    dispatchEvent(event) { signals.push(event); return true; }
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(source.slice(source.indexOf("const API")), context);
  vm.runInContext(`
    session = Object.freeze({
      apiVersion: "gate.remote-cockpit-session/v1", sessionRevision: 5,
      csrf: "${"a".repeat(43)}", expiresAt: "2099-01-01T00:00:00.000Z", caseId: "alpha-case"
    });
    installBridge();
  `, context);
  const at = new Date().toISOString();
  assert.equal(vm.runInContext("acceptState", context)(remoteState(at)), true);
  assert.equal(vm.runInContext("acceptFleet", context)(remoteFleet(at)), true);
  assert.ok(context.GATE_REMOTE_COCKPIT_BRIDGE);
  listeners.get("pageshow")({ persisted: false });
  assert.equal(reloads, 0);
  listeners.get("pagehide")(new Event("pagehide"));
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, undefined);
  assert.equal(signals.at(-1).type, "gate:remote-connection");
  assert.equal(signals.at(-1).detail.state, "offline");
  assert.equal(signals.at(-2).type, "gate:remote-projection-unavailable");
  assert.equal(signals.at(-2).detail.projection, "state");
  listeners.get("pageshow")({ persisted: true });
  assert.equal(reloads, 1);
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, undefined);
});

test("remote client expires and withdraws unavailable projections while SSE stays ready", async () => {
  const source = await read("remote/client.js");
  const listeners = new Map();
  const projectionSignals = [];
  const fetches = [];
  let expiryResolve;
  const expired = new Promise(resolve => { expiryResolve = resolve; });
  const context = {
    ...model,
    AbortController, CustomEvent, Date, Event, Intl, Promise, Response, TextDecoder, TextEncoder,
    console, crypto: globalThis.crypto,
    document: { readyState: "loading", addEventListener() {} },
    queueMicrotask,
    setInterval: () => 1,
    clearInterval() {},
    setTimeout,
    clearTimeout,
    addEventListener(name, callback) {
      listeners.set(name, [...(listeners.get(name) || []), callback]);
    },
    dispatchEvent(event) {
      if (event.type === "gate:remote-projection-unavailable") {
        projectionSignals.push(event.detail);
        expiryResolve?.();
      }
      for (const callback of listeners.get(event.type) || []) callback(event);
      return true;
    },
    async fetch(url) {
      fetches.push(url);
      if (url.endsWith("/state")) {
        return new Response(JSON.stringify({
          apiVersion: "gate.remote-error/v1", error: { code: "projection-unavailable", message: "Unavailable" }
        }), { status: 503, headers: { "content-type": "application/json" } });
      }
      throw new Error(`unexpected fetch ${url}`);
    }
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(source.slice(source.indexOf("const API")), context);
  vm.runInContext(`
    session = Object.freeze({
      apiVersion: "gate.remote-cockpit-session/v1", sessionRevision: 5,
      csrf: "${"a".repeat(43)}", expiresAt: "2099-01-01T00:00:00.000Z", caseId: "alpha-case"
    });
    streamReady = true;
    installBridge();
  `, context);
  const bridge = context.GATE_REMOTE_COCKPIT_BRIDGE;
  const observedAt = new Date().toISOString();
  const state = remoteState(observedAt, {
    validUntil: new Date(Date.parse(observedAt) + 200).toISOString()
  });
  assert.equal(vm.runInContext("acceptState", context)(state), true);
  assert.equal(vm.runInContext("acceptFleet", context)(remoteFleet(observedAt)), true);
  let expiryTimeout;
  await Promise.race([
    expired,
    new Promise((_, reject) => {
      expiryTimeout = setTimeout(() => reject(new Error("projection expiry timeout")), 2_000);
    })
  ]).finally(() => clearTimeout(expiryTimeout));
  assert.equal(projectionSignals.length, 1);
  assert.equal(projectionSignals[0].apiVersion, "gate.remote-projection-unavailable/v1");
  assert.equal(projectionSignals[0].projection, "state");
  assert.equal(vm.runInContext("latestState", context), null);
  assert.equal(vm.runInContext("latestFleet", context), null);
  assert.equal(vm.runInContext("streamReady", context), true);
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, bridge);
  await assert.rejects(bridge.submitMessage({
    apiVersion: "gate.remote-message-request/v1", requestId: "req-00000000-0000-4000-8000-000000000000",
    sessionRevision: 5, message: "Do not send stale work"
  }), /rejected/);

  const recoveredAt = new Date().toISOString();
  assert.equal(vm.runInContext("acceptState", context)(remoteState(recoveredAt, { stateRevision: 2 })), true);
  assert.equal(vm.runInContext("acceptFleet", context)(remoteFleet(recoveredAt, { revision: 2 })), true);
  assert.equal(await vm.runInContext("readState()", context), false);
  assert.equal(projectionSignals.length, 2);
  assert.equal(projectionSignals[1].apiVersion, "gate.remote-projection-unavailable/v1");
  assert.equal(projectionSignals[1].projection, "state");
  assert.equal(vm.runInContext("latestState", context), null);
  assert.equal(vm.runInContext("latestFleet", context), null);
  assert.equal(vm.runInContext("streamReady", context), true);
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, bridge);
  assert.equal(fetches.filter(url => url.endsWith("/messages")).length, 0);
  vm.runInContext("clearTimers(); stopped = true", context);
});

test("remote fleet expiry clears campaign telemetry while conversation state stays usable", async () => {
  const source = await read("remote/client.js");
  const listeners = new Map();
  const projectionSignals = [];
  let fleetExpiryResolve;
  const fleetExpired = new Promise(resolve => { fleetExpiryResolve = resolve; });
  const context = {
    ...model,
    AbortController, CustomEvent, Date, Event, Intl, Promise, Response, TextDecoder, TextEncoder,
    console, crypto: globalThis.crypto,
    document: { readyState: "loading", addEventListener() {} },
    queueMicrotask,
    setInterval: () => 1,
    clearInterval() {},
    setTimeout,
    clearTimeout,
    addEventListener(name, callback) {
      listeners.set(name, [...(listeners.get(name) || []), callback]);
    },
    dispatchEvent(event) {
      if (event.type === "gate:remote-projection-unavailable") {
        projectionSignals.push(event.detail);
        if (event.detail.projection === "fleet") fleetExpiryResolve?.();
      }
      for (const callback of listeners.get(event.type) || []) callback(event);
      return true;
    },
    async fetch(url) { throw new Error(`unexpected fetch ${url}`); }
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(source.slice(source.indexOf("const API")), context);
  vm.runInContext(`
    session = Object.freeze({
      apiVersion: "gate.remote-cockpit-session/v1", sessionRevision: 5,
      csrf: "${"a".repeat(43)}", expiresAt: "2099-01-01T00:00:00.000Z", caseId: "alpha-case"
    });
    streamReady = true;
    installBridge();
  `, context);
  const at = new Date().toISOString();
  assert.equal(vm.runInContext("acceptState", context)(remoteState(at, {
    validUntil: new Date(Date.parse(at) + 5_000).toISOString()
  })), true);
  assert.equal(vm.runInContext("acceptFleet", context)(remoteFleet(at, {
    validUntil: new Date(Date.parse(at) + 200).toISOString()
  })), true);
  let timeout;
  await Promise.race([
    fleetExpired,
    new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("fleet expiry timeout")), 2_000); })
  ]).finally(() => clearTimeout(timeout));
  assert.equal(projectionSignals.at(-1).projection, "fleet");
  assert.equal(vm.runInContext("latestFleet", context), null);
  assert.equal(vm.runInContext("latestState.conversation[0].text", context), "Remote session ready");
  assert.ok(context.GATE_REMOTE_COCKPIT_BRIDGE);
  vm.runInContext("clearTimers(); stopped = true", context);
});

test("remote client replays expired fleet history after resync, reaches newer frames, and revokes writes on disconnect", async () => {
  const source = await read("remote/client.js");
  const listeners = new Map();
  const encoder = new TextEncoder();
  const at = new Date();
  const expiresAt = new Date(at.getTime() + 60 * 60_000).toISOString();
  let stateReads = 0;
  let fleetReads = 0;
  let eventController;
  let streamCancelled = false;
  const stateProjections = [];
  const fleetProjections = [];
  const projectionUnavailable = [];
  let eventRequestedResolve;
  const eventRequested = new Promise(resolve => { eventRequestedResolve = resolve; });
  let connectedResolve;
  const connected = new Promise(resolve => { connectedResolve = resolve; });
  const connections = [];
  const fetches = [];
  const statusPosts = [];
  const fleetProjection = (revision) => {
    const unavailable = () => ({ value: null, precision: "unavailable" });
    const scan = (profile = false) => ({
      availability: "unavailable", discovered: null, scanned: null, omitted: null, invalid: null,
      discoveredAtLeast: false, omittedAtLeast: false, complete: false, truncated: true,
      ...(profile ? { visible: null, representedByCases: null } : {})
    });
    return {
      apiVersion: "gate.remote-fleet/v2", sessionRevision: 5, revision, selectionEpoch: "0".repeat(32),
      observedAt: null, receivedAt: new Date().toISOString(),
      validUntil: new Date(Date.now() + 15_000).toISOString(),
      connection: "unavailable", sourceFreshness: "unavailable",
      coverage: { state: "unavailable", cases: scan(), profiles: scan(true) },
      summary: {
        campaigns: unavailable(), active: unavailable(), waiting: unavailable(), attention: unavailable(),
        profileAnswers: { answered: null, total: null, precision: "unavailable" },
        runningExecutions: unavailable(), activeWorkflows: unavailable(), runningAnalyses: unavailable(), setupBlockers: unavailable(), blockers: unavailable(),
        campaignTokens: { availability: "unavailable", total: null },
        hostTokens: {
          availability: "unavailable", input: null, cachedInput: null, output: null, total: null,
          cost: { availability: "unavailable", amountMicros: null, unit: null }
        }
      },
      campaigns: []
    };
  };
  const context = {
    ...model,
    AbortController, CustomEvent, Date, Event, Intl, Promise, ReadableStream, Response, TextDecoder, TextEncoder,
    console, crypto: globalThis.crypto,
    document: { readyState: "complete" },
    queueMicrotask,
    setInterval: () => 1,
    clearInterval() {},
    setTimeout,
    clearTimeout,
    addEventListener(name, callback) {
      listeners.set(name, [...(listeners.get(name) || []), callback]);
    },
    dispatchEvent(event) {
      if (event.type === "gate:remote-connection") {
        connections.push(event.detail.state);
        if (event.detail.state === "connected") connectedResolve();
      }
      if (event.type === "gate:remote-projection-unavailable") projectionUnavailable.push(event.detail.projection);
      for (const callback of listeners.get(event.type) || []) callback(event);
      return true;
    },
    async fetch(url, init = {}) {
      fetches.push(url);
      if (url.endsWith("/session")) {
        return new Response(JSON.stringify({
          apiVersion: "gate.remote-cockpit-session/v1", sessionRevision: 5,
          csrf: "a".repeat(43), expiresAt, caseId: "alpha-case"
        }), { headers: { "content-type": "application/json" } });
      }
      if (url.endsWith("/state")) {
        stateReads += 1;
        const observedAt = new Date().toISOString();
        const projection = remoteState(observedAt, { stateRevision: stateReads });
        stateProjections.push(projection);
        return new Response(JSON.stringify(projection), {
          headers: { "content-type": "application/json" }
        });
      }
      if (url.endsWith("/fleet")) {
        fleetReads += 1;
        const projection = fleetProjection(fleetReads);
        fleetProjections.push(projection);
        return new Response(JSON.stringify(projection), {
          headers: { "content-type": "application/json" }
        });
      }
      if (url.endsWith("/commands/status")) {
        statusPosts.push(init);
        const request = JSON.parse(init.body);
        return new Response(JSON.stringify({
          apiVersion: "gate.remote-command-status-response/v1",
          caseId: request.caseId,
          sessionRevision: request.sessionRevision,
          commands: request.commands.map((reference) => ({ ...reference, state: "completed" }))
        }), { headers: { "content-type": "application/json" } });
      }
      if (url.includes("/events?cursor=0")) {
        const body = new ReadableStream({
          start(controller) { eventController = controller; },
          cancel() { streamCancelled = true; }
        });
        eventRequestedResolve();
        return new Response(body, { headers: { "content-type": "text/event-stream" } });
      }
      throw new Error(`unexpected fetch ${url}`);
    }
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(source.slice(source.indexOf("const API")), context);
  await eventRequested;
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, undefined);

  eventController.enqueue(encoder.encode(
    'id: 7\nevent: resync\ndata: {"apiVersion":"gate.remote-resync/v1","cursor":7}\n\n'
  ));
  for (let attempt = 0; attempt < 20 && (stateReads < 2 || fleetReads < 2); attempt += 1) {
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.equal(stateReads, 2);
  assert.equal(fleetReads, 2);
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, undefined, "resync alone must remain read-only");
  assert.equal(streamCancelled, false, `stream closed during resync: ${connections.join(",")}`);

  eventController.enqueue(encoder.encode(
    'event: ready\ndata: {"apiVersion":"gate.remote-events-ready/v1","cursor":7}\n\n'
  ));
  await Promise.race([
    connected,
    new Promise((_, reject) => setTimeout(() => reject(new Error("ready event timeout")), 1_000))
  ]);
  const bridge = context.GATE_REMOTE_COCKPIT_BRIDGE;
  assert.equal(bridge?.apiVersion, "gate.remote-cockpit-bridge/v1");
  assert.equal(bridge?.caseId, "alpha-case");
  assert.deepEqual(connections.slice(-2), ["connecting", "connected"]);

  const statusRequest = {
    apiVersion: "gate.remote-command-status-request/v1",
    caseId: "alpha-case",
    sessionRevision: 5,
    commands: [{
      requestId: "req-00000000-0000-4000-8000-000000000000",
      commandId: `cmd_${"a".repeat(36)}`
    }]
  };
  assert.equal((await bridge.reconcileCommands(statusRequest)).commands[0].state, "completed");
  assert.equal(statusPosts.length, 1);
  assert.equal(statusPosts[0].method, "POST");
  assert.equal(statusPosts[0].headers["X-GATE-CSRF"], "a".repeat(43));
  assert.deepEqual(JSON.parse(statusPosts[0].body), statusRequest);

  context.GATE_PUBLIC_COCKPIT_BRIDGE = {};
  await assert.rejects(bridge.submitMessage({
    apiVersion: "gate.remote-message-request/v1", requestId: "req-00000000-0000-4000-8000-000000000000",
    sessionRevision: 5, message: "Continue"
  }), /rejected/);
  delete context.GATE_PUBLIC_COCKPIT_BRIDGE;

  eventController.enqueue(encoder.encode(
    `id: 8\nevent: state\ndata: ${JSON.stringify(stateProjections[0])}\n\n`
  ));
  const expiredFleetAt = new Date(Date.now() - 30_000).toISOString();
  const expiredFleetReplay = remoteFleet(expiredFleetAt, { revision: 1 });
  eventController.enqueue(encoder.encode(
    `id: 9\nevent: fleet\ndata: ${JSON.stringify(expiredFleetReplay)}\n\n`
  ));
  eventController.enqueue(encoder.encode(
    `id: 10\nevent: state\ndata: ${JSON.stringify(stateProjections[1])}\n\n`
  ));
  const currentExpiredFleetReplay = remoteFleet(expiredFleetAt, { revision: 3 });
  eventController.enqueue(encoder.encode(
    `id: 11\nevent: fleet\ndata: ${JSON.stringify(currentExpiredFleetReplay)}\n\n`
  ));
  const recoveredFleet = fleetProjection(4);
  eventController.enqueue(encoder.encode(
    `id: 12\nevent: fleet\ndata: ${JSON.stringify(recoveredFleet)}\n\n`
  ));
  for (let attempt = 0; attempt < 20 && vm.runInContext("lastCursor", context) < 12; attempt += 1) {
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.equal(vm.runInContext("lastCursor", context), 12,
    "valid stale, expired, and duplicate projections must advance the stream cursor");
  assert.ok(projectionUnavailable.includes("fleet"), "an expired current fleet frame must clear its UI projection");
  assert.equal(vm.runInContext("latestFleet.revision", context), 4,
    "a newer fleet projection must be accepted after expired history");
  assert.equal(vm.runInContext("acceptFleet", context)(expiredFleetReplay), false,
    "ordinary fleet reads must remain freshness-strict");
  assert.equal(vm.runInContext("acceptFleet", context)(
    { ...expiredFleetReplay, privateCanary: "must-not-cross" }, { allowExpiredReplay: true }
  ), false, "expired replay must retain the exact private projection boundary");
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, bridge);
  assert.equal(streamCancelled, false);

  const conflictingState = {
    ...stateProjections[1],
    codex: { state: stateProjections[1].codex.state === "idle" ? "working" : "idle" }
  };
  eventController.enqueue(encoder.encode(
    `id: 13\nevent: state\ndata: ${JSON.stringify(conflictingState)}\n\n`
  ));
  for (let attempt = 0; attempt < 20 && !streamCancelled; attempt += 1) {
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.equal(streamCancelled, true, "same-revision projection conflicts must close the stream");
  assert.equal(vm.runInContext("lastCursor", context), 12, "a conflicting projection must not advance the cursor");
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, undefined);

  for (const callback of listeners.get("pagehide") || []) callback(new Event("pagehide"));
  assert.equal(context.GATE_REMOTE_COCKPIT_BRIDGE, undefined);
  await assert.rejects(bridge.submitMessage({
    apiVersion: "gate.remote-message-request/v1", requestId: "req-00000000-0000-4000-8000-000000000000",
    sessionRevision: 5, message: "Continue"
  }), /rejected/);
  assert.equal(fetches.filter(url => url.endsWith("/messages")).length, 0);
});
