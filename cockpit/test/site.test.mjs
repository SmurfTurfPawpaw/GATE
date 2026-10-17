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
  const html = await readFile(new URL("index.html", output), "utf8");
  assert.doesNotMatch(html, /api\/fleet|session=|csrf=/u);
});

test("public snapshot names the exact repository version", async () => {
  const snapshot = JSON.parse(await read("data/status.json"));
  const repositoryPackage = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
  assert.equal(snapshot.gate.version, repositoryPackage.version);
});

test("concise preview puts disabled steering first and keeps exactly four metrics", async () => {
  const { all, byId } = documentModel(await read("index.html"));
  assert.equal(byId("mode-banner").children.some(element => element.tag === "strong" && element.text === "PREVIEW · NOT LIVE"), true);
  for (const id of ["message-input", "message-send"]) assert.ok("disabled" in byId(id).attributes);
  assert.equal("hidden" in byId("decision-panel").attributes, false);
  assert.ok(all.indexOf(byId("decision-panel")) < all.findIndex(element => element.attributes.class === "metric-grid"));
  const metrics = all.find(element => element.attributes.class === "metric-grid");
  assert.equal(metrics.children.filter(element => element.attributes.class?.includes("metric-card")).length, 4);
  for (const id of ["running-count", "question-count", "blocker-count", "token-usage"]) assert.ok(byId(id));
  for (const id of ["token-rail-scope", "overall-progress", "learning-count", "freshness-value", "snapshot-time"]) {
    assert.equal(byId(id), undefined);
  }
  assert.equal(all.some(element => element.attributes.class?.includes("terminal-controls")), false);
  assert.equal(all.some(element => element.attributes.class?.includes("terminal-command")), false);
  assert.equal(all.some(element => element.attributes.class?.includes("boundary-note")), false);
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

async function browser(snapshot) {
  const elements = new Map();
  const events = {};
  const requests = [];
  const context = {
    ...model, console, Intl, Date, TextEncoder, crypto: globalThis.crypto,
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
  assert.equal(elements.get("token-usage").textContent, "—");
  assert.equal(elements.get("running-count").textContent, "—");
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
  assert.equal(page.elements.get("token-usage").textContent, "—");
  assert.match(page.elements.get("token-summary").textContent, /unavailable/i);
  const group = page.elements.get("choice-list").children[0];
  group.children[1].children[1].listeners.click();
  await page.elements.get("choice-list").children.at(-1).listeners.click();
  assert.equal(submitted.answers.depth, "Focused");
  assert.equal(submitted.sessionRevision, 1);
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
