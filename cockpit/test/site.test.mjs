import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

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

test("all browser assets and navigation are relative for a GitHub Pages subpath", async () => {
  const html = await read("index.html");
  const references = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
  assert.ok(references.length >= 5);
  for (const reference of references) {
    if (reference.startsWith("#")) continue;
    assert.match(reference, /^\.\//, `expected relative reference, received ${reference}`);
    assert.doesNotMatch(reference, /^\//);
    assert.doesNotMatch(reference, /^https?:/);
  }

  const app = await read("assets/app.js");
  assert.match(app, /fetch\("\.\/data\/status\.json"/);
  assert.doesNotMatch(app, /fetch\("\//);
});

test("page has no third-party assets and declares a restrictive CSP and noindex", async () => {
  const html = await read("index.html");
  assert.doesNotMatch(html, /https?:\/\//);
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'self'/);
  assert.match(html, /connect-src 'self'/);
  assert.match(html, /base-uri 'none'/);
  assert.match(html, /name="robots" content="noindex, nofollow, noarchive, nosnippet"/);
  assert.doesNotMatch(html, /<script(?![^>]*src=)/);
  assert.doesNotMatch(html, /<style[\s>]/);
});

test("renderer uses textContent and never injects payload HTML", async () => {
  const app = await read("assets/app.js");
  assert.match(app, /textContent/);
  assert.doesNotMatch(app, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
});

test("private companion events visibly drive conversation, activity, tokens, and native choices", async () => {
  const app = await read("assets/app.js");
  const client = await read("companion/client.js");
  const model = await read("assets/model.js");
  assert.match(app, /addEventListener\("gate:companion-private-state"/u);
  assert.match(app, /addEventListener\("gate:companion-activity"/u);
  assert.match(app, /addEventListener\("gate:companion-connection"/u);
  assert.match(app, /addEventListener\("gate:companion-fleet"/u);
  assert.match(app, /renderLocalConversation\(\)/u);
  assert.match(app, /renderNativeQuestions\(pending, exactBridge\(\)\)/u);
  assert.match(app, /localState\.tokens\.total/u);
  assert.match(app, /bridge\.submitQuestion/u);
  assert.match(client, /submitQuestion: \(request\) => post\("\.\/api\/question", request\)/u);
  assert.match(client, /gate:companion-private-state/u);
  assert.match(client, /gate:companion-activity/u);
  assert.match(client, /fetch\("\.\/api\/fleet"/u);
  assert.match(client, /gate:companion-fleet/u);
  assert.match(model, /gate\.local-companion-state\/v1/u);
  assert.match(model, /gate\.local-cockpit-event\/v1/u);
  assert.match(model, /gate\.local-fleet\/v1/u);
});

test("sticky token rail exposes bounded counters, provenance, cost state, and attribution status", async () => {
  const html = await read("index.html");
  const app = await read("assets/app.js");
  const styles = await read("assets/styles.css");
  for (const id of [
    "token-provenance", "token-input-detail", "token-cached-detail", "token-output-detail",
    "token-total-detail", "token-cost-detail", "token-attribution"
  ]) assert.match(html, new RegExp(`id="${id}"`, "u"));
  assert.match(html, /Awaiting attribution/u);
  assert.match(app, /function renderTokenRail/u);
  assert.match(app, /Dedicated companion thread/u);
  assert.match(app, /Awaiting attribution/u);
  assert.match(styles, /\.token-rail\s*\{[^}]*position:\s*sticky/su);
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

test("preview honesty and disabled composer are visible before JavaScript", async () => {
  const html = await read("index.html");
  assert.match(html, /PREVIEW · NOT LIVE/);
  assert.match(html, /id="message-input"[^>]*disabled/);
  assert.match(html, /id="message-send"[^>]*disabled/);
  assert.ok(html.indexOf('id="decision-panel"') < html.indexOf('class="metric-grid"'));
  assert.doesNotMatch(html, /decision-panel[^>]*hidden/);

  const app = await read("assets/app.js");
  assert.match(app, /PREVIEW · NOT LIVE/);
  assert.match(app, /mode === "observed"/);
  assert.match(app, /acknowledgedDecisions/);
  assert.match(app, /display\.generatedAt === currentDisplay\.generatedAt/);
});

test("robots policy requests no crawling", async () => {
  const robots = await read("robots.txt");
  assert.match(robots, /^User-agent: \*\nDisallow: \/\n$/);
});
