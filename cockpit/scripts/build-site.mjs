import { parsePublicSnapshot } from "../assets/model.js";
import { lstat, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(root, "..");
const output = path.join(root, "_site");
const publicFiles = Object.freeze([
  ".nojekyll",
  "index.html",
  "robots.txt",
  "assets/app.js",
  "assets/favicon.svg",
  "assets/model.js",
  "assets/styles.css",
  "data/status.json"
]);

async function readStableRegularFile(file) {
  const before = await lstat(file, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`public cockpit source must be a regular file: ${file}`);
  const bytes = await readFile(file);
  const after = await lstat(file, { bigint: true });
  if (!after.isFile() || after.isSymbolicLink()
      || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs) {
    throw new Error(`public cockpit source changed during build: ${file}`);
  }
  return bytes;
}

const sourceEntries = await Promise.all(publicFiles.map(async (relative) => [
  relative,
  await readStableRegularFile(path.join(root, relative))
]));
const sourceBytes = new Map(sourceEntries);
const repositoryPackage = await readStableRegularFile(path.join(repositoryRoot, "package.json"));
const publicSnapshot = sourceBytes.get("data/status.json");
const gateVersion = JSON.parse(repositoryPackage.toString("utf8")).version;
const snapshot = JSON.parse(publicSnapshot.toString("utf8"));
if (publicSnapshot.length > 65_536 || parsePublicSnapshot(snapshot).kind !== "available") {
  throw new Error("public cockpit snapshot is invalid");
}
const snapshotVersion = snapshot.gate.version;
if (typeof gateVersion !== "string" || snapshotVersion !== gateVersion) {
  throw new Error(`public cockpit GATE version ${snapshotVersion ?? "missing"} does not match package version ${gateVersion ?? "missing"}`);
}

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: false });
for (const relative of publicFiles) {
  const destination = path.join(output, relative);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, sourceBytes.get(relative), { flag: "wx" });
}

const html = await readFile(path.join(output, "index.html"), "utf8");
for (const required of ["./assets/styles.css", "./assets/app.js", "./assets/favicon.svg"]) {
  if (!html.includes(required)) throw new Error(`missing relative asset reference: ${required}`);
}
