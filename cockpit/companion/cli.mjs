#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { CodexCompanionAdapter } from "./app-server.mjs";
import { createGateFleetProvider, gateFleetInternals } from "./gate-fleet.mjs";
import { startCompanionServer } from "./server.mjs";

const COCKPIT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function usage() {
  return `Usage: node cockpit/companion/cli.mjs [options]

Options:
  --cwd PATH         Dedicated Codex thread working directory (default: GATE_REPO,
                     integrated GATE checkout)
  --gate-observer URL
                     Exact loopback GATE /api/status endpoint
                     (default: ${gateFleetInternals.DEFAULT_OBSERVER_URL})
  --host ADDRESS     127.0.0.1 or ::1 (default: 127.0.0.1)
  --port NUMBER      Loopback port, or 0 for an ephemeral port (default: 0)
  --thread-id ID     Resume one dedicated Codex app-server thread
  --persistent       Persist a newly created Codex thread
  --open             Open the private cockpit URL in the local browser
  --help             Show this help
`;
}

function defaultCodexCwd() {
  const configured = process.env.GATE_REPO?.trim();
  if (configured) return path.resolve(configured);
  return path.resolve(COCKPIT_ROOT, "..");
}

function parseArguments(argv) {
  const values = {
    cwd: defaultCodexCwd(),
    gateObserver: gateFleetInternals.DEFAULT_OBSERVER_URL,
    host: "127.0.0.1",
    port: 0,
    threadId: null,
    ephemeral: true,
    open: false
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help") return { help: true };
    if (argument === "--persistent") { values.ephemeral = false; continue; }
    if (argument === "--open") { values.open = true; continue; }
    if (!["--cwd", "--gate-observer", "--host", "--port", "--thread-id"].includes(argument)) {
      throw new Error(`unknown option: ${argument}`);
    }
    const value = argv[++index];
    if (!value) throw new Error(`${argument} requires a value`);
    if (argument === "--cwd") values.cwd = path.resolve(value);
    if (argument === "--gate-observer") values.gateObserver = value;
    if (argument === "--host") values.host = value;
    if (argument === "--port") values.port = Number(value);
    if (argument === "--thread-id") values.threadId = value;
  }
  return values;
}

function browserCommand(url) {
  if (process.platform === "win32") return ["rundll32.exe", ["url.dll,FileProtocolHandler", url]];
  if (process.platform === "darwin") return ["/usr/bin/open", [url]];
  const candidates = process.env.WSL_DISTRO_NAME
    ? ["/usr/bin/wslview", "/mnt/c/Windows/System32/rundll32.exe", "/usr/bin/xdg-open"]
    : ["/usr/bin/xdg-open"];
  const command = candidates.find((candidate) => fs.existsSync(candidate));
  if (!command) return null;
  return command.endsWith("rundll32.exe")
    ? [command, ["url.dll,FileProtocolHandler", url]]
    : [command, [url]];
}

function openBrowser(url) {
  const descriptor = browserCommand(url);
  if (!descriptor) return false;
  const child = spawn(descriptor[0], descriptor[1], {
    detached: true,
    shell: false,
    stdio: "ignore",
    windowsHide: true
  });
  child.unref();
  return true;
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${usage()}`);
    process.exitCode = 2;
    return;
  }
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  let fleetProvider;
  try {
    fleetProvider = createGateFleetProvider({ observerUrl: options.gateObserver });
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
    return;
  }
  const adapter = new CodexCompanionAdapter({
    cwd: options.cwd,
    ephemeral: options.ephemeral,
    threadId: options.threadId
  });
  process.stdout.write("GATE // Welcome, Giovanni.\nConnecting the private cockpit companion to a dedicated Codex thread…\n");
  try {
    await adapter.connect();
  } catch {
    process.stderr.write("Codex app-server is unavailable. Sign in with Codex, then restart this command.\n");
    process.exitCode = 1;
    await adapter.close().catch(() => {});
    return;
  }
  let companion;
  try {
    companion = await startCompanionServer({
      adapter,
      host: options.host,
      port: options.port,
      fleetProvider
    });
  } catch (error) {
    process.stderr.write(`The local cockpit companion could not start: ${error.message}\n`);
    process.exitCode = 1;
    await adapter.close().catch(() => {});
    return;
  }
  process.stdout.write(`Private cockpit: ${companion.url}\n`);
  process.stdout.write(`GATE fleet source: ${options.gateObserver}\n`);
  process.stdout.write("Keep this terminal open. Press Ctrl+C to stop the companion and its Codex app-server.\n");
  if (options.open) openBrowser(companion.url);

  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    await companion.close().catch(() => {});
  };
  process.once("SIGINT", () => close().then(() => process.exit(0)));
  process.once("SIGTERM", () => close().then(() => process.exit(0)));
}

await main();

export const cliInternals = Object.freeze({ browserCommand, defaultCodexCwd, parseArguments, usage });
