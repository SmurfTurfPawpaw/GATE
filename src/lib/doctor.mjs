import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { validateRepository } from "./validation.mjs";

const toolChecks = [
  { id: "node", command: "node", args: ["--version"], required: true },
  { id: "npm", command: "npm", args: ["--version"], required: true },
  { id: "git", command: "git", args: ["--version"], required: true },
  { id: "gh", command: "gh", args: ["--version"], required: true },
  { id: "codex", command: "codex", args: ["--version"], required: true },
  { id: "docker", command: "docker", args: ["--version"], required: false },
  { id: "tmux", command: "tmux", args: ["-V"], required: false },
  { id: "treehouse", command: "treehouse", args: ["--version"], required: false },
  { id: "gnhf", command: "gnhf", args: ["--version"], required: false },
  { id: "no-mistakes", command: "no-mistakes", args: ["version"], required: false },
  { id: "lavish-axi", command: "lavish-axi", args: ["--version"], required: false },
  { id: "rea", command: "rea", args: ["--version"], required: false }
];

function probeEnvironment() {
  const environment = {
    PATH: process.env.PATH || "",
    DISABLE_TELEMETRY: "1",
    DO_NOT_TRACK: "1",
    GNHF_TELEMETRY: "0",
    NO_MISTAKES_TELEMETRY: "0",
    LAVISH_AXI_TELEMETRY: "0"
  };
  for (const name of ["SystemRoot", "WINDIR", "PATHEXT", "LANG", "LC_ALL"]) {
    if (process.env[name]) environment[name] = process.env[name];
  }
  return environment;
}

function executablePresent(command) {
  const extensions = process.platform === "win32"
    ? (process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM").split(";")
    : [""];
  const directories = (process.env.PATH || "").split(pathDelimiter()).filter(Boolean);
  for (const directory of directories) {
    for (const extension of extensions) {
      const candidate = `${directory}/${command}${extension}`;
      try {
        fs.accessSync(candidate, process.platform === "win32" ? fs.constants.F_OK : fs.constants.X_OK);
        if (fs.statSync(candidate).isFile()) return true;
      } catch {
        // Continue through the bounded PATH supplied by the operator.
      }
    }
  }
  return false;
}

function pathDelimiter() {
  return process.platform === "win32" ? ";" : ":";
}

function checkTool(tool) {
  if (!tool.required) {
    return {
      ...tool,
      available: executablePresent(tool.command),
      version: null,
      error: null,
      probe: "presence-only"
    };
  }
  const result = spawnSync(tool.command, tool.args, {
    encoding: "utf8",
    timeout: 5000,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: probeEnvironment()
  });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim().split("\n")[0] || null;
  return {
    ...tool,
    available: !result.error && result.status === 0,
    version: output,
    error: result.error?.code || (result.status === null ? "timeout" : null),
    probe: "version"
  };
}

function readText(file) {
  try {
    return fs.readFileSync(file, "utf8").trim();
  } catch {
    return null;
  }
}

function linuxCapability(bit) {
  if (process.platform !== "linux") return null;
  const effective = readText("/proc/self/status")?.match(/^CapEff:\s*([a-f0-9]+)$/im)?.[1];
  if (!effective) return null;
  return (BigInt(`0x${effective}`) & (1n << BigInt(bit))) !== 0n;
}

function inspectCapabilities(host) {
  const interfaces = os.networkInterfaces();
  const interfaceNames = Object.entries(interfaces)
    .filter(([, addresses]) => addresses?.some((address) => !address.internal))
    .map(([name]) => name)
    .sort();
  const ptraceScope = readText("/proc/sys/kernel/yama/ptrace_scope");
  const capNetRaw = linuxCapability(13);
  const capNetAdmin = linuxCapability(12);
  return {
    capture: {
      nonLoopbackInterfaceCount: interfaceNames.length,
      interfaceNames,
      rawSocketCapability: capNetRaw,
      networkAdminCapability: capNetAdmin,
      note: capNetRaw === true
        ? "the current Linux process has CAP_NET_RAW"
        : capNetRaw === false
          ? "the current Linux process does not have CAP_NET_RAW"
          : "raw-socket capability was not established on this host"
    },
    debugger: {
      ptraceScope: ptraceScope === null ? null : Number(ptraceScope),
      note: ptraceScope === "0"
        ? "Linux Yama does not add a ptrace restriction"
        : ptraceScope === null
          ? "ptrace policy was not established on this host"
          : "Linux Yama restricts ptrace; exact access still depends on process ownership and capabilities"
    },
    usb: {
      linuxDeviceBusPresent: fs.existsSync("/dev/bus/usb"),
      note: host.wsl
        ? "WSL USB access also requires an attached device path such as usbipd-win"
        : "device presence does not establish permission or hardware support"
    },
    containers: {
      dockerSocketPresent: process.platform === "linux" ? fs.existsSync("/var/run/docker.sock") : null,
      engineReachability: "unprobed",
      note: "Doctor does not execute an optional Docker client; use docker info when an operator chooses to probe the engine"
    }
  };
}

export function runDoctor(options = {}) {
  const tools = toolChecks.map(checkTool);
  const validation = validateRepository(options);
  const requiredTools = tools.filter((tool) => tool.required);
  const host = {
    platform: process.platform,
    release: os.release(),
    architecture: process.arch,
    wsl: Boolean(process.env.WSL_DISTRO_NAME || os.release().toLowerCase().includes("microsoft"))
  };
  const result = {
    ok: validation.ok && requiredTools.every((tool) => tool.available),
    host,
    tools,
    repository: validation
  };
  if (options.full) result.capabilities = inspectCapabilities(host);
  return result;
}
