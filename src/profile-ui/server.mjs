import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runtimePaths } from "../lib/paths.mjs";
import { createProfileWizardController, ProfileUiError } from "./controller.mjs";

const STATIC_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../profile-ui");
const MAX_BODY_BYTES = 512 * 1024;
const DEFAULT_MAX_REQUESTS = 4096;
const STATIC_FILES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["index.html", "text/html; charset=utf-8"]],
  ["/profile-ui/styles.css", ["styles.css", "text/css; charset=utf-8"]],
  ["/profile-ui/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/profile-ui/accessibility.js", ["accessibility.js", "text/javascript; charset=utf-8"]],
  ["/profile-ui/time.js", ["time.js", "text/javascript; charset=utf-8"]]
]);
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "font-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join("; ");

function token() {
  return crypto.randomBytes(32).toString("base64url");
}

function sameToken(actual, expected) {
  if (typeof actual !== "string") return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function isLoopback(host) {
  return host === "127.0.0.1" || host === "::1";
}

function commonHeaders(contentType) {
  return {
    "Cache-Control": "no-store, max-age=0",
    "Content-Security-Policy": CSP,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Type": contentType
  };
}

function reply(res, status, body, contentType = "application/json; charset=utf-8") {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  res.writeHead(status, { ...commonHeaders(contentType), "Content-Length": bytes.length });
  res.end(bytes);
}

function json(res, status, value) {
  reply(res, status, `${JSON.stringify(value)}\n`);
}

async function readJson(req) {
  if (!String(req.headers["content-type"] || "").toLowerCase().startsWith("application/json")) {
    throw new ProfileUiError(415, "json-required", "This endpoint accepts JSON only.");
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw new ProfileUiError(413, "request-too-large", "The answer is too large for the local profile form.");
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("object required");
    return value;
  } catch (error) {
    if (error instanceof ProfileUiError) throw error;
    throw new ProfileUiError(400, "invalid-json", "The browser sent an invalid form payload. Reload and try again.");
  }
}

function publicError(error) {
  if (error instanceof ProfileUiError) {
    return {
      status: error.status,
      body: {
        ok: false,
        error: {
          code: error.code,
          message: error.publicMessage,
          fields: error.fields
        }
      }
    };
  }
  return {
    status: 500,
    body: { ok: false, error: { code: "profile-ui-failure", message: "The local profile form could not complete that action." } }
  };
}

function expectedHost(host, port) {
  const canonicalHost = host === "::1" ? "[::1]" : host;
  return port === 80 ? canonicalHost : `${canonicalHost}:${port}`;
}

function browserCommand(url, options = {}) {
  if (typeof options.browserOpener === "function") return { custom: options.browserOpener, url };
  const platform = options.platform || process.platform;
  if (platform === "win32") return { command: "rundll32.exe", args: ["url.dll,FileProtocolHandler", url] };
  if (platform === "darwin") return { command: "/usr/bin/open", args: [url] };
  const candidates = process.env.WSL_DISTRO_NAME
    ? ["/usr/bin/wslview", "/mnt/c/Windows/System32/rundll32.exe", "/usr/bin/xdg-open"]
    : ["/usr/bin/xdg-open"];
  const command = candidates.find((candidate) => fs.existsSync(candidate));
  if (!command) return null;
  return command.endsWith("rundll32.exe")
    ? { command, args: ["url.dll,FileProtocolHandler", url] }
    : { command, args: [url] };
}

async function openLocalBrowser(url, options = {}) {
  const descriptor = browserCommand(url, options);
  if (!descriptor) return false;
  if (descriptor.custom) {
    await descriptor.custom(url);
    return true;
  }
  return new Promise((resolve) => {
    const child = spawn(descriptor.command, descriptor.args, {
      detached: true,
      stdio: "ignore",
      shell: false,
      windowsHide: true
    });
    child.once("spawn", () => { child.unref(); resolve(true); });
    child.once("error", () => resolve(false));
  });
}

export async function startProfileWizardServer(options = {}) {
  const host = options.host || "127.0.0.1";
  if (!isLoopback(host)) throw new Error("profile wizard server must bind to an explicit loopback address");
  const requestedPort = options.port === undefined ? 0 : Number(options.port);
  if (!Number.isSafeInteger(requestedPort) || requestedPort < 0 || requestedPort > 65535) {
    throw new Error("profile wizard port must be an integer from 0 through 65535");
  }
  const maxRequests = options.maxRequests === undefined ? DEFAULT_MAX_REQUESTS : Number(options.maxRequests);
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > 100_000) {
    throw new Error("profile wizard request limit must be an integer from 1 through 100000");
  }
  const paths = options.paths || runtimePaths({
    repo: options.rootDir || options.repo,
    home: options.gateHome || options.home,
    env: options.env
  });
  const controller = createProfileWizardController({
    profileId: options.profileId,
    paths,
    now: options.now,
    recommendations: options.recommendations || null
  });
  // Validate the selected profile before opening a listener. A process owns
  // exactly this profile for its lifetime.
  controller.state();
  const sessionToken = token();
  const csrfToken = token();
  let requestCount = 0;
  let origin;
  let hostHeader;

  const server = http.createServer(async (req, res) => {
    requestCount += 1;
    if (requestCount > maxRequests) {
      json(res, 429, { ok: false, error: { code: "request-limit", message: "This local profile session reached its request limit. Restart it to continue." } });
      return;
    }
    req.setTimeout(10_000, () => req.destroy());
    if (req.headers.host !== hostHeader) {
      json(res, 421, { ok: false, error: { code: "host-rejected", message: "The local profile form rejected an unexpected host." } });
      return;
    }
    let pathname;
    try {
      pathname = new URL(req.url || "/", origin).pathname;
    } catch {
      json(res, 400, { ok: false, error: { code: "request-invalid", message: "The local profile form rejected the request." } });
      return;
    }

    const staticFile = STATIC_FILES.get(pathname);
    if (req.method === "GET" && staticFile) {
      const [name, type] = staticFile;
      reply(res, 200, fs.readFileSync(path.join(STATIC_ROOT, name)), type);
      return;
    }

    if (pathname.startsWith("/api/")) {
      if (!sameToken(req.headers["x-gate-session"], sessionToken)) {
        json(res, 401, { ok: false, error: { code: "session-required", message: "Open this form from the GATE command that started it." } });
        return;
      }
      if (req.method === "GET" && pathname === "/api/state") {
        try {
          json(res, 200, { ok: true, state: controller.state() });
        } catch (error) {
          const failure = publicError(error);
          json(res, failure.status, failure.body);
        }
        return;
      }
      if (req.method !== "POST" || ![
        "/api/answer",
        "/api/answer/clear",
        "/api/recommendation",
        "/api/recommendations/apply"
      ].includes(pathname)) {
        json(res, 405, { ok: false, error: { code: "method-rejected", message: "That local profile action is not available." } });
        return;
      }
      if (req.headers.origin !== origin || !sameToken(req.headers["x-gate-csrf"], csrfToken)) {
        json(res, 403, { ok: false, error: { code: "csrf-rejected", message: "Reload the local profile form before saving." } });
        return;
      }
      try {
        const input = await readJson(req);
        const state = pathname === "/api/answer"
          ? controller.saveAnswer(input)
          : pathname === "/api/answer/clear"
            ? controller.clearAnswer(input)
          : pathname === "/api/recommendation"
            ? controller.applyRecommendation(input)
            : controller.applySupportedRecommendations(input);
        json(res, 200, { ok: true, state });
      } catch (error) {
        const failure = publicError(error);
        json(res, failure.status, failure.body);
      }
      return;
    }

    json(res, 404, { ok: false, error: { code: "not-found", message: "That local profile page does not exist." } });
  });
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  });

  await new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once("error", onError);
    server.listen(requestedPort, host, () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : requestedPort;
  hostHeader = expectedHost(host, port);
  origin = `http://${hostHeader}`;
  const fragment = new URLSearchParams({ session: sessionToken, csrf: csrfToken }).toString();
  const url = `${origin}/#${fragment}`;
  const browserOpened = options.openBrowser === true
    ? await openLocalBrowser(url, options)
    : false;
  return Object.freeze({
    host,
    port,
    origin,
    url,
    browserOpened,
    profileId: controller.profileId,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  });
}

export const profileUiServerInternals = Object.freeze({
  CSP,
  DEFAULT_MAX_REQUESTS,
  MAX_BODY_BYTES,
  STATIC_FILES,
  isLoopback,
  expectedHost,
  browserCommand,
  openLocalBrowser,
  publicError
});
