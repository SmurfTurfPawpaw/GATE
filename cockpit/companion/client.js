// Register renderer listeners before delivering the initial private state.
import "../assets/app.js";

const parameters = new URLSearchParams(globalThis.location.hash.slice(1));
const session = parameters.get("session");
const csrf = parameters.get("csrf");
const tokenPattern = /^[A-Za-z0-9_-]{43}$/u;

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function validReceipt(value, requestId) {
  return exactKeys(value, ["apiVersion", "requestId", "status"])
    && value.apiVersion === "gate.local-cockpit-receipt/v1"
    && value.requestId === requestId
    && value.status === "accepted";
}

async function post(path, request) {
  const response = await fetch(path, {
    method: "POST",
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-GATE-Session": session,
      "X-GATE-CSRF": csrf
    },
    body: JSON.stringify(request)
  });
  let value;
  try {
    value = await response.json();
  } catch {
    throw new Error("The local companion returned an invalid response.");
  }
  if (!response.ok || !validReceipt(value, request.requestId)) {
    throw new Error(value?.error?.message || "The local companion did not accept the request.");
  }
  await readPrivateState();
  return Object.freeze(value);
}

async function readPrivateState() {
  try {
    const response = await fetch("./api/private-state", {
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      headers: { Accept: "application/json", "X-GATE-Session": session }
    });
    const value = await response.json();
    if (response.ok && value?.ok === true && value.state?.apiVersion === "gate.local-companion-state/v1") {
      globalThis.dispatchEvent(new CustomEvent("gate:companion-private-state", { detail: value.state }));
    }
  } catch {
    // The public cockpit stays usable if the private companion state is absent.
  }
}

async function readFleet() {
  try {
    const response = await fetch("./api/fleet", {
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      headers: { Accept: "application/json", "X-GATE-Session": session }
    });
    const value = await response.json();
    if (response.ok && exactKeys(value, ["ok", "fleet"]) && value.ok === true
        && value.fleet?.apiVersion === "gate.local-fleet/v2") {
      globalThis.dispatchEvent(new CustomEvent("gate:companion-fleet", { detail: value.fleet }));
    }
  } catch {
    // Fleet telemetry is optional; the private Codex conversation remains usable.
  }
}

async function streamEvents() {
  let lastEventId = 0;
  let delay = 1_000;
  while (true) {
    try {
      const response = await fetch("./api/events", {
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        headers: {
          Accept: "text/event-stream",
          "Last-Event-ID": String(lastEventId),
          "X-GATE-Session": session
        }
      });
      if (!response.ok || !response.body) throw new Error("event stream unavailable");
      globalThis.dispatchEvent(new CustomEvent("gate:companion-connection", { detail: { connected: true } }));
      delay = 1_000;
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += value;
        while (true) {
          const boundary = buffer.indexOf("\n\n");
          if (boundary < 0) break;
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          let data = null;
          let eventName = "message";
          for (const line of frame.split("\n")) {
            if (line.startsWith("event: ")) eventName = line.slice(7);
            if (line.startsWith("id: ")) {
              const candidate = Number(line.slice(4));
              if (Number.isSafeInteger(candidate) && candidate > lastEventId) lastEventId = candidate;
            }
            if (line.startsWith("data: ")) data = line.slice(6);
          }
          if (!data) continue;
          let event;
          try { event = JSON.parse(data); } catch { continue; }
          if (eventName === "state" && event?.apiVersion === "gate.local-companion-state-signal/v1") {
            await readPrivateState();
            globalThis.dispatchEvent(new Event("gate:companion-snapshot"));
            continue;
          }
          if (event?.apiVersion !== "gate.local-cockpit-event/v1" || !Number.isSafeInteger(event.sequence)) continue;
          globalThis.dispatchEvent(new CustomEvent("gate:companion-activity", { detail: event }));
          globalThis.dispatchEvent(new Event("gate:companion-snapshot"));
          readPrivateState();
        }
      }
    } catch {
      globalThis.dispatchEvent(new CustomEvent("gate:companion-connection", { detail: { connected: false } }));
    }
    await new Promise((resolve) => setTimeout(resolve, delay));
    delay = Math.min(delay * 2, 15_000);
  }
}

if (tokenPattern.test(session || "") && tokenPattern.test(csrf || "")) {
  const bridge = Object.freeze({
    apiVersion: "gate.local-cockpit-bridge/v1",
    submitMessage: (request) => post("./api/message", request),
    submitQuestion: (request) => post("./api/question", request)
  });
  Object.defineProperty(globalThis, "GATE_PUBLIC_COCKPIT_BRIDGE", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: bridge
  });
  const start = async () => {
    globalThis.dispatchEvent(new CustomEvent("gate:companion-connection", { detail: { connected: true } }));
    await Promise.all([readPrivateState(), readFleet()]);
    streamEvents();
    globalThis.setInterval(readPrivateState, 5_000);
    globalThis.setInterval(readFleet, 3_000);
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    globalThis.queueMicrotask(start);
  }
}
