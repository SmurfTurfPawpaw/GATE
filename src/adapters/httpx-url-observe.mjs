import net from "node:net";

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} must contain exactly: ${wanted.join(", ")}`);
  }
}
function exactUrl(value) {
  if (typeof value !== "string" || value.length > 500 || /[\u0000\r\n]/u.test(value)) {
    throw new Error("the HTTPx target must be one bounded single-line URL");
  }
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new Error("the HTTPx target must be a valid HTTP or HTTPS URL"); }
  if (!new Set(["http:", "https:"]).has(parsed.protocol)) {
    throw new Error("the HTTPx target must use HTTP or HTTPS");
  }
  if (parsed.username || parsed.password) throw new Error("the HTTPx adapter does not admit URL credentials");
  if (parsed.hash || value.includes("#")) throw new Error("the HTTPx adapter does not admit URL fragments");
  if (!parsed.hostname || value.includes(",")) throw new Error("the HTTPx target must contain one exact host and no comma");
  if (parsed.href !== value) throw new Error(`the HTTPx target must use its canonical URL form exactly: ${parsed.href}`);
  return value;
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function canonicalIp(value) {
  const version = typeof value === "string" ? net.isIP(value) : 0;
  if (version === 0) throw new Error("HTTPx allowedIp must be one literal IPv4 or IPv6 address");
  if (version === 4) return value;
  const normalized = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  if (normalized !== value.toLowerCase()) {
    throw new Error(`HTTPx allowedIp must use its canonical form exactly: ${normalized}`);
  }
  return normalized;
}

function hostnameIp(value) {
  const unwrapped = value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
  return net.isIP(unwrapped) === 0 ? null : canonicalIp(unwrapped);
}

function pinnedRequest(url, allowedIp) {
  const approved = new URL(url);
  const approvedHostIp = hostnameIp(approved.hostname);
  if (approvedHostIp && approvedHostIp !== allowedIp) {
    throw new Error("HTTPx allowedIp must equal the literal IP in the approved URL");
  }
  const dial = new URL(url);
  dial.hostname = net.isIP(allowedIp) === 6 ? `[${allowedIp}]` : allowedIp;
  return {
    dialUrl: dial.href,
    hostHeader: approved.host,
    tlsServerName: approved.protocol === "https:" && !approvedHostIp ? approved.hostname : null
  };
}

export function compileHttpxUrlObserve({ target, operation, bounds }) {
  const url = exactUrl(target);
  exactKeys(operation, ["kind", "maxResponseBytes", "method", "allowedIp", "timeoutSeconds"], "HTTPx operation");
  if (operation.kind !== "http-get") throw new Error("HTTPx operation kind must be http-get");
  if (operation.method !== "GET") throw new Error("the HTTPx adapter admits GET only");
  const allowedIp = canonicalIp(operation.allowedIp);
  const request = pinnedRequest(url, allowedIp);
  const timeoutSeconds = boundedInteger(operation.timeoutSeconds, "HTTPx timeoutSeconds", 1, 15);
  const maxResponseBytes = boundedInteger(operation.maxResponseBytes, "HTTPx maxResponseBytes", 1024, 1_048_576);
  const rate = boundedInteger(bounds.maxRatePerSecond, "HTTPx maxRatePerSecond", 1, 2);
  if (bounds.estimatedRequests !== 1) throw new Error("HTTPx exact-URL observation requires estimatedRequests to equal 1");
  if (bounds.maxParallel !== 1) throw new Error("HTTPx exact-URL observation requires maxParallel to equal 1");
  if (bounds.maxMinutes > 5) throw new Error("HTTPx exact-URL observation is limited to 5 minutes");
  if (timeoutSeconds > bounds.maxMinutes * 60) throw new Error("HTTPx timeout exceeds the declared duration");

  return {
    typedOperation: {
      kind: "http-get", method: "GET", allowedIp, timeoutSeconds, maxResponseBytes
    },
    argv: [
      "-u", request.dialUrl,
      "-x", "GET",
      "-allow", allowedIp,
      "-H", `Host: ${request.hostHeader}`,
      ...(request.tlsServerName ? ["-sni-name", request.tlsServerName] : []),
      "-nfs",
      "-no-stdin",
      "-t", "1",
      "-rl", String(rate),
      "-retries", "0",
      "-timeout", String(timeoutSeconds),
      "-rstr", String(maxResponseBytes),
      "-rsts", String(maxResponseBytes),
      "-json",
      "-omit-body",
      "-status-code",
      "-content-length",
      "-content-type",
      "-location",
      "-method",
      "-ip",
      "-silent",
      "-nc",
      "-disable-update-check",
      "-auth=false",
      "-random-agent=false",
      "-cdn=false"
    ],
    requestEstimate: 1,
    controls: {
      exactApprovedUrl: true,
      exactDialUrl: true,
      method: "GET",
      approvedUrl: url,
      allowedIp,
      dialUrl: request.dialUrl,
      hostHeader: request.hostHeader,
      ...(request.tlsServerName ? { tlsServerName: request.tlsServerName } : {}),
      tlsServerNameApplied: Boolean(request.tlsServerName),
      socketDestinationPinned: true,
      redirects: false,
      requestBody: false,
      operatorCustomHeaders: false,
      compilerGeneratedHostHeader: true,
      headless: false,
      authentication: false,
      fallbackScheme: false,
      retries: 0,
      concurrency: 1,
      ratePerSecond: rate,
      timeoutSeconds,
      maxResponseBytes,
      cloudAuth: false,
      updateCheck: false
    }
  };
}
