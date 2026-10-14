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

function exactDomain(value) {
  if (typeof value !== "string" || value.length > 253 || value !== value.toLowerCase() || value.endsWith(".")) {
    throw new Error("the DNSx target must be a lowercase canonical domain without a trailing dot");
  }
  const labels = value.split(".");
  if (labels.length < 2 || labels.some((label) =>
    label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
  )) {
    throw new Error("the DNSx target must be one exact DNS domain name");
  }
  return value;
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function exactResolver(value) {
  if (typeof value !== "string" || /[\u0000\r\n,\s]/u.test(value)) {
    throw new Error("DNSx resolver must be one literal IP with an explicit port");
  }
  let address;
  let portText;
  if (value.startsWith("[")) {
    const match = /^\[([^\]]+)\]:(\d+)$/u.exec(value);
    if (!match || net.isIP(match[1]) !== 6) throw new Error("DNSx IPv6 resolver syntax must be [IP]:PORT");
    [, address, portText] = match;
  } else {
    const separator = value.lastIndexOf(":");
    address = value.slice(0, separator);
    portText = value.slice(separator + 1);
    if (separator < 1 || net.isIP(address) !== 4) throw new Error("DNSx IPv4 resolver syntax must be IP:PORT");
  }
  boundedInteger(Number(portText), "DNSx resolver port", 1, 65535);
  return value;
}

export function compileDnsxDomainObserve({ target, operation, bounds }) {
  const domain = exactDomain(target);
  exactKeys(operation, ["kind", "recordType", "resolver", "timeoutSeconds"], "DNSx operation");
  if (operation.kind !== "dns-query") throw new Error("DNSx operation kind must be dns-query");
  if (operation.recordType !== "A") throw new Error("the first DNSx adapter admits A queries only");
  const resolver = exactResolver(operation.resolver);
  const timeoutSeconds = boundedInteger(operation.timeoutSeconds, "DNSx timeoutSeconds", 1, 15);
  const rate = boundedInteger(bounds.maxRatePerSecond, "DNSx maxRatePerSecond", 1, 2);
  if (bounds.estimatedRequests !== 1) throw new Error("DNSx exact-domain observation requires estimatedRequests to equal 1");
  if (bounds.maxParallel !== 1) throw new Error("DNSx exact-domain observation requires maxParallel to equal 1");
  if (bounds.maxMinutes > 5) throw new Error("DNSx exact-domain observation is limited to 5 minutes");
  if (timeoutSeconds > bounds.maxMinutes * 60) throw new Error("DNSx timeout exceeds the declared duration");

  return {
    typedOperation: { kind: "dns-query", recordType: "A", resolver, timeoutSeconds },
    argv: [
      "-l", domain,
      "-a",
      "-retry", "1",
      "-t", "1",
      "-rl", String(rate),
      "-timeout", `${timeoutSeconds}s`,
      "-resolver", resolver,
      "-json",
      "-omit-raw",
      "-silent",
      "-nc",
      "-disable-update-check",
      "-auth=false"
    ],
    requestEstimate: 1,
    controls: {
      exactInput: true,
      discoveredTargetExpansion: false,
      queryTypes: [operation.recordType],
      resolver,
      attempts: 1,
      concurrency: 1,
      ratePerSecond: rate,
      timeoutSeconds,
      cloudAuth: false,
      updateCheck: false
    }
  };
}
