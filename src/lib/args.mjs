export function parseArgs(argv) {
  const positional = [];
  // A null-prototype map keeps option names such as __proto__ or constructor
  // from mutating or consulting Object.prototype before assertFlags rejects
  // them.
  const flags = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--") {
      return { positional, flags, passthrough: argv.slice(index + 1) };
    }
    if (!value.startsWith("--")) {
      positional.push(value);
      continue;
    }
    const equals = value.indexOf("=");
    if (equals !== -1) {
      flags[value.slice(2, equals)] = value.slice(equals + 1);
      continue;
    }
    const key = value.slice(2);
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[key] = next;
      index += 1;
    } else {
      flags[key] = true;
    }
  }
  return { positional, flags, passthrough: [] };
}

export function requiredFlag(flags, name) {
  const value = flags[name];
  if (typeof value !== "string" || !value.trim()) throw new Error(`--${name} is required`);
  return value;
}

export function listFlag(flags, name) {
  const value = flags[name];
  if (value === undefined) return [];
  if (value === true) throw new Error(`--${name} needs a comma-separated value`);
  return String(value).split(",").map((item) => item.trim()).filter(Boolean);
}
