const DEFAULT_OPERATOR_DISPLAY_NAME = "Operator";
const MAX_OPERATOR_DISPLAY_NAME_CODE_POINTS = 64;
const TERMINAL_CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;

/**
 * Return a terminal-safe, single-line operator name.
 *
 * Terminal control bytes, including ANSI escape introducers and line breaks,
 * reject the complete supplied value instead of trying to preserve fragments
 * around them. This keeps an unsafe local override from injecting extra banner
 * lines or terminal instructions.
 */
export function sanitizeOperatorDisplayName(value) {
  if (typeof value !== "string" || TERMINAL_CONTROL.test(value)) {
    return DEFAULT_OPERATOR_DISPLAY_NAME;
  }
  const normalized = value.normalize("NFC").trim();
  if (!normalized || [...normalized].length > MAX_OPERATOR_DISPLAY_NAME_CODE_POINTS) {
    return DEFAULT_OPERATOR_DISPLAY_NAME;
  }
  return normalized;
}

export function readOperatorDisplayName(config) {
  return sanitizeOperatorDisplayName(config?.operator?.displayName);
}

export function terminalWelcomeLines(config) {
  const displayName = readOperatorDisplayName(config);
  return [
    `GATE // Welcome, ${displayName}.`,
    "GATE // Cockpit: preparing local read-only observer.",
    "GATE // Progress: waiting for observed runtime state."
  ];
}

export function terminalWelcomeBanner(config) {
  return `${terminalWelcomeLines(config).join("\n")}\n`;
}
