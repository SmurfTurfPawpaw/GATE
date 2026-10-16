const LABELABLE_TAGS = new Set(["INPUT", "SELECT", "TEXTAREA"]);

export function bindFieldLabel(label, root, createId = () => crypto.randomUUID()) {
  const direct = LABELABLE_TAGS.has(String(root?.tagName || "").toUpperCase()) ? root : null;
  const control = direct || root?.querySelector?.('[data-field-control="primary"]') || null;
  if (!control) return null;
  const id = control.id || `field-${createId()}`;
  control.id = id;
  label.setAttribute("for", id);
  return control;
}

export const profileUiAccessibilityInternals = Object.freeze({ LABELABLE_TAGS });
