// Toolbox script parameters (docs/75): read a PowerShell item's own `param(...)` block so the console can draw one
// input per parameter. Display only: the agent's PowerShell is the authority on binding, types and Mandatory, and
// the server rejects names outside PARAM_NAME. A cmd item has no parameters (docs/75 D1).

export type ToolboxParam = {
  name: string;
  /** `[Parameter(Mandatory)]` or `Mandatory = $true`: the console requires a value before Run. */
  mandatory: boolean;
  /** The declared type, lower-cased without brackets (e.g. "string", "int"), or "" when none. */
  type: string;
  /** A literal default shown as a placeholder, or "" when none or not a simple literal. */
  defaultText: string;
  /** SecureString / PSCredential cannot be passed by value (docs/75 D9). */
  unsupported: boolean;
  /** A name that looks like a secret is drawn as a password input (display only; values are never stored). */
  secretLooking: boolean;
};

export type ParamParse = { params: ToolboxParam[]; unsupported: boolean };

/** Mirrors the server's rule (control-plane/toolbox_params.go). */
export const PARAM_NAME = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
export const MAX_PARAMS = 16;
export const MAX_PARAM_VALUE_BYTES = 2048;

const SECRET_NAME = /pass(word)?|pwd|secret|token|key|credential|pin$/i;
/** PowerShell common parameters and aliases; the server refuses them (control-plane/toolbox_params.go). */
const RESERVED = new Set(["verbose", "vb", "debug", "db", "erroraction", "ea", "warningaction", "wa", "informationaction",
  "infa", "progressaction", "proga", "errorvariable", "ev", "warningvariable", "wv", "informationvariable", "iv",
  "outvariable", "ov", "outbuffer", "ob", "pipelinevariable", "pv", "whatif", "wi", "confirm", "cf"]);

/** A value the technician typed, read only from the map's OWN keys: a param named `constructor` must not see
 *  Object.prototype (security review SEC-005). */
export function paramValue(values: Record<string, string>, name: string): string {
  return Object.prototype.hasOwnProperty.call(values, name) ? values[name] : "";
}
const UNSUPPORTED_TYPES = new Set(["securestring", "pscredential", "system.security.securestring",
  "system.management.automation.pscredential"]);

/** Strip `#` line comments and `<# ... #>` block comments, keeping string literals intact enough for our scan. */
function stripComments(src: string): string {
  let out = "";
  let i = 0;
  let quote: string | null = null;
  while (i < src.length) {
    const c = src[i];
    if (quote) {
      out += c;
      if (c === quote) quote = null;
      i++;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      out += c;
      i++;
      continue;
    }
    if (c === "<" && src[i + 1] === "#") {
      const end = src.indexOf("#>", i + 2);
      i = end < 0 ? src.length : end + 2;
      out += " ";
      continue;
    }
    if (c === "#") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** The text inside the leading param( ... ), honouring nested parentheses and quotes, or null when there is none. */
function leadingParamBlock(code: string): string | null {
  // Only [CmdletBinding()] and other attributes may precede param( at script scope.
  const m = /^\s*(?:\[[^\]]*\]\s*)*param\s*\(/i.exec(code);
  if (!m) return null;
  let depth = 1;
  let quote: string | null = null;
  for (let i = m[0].length; i < code.length; i++) {
    const c = code[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return code.slice(m[0].length, i);
  }
  return null;
}

/** Split on commas at depth 0 (outside (), [], {} and quotes). */
function splitTopLevel(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) {
      parts.push(s.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(s.slice(start));
  return parts.map((p) => p.trim()).filter((p) => p !== "");
}

export function parseToolboxParams(shell: string, body: string): ParamParse {
  if (shell !== "powershell") return { params: [], unsupported: false };
  const block = leadingParamBlock(stripComments(body));
  if (block === null) return { params: [], unsupported: false };
  const params: ToolboxParam[] = [];
  for (const decl of splitTopLevel(block)) {
    const v = /\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*([\s\S]*))?$/.exec(decl);
    if (!v) continue;
    const name = v[1];
    const attrs = decl.slice(0, v.index);
    const mandatory = /Mandatory\s*(?:=\s*\$true)?\s*[,)]/i.test(attrs);
    const types = [...attrs.matchAll(/\[\s*([A-Za-z_][\w.]*)\s*(?:\[\s*\])?\s*\]/g)]
      .map((t) => t[1].toLowerCase())
      .filter((t) => t !== "parameter" && !t.startsWith("validate") && t !== "alias" && t !== "allowemptystring");
    const type = types[types.length - 1] ?? "";
    const rawDefault = (v[2] ?? "").trim();
    const lit = /^'((?:[^']|'')*)'$|^"([^"$`]*)"$|^(-?\d+(?:\.\d+)?|\$true|\$false)$/i.exec(rawDefault);
    const defaultText = lit ? (lit[1]?.replace(/''/g, "'") ?? lit[2] ?? lit[3] ?? "") : "";
    params.push({
      name,
      mandatory,
      type,
      defaultText,
      unsupported: UNSUPPORTED_TYPES.has(type) || !PARAM_NAME.test(name) || RESERVED.has(name.toLowerCase()),
      secretLooking: SECRET_NAME.test(name),
    });
  }
  return { params, unsupported: params.some((p) => p.unsupported) || params.length > MAX_PARAMS };
}

/** What Run sends: only the fields the technician filled (empty means "let PowerShell use its default"). */
export function paramsForRun(values: Record<string, string>, declared: ToolboxParam[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of declared) {
    const v = paramValue(values, p.name);
    if (v !== "") out[p.name] = v;
  }
  return out;
}

/** The first reason Run must stay disabled, or null when the inputs are acceptable. */
export function paramsProblem(values: Record<string, string>, parse: ParamParse): string | null {
  if (parse.params.length > MAX_PARAMS) return `This script declares more than ${MAX_PARAMS} parameters.`;
  const bad = parse.params.find((p) => p.unsupported);
  if (bad) return `Parameter ${bad.name} cannot be filled in from the Toolbox (credential or unsupported name).`;
  for (const p of parse.params) {
    const v = paramValue(values, p.name);
    if (p.mandatory && v === "") return `${p.name} is required.`;
    if (v.includes("\0")) return `${p.name} contains a NUL character.`;
    if (new TextEncoder().encode(v).length > MAX_PARAM_VALUE_BYTES) return `${p.name} is too long (max ${MAX_PARAM_VALUE_BYTES} bytes).`;
  }
  return null;
}
