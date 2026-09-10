/* Sensitive-pattern detection and redaction. Pattern-for-pattern port of the
   Python implementation (redact.py) so both recorders flag and redact the
   same content the same way.

   Detection is two layers, both deterministic and explainable (never a model
   judgement): (1) a list of known secret/PII patterns — API keys, tokens,
   private keys, DB connection strings, JWTs, credit cards, SSNs, emails, phone
   numbers, IBANs, internal IPs — and (2) a high-entropy catch-all that flags
   long random-looking tokens the patterns miss (the provider-specific key
   formats nobody has hardcoded yet).

   Coverage is by named pattern, so it is best-effort, not comprehensive:
   free-form personal data with no fixed shape (a person's name, a postal
   address) has no reliable pattern and is not detected. Treat redaction as
   defense-in-depth for an artifact handed to a third party, not a guarantee
   that a summary can carry no personal data (see LIMITS.md). Over-redaction is
   the safe failure. */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  type: string;
  severity: Severity;
  /** Redacted excerpt. Omitted in hash-only records (summaries: false). */
  sample?: string;
}

const PATTERNS: Array<[string, Severity, RegExp]> = [
  ["api_key",      "CRITICAL", /(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9-]{10,})/g],
  ["gcp_api_key",  "CRITICAL", /AIza[0-9A-Za-z_\-]{35,}/g],
  ["aws_secret_key", "CRITICAL", /aws_secret_access_key(?:\s*[=:]\s*|\s+)["']?[A-Za-z0-9/+=]{40}/gi],
  ["webhook_url",   "CRITICAL", /https:\/\/(?:hooks\.slack\.com\/services\/|discord(?:app)?\.com\/api\/webhooks\/|[a-z0-9.-]+\.webhook\.office\.com\/webhookb2\/|outlook\.office\.com\/webhook\/)[^\s"'<>]+/g],
  ["stripe_key",   "CRITICAL", /(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}/g],
  ["github_token", "CRITICAL", /(?:gh[opsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})/g],
  // Matches the whole PEM block when the footer is present (so the key body is
  // masked, not just the header line). When the block is truncated, consumes
  // the base64-shaped body lines that follow the header, so a partial key
  // still cannot leak through the mask.
  ["private_key",  "CRITICAL", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----(?:[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:\n[A-Za-z0-9+\/=]+(?![^\n]))*)/g],
  ["db_conn",      "CRITICAL", /(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]+/g],
  ["jwt",          "HIGH",     /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
  ["credit_card",  "HIGH",     /\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[ -]?[0-9]){9,13}\b/g],
  ["ssn",          "HIGH",     /\b\d{3}[- ]\d{2}[- ]\d{4}\b/g],
  ["bearer_token", "HIGH",     /Bearer\s+[a-zA-Z0-9\-_.]{20,}/g],
  ["email",        "MEDIUM",   /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g],
  ["ip_internal",  "MEDIUM",   /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g],
  ["phone",        "MEDIUM",   /\b(?:\+?1[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g],
  ["iban",         "HIGH",     /\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}\b/g],
];

export const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0,
};

/* High-entropy catch-all. A token is flagged when it is long, mixed enough to
   be machine-generated rather than prose, and not a recognizable hash/UUID/id. */
const HIGH_ENTROPY_TYPE = "high_entropy_secret";
const HIGH_ENTROPY_MIN_LEN = 24;
const HIGH_ENTROPY_BITS = 3.5;
const TOKEN_RE = /[A-Za-z0-9+/=_-]{24,}/g;
const MAX_PER_TYPE = 25;

function shannonBits(s: string): number {
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikeSecret(tok: string): boolean {
  if (tok.length < HIGH_ENTROPY_MIN_LEN) return false;
  if (/^[0-9a-f]+$/i.test(tok)) return false;                       // hex digest
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-/i.test(tok)) return false; // UUID
  if (/^\d+$/.test(tok)) return false;                              // long number / id
  const hasDigit = /[0-9]/.test(tok);
  const hasUpper = /[A-Z]/.test(tok);
  const hasLower = /[a-z]/.test(tok);
  if (!(hasDigit || (hasUpper && hasLower))) return false;          // prose / slugs
  return shannonBits(tok) >= HIGH_ENTROPY_BITS;
}

export function redactSample(ftype: string, value: unknown): string {
  const v = String(value);
  if (ftype === "aws_secret_key") {
    const i = Math.max(v.lastIndexOf("="), v.lastIndexOf(":"), v.lastIndexOf(" "));
    return i > 0 ? v.slice(0, i + 1) + "****" : "****";
  }
  if (ftype === "webhook_url") {
    const m = v.match(/^https:\/\/[^/]+\/[a-z0-9]+\//);
    return m ? m[0] + "****" : "https://****";
  }
  if (ftype === "email") {
    const m = v.match(/^([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@.+)$/);
    return m ? m[1] + "****" + m[2] : "****";
  }
  if (ftype === "db_conn") return v.replace(/:\/\/([^:/@]+):[^@]+@/, "://$1:****@");
  if (ftype === "bearer_token") return "Bearer ****";
  // Deliberately header-free: a mask that echoed the PEM header would trip
  // secret scanners on every artifact that contains it, and re-redaction
  // would not be idempotent.
  if (ftype === "private_key") return "[PRIVATE KEY REDACTED]";
  if (ftype === "jwt") return "eyJ****";
  if (ftype === "api_key" || ftype === "gcp_api_key" || ftype === "stripe_key" || ftype === "github_token") {
    return v.length > 4 ? v.slice(0, 4) + "****" : "****";
  }
  if (ftype === HIGH_ENTROPY_TYPE) return v.length > 3 ? v.slice(0, 3) + "****" : "****";
  if (ftype === "credit_card") {
    const digits = v.replace(/\D/g, "");
    return digits.length >= 4 ? "****" + digits.slice(-4) : "****";
  }
  if (ftype === "ssn") return v.length >= 4 ? "***-**-" + v.slice(-4) : "****";
  if (ftype === "phone") {
    const digits = v.replace(/\D/g, "");
    return digits.length >= 4 ? "***-***-" + digits.slice(-4) : "****";
  }
  if (ftype === "iban") return v.length > 2 ? v.slice(0, 2) + "****" : "****";
  if (ftype === "ip_internal") {
    const parts = v.split(".");
    return parts.length === 4 ? [parts[0], parts[1], "*", "*"].join(".") : "****";
  }
  return "****";
}

/* Luhn check over the digits of `value` (13–19 long). Distinguishes a real card
   number from an incidental digit run — e.g. the numeric body of an IBAN, whose
   groups can look card-shaped — so a card finding is only raised for a number
   that actually checksums as one. */
function luhnOk(value: string): boolean {
  const digits = String(value).replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let total = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  }
  return total % 10 === 0;
}

/* Apply only the known-pattern redactions. */
function applyPatterns(text: string): string {
  let out = text;
  for (const [name, , pattern] of PATTERNS) {
    out = out.replace(new RegExp(pattern.source, pattern.flags), (m) =>
      name === "credit_card" && !luhnOk(m) ? m : redactSample(name, m));
  }
  return out;
}

/* Mask only the named secret/PII patterns — no high-entropy catch-all. For
   fields whose legitimate values ARE high-entropy (authority hashes and refs),
   where the catch-all would mangle the very thing the field exists to carry. */
export function maskKnownSecrets(text: unknown): string {
  return applyPatterns(String(text));
}

export function redactText(text: unknown, entropy = true): string {
  // Patterns first, then sweep the residual for high-entropy tokens the
  // patterns did not cover. Running entropy on the residual (not the raw text)
  // avoids re-masking something already redacted to "****". `entropy=false`
  // keeps the named patterns and skips the catch-all: used for path-typed
  // argument fields, whose legitimate values look like secrets.
  const afterPatterns = applyPatterns(String(text));
  if (!entropy) return afterPatterns;
  return afterPatterns.replace(
    new RegExp(TOKEN_RE.source, TOKEN_RE.flags),
    (tok) => (looksLikeSecret(tok) ? redactSample(HIGH_ENTROPY_TYPE, tok) : tok),
  );
}

/* Return redacted findings for every sensitive pattern in `text`. Emits one
   finding per distinct match (deduped on the redacted sample, capped per type)
   so counts reflect reality instead of collapsing to one-per-kind. */
export function scan(text: unknown, entropy = true): Finding[] {
  const s = String(text);
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const [name, severity, pattern] of PATTERNS) {
    const matches = s.match(new RegExp(pattern.source, pattern.flags));
    if (!matches) continue;
    let n = 0;
    for (const m of matches) {
      if (name === "credit_card" && !luhnOk(m)) continue;
      const sample = redactSample(name, String(m).slice(0, 120));
      const key = name + ":" + sample;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ type: name, severity, sample });
      if (++n >= MAX_PER_TYPE) break;
    }
  }

  // High-entropy catch-all over the pattern-redacted residual, so tokens
  // already flagged above are not double-counted.
  if (!entropy) return findings;
  findings.push(...entropyFindings(s, seen));

  return findings;
}

export function topSeverity(findings: Finding[]): Severity {
  if (!findings || findings.length === 0) return "INFO";
  let best = findings[0];
  for (const f of findings.slice(1)) {
    if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[best.severity] ?? 0)) best = f;
  }
  return best.severity;
}

/* Argument keys whose values are file-system paths, globs, or URLs by
   contract. A path is exactly the shape the entropy catch-all misreads as a
   secret. Under these keys, when the value is anchored as a path (leading
   slash, drive letter, scheme, dot-relative prefix, file extension, or glob
   metacharacter) and carries no query or credential separators, the value is
   left READABLE in the summary — but it is still scanned: an entropy hit there
   is reported as `high_entropy_path_value` (LOW) instead of masked, so
   `findings: []` keeps meaning "the scanner found nothing anywhere".
   Mirrors the Python package's PATH_KEYS / path_value / redact_fields / scan_fields. */
export const PATH_KEYS = new Set([
  "file_path", "filePath", "notebook_path", "notebookPath", "path", "paths",
  "filenames", "files", "file", "cwd", "pattern", "glob", "directory", "dir",
  "old_path", "new_path", "target_file", "source_file", "workdir",
  "url", "uri", "href", "urls",
]);
export const HIGH_ENTROPY_PATH_TYPE = "high_entropy_path_value";
const NOT_PATH_CHARS = ["=", "?", "&", "%", "@"];
const PATH_ANCHOR_RE = /^(?:[/~]|\.\/|\.\.\/|[A-Za-z]:[\\/]|[a-z][a-z0-9+.-]*:\/\/)/;
const PATH_EXT_RE = /\.[A-Za-z0-9]{1,6}$/;
const GLOB_CHARS = ["*", "[", "{"];

export function pathValue(key: string | null | undefined, value: unknown): boolean {
  if (key == null || !PATH_KEYS.has(key) || typeof value !== "string" || !value) return false;
  if (NOT_PATH_CHARS.some((c) => value.includes(c))) return false;
  if ((value[0] === "/" || value[0] === "~") && !value.slice(1).includes("/") && !value.includes(".")) return false;
  return PATH_ANCHOR_RE.test(value) || PATH_EXT_RE.test(value) || GLOB_CHARS.some((c) => value.includes(c));
}

function entropyFindings(text: string, seen: Set<string>, ftype = HIGH_ENTROPY_TYPE, severity: Severity = "HIGH"): Finding[] {
  const out: Finding[] = [];
  const residual = applyPatterns(text);
  let e = 0;
  for (const tok of residual.match(new RegExp(TOKEN_RE.source, TOKEN_RE.flags)) ?? []) {
    if (!looksLikeSecret(tok)) continue;
    const sample = redactSample(HIGH_ENTROPY_TYPE, tok);
    const key = ftype + ":" + sample;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ type: ftype, severity, sample });
    if (++e >= MAX_PER_TYPE) break;
  }
  return out;
}

const PATCH_HEADER_RE = /^(\*\*\* (?:Update|Add|Delete|Move to) File: )(.+)$/gm;

/* Split a patch body into (segment, isPath) pieces so file headers can be
   treated as path values while the body keeps the full pass. */
function splitPatchHeaders(text: string): Array<[string, boolean]> {
  const out: Array<[string, boolean]> = [];
  let pos = 0;
  for (const m of text.matchAll(PATCH_HEADER_RE)) {
    const start = (m.index ?? 0) + m[1].length;
    out.push([text.slice(pos, start), false]);
    out.push([m[2], true]);
    pos = start + m[2].length;
  }
  out.push([text.slice(pos), false]);
  return out;
}

/* Redact a tool-argument structure leaf by leaf, keeping its shape. */
export function redactFields(obj: unknown, entropy = true, depth = 0): unknown {
  if (depth > 8) return "…";
  if (typeof obj === "string") {
    if (entropy && obj.includes("*** Begin Patch")) {
      return splitPatchHeaders(obj).map(([seg, isPath]) => redactText(seg, !(isPath && pathValue("file_path", seg)))).join("");
    }
    return redactText(obj, entropy);
  }
  if (Array.isArray(obj)) return obj.map((v) => redactFields(v, entropy, depth + 1));
  if (obj !== null && typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      const rk = redactText(k);
      out[rk] = Array.isArray(v)
        ? v.map((el) => redactFields(el, !pathValue(k, el), depth + 1))
        : redactFields(v, !pathValue(k, v), depth + 1);
    }
    return out;
  }
  return obj;
}

/* Findings over a tool-argument structure, leaf by leaf, deduped. The scanner
   looks everywhere; under a path-typed key an entropy hit is reported as
   `high_entropy_path_value` (LOW) rather than as a secret. */
export function scanFields(obj: unknown, entropy = true, depth = 0, seen = new Set<string>(), key: string | null = null): Finding[] {
  const out: Finding[] = [];
  const add = (fs: Finding[]) => { for (const f of fs) { const k = f.type + ":" + (f.sample ?? ""); if (!seen.has(k)) { seen.add(k); out.push(f); } } };
  if (depth > 8) return out;
  if (typeof obj === "string") {
    if (entropy && obj.includes("*** Begin Patch")) {
      for (const [seg, isPath] of splitPatchHeaders(obj)) out.push(...scanFields(seg, entropy, depth + 1, seen, isPath ? "file_path" : null));
      return out;
    }
    if (pathValue(key, obj)) { add(scan(obj, false)); out.push(...entropyFindings(obj, seen, HIGH_ENTROPY_PATH_TYPE, "LOW")); return out; }
    add(scan(obj, entropy));
    return out;
  }
  if (Array.isArray(obj)) { for (const v of obj) out.push(...scanFields(v, entropy, depth + 1, seen, null)); return out; }
  if (obj !== null && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out.push(...scanFields(k, true, depth + 1, seen, null));
      if (Array.isArray(v)) { for (const el of v) out.push(...scanFields(el, entropy, depth + 1, seen, k)); }
      else out.push(...scanFields(v, entropy, depth + 1, seen, k));
    }
    return out;
  }
  return obj == null ? out : scanFields(String(obj), entropy, depth + 1, seen, null);
}
