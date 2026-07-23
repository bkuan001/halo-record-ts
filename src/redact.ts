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
  sample: string;
}

const PATTERNS: Array<[string, Severity, RegExp]> = [
  ["api_key",      "CRITICAL", /(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9-]{10,})/g],
  ["gcp_api_key",  "CRITICAL", /AIza[0-9A-Za-z_\-]{35}/g],
  ["stripe_key",   "CRITICAL", /(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}/g],
  ["github_token", "CRITICAL", /(?:gh[opsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})/g],
  ["private_key",  "CRITICAL", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ["db_conn",      "CRITICAL", /(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]+/g],
  ["jwt",          "HIGH",     /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
  ["credit_card",  "HIGH",     /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g],
  ["ssn",          "HIGH",     /\b\d{3}-\d{2}-\d{4}\b/g],
  ["bearer_token", "HIGH",     /Bearer\s+[a-zA-Z0-9\-_.]{20,}/g],
  ["email",        "MEDIUM",   /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g],
  ["ip_internal",  "MEDIUM",   /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g],
  ["phone",        "MEDIUM",   /\b(?:\+?1[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g],
  ["iban",         "HIGH",     /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g],
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
  if (ftype === "email") {
    const m = v.match(/^([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@.+)$/);
    return m ? m[1] + "****" + m[2] : "****";
  }
  if (ftype === "db_conn") return v.replace(/:\/\/([^:/@]+):[^@]+@/, "://$1:****@");
  if (ftype === "bearer_token") return "Bearer ****";
  if (ftype === "private_key") return "-----BEGIN PRIVATE KEY----- ****";
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

/* Apply only the known-pattern redactions. */
function applyPatterns(text: string): string {
  let out = text;
  for (const [name, , pattern] of PATTERNS) {
    out = out.replace(new RegExp(pattern.source, pattern.flags), (m) => redactSample(name, m));
  }
  return out;
}

export function redactText(text: unknown): string {
  // Patterns first, then sweep the residual for high-entropy tokens the
  // patterns did not cover. Running entropy on the residual (not the raw text)
  // avoids re-masking something already redacted to "****".
  const afterPatterns = applyPatterns(String(text));
  return afterPatterns.replace(
    new RegExp(TOKEN_RE.source, TOKEN_RE.flags),
    (tok) => (looksLikeSecret(tok) ? redactSample(HIGH_ENTROPY_TYPE, tok) : tok),
  );
}

/* Return redacted findings for every sensitive pattern in `text`. Emits one
   finding per distinct match (deduped on the redacted sample, capped per type)
   so counts reflect reality instead of collapsing to one-per-kind. */
export function scan(text: unknown): Finding[] {
  const s = String(text);
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const [name, severity, pattern] of PATTERNS) {
    const matches = s.match(new RegExp(pattern.source, pattern.flags));
    if (!matches) continue;
    let n = 0;
    for (const m of matches) {
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
  const residual = applyPatterns(s);
  let e = 0;
  for (const tok of residual.match(new RegExp(TOKEN_RE.source, TOKEN_RE.flags)) ?? []) {
    if (!looksLikeSecret(tok)) continue;
    const sample = redactSample(HIGH_ENTROPY_TYPE, tok);
    const key = HIGH_ENTROPY_TYPE + ":" + sample;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({ type: HIGH_ENTROPY_TYPE, severity: "HIGH", sample });
    if (++e >= MAX_PER_TYPE) break;
  }

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
