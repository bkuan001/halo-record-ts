/* Sensitive-pattern detection and redaction. Pattern-for-pattern port of the
   Python implementation (redact.py) so both recorders flag and redact the
   same content the same way. */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  type: string;
  severity: Severity;
  sample: string;
}

const PATTERNS: Array<[string, Severity, RegExp]> = [
  ["api_key",      "CRITICAL", /(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9-]{10,})/g],
  ["private_key",  "CRITICAL", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ["db_conn",      "CRITICAL", /(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]+/g],
  ["credit_card",  "HIGH",     /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g],
  ["ssn",          "HIGH",     /\b\d{3}-\d{2}-\d{4}\b/g],
  ["email",        "MEDIUM",   /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g],
  ["ip_internal",  "MEDIUM",   /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g],
  ["bearer_token", "HIGH",     /Bearer\s+[a-zA-Z0-9\-_.]{20,}/g],
];

export const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0,
};

export function redactSample(ftype: string, value: unknown): string {
  const v = String(value);
  if (ftype === "email") {
    const m = v.match(/^([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@.+)$/);
    return m ? m[1] + "****" + m[2] : "****";
  }
  if (ftype === "db_conn") return v.replace(/:\/\/([^:/@]+):[^@]+@/, "://$1:****@");
  if (ftype === "bearer_token") return "Bearer ****";
  if (ftype === "private_key") return "-----BEGIN PRIVATE KEY----- ****";
  if (ftype === "api_key") return v.length > 4 ? v.slice(0, 4) + "****" : "****";
  if (ftype === "credit_card") {
    const digits = v.replace(/\D/g, "");
    return digits.length >= 4 ? "****" + digits.slice(-4) : "****";
  }
  if (ftype === "ssn") return v.length >= 4 ? "***-**-" + v.slice(-4) : "****";
  if (ftype === "ip_internal") {
    const parts = v.split(".");
    return parts.length === 4 ? [parts[0], parts[1], "*", "*"].join(".") : "****";
  }
  return "****";
}

export function redactText(text: unknown): string {
  let out = String(text);
  for (const [name, , pattern] of PATTERNS) {
    out = out.replace(new RegExp(pattern.source, pattern.flags), (m) => redactSample(name, m));
  }
  return out;
}

/* Return a list of redacted findings for any sensitive patterns in `text`. */
export function scan(text: unknown): Finding[] {
  const findings: Finding[] = [];
  const s = String(text);
  for (const [name, severity, pattern] of PATTERNS) {
    const matches = s.match(new RegExp(pattern.source, pattern.flags));
    if (matches && matches.length) {
      findings.push({
        type: name,
        severity,
        sample: redactSample(name, String(matches[0]).slice(0, 120)),
      });
    }
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
