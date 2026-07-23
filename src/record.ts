/* Build and append Halo Runtime Records (Schema v0.1).
   Port of the Python implementation (record.py), including the symmetric
   input/outcome redaction. Records written here verify with the Python
   verifier and anchor to the same witness — the chain format is language-
   independent. */

import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

import { GENESIS_PREV, computeHash, inputHash } from "./canon.ts";
import { redactText, scan, topSeverity, type Finding } from "./redact.ts";

export const SCHEMA_VERSION = "0.1";

export const ACTION_TYPES = new Set(["tool_call", "agent_message", "read", "write", "network"]);
export const CATEGORIES = new Set(["security", "safety", "reliability", "privacy"]);

export interface Source {
  adapter: string;
  via: string;
  capture: "captured" | "ingested";
}

/* Where a record came from — "captured" (Halo saw the call at the trust
   boundary; strongest) vs "ingested" (built from telemetry the vendor already
   emits; weaker). Same table as the Python package. */
export const SOURCES: Record<string, Source> = {
  recorder:      { adapter: "recorder",      via: "Halo recorder (native)",    capture: "captured" },
  mcp:           { adapter: "mcp",           via: "MCP interceptor",           capture: "captured" },
  langchain:     { adapter: "langchain",     via: "LangChain / LangGraph",     capture: "captured" },
  openai_agents: { adapter: "openai_agents", via: "OpenAI Agents SDK",         capture: "captured" },
  vercel_ai:     { adapter: "vercel_ai",     via: "Vercel AI SDK",             capture: "captured" },
  claude_agent_sdk: { adapter: "claude_agent_sdk", via: "Claude Agent SDK",    capture: "captured" },
  otel:          { adapter: "otel",          via: "OpenTelemetry GenAI spans", capture: "ingested" },
  litellm:       { adapter: "litellm",       via: "LiteLLM gateway",           capture: "ingested" },
  langfuse:      { adapter: "langfuse",      via: "Langfuse traces",           capture: "ingested" },
  gateway:       { adapter: "gateway",       via: "LLM gateway / proxy log",   capture: "ingested" },
};

/* Unknown ids fall back to "ingested" — the conservative tier, so an
   unrecognized origin is never overstated as boundary-captured. */
export function normalizeSource(source: string | Partial<Source> | null | undefined): Source | null {
  if (source == null) return null;
  if (typeof source === "string") {
    return { ...(SOURCES[source] ?? { adapter: source, via: source, capture: "ingested" }) };
  }
  const src = { ...source } as Source;
  src.capture ??= "ingested";
  src.via ??= src.adapter ?? "unknown";
  return src;
}

function now(): string {
  return new Date().toISOString();
}

function normSubject(subject: string | { id: string; name?: string } | null | undefined) {
  if (subject == null) return null;
  if (typeof subject === "string") return { id: subject };
  return subject;
}

const PRINCIPAL_KEYS = ["human_id", "creator_id", "service_account", "role_scope"] as const;

/* Keep only the four schema-defined principal layers; drop unknown keys and
   empty values. Returns null if nothing usable remains. */
function normPrincipal(principal: Record<string, unknown> | null | undefined) {
  if (principal == null || typeof principal !== "object") return null;
  const out: Record<string, string> = {};
  for (const k of PRINCIPAL_KEYS) {
    const v = (principal as Record<string, unknown>)[k];
    if (v != null && v !== "") out[k] = String(v);
  }
  return Object.keys(out).length ? out : null;
}

/* Normalize ingested threats into schema shape ([{type, ref?}]). Threats are
   INGESTED from an upstream guardrail/detector — Halo records that a threat was
   flagged, it does not itself judge or detect. Accepts a list of bare type
   strings and/or {type, ref?} objects, or a single bare string (so
   threats="prompt_injection" is one threat, not iterated character by
   character). Entries without a type are dropped. */
function normThreats(threats: unknown): Array<Record<string, string>> | null {
  if (typeof threats === "string") threats = threats ? [threats] : [];
  // a single {type,...} object is one threat — do not iterate its keys
  else if (threats && typeof threats === "object" && !Array.isArray(threats)) threats = [threats];
  if (!Array.isArray(threats) || threats.length === 0) return null;
  const out: Array<Record<string, string>> = [];
  for (const t of threats) {
    if (typeof t === "string") {
      if (t) out.push({ type: t });
    } else if (t && typeof t === "object" && (t as Record<string, unknown>)["type"]) {
      const item: Record<string, string> = { type: String((t as Record<string, unknown>)["type"]) };
      const ref = (t as Record<string, unknown>)["ref"];
      if (ref != null && ref !== "") item["ref"] = String(ref);
      out.push(item);
    }
  }
  return out.length ? out : null;
}

// Which redaction finding types are personal data (vs. secrets/credentials).
// data.pii_types is DERIVED from the scanner's named personal-data categories —
// not comprehensive PII coverage (free-form names/addresses have no pattern; see
// LIMITS.md).
const PII_FINDING_TYPES = new Set(["email", "ssn", "credit_card", "phone", "iban"]);

function piiTypesFromFindings(findings: Finding[]): string[] | null {
  const types = [...new Set(
    findings.map((f) => f.type).filter((t) => PII_FINDING_TYPES.has(t)),
  )].sort();
  return types.length ? types : null;
}

/* Recursively make a value safe for RFC 8785 canonicalization, which permits only
   integer-valued numbers: a non-integer number is preserved as a string instead
   of crashing the recorder when the record is hashed. A no-op on any value that
   was already canonicalizable, so it never changes an existing hash — instrumentation
   must never take down the tool it is recording. */
function canonSafe(value: unknown): unknown {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isInteger(value) ? value : String(value);
  if (Array.isArray(value)) return value.map(canonSafe);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = canonSafe(v);
    return out;
  }
  return value;
}

/* Normalize the caller's data block so intuitive input can neither crash the
   recorder nor seal a schema-invalid record: region/purpose coerced to string,
   cross_region to 0/1 from a bool or integer number (dropped if non-numeric so a
   stray "yes" never poisons the chain); every other key made canon-safe. */
function normData(data: unknown): Record<string, unknown> {
  if (!data || typeof data !== "object" || Array.isArray(data)) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data as Record<string, unknown>)) {
    if (k === "cross_region") {
      if (typeof v === "boolean") out[k] = v ? 1 : 0;
      else if (typeof v === "number" && Number.isInteger(v)) out[k] = v;
      // a non-numeric cross_region is dropped, not sealed as invalid
    } else if (k === "region" || k === "purpose") {
      out[k] = typeof v === "string" ? v : String(v);
    } else {
      out[k] = canonSafe(v);
    }
  }
  return out;
}

export interface BuildOptions {
  tool?: string;
  toolInput?: unknown;
  sessionId?: string;
  agent?: { id: string; name: string };
  scope?: string;
  decision?: string;
  approver?: string;
  findings?: Finding[] | null;
  outcome?: Record<string, unknown> | null;
  ts?: string;
  subject?: string | { id: string; name?: string } | null;
  source?: string | Partial<Source> | null;
  summaries?: boolean;
  principal?: Record<string, unknown> | null;
  parentId?: string | null;
  threats?: unknown;
  data?: Record<string, unknown> | null;
}

export type HaloRecord = Record<string, unknown>;

/* Construct a v0.1 record (without integrity.hash filled in). tool_input is
   hashed and, by default, a redacted summary is stored; raw arguments never
   enter the record. Outcome summaries are redacted and scanned symmetrically
   with input. */
export function build(actionType: string, category: string, opts: BuildOptions = {}): HaloRecord {
  const {
    tool, toolInput, sessionId = "local", agent, scope, decision = "allowed",
    approver, outcome: outcomeIn, ts, subject, source, summaries = true,
    principal, parentId, threats, data,
  } = opts;
  let findings = opts.findings ?? null;

  if (!ACTION_TYPES.has(actionType)) {
    throw new RangeError("action.type must be one of " + [...ACTION_TYPES].sort().join(", "));
  }
  if (!CATEGORIES.has(category)) {
    throw new RangeError("action.category must be one of " + [...CATEGORIES].sort().join(", "));
  }

  const action: Record<string, unknown> = { type: actionType, category };
  if (tool !== undefined) action["tool"] = tool;
  if (scope !== undefined || decision !== undefined) {
    const auth: Record<string, unknown> = { decision };
    if (scope !== undefined) auth["scope"] = scope;
    if (approver !== undefined) auth["approver"] = approver;
    action["authorization"] = auth;
  }
  if (toolInput !== undefined) {
    const inp: Record<string, unknown> = { hash: inputHash(toolInput) };
    if (summaries) inp["summary"] = redactText(stringify(toolInput)).slice(0, 200);
    action["input"] = inp;
  }

  // Normalize the outcome up front so its summary is redacted before it is
  // sealed/served and so it can be scanned for secrets alongside the input.
  let outcome: Record<string, unknown> | null = null;
  let outcomeSummaryRaw: string | null = null;
  if (outcomeIn != null) {
    outcome = { ...outcomeIn };
    if ("summary" in outcome && outcome["summary"] != null) {
      outcomeSummaryRaw = String(outcome["summary"]);
    }
    if (!summaries) {
      delete outcome["summary"];
    } else if (outcomeSummaryRaw !== null) {
      outcome["summary"] = redactText(outcomeSummaryRaw).slice(0, 200);
    }
  }

  if (findings == null) {
    findings = [];
    if (toolInput !== undefined) findings.push(...scan(stringify(toolInput)));
    if (outcomeSummaryRaw !== null) findings.push(...scan(outcomeSummaryRaw));
  }

  const record: HaloRecord = {
    schema_version: SCHEMA_VERSION,
    record_id: randomUUID(),
    session_id: sessionId,
    ts: ts ?? now(),
    agent: agent ?? { id: "unknown", name: "unknown" },
    action,
    severity: topSeverity(findings),
    findings,
    integrity: { alg: "sha-256", canon: "rfc8785", prev_hash: "", hash: "" },
  };
  const subj = normSubject(subject);
  if (subj !== null) record["subject"] = subj;
  const prin = normPrincipal(principal);
  if (prin !== null) record["principal"] = prin;
  if (parentId != null && String(parentId) !== "") record["parent_id"] = String(parentId);
  const src = normalizeSource(source);
  if (src !== null) record["source"] = src;
  const thr = normThreats(threats);
  if (thr !== null) record["threats"] = thr;
  // data.pii_types is derived from the scanner's personal-data findings and
  // merged with any caller-supplied request-context (region/purpose/...).
  const dataBlock = normData(data);
  const piiTypes = piiTypesFromFindings(findings);
  if (piiTypes !== null) dataBlock["pii_types"] = piiTypes;
  if (Object.keys(dataBlock).length) record["data"] = dataBlock;
  if (outcome !== null) record["outcome"] = outcome;
  // Final guard: a caller-supplied non-integer number (a float score in
  // data/outcome, say) must never crash the recorder when the record is hashed.
  // No-op on a record that was already canonicalizable, so valid hashes are unchanged.
  return canonSafe(record) as HaloRecord;
}

function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function expandHome(p: string): string {
  return p.startsWith("~") ? join(homedir(), p.slice(1)) : p;
}

/* Append-only writer that maintains the hash chain in a JSONL file.

   append() is fully synchronous, so within a Node process parallel tool calls
   cannot interleave mid-append (the event loop runs the read-hash/write block
   atomically). The chain head is cached after the first read so appending
   stays O(1) per record instead of re-scanning the file. One Recorder
   instance should own a given log file per process. */
export class Recorder {
  path: string;
  #lastHash: string | null = null;

  constructor(path: string) {
    this.path = expandHome(path);
  }

  lastHash(): string {
    if (this.#lastHash !== null) return this.#lastHash;
    if (!existsSync(this.path)) return GENESIS_PREV;
    const lines = readFileSync(this.path, "utf8").split("\n").filter((l) => l.trim());
    if (lines.length === 0) return GENESIS_PREV;
    try {
      const rec = JSON.parse(lines[lines.length - 1]) as HaloRecord;
      const integ = (rec["integrity"] ?? {}) as Record<string, unknown>;
      return (integ["hash"] as string) || GENESIS_PREV;
    } catch {
      return GENESIS_PREV;
    }
  }

  append(record: HaloRecord): HaloRecord {
    const prev = this.lastHash();
    const integ = (record["integrity"] ??= {}) as Record<string, unknown>;
    integ["prev_hash"] = prev;
    integ["hash"] = computeHash(record, prev);
    appendFileSync(this.path, JSON.stringify(record) + "\n", "utf8");
    this.#lastHash = integ["hash"] as string;
    return record;
  }

  /* Convenience: build + append in one call. */
  record(actionType: string, category: string, opts: BuildOptions = {}): HaloRecord {
    return this.append(build(actionType, category, opts));
  }
}

/* Routes each record to a per-subject log, each its own hash chain. */
export class TenantRecorder {
  directory: string;
  default: string;
  private recorders: Map<string, Recorder> = new Map();

  constructor(directory: string, opts: { default?: string } = {}) {
    this.directory = expandHome(directory);
    this.default = opts.default ?? "_local";
  }

  static safe(name: unknown): string {
    const cleaned = String(name)
      .split("")
      .map((c) => (/[a-zA-Z0-9\-_.]/.test(c) ? c : "_"))
      .join("")
      .replace(/^[._]+|[._]+$/g, "");
    return cleaned || "tenant";
  }

  subjectId(record: HaloRecord): string {
    const subj = record["subject"];
    if (subj && typeof subj === "object" && (subj as Record<string, unknown>)["id"]) {
      return String((subj as Record<string, unknown>)["id"]);
    }
    return this.default;
  }

  pathFor(subjectId: string): string {
    return join(this.directory, TenantRecorder.safe(subjectId) + ".jsonl");
  }

  recorderFor(subjectId: string): Recorder {
    let r = this.recorders.get(subjectId);
    if (!r) {
      r = new Recorder(this.pathFor(subjectId));
      this.recorders.set(subjectId, r);
    }
    return r;
  }

  append(record: HaloRecord): HaloRecord {
    return this.recorderFor(this.subjectId(record)).append(record);
  }
}
