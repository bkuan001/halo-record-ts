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
  const src = normalizeSource(source);
  if (src !== null) record["source"] = src;
  if (outcome !== null) record["outcome"] = outcome;
  return record;
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
