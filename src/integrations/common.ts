/* Shared, framework-independent core for the adapters — port of the Python
   integrations/_common.py funnel. Every adapter ultimately does the same
   thing: take a tool name, its input, and an outcome (return value or error),
   and append one Halo Runtime Record. No framework imports here. */

import { inputHash } from "../canon.ts";
import { redactText } from "../redact.ts";
import { build, type HaloRecord, type Source } from "../record.ts";

export type ActionClass = "connector" | "exec" | "data_write" | "data_read" | "network" | "other";

export const ACTION_TYPE_BY_CLASS: Record<ActionClass, string> = {
  connector: "tool_call",
  exec: "tool_call",
  data_write: "write",
  data_read: "read",
  network: "network",
  other: "tool_call",
};

export const CATEGORY_BY_CLASS: Record<ActionClass, string> = {
  connector: "security",
  exec: "security",
  data_write: "safety",
  data_read: "privacy",
  network: "security",
  other: "security",
};

/* Map an arbitrary tool name to a Halo action class. Never returns null
   (adapters decide what to skip) — an unrecognized tool is a generic
   "connector" call, the safe default for a trust-boundary action whose nature
   we can't infer from the name alone. */
export function classifyTool(toolName: string | null | undefined): ActionClass {
  if (!toolName) return "connector";
  if (toolName.startsWith("mcp__") || toolName.startsWith("mcp:")) return "connector";
  const lowered = toolName.toLowerCase();
  if (["bash", "shell", "exec", "python", "code_interpreter"].includes(lowered)) return "exec";
  if (["write", "edit", "write_file", "create_file", "put"].includes(lowered)) return "data_write";
  if (["read", "glob", "grep", "ls", "read_file", "list", "get"].includes(lowered)) return "data_read";
  if (["webfetch", "websearch", "fetch", "search", "http", "browse"].includes(lowered)) return "network";
  return "connector";
}

export function deriveScope(cls: ActionClass, toolName: string): string {
  if (cls === "connector") {
    const parts = toolName.split("__");
    const server = parts.length > 1 ? parts[1] : "mcp";
    return "mcp:" + server;
  }
  return ({ data_read: "fs.read", data_write: "fs.write", exec: "exec", network: "network" } as Record<string, string>)[cls] ?? "tool";
}

function extractText(obj: unknown, depth = 0): string {
  if (depth > 6) return "";
  if (typeof obj === "string") return obj;
  if (Array.isArray(obj)) return obj.map((i) => extractText(i, depth + 1)).join(" ");
  if (obj !== null && typeof obj === "object") {
    return Object.values(obj).map((v) => extractText(v, depth + 1)).join(" ");
  }
  return String(obj);
}

/* Deterministic outcome block: what the call actually did. status is "error"
   only on a thrown error or an explicit error marker in the response — never
   inferred (ledger, not classifier). The full response is hashed into the
   chain; only a redacted summary is stored, never the raw content. */
export function deriveOutcome(response: unknown, error?: unknown): Record<string, unknown> {
  if (error !== undefined && error !== null) {
    return {
      status: "error",
      summary: redactText(String(error)).slice(0, 200),
      hash: inputHash({ error: String(error) }),
    };
  }
  let status = "ok";
  if (response !== null && typeof response === "object" && !Array.isArray(response)) {
    const r = response as Record<string, unknown>;
    if (r["is_error"] || r["error"] || r["status"] === "error") status = "error";
  }
  const out: Record<string, unknown> = { status, hash: inputHash(response ?? null) };
  const summary = redactText(extractText(response ?? "")).slice(0, 200);
  if (summary) out["summary"] = summary;
  return out;
}

export interface RecorderLike {
  append(record: HaloRecord): HaloRecord;
}

export interface ToolCallOptions {
  response?: unknown;
  error?: unknown;
  agent?: { id: string; name: string };
  cls?: ActionClass;
  actionType?: string;
  category?: string;
  scope?: string;
  sessionId?: string;
  decision?: string;
  approver?: string;
  subject?: string | { id: string; name?: string } | null;
  source?: string | Partial<Source> | null;
  summaries?: boolean;
}

export interface ModelCallOptions {
  provider: string;
  model: string;
  zdr?: boolean;
  purpose?: string;
  messages?: number;
  response?: unknown;
  error?: unknown;
  agent?: { id: string; name: string };
  sessionId?: string;
  subject?: string | { id: string; name?: string } | null;
  source?: string | Partial<Source> | null;
  summaries?: boolean;
}

/* Record one LLM generation as a first-class action. The buyer's first
   question about a bought agent is "which model saw my data, and was it
   allowed to keep it?" — so model calls get their own loud entry:
   tool=model.generate, scope=model:<provider>, category privacy, with
   provider / model / zero-data-retention / purpose in the (hashed +
   summarized) input. Raw prompts and completions never enter the record. */
export function recordModelCall(recorder: RecorderLike, opts: ModelCallOptions): HaloRecord {
  const toolInput: Record<string, unknown> = { provider: opts.provider, model: opts.model };
  if (opts.zdr !== undefined) toolInput["zdr"] = Boolean(opts.zdr);
  if (opts.purpose) toolInput["purpose"] = opts.purpose;
  if (opts.messages !== undefined) toolInput["messages"] = opts.messages;
  return recordToolCall(recorder, "model.generate", toolInput, {
    response: opts.response,
    error: opts.error,
    agent: opts.agent,
    actionType: "tool_call",
    category: "privacy",
    scope: "model:" + opts.provider,
    sessionId: opts.sessionId ?? "local",
    subject: opts.subject,
    source: opts.source,
    summaries: opts.summaries ?? true,
  });
}

/* Build and append one record for a completed tool call — the single funnel
   every adapter goes through, so classification, scope derivation, redaction,
   and hashing behave identically regardless of ecosystem. */
export function recordToolCall(
  recorder: RecorderLike,
  toolName: string,
  toolInput?: unknown,
  opts: ToolCallOptions = {},
): HaloRecord {
  const cls = opts.cls ?? classifyTool(toolName);
  const record = build(
    opts.actionType ?? ACTION_TYPE_BY_CLASS[cls] ?? "tool_call",
    opts.category ?? CATEGORY_BY_CLASS[cls] ?? "security",
    {
      tool: toolName,
      toolInput,
      sessionId: opts.sessionId ?? "local",
      agent: opts.agent,
      scope: opts.scope ?? deriveScope(cls, toolName),
      decision: opts.decision ?? "allowed",
      approver: opts.approver,
      outcome: deriveOutcome(opts.response, opts.error),
      subject: opts.subject,
      source: opts.source,
      summaries: opts.summaries ?? true,
    },
  );
  return recorder.append(record);
}
