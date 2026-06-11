/* MCP (Model Context Protocol) adapter — TypeScript SDK.

   Client side: instrument an MCP client so every callTool is recorded:

       import { Recorder, instrumentMcpClient } from "halo-record";
       const rec = new Recorder("audit.jsonl");
       instrumentMcpClient(client, rec, { server: "gmail" });

   Server side: wrap a tool handler so calls are recorded where they execute:

       server.setRequestHandler(CallToolRequestSchema,
         wrapMcpToolHandler(handler, rec, { server: "gmail" }));

   Tool names are normalized to mcp__<server>__<name> so they classify as
   connectors with scope mcp:<server> — the same shape the Python adapter and
   the Claude Code hook produce, so reports look identical across on-ramps. */

import { recordToolCall, type RecorderLike } from "./common.ts";

const AGENT = { id: "mcp", name: "mcp" };

export interface McpOptions {
  server?: string;
  agent?: { id: string; name: string };
  sessionId?: string;
  subject?: string | { id: string; name?: string } | null;
  summaries?: boolean;
}

/* Flatten an MCP tool result (content blocks + isError) into the payload
   shape deriveOutcome understands — mirrors the Python _result_payload. */
function resultPayload(response: unknown): Record<string, unknown> {
  if (response === null || response === undefined) return { is_error: false };
  const r = response as Record<string, unknown>;
  const isError = Boolean(r["isError"] ?? r["is_error"]);
  const textParts: string[] = [];
  const content = r["content"];
  if (Array.isArray(content)) {
    for (const item of content) {
      const t = (item as Record<string, unknown>)?.["text"];
      if (typeof t === "string") textParts.push(t);
    }
  }
  const payload: Record<string, unknown> = { is_error: isError };
  if (textParts.length) payload["summary"] = textParts.join(" ");
  return payload;
}

function normalizeName(name: string, server: string): string {
  return name.startsWith("mcp__") ? name : `mcp__${server}__${name}`;
}

/* Record one MCP tool call (use directly when you own the call site). */
export function recordMcpCall(
  recorder: RecorderLike,
  name: string,
  args: unknown,
  opts: McpOptions & { response?: unknown; error?: unknown } = {},
) {
  return recordToolCall(recorder, normalizeName(name, opts.server ?? "mcp"), args, {
    response: opts.error === undefined ? resultPayload(opts.response) : undefined,
    error: opts.error,
    agent: opts.agent ?? AGENT,
    cls: "connector",
    sessionId: opts.sessionId ?? "local",
    subject: opts.subject,
    source: "mcp",
    summaries: opts.summaries ?? true,
  });
}

interface CallToolParams {
  name: string;
  arguments?: Record<string, unknown>;
}

interface McpClientLike {
  callTool(params: CallToolParams, ...rest: unknown[]): Promise<unknown>;
}

/* Wrap client.callTool so every tool call is recorded. Returns the client
   (now instrumented). Idempotent: a client is only wrapped once. */
export function instrumentMcpClient<T extends McpClientLike>(
  client: T,
  recorder: RecorderLike,
  opts: McpOptions = {},
): T {
  const original = client.callTool?.bind(client);
  if (!original || (client.callTool as { _haloWrapped?: boolean })._haloWrapped) return client;

  const wrapped = async (params: CallToolParams, ...rest: unknown[]) => {
    try {
      const result = await original(params, ...rest);
      recordMcpCall(recorder, params.name, params.arguments, { ...opts, response: result });
      return result;
    } catch (err) {
      recordMcpCall(recorder, params.name, params.arguments, { ...opts, error: err });
      throw err;
    }
  };
  (wrapped as { _haloWrapped?: boolean })._haloWrapped = true;
  client.callTool = wrapped as T["callTool"];
  return client;
}

type ToolHandler = (request: { params: CallToolParams }, ...rest: unknown[]) => Promise<unknown>;

/* Wrap an MCP server CallToolRequest handler so every executed tool call is
   recorded at the server boundary. */
export function wrapMcpToolHandler(
  handler: ToolHandler,
  recorder: RecorderLike,
  opts: McpOptions = {},
): ToolHandler {
  return async (request, ...rest) => {
    const { name, arguments: args } = request.params;
    try {
      const result = await handler(request, ...rest);
      recordMcpCall(recorder, name, args, { ...opts, response: result });
      return result;
    } catch (err) {
      recordMcpCall(recorder, name, args, { ...opts, error: err });
      throw err;
    }
  };
}
