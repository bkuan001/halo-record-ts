/* LangChain.js / LangGraph.js adapter.

   Returns a plain callback-handler object (LangChain.js accepts handler
   objects in the `callbacks` array — no subclassing, no dependency on the
   langchain package):

       import { Recorder } from "halo-record";
       import { createLangChainHandler } from "halo-record";

       const rec = new Recorder("audit.jsonl");
       await agent.invoke(inputs, { callbacks: [createLangChainHandler(rec)] });

   Mirrors the Python HaloCallbackHandler: tool calls keyed by runId, one
   record emitted on end or error. */

import { recordToolCall, type RecorderLike } from "./common.ts";
import type { Source } from "../record.ts";

const AGENT = { id: "langchain", name: "langchain" };

export interface LangChainHandlerOptions {
  category?: string;
  scope?: string;
  sessionId?: string;
  agent?: { id: string; name: string };
  subject?: string | { id: string; name?: string } | null;
  source?: string | Partial<Source>;
  summaries?: boolean;
}

interface Pending {
  tool: string;
  input: unknown;
}

export function createLangChainHandler(recorder: RecorderLike, opts: LangChainHandlerOptions = {}) {
  const pending = new Map<string, Pending>();

  const emit = (runId: string, output?: unknown, error?: unknown) => {
    const p = pending.get(runId);
    if (!p) return;
    pending.delete(runId);
    recordToolCall(recorder, p.tool, p.input, {
      response: output,
      error,
      agent: opts.agent ?? AGENT,
      category: opts.category,
      scope: opts.scope,
      sessionId: opts.sessionId ?? "local",
      subject: opts.subject,
      source: opts.source ?? "langchain",
      summaries: opts.summaries ?? true,
    });
  };

  return {
    name: "halo-record",

    handleToolStart(
      tool: { name?: string; id?: string[] } | undefined,
      input: string,
      runId: string,
    ): void {
      const name = tool?.name ?? (Array.isArray(tool?.id) ? tool.id[tool.id.length - 1] : undefined) ?? "tool";
      pending.set(runId, { tool: name, input });
    },

    handleToolEnd(output: unknown, runId: string): void {
      emit(runId, output);
    },

    handleToolError(err: unknown, runId: string): void {
      emit(runId, undefined, err);
    },
  };
}
