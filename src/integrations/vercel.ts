/* Vercel AI SDK adapter.

   Two on-ramps, both boundary-captured:

   1. Wrap your tools object — every execute() is recorded, including errors:

        import { Recorder, wrapVercelTools } from "halo-record";
        const rec = new Recorder("audit.jsonl");
        const result = await generateText({ model, tools: wrapVercelTools(tools, rec), ... });

   2. Or record from onStepFinish (no tool wrapping; pairs toolCalls with
      toolResults per step):

        await generateText({ model, tools,
          onStepFinish: createStepRecorder(rec) });

   No dependency on the `ai` package; shapes are structural. */

import { recordToolCall, type RecorderLike } from "./common.ts";
import type { Source } from "../record.ts";

const AGENT = { id: "vercel_ai", name: "vercel_ai" };

export interface VercelOptions {
  category?: string;
  scope?: string;
  sessionId?: string;
  agent?: { id: string; name: string };
  subject?: string | { id: string; name?: string } | null;
  source?: string | Partial<Source>;
  summaries?: boolean;
}

interface VercelToolLike {
  execute?: (args: unknown, options?: unknown) => Promise<unknown> | unknown;
  [k: string]: unknown;
}

/* Wrap each tool's execute so the call is recorded where it runs. Tools
   without an execute function (client-side tools) pass through untouched. */
export function wrapVercelTools<T extends Record<string, VercelToolLike>>(
  tools: T,
  recorder: RecorderLike,
  opts: VercelOptions = {},
): T {
  const out: Record<string, VercelToolLike> = {};
  for (const [name, tool] of Object.entries(tools)) {
    if (typeof tool?.execute !== "function") {
      out[name] = tool;
      continue;
    }
    const original = tool.execute.bind(tool);
    out[name] = {
      ...tool,
      execute: async (args: unknown, options?: unknown) => {
        try {
          const result = await original(args, options);
          recordToolCall(recorder, name, args, {
            response: result,
            agent: opts.agent ?? AGENT,
            category: opts.category,
            scope: opts.scope,
            sessionId: opts.sessionId ?? "local",
            subject: opts.subject,
            source: opts.source ?? "vercel_ai",
            summaries: opts.summaries ?? true,
          });
          return result;
        } catch (err) {
          recordToolCall(recorder, name, args, {
            error: err,
            agent: opts.agent ?? AGENT,
            category: opts.category,
            scope: opts.scope,
            sessionId: opts.sessionId ?? "local",
            subject: opts.subject,
            source: opts.source ?? "vercel_ai",
            summaries: opts.summaries ?? true,
          });
          throw err;
        }
      },
    };
  }
  return out as T;
}

interface StepLike {
  toolCalls?: Array<{ toolCallId?: string; toolName?: string; args?: unknown; input?: unknown }>;
  toolResults?: Array<{ toolCallId?: string; toolName?: string; result?: unknown; output?: unknown }>;
}

/* onStepFinish handler: records each toolCall paired with its toolResult.
   Use when you can't (or don't want to) wrap tool execute functions. */
export function createStepRecorder(recorder: RecorderLike, opts: VercelOptions = {}) {
  return (step: StepLike): void => {
    const calls = step.toolCalls ?? [];
    const results = new Map(
      (step.toolResults ?? []).map((r) => [r.toolCallId ?? r.toolName, r.result ?? r.output]),
    );
    for (const call of calls) {
      const name = call.toolName ?? "tool";
      recordToolCall(recorder, name, call.args ?? call.input, {
        response: results.get(call.toolCallId ?? name),
        agent: opts.agent ?? AGENT,
        category: opts.category,
        scope: opts.scope,
        sessionId: opts.sessionId ?? "local",
        subject: opts.subject,
        source: opts.source ?? "vercel_ai",
        summaries: opts.summaries ?? true,
      });
    }
  };
}
