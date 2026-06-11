/* OpenAI Agents SDK (JavaScript) adapter.

   Returns a hooks object whose onToolStart/onToolEnd methods record each tool
   call — mirrors the Python HaloRunHooks. Pass it wherever the SDK accepts
   run hooks. No dependency on @openai/agents; the shape is structural:

       import { Recorder, createAgentsHooks } from "halo-record";
       const rec = new Recorder("audit.jsonl");
       const hooks = createAgentsHooks(rec);
       // run(agent, input, { hooks })  — or attach per the SDK version in use
*/

import { recordToolCall, type RecorderLike } from "./common.ts";
import type { Source } from "../record.ts";

const AGENT = { id: "openai_agents", name: "openai_agents" };

export interface AgentsHooksOptions {
  category?: string;
  scope?: string;
  sessionId?: string;
  agent?: { id: string; name: string };
  subject?: string | { id: string; name?: string } | null;
  source?: string | Partial<Source>;
  summaries?: boolean;
}

interface ToolLike {
  name?: string;
  toolName?: string;
}

function toolName(tool: ToolLike | string | undefined): string {
  if (typeof tool === "string") return tool;
  return tool?.name ?? tool?.toolName ?? "tool";
}

export function createAgentsHooks(recorder: RecorderLike, opts: AgentsHooksOptions = {}) {
  const pending = new Map<unknown, string>();

  return {
    async onToolStart(_context: unknown, _agent: unknown, tool: ToolLike | string): Promise<void> {
      pending.set(typeof tool === "object" ? tool : String(tool), toolName(tool));
    },

    async onToolEnd(_context: unknown, _agent: unknown, tool: ToolLike | string, result: unknown): Promise<void> {
      const key = typeof tool === "object" ? tool : String(tool);
      const name = pending.get(key) ?? toolName(tool);
      pending.delete(key);
      recordToolCall(recorder, name, undefined, {
        response: result,
        agent: opts.agent ?? AGENT,
        category: opts.category,
        scope: opts.scope,
        sessionId: opts.sessionId ?? "local",
        subject: opts.subject,
        source: opts.source ?? "openai_agents",
        summaries: opts.summaries ?? true,
      });
    },
  };
}
