/* Claude Agent SDK adapter.

   Returns a PostToolUse hook callback — every tool call the agent makes is
   recorded, and the hook never blocks or alters the call (record-only, by
   design). No dependency on @anthropic-ai/claude-agent-sdk; the hook input
   shape is structural (same event JSON as the Claude Code hook):

       import { Recorder, createClaudeAgentHook } from "halo-record";

       const rec = new Recorder("audit.jsonl");
       const result = query({
         prompt,
         options: {
           hooks: { PostToolUse: [{ hooks: [createClaudeAgentHook(rec)] }] },
         },
       });

   Skips the same workflow-internal tools as the Python Claude Code hook
   (TodoWrite, Task, etc.) — override with opts.skipTools. */

import { recordToolCall, type RecorderLike } from "./common.ts";
import type { Source } from "../record.ts";

const AGENT = { id: "claude_agent_sdk", name: "claude_agent_sdk" };

/* Same defaults as the Python hook's SKIP_TOOLS. */
export const DEFAULT_SKIP_TOOLS = new Set([
  "TodoWrite", "ExitPlanMode", "Task", "Skill", "BashOutput", "KillShell",
]);

export interface ClaudeAgentHookOptions {
  category?: string;
  scope?: string;
  sessionId?: string;
  agent?: { id: string; name: string };
  subject?: string | { id: string; name?: string } | null;
  source?: string | Partial<Source>;
  summaries?: boolean;
  skipTools?: Set<string>;
}

interface PostToolUseInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: unknown;
  tool_response?: unknown;
  session_id?: string;
  [k: string]: unknown;
}

export function createClaudeAgentHook(recorder: RecorderLike, opts: ClaudeAgentHookOptions = {}) {
  const skip = opts.skipTools ?? DEFAULT_SKIP_TOOLS;

  return async (input: PostToolUseInput, _toolUseID?: string, _extra?: unknown): Promise<Record<string, never>> => {
    const name = input?.tool_name;
    if (name && !skip.has(name)) {
      recordToolCall(recorder, name, input.tool_input, {
        response: input.tool_response,
        agent: opts.agent ?? AGENT,
        category: opts.category,
        scope: opts.scope,
        sessionId: opts.sessionId ?? (typeof input.session_id === "string" ? input.session_id : "local"),
        subject: opts.subject,
        source: opts.source ?? "claude_agent_sdk",
        summaries: opts.summaries ?? true,
      });
    }
    return {}; // record-only: never block, never modify
  };
}
