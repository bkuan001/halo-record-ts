/* halo-record — tamper-evident Runtime Records for AI agents (TypeScript).
   Same chain format as the Python package: records written here verify with
   either verifier and anchor to the same witness. */

export { GENESIS_PREV, canon, sha256Hex, computeHash, inputHash } from "./canon.ts";
export { redactText, redactSample, scan, topSeverity, SEVERITY_RANK, type Finding, type Severity } from "./redact.ts";
export {
  SCHEMA_VERSION, ACTION_TYPES, CATEGORIES, SOURCES, normalizeSource,
  build, Recorder, TenantRecorder,
  type Source, type BuildOptions, type HaloRecord,
} from "./record.ts";
export { loadSchema, validateRecord, verifyRecords, verifyLog, readLog, type VerifyResult } from "./verify.ts";
export {
  chainRoot, head, checkpoint, verifyCompleteness,
  type Checkpoint, type CompletenessResult,
} from "./anchor.ts";
export { anchorRemote, fetchCheckpoints } from "./witness.ts";
export {
  classifyTool, deriveScope, deriveOutcome, recordToolCall, recordModelCall,
  ACTION_TYPE_BY_CLASS, CATEGORY_BY_CLASS,
  type ActionClass, type RecorderLike, type ToolCallOptions, type ModelCallOptions,
} from "./integrations/common.ts";
export { createLangChainHandler, type LangChainHandlerOptions } from "./integrations/langchain.ts";
export { recordMcpCall, instrumentMcpClient, wrapMcpToolHandler, type McpOptions } from "./integrations/mcp.ts";
export { createAgentsHooks, type AgentsHooksOptions } from "./integrations/openaiAgents.ts";
export { wrapVercelTools, createStepRecorder, type VercelOptions } from "./integrations/vercel.ts";
export { createClaudeAgentHook, DEFAULT_SKIP_TOOLS, type ClaudeAgentHookOptions } from "./integrations/claudeAgent.ts";
