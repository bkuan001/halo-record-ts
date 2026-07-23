/* Adapter tests with framework fakes — same approach as the Python suite:
   no framework packages required; the fakes exercise the structural contract
   each adapter expects. Every test ends by verifying the emitted chain. */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { build, Recorder } from "../src/record.ts";
import { verifyLog, readLog } from "../src/verify.ts";
import { classifyTool, deriveScope, deriveOutcome } from "../src/integrations/common.ts";
import { createLangChainHandler } from "../src/integrations/langchain.ts";
import { recordMcpCall, instrumentMcpClient, wrapMcpToolHandler } from "../src/integrations/mcp.ts";
import { createAgentsHooks } from "../src/integrations/openaiAgents.ts";
import { wrapVercelTools, createStepRecorder } from "../src/integrations/vercel.ts";

function tmpChain(): { dir: string; path: string; rec: Recorder } {
  const dir = mkdtempSync(join(tmpdir(), "halo-adapters-"));
  const path = join(dir, "chain.jsonl");
  return { dir, path, rec: new Recorder(path) };
}

test("common: classification + scope mirror Python tables", () => {
  assert.equal(classifyTool("mcp__gmail__search"), "connector");
  assert.equal(classifyTool("bash"), "exec");
  assert.equal(classifyTool("write_file"), "data_write");
  assert.equal(classifyTool("read"), "data_read");
  assert.equal(classifyTool("webfetch"), "network");
  assert.equal(classifyTool("frobnicate"), "connector");
  assert.equal(deriveScope("connector", "mcp__gmail__search"), "mcp:gmail");
  assert.equal(deriveScope("data_read", "read"), "fs.read");
});

test("common: deriveOutcome — error wins, explicit markers only; build redacts+scans", () => {
  assert.equal(deriveOutcome({ ok: true })["status"], "ok");
  assert.equal(deriveOutcome({ is_error: true })["status"], "error");
  assert.equal(deriveOutcome({ status: "error" })["status"], "error");
  assert.equal(deriveOutcome("fine", new Error("boom"))["status"], "error");
  // deriveOutcome carries the RAW summary; build() is the single place that
  // scans it (so response secrets are flagged) and redacts it before storage.
  const out = deriveOutcome({ text: "key sk-ABCDEFGHIJKLMNOPQRSTUVWX here" });
  const rec = build("tool_call", "security", { tool: "t", outcome: out });
  const flat = JSON.stringify(rec);
  assert.ok(!flat.includes("sk-ABCDEFGHIJKLMNOPQRSTUVWX"), "secret survived into record");
  assert.equal((rec["severity"] as string), "CRITICAL");
});

test("langchain: fake agent run → records on end and error, chain verifies", () => {
  const { dir, path, rec } = tmpChain();
  try {
    const h = createLangChainHandler(rec, { subject: "acme" });
    h.handleToolStart({ name: "search" }, '{"q":"weather"}', "run-1");
    h.handleToolEnd("sunny", "run-1");
    h.handleToolStart({ name: "db_query" }, '{"q":"select"}', "run-2");
    h.handleToolError(new Error("timeout"), "run-2");
    h.handleToolEnd("orphan output", "run-unknown"); // no start → no record

    const records = readLog(path);
    assert.equal(records.length, 2);
    assert.equal((records[0]["action"] as any)["tool"], "search");
    assert.equal((records[0]["outcome"] as any)["status"], "ok");
    assert.equal((records[1]["outcome"] as any)["status"], "error");
    assert.equal((records[0]["source"] as any)["adapter"], "langchain");
    assert.equal((records[0]["source"] as any)["capture"], "captured");
    assert.ok(verifyLog(path).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mcp: client instrumentation records success and failure, names normalized", async () => {
  const { dir, path, rec } = tmpChain();
  try {
    const client = {
      async callTool(params: { name: string; arguments?: Record<string, unknown> }) {
        if (params.name === "explode") throw new Error("server fell over");
        return { content: [{ type: "text", text: "42 results" }], isError: false };
      },
    };
    instrumentMcpClient(client, rec, { server: "gmail", subject: "acme" });
    instrumentMcpClient(client, rec, { server: "gmail" }); // idempotent

    await client.callTool({ name: "search_threads", arguments: { q: "x" } });
    await assert.rejects(() => client.callTool({ name: "explode" }));

    const records = readLog(path);
    assert.equal(records.length, 2);
    assert.equal((records[0]["action"] as any)["tool"], "mcp__gmail__search_threads");
    assert.equal((records[0]["action"] as any)["authorization"]["scope"], "mcp:gmail");
    assert.equal((records[0]["outcome"] as any)["status"], "ok");
    assert.equal((records[1]["outcome"] as any)["status"], "error");
    assert.ok(verifyLog(path).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mcp: server handler wrapper records at the boundary; isError marks error", async () => {
  const { dir, path, rec } = tmpChain();
  try {
    const handler = async (req: { params: { name: string; arguments?: Record<string, unknown> } }) => {
      return { content: [{ type: "text", text: "denied" }], isError: true };
    };
    const wrapped = wrapMcpToolHandler(handler, rec, { server: "files" });
    await wrapped({ params: { name: "delete_all", arguments: {} } });

    const records = readLog(path);
    assert.equal(records.length, 1);
    assert.equal((records[0]["outcome"] as any)["status"], "error");
    assert.ok(verifyLog(path).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("openai agents: hooks record tool end with result", async () => {
  const { dir, path, rec } = tmpChain();
  try {
    const hooks = createAgentsHooks(rec, { subject: "acme" });
    const tool = { name: "refund_lookup" };
    await hooks.onToolStart({}, {}, tool);
    await hooks.onToolEnd({}, {}, tool, "refund issued: $48");

    const records = readLog(path);
    assert.equal(records.length, 1);
    assert.equal((records[0]["action"] as any)["tool"], "refund_lookup");
    assert.equal((records[0]["source"] as any)["adapter"], "openai_agents");
    assert.ok(String((records[0]["outcome"] as any)["summary"]).includes("refund issued"));
    assert.ok(verifyLog(path).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("vercel: wrapVercelTools records execute success/error; non-executable tools pass through", async () => {
  const { dir, path, rec } = tmpChain();
  try {
    const tools = {
      weather: { description: "get weather", execute: async (args: unknown) => ({ temp: 72 }) },
      crash: { execute: async () => { throw new Error("api down"); } },
      clientSide: { description: "no execute" },
    };
    const wrapped = wrapVercelTools(tools as any, rec, { subject: "acme" });
    assert.equal(wrapped.clientSide, tools.clientSide);

    await wrapped.weather.execute!({ city: "LA" });
    await assert.rejects(() => Promise.resolve(wrapped.crash.execute!({})));

    const records = readLog(path);
    assert.equal(records.length, 2);
    assert.equal((records[0]["action"] as any)["tool"], "weather");
    assert.equal((records[0]["source"] as any)["adapter"], "vercel_ai");
    assert.equal((records[0]["source"] as any)["capture"], "captured");
    assert.equal((records[1]["outcome"] as any)["status"], "error");
    assert.ok(verifyLog(path).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("vercel: createStepRecorder pairs toolCalls with toolResults", () => {
  const { dir, path, rec } = tmpChain();
  try {
    const onStepFinish = createStepRecorder(rec);
    onStepFinish({
      toolCalls: [
        { toolCallId: "c1", toolName: "search", args: { q: "x" } },
        { toolCallId: "c2", toolName: "send_email", args: { to: "a@b.co" } },
      ],
      toolResults: [
        { toolCallId: "c1", result: "found 3" },
        { toolCallId: "c2", result: { is_error: true, reason: "blocked" } },
      ],
    });
    const records = readLog(path);
    assert.equal(records.length, 2);
    assert.equal((records[0]["outcome"] as any)["status"], "ok");
    assert.equal((records[1]["outcome"] as any)["status"], "error");
    assert.ok(verifyLog(path).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("claude agent sdk: PostToolUse hook records, skips workflow tools, never blocks", async () => {
  const { mkdtempSync: mk, rmSync: rm } = await import("node:fs");
  const { tmpdir: td } = await import("node:os");
  const { join: j } = await import("node:path");
  const { Recorder: R } = await import("../src/record.ts");
  const { verifyLog: vl, readLog: rl } = await import("../src/verify.ts");
  const { createClaudeAgentHook } = await import("../src/integrations/claudeAgent.ts");

  const dir = mk(j(td(), "halo-cas-"));
  const path = j(dir, "chain.jsonl");
  try {
    const rec = new R(path);
    const hook = createClaudeAgentHook(rec, { subject: "acme" });

    const out1 = await hook({ hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_response: { stdout: "file.txt" }, session_id: "s-9" });
    assert.deepEqual(out1, {}); // record-only: empty hook output, never blocks
    await hook({ hook_event_name: "PostToolUse", tool_name: "TodoWrite", tool_input: {} }); // skipped
    await hook({ hook_event_name: "PostToolUse", tool_name: "mcp__gmail__search_threads", tool_input: { q: "x" }, tool_response: "2 threads" });

    const records = rl(path);
    assert.equal(records.length, 2);
    assert.equal((records[0]["action"] as any)["tool"], "Bash");
    assert.equal(records[0]["session_id"], "s-9");
    assert.equal((records[0]["source"] as any)["adapter"], "claude_agent_sdk");
    assert.equal((records[0]["source"] as any)["capture"], "captured");
    assert.equal((records[1]["action"] as any)["authorization"]["scope"], "mcp:gmail");
    assert.ok(vl(path).ok);
  } finally {
    rm(dir, { recursive: true, force: true });
  }
});
