import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { build, Recorder } from "../src/record.ts";

function dir() { return mkdtempSync(join(tmpdir(), "halo-auth-")); }

test("authority: known secret formats are masked at seal time", () => {
  const rec = build("tool_call", "security", {
    tool: "t",
    authority: { snapshot_id: "auth_1", skills: { deploy: "sk-" + "a1B2".repeat(8) }, note: "Bearer " + "tok".repeat(12) },
  });
  const auth = JSON.stringify(rec["authority"]);
  assert.ok(!auth.includes("sk-" + "a1B2".repeat(8)));
  assert.ok(!auth.includes("tok".repeat(12)));
});

test("authority: hashes and refs survive unmasked", () => {
  const legit = {
    snapshot_id: "auth_1",
    path_hash: "sha256:" + "ab12".repeat(16),
    worktree_hash: "9f".repeat(32),
    ref: "refs/heads/main@e908f88",
  };
  const rec = build("tool_call", "security", { tool: "t", authority: { ...legit } });
  assert.deepEqual(rec["authority"], legit);
});

test("authority: same id + same content compacts; changed content stores full body", () => {
  const rec = new Recorder(join(dir(), "c.jsonl"));
  const a = { snapshot_id: "auth_1", rules_hash: "ab".repeat(32) };
  rec.record("tool_call", "security", { tool: "a", authority: { ...a } });
  const second = rec.record("tool_call", "security", { tool: "b", authority: { ...a } });
  assert.deepEqual(second["authority"], { snapshot_id: "auth_1", same_as_previous: true });
  const changed = { snapshot_id: "auth_1", rules_hash: "cd".repeat(32) };
  const third = rec.record("tool_call", "security", { tool: "c", authority: { ...changed } });
  assert.deepEqual(third["authority"], changed);
});

test("hash-only outcome keeps schema fields only", () => {
  const rec = build("tool_call", "security", {
    tool: "t",
    outcome: { status: "ok", summary: "sent it", notes: "free text", rows: 3 },
    summaries: false,
  });
  assert.deepEqual(Object.keys(rec["outcome"] as object), ["status"]);
  const def = build("tool_call", "security", {
    tool: "t", outcome: { status: "ok", summary: "sent it", rows: 3 },
  });
  assert.equal((def["outcome"] as Record<string, unknown>)["rows"], 3);
});

test("authority: fresh process over compacted tail stores full body", () => {
  const path = join(dir(), "c.jsonl");
  const rec = new Recorder(path);
  const a = { snapshot_id: "auth_1", rules_hash: "ab".repeat(32) };
  rec.record("tool_call", "security", { tool: "a", authority: { ...a } });
  rec.record("tool_call", "security", { tool: "b", authority: { ...a } });
  const fresh = new Recorder(path);
  const changed = { snapshot_id: "auth_1", rules_hash: "cd".repeat(32) };
  const third = fresh.record("tool_call", "security", { tool: "c", authority: { ...changed } });
  assert.deepEqual(third["authority"], changed);
});

test("authority: secret used as a key is masked", () => {
  const rec = build("tool_call", "security", {
    tool: "t",
    authority: { snapshot_id: "auth_1", ["sk-" + "a1B2".repeat(8)]: "value" },
  });
  assert.ok(!JSON.stringify(rec["authority"]).includes("sk-" + "a1B2".repeat(8)));
});

test("hash-only rejects payload-shaped status and hash, keeps valid hash", () => {
  const bad = build("tool_call", "security", {
    tool: "t",
    outcome: { status: "the customer's SSN is 123-45-6789", hash: "free text hiding here" },
    summaries: false,
  });
  assert.deepEqual(bad["outcome"] ?? {}, {});
  const good = build("tool_call", "security", {
    tool: "t",
    outcome: { status: "ok", hash: "sha256:" + "ab".repeat(16) },
    summaries: false,
  });
  assert.deepEqual(Object.keys(good["outcome"] as object).sort(), ["hash", "status"]);
});
