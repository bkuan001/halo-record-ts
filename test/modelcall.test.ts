import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Recorder } from "../src/record.ts";
import { verifyLog } from "../src/verify.ts";
import { recordModelCall } from "../src/integrations/common.ts";

test("recordModelCall: provider, ZDR, purpose disclosed; privacy lens; chain verifies", () => {
  const dir = mkdtempSync(join(tmpdir(), "halo-mc-"));
  const path = join(dir, "chain.jsonl");
  try {
    const rec = new Recorder(path);
    const record = recordModelCall(rec, {
      provider: "anthropic",
      model: "claude-opus-4-8",
      zdr: true,
      purpose: "draft SIG questionnaire answers",
      messages: 9,
      response: { summary: "drafted 42 answers" },
      subject: "acme-corp",
      source: "litellm",
    });

    assert.equal((record["action"] as any)["tool"], "model.generate");
    assert.equal((record["action"] as any)["category"], "privacy");
    assert.equal((record["action"] as any)["authorization"]["scope"], "model:anthropic");
    const summary = (record["action"] as any)["input"]["summary"] as string;
    assert.ok(summary.includes("anthropic"));
    assert.ok(summary.includes("zdr"));
    assert.equal((record["source"] as any)["capture"], "ingested");
    assert.ok(verifyLog(path).ok);

    const errRecord = recordModelCall(rec, { provider: "openai", model: "gpt-5", error: new Error("429") });
    assert.equal((errRecord["outcome"] as any)["status"], "error");
    assert.ok(verifyLog(path).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
