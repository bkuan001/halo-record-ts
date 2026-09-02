import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { build, Recorder } from "../src/record.ts";
import { checkpoint, verifyCompleteness } from "../src/anchor.ts";

function chain(n: number, subject?: string) {
  const dir = mkdtempSync(join(tmpdir(), "halo-caveat-"));
  const rec = new Recorder(join(dir, "c.jsonl"));
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(rec.record("tool_call", "security", { tool: "t" + i, subject }));
  }
  return out;
}

test("subjectless verdicts carry the chain_root caveat", () => {
  const recs = chain(3);
  const ok = verifyCompleteness(recs, [checkpoint(recs)]);
  assert.equal(ok.ok, true);
  assert.ok(ok.subjectless_caveat?.includes("chain_root"));
  const rerooted = recs.slice(1);
  const none = verifyCompleteness(rerooted, [checkpoint(recs)]);
  assert.equal(none.ok, null);
  assert.ok(none.subjectless_caveat);
});

test("subjectful verdicts carry no caveat", () => {
  const recs = chain(3, "acme-corp");
  const ok = verifyCompleteness(recs, [checkpoint(recs)]);
  assert.equal(ok.ok, true);
  assert.equal(ok.subjectless_caveat, undefined);
});
