import { test } from "node:test";
import assert from "node:assert/strict";

import { redactText, scan } from "../src/redact.ts";
import { build } from "../src/record.ts";

const PEM =
  "-----BEGIN PRIVATE KEY-----\n" +
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n" +
  "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n" +
  "MIIEfakefakefake\n" +
  "-----END PRIVATE KEY-----";

test("redact: full PEM block is masked, body included", () => {
  const out = redactText("key follows " + PEM + " end");
  assert.ok(out.includes("[PRIVATE KEY REDACTED]"));
  assert.ok(!out.includes("MIIEvQIBADAN"));
  assert.ok(!out.includes("MIIEfakefakefake"));
  assert.ok(!out.includes("BEGIN PRIVATE KEY"));
  assert.ok(!out.includes("END PRIVATE KEY"));
});

test("redact: truncated PEM masks body too", () => {
  const out = redactText("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\nshortline\nand then prose continues here");
  assert.ok(!out.includes("BEGIN PRIVATE KEY"));
  assert.ok(!out.includes("MIIEvQIBADAN"));
  assert.ok(!out.includes("shortline"));
  assert.ok(out.includes("prose continues here"));
});

test("redact: mask is scanner-quiet and idempotent", () => {
  const mask = "[PRIVATE KEY REDACTED]";
  assert.deepEqual(scan(mask), []);
  assert.equal(redactText(mask), mask);
});

test("record: summary carries no key material", () => {
  const rec = build("tool_call", "security", { tool: "deploy", toolInput: { pem: PEM } });
  const summary = (rec["action"] as any)["input"]["summary"] as string;
  assert.ok(!summary.includes("MIIE"));
  assert.ok(!summary.includes("BEGIN PRIVATE KEY"));
});

test("record: hash-only records have no samples or summaries", () => {
  const rec = build("tool_call", "security", {
    tool: "pay",
    toolInput: { ssn: "123-45-6789", email: "jane@example.com" },
    outcome: { status: "ok", summary: "sent to jane@example.com" },
    summaries: false,
  });
  assert.ok(!("summary" in (rec["action"] as any)["input"]));
  assert.ok(!("summary" in ((rec["outcome"] as any) ?? {})));
  const findings = rec["findings"] as Array<Record<string, unknown>>;
  assert.ok(findings.length > 0, "scanner should still classify");
  for (const f of findings) {
    assert.ok(!("sample" in f));
    assert.ok("type" in f && "severity" in f);
  }
});

test("redact: internal IP covers 172.16/12", () => {
  const hits = new Set(scan("hosts: 172.16.0.1 172.31.9.9 172.15.0.1 172.32.0.1").map((f) => f.type));
  assert.ok(hits.has("ip_internal"));
  const out = redactText("172.16.0.1 172.31.9.9 172.15.0.1 172.32.0.1");
  assert.ok(!out.includes("172.16.0.1"));
  assert.ok(!out.includes("172.31.9.9"));
  assert.ok(out.includes("172.15.0.1"));
  assert.ok(out.includes("172.32.0.1"));
});
