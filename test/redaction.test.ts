import { test } from "node:test";
import assert from "node:assert/strict";

import { redactText, scan } from "../src/redact.ts";
import { build } from "../src/record.ts";
import { deriveOutcome } from "../src/integrations/common.ts";

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

test("path-typed keys stay readable but are still scanned; free text keeps the full pass", () => {
  const types = (r: any) => (r["findings"] as any[]).map((f) => [f.type, f.severity]);
  const p = "/Users/dev/Projects/Acme-Billing/handlers/Stripe_webhook.ts";
  const r = build("read", "privacy", { tool: "Read", toolInput: { file_path: p } });
  assert.ok(String((r["action"] as any)["input"]["summary"]).includes(p));
  assert.ok(!types(r).some(([t]) => t === "high_entropy_secret"));
  assert.ok(["INFO", "LOW"].includes(String(r["severity"])));

  // an unanchored value under a path key gets the full pass
  const r2 = build("read", "privacy", { tool: "Read", toolInput: { file_path: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" } });
  assert.ok(!String((r2["action"] as any)["input"]["summary"]).includes("wJalrXUtnFEMI"));
  assert.ok(types(r2).some(([t, s]) => t === "high_entropy_secret" && s === "HIGH"));

  // an anchored secret-looking path stays readable but is reported LOW
  const r3 = build("read", "privacy", { tool: "Read", toolInput: { file_path: "/tmp/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" } });
  assert.ok(String((r3["action"] as any)["input"]["summary"]).includes("/tmp/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
  assert.ok(types(r3).some(([t, s]) => t === "high_entropy_path_value" && s === "LOW"));

  // list elements judged one by one; dict keys scanned
  const r4 = build("read", "privacy", { tool: "Glob", toolInput: { pattern: "**/*.ts", paths: [p, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"] } });
  const s4 = String((r4["action"] as any)["input"]["summary"]);
  assert.ok(s4.includes(p) && !s4.includes("wJalrXUtnFEMI"));
  const r5 = build("tool_call", "security", { tool: "x", toolInput: { "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "v" } });
  assert.ok(!String((r5["action"] as any)["input"]["summary"]).includes("wJalrXUtnFEMI"));

  // named patterns still run under path keys; AWS secret key is CRITICAL in free text
  const r6 = build("read", "privacy", { tool: "Read", toolInput: { file_path: "/tmp/AKIAIOSFODNN7EXAMPLE/x" } });
  assert.ok(String((r6["action"] as any)["input"]["summary"]).includes("AKIA****"));
  const r7 = build("tool_call", "security", { tool: "Bash", toolInput: { command: "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" } });
  assert.ok(String((r7["action"] as any)["input"]["summary"]).includes("AWS_SECRET_ACCESS_KEY=****"));
  assert.ok(types(r7).some(([t, s]) => t === "aws_secret_key" && s === "CRITICAL"));

  // url readable; query token under a path key still masked
  const u = "https://github.com/bkuan001/halo-record/blob/main/LIMITS.md";
  const r8 = build("tool_call", "security", { tool: "WebFetch", toolInput: { url: u } });
  assert.ok(String((r8["action"] as any)["input"]["summary"]).includes(u));
  const r9 = build("read", "privacy", { tool: "Read", toolInput: { path: "/cb?access_token=A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6" } });
  assert.ok(!String((r9["action"] as any)["input"]["summary"]).includes("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"));
});

test("responses: path fields leave the summary but never the scanner; exit codes mark errors", () => {
  const out = deriveOutcome({ filePath: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" });
  const r = build("read", "privacy", { tool: "Read", toolInput: { file_path: "/Users/dev/x.py" }, outcome: out });
  assert.ok((r["findings"] as any[]).some((f) => f.type === "high_entropy_secret"));
  assert.ok(!("_scan" in (r["outcome"] as any)));
  assert.equal(deriveOutcome({ stderr: "permission denied", exit_code: 1 })["status"], "error");
  assert.equal(deriveOutcome({ stdout: "x", exit_code: "1" })["status"], "error");
  assert.equal(deriveOutcome({ stdout: "ok", exit_code: 0 })["status"], "ok");
});

test("webhook URLs are CRITICAL even under url keys; AWS CLI space form is CRITICAL", () => {
  const u = "https://hooks.slack.com/services/T7Kq2Zp9L/B4Rt8Vx1N/c3Bd6Fg0Hj5Sw9AbQmXk";
  const r = build("tool_call", "security", { tool: "WebFetch", toolInput: { url: u } });
  assert.ok(!String((r["action"] as any)["input"]["summary"]).includes(u));
  assert.ok((r["findings"] as any[]).some((f) => f.type === "webhook_url" && f.severity === "CRITICAL"));
  const r2 = build("tool_call", "security", { tool: "Bash", toolInput: { command: "aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" } });
  assert.ok((r2["findings"] as any[]).some((f) => f.type === "aws_secret_key" && f.severity === "CRITICAL"));
});

test("response filename lists stay readable, findings dedupe across input and response, patch headers readable", () => {
  const p = "/Users/dev/acme-billing/src/services/InvoiceReconciliationService.ts";
  const r = build("read", "privacy", { tool: "Glob", toolInput: { pattern: "src/**/*.ts" }, outcome: deriveOutcome({ filenames: [p], numFiles: 1 }) });
  assert.ok(!String((r["outcome"] as any)["summary"] ?? "").includes("/Us****"));
  const r2 = build("read", "privacy", { tool: "Read", toolInput: { file_path: p }, outcome: deriveOutcome({ filePath: p, content: "x" }) });
  const keys = (r2["findings"] as any[]).map((f) => f.type + ":" + f.sample);
  assert.equal(keys.length, new Set(keys).size);
  const patch = "*** Begin Patch\n*** Update File: src/generated/AcmeBillingClientV2Generated/index.ts\n@@\n+  key = 'AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8YzA9bCd0'\n*** End Patch\n";
  const r3 = build("write", "safety", { tool: "apply_patch", toolInput: { command: patch } });
  const s3 = String((r3["action"] as any)["input"]["summary"]);
  assert.ok(s3.includes("src/generated/AcmeBillingClientV2Generated/index.ts"));
  assert.ok(!s3.includes("AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8YzA9bCd0"));
});
