import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canon, computeHash, inputHash, GENESIS_PREV, sha256Hex } from "../src/canon.ts";
import { redactText, scan, topSeverity } from "../src/redact.ts";
import { build, Recorder, TenantRecorder, normalizeSource } from "../src/record.ts";
import { verifyLog, verifyRecords, readLog } from "../src/verify.ts";
import { checkpoint, verifyCompleteness, chainRoot, head } from "../src/anchor.ts";

test("canon: deterministic key order, escapes, integers", () => {
  assert.equal(canon({ b: 1, a: "x" }), '{"a":"x","b":1}');
  assert.equal(canon([1, "two", null, true, false]), '[1,"two",null,true,false]');
  assert.equal(canon({ s: 'q"\\\n\t' }), '{"s":"q\\"\\\\\\n\\t"}');
  assert.equal(canon({ n: 42 }), '{"n":42}');
  assert.equal(canon({ u: "héllo ✦" }), '{"u":"héllo ✦"}');
  assert.throws(() => canon({ f: 1.5 }), RangeError);
});

test("canon: control chars escape as lowercase \\u00xx", () => {
  assert.equal(canon(""), '"\\u0001"');
  assert.equal(canon(""), '"\\u001f"');
});

test("inputHash is stable and prefixed", () => {
  const h = inputHash({ url: "https://x.test", n: 3 });
  assert.match(h, /^sha256:[0-9a-f]{64}$/);
  assert.equal(h, inputHash({ n: 3, url: "https://x.test" }));
});

test("redaction: secrets never survive into a record; outcome symmetric with input", () => {
  const rec = build("tool_call", "security", {
    tool: "http",
    toolInput: { auth: "sk-ABCDEFGHIJKLMNOPQRSTUVWX" },
    outcome: { status: "ok", summary: "body: sk-ZYXWVUTSRQPONMLKJIHGFEDCBA and bob@acme.com" },
  });
  const flat = JSON.stringify(rec);
  assert.ok(!flat.includes("sk-ABCDEFGHIJKLMNOPQRSTUVWX"), "raw input secret leaked");
  assert.ok(!flat.includes("sk-ZYXWVUTSRQPONMLKJIHGFEDCBA"), "raw outcome secret leaked");
  assert.equal(rec["severity"], "CRITICAL");
  const findings = rec["findings"] as Array<{ type: string }>;
  assert.ok(findings.some((f) => f.type === "api_key"));
  assert.ok(findings.some((f) => f.type === "email"));
});

test("redactText + scan basics", () => {
  assert.equal(redactText("call me at bob@acme.com"), "call me at b****@acme.com");
  const f = scan("Bearer abcdefghijklmnopqrstuvwx and 10.0.0.5");
  assert.ok(f.some((x) => x.type === "bearer_token"));
  assert.ok(f.some((x) => x.type === "ip_internal"));
  assert.equal(topSeverity(f), "HIGH");
});

test("redaction: expanded provider patterns + high-entropy catch-all", () => {
  // Keys assembled at runtime so no secret-shaped literal sits in source.
  const gcp = "AIza" + "x".repeat(35);
  const stripe = "sk_" + "live_" + "x".repeat(20);
  const gh = "ghp_" + "a".repeat(36);
  const jwt = "eyJ" + "x".repeat(12) + "." + "y".repeat(12) + "." + "z".repeat(12);
  const text = `gcp=${gcp} stripe=${stripe} gh=${gh} jwt=${jwt}`;
  const red = redactText(text);
  for (const secret of [gcp, stripe, gh, jwt]) {
    assert.ok(!red.includes(secret), `leaked: ${secret}`);
  }
  const types = new Set(scan(text).map((x) => x.type));
  for (const t of ["gcp_api_key", "stripe_key", "github_token", "jwt"]) {
    assert.ok(types.has(t), `missing finding type: ${t}`);
  }

  // High-entropy token with no known prefix is still caught.
  const random = "Zx9Qw7Lp2Rt5Vn8Mb3Kc6Hd1Gf4Js0Ay";
  assert.ok(!redactText(`token ${random}`).includes(random), "high-entropy token leaked");
  assert.ok(scan(`token ${random}`).some((x) => x.type === "high_entropy_secret"));

  // Must NOT flag benign UUIDs (over-redaction has limits).
  const uuid = "550e8400-e29b-41d4-a716-446655440000";
  assert.equal(redactText(`id ${uuid}`), `id ${uuid}`, "UUID wrongly redacted");
  assert.ok(!scan(`id ${uuid}`).some((x) => x.type === "high_entropy_secret"));
});

test("summaries=false drops outcome summary entirely", () => {
  const rec = build("tool_call", "privacy", {
    outcome: { status: "ok", summary: "sk-ABCDEFGHIJKLMNOPQRSTUVWX" },
    summaries: false,
  });
  const outcome = rec["outcome"] as Record<string, unknown>;
  assert.ok(!("summary" in outcome));
});

test("normalizeSource: unknown ids fall back to ingested", () => {
  assert.equal(normalizeSource("mcp")!.capture, "captured");
  assert.equal(normalizeSource("mystery")!.capture, "ingested");
  assert.equal(normalizeSource(null), null);
});

test("chain: build, append, verify, tamper detection", () => {
  const dir = mkdtempSync(join(tmpdir(), "halo-ts-"));
  const path = join(dir, "chain.jsonl");
  try {
    const r = new Recorder(path);
    r.record("tool_call", "security", { tool: "db.query", toolInput: { q: "select 1" }, subject: "acme-corp", source: "recorder" });
    r.record("tool_call", "privacy", { tool: "email.send", toolInput: { to: "a@b.co" }, subject: "acme-corp", source: "mcp" });
    r.record("network", "reliability", { tool: "http.fetch", toolInput: { url: "https://api.test" }, subject: "acme-corp", source: "otel" });

    const res = verifyLog(path);
    assert.ok(res.ok, res.problems.join("; "));
    assert.equal(res.count, 3);

    const records = readLog(path);
    assert.equal((records[0]["integrity"] as Record<string, unknown>)["prev_hash"], GENESIS_PREV);

    // tamper: flip a field → chain must break
    (records[1]["action"] as Record<string, unknown>)["tool"] = "email.send_all";
    const tampered = verifyRecords(records);
    assert.ok(!tampered.ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("completeness: truncation below witnessed length goes RED while chain stays green", () => {
  const dir = mkdtempSync(join(tmpdir(), "halo-ts-"));
  const path = join(dir, "chain.jsonl");
  try {
    const r = new Recorder(path);
    for (let i = 0; i < 4; i++) {
      r.record("tool_call", "security", { tool: "t" + i, toolInput: { i }, subject: "acme" });
    }
    const full = readLog(path);
    const cp = checkpoint(full);
    assert.equal(cp.count, 4);
    assert.equal(cp.subject, "acme");
    assert.equal(cp.chain_root, chainRoot(full));
    assert.equal(cp.head, head(full));

    assert.equal(verifyCompleteness(full, [cp]).ok, true);

    const truncated = full.slice(0, 3);
    assert.ok(verifyRecords(truncated).ok, "shortened chain should still verify (integrity)");
    const res = verifyCompleteness(truncated, [cp]);
    assert.equal(res.ok, false);
    assert.equal(res.why, "chain truncated below witnessed length");

    assert.equal(verifyCompleteness(full, []).ok, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("TenantRecorder routes per subject", () => {
  const dir = mkdtempSync(join(tmpdir(), "halo-ts-"));
  try {
    const tr = new TenantRecorder(dir);
    tr.append(build("tool_call", "security", { tool: "a", subject: "acme-corp" }));
    tr.append(build("tool_call", "security", { tool: "b", subject: "initech" }));
    tr.append(build("tool_call", "security", { tool: "c", subject: "acme-corp" }));
    assert.ok(verifyLog(join(dir, "acme-corp.jsonl")).ok);
    assert.equal(verifyLog(join(dir, "acme-corp.jsonl")).count, 2);
    assert.equal(verifyLog(join(dir, "initech.jsonl")).count, 1);
    assert.equal(TenantRecorder.safe("../weird name!"), "weird_name");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sha256Hex sanity", () => {
  assert.equal(sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("computeHash ignores any pre-set integrity.hash", () => {
  const rec = build("tool_call", "security", { tool: "x", ts: "2026-06-09T00:00:00Z" });
  const a = computeHash(rec, GENESIS_PREV);
  (rec["integrity"] as Record<string, unknown>)["hash"] = "junk";
  assert.equal(computeHash(rec, GENESIS_PREV), a);
});

test("append: parallel async tool calls keep the chain intact", async () => {
  const dir = mkdtempSync(join(tmpdir(), "halo-ts-"));
  const path = join(dir, "chain.jsonl");
  try {
    const r = new Recorder(path);
    await Promise.all(
      Array.from({ length: 30 }, (_, i) => (async () => {
        await new Promise((res) => setTimeout(res, Math.random() * 5));
        r.record("tool_call", "security", { tool: "t" + i, toolInput: { i } });
      })()),
    );
    const res = verifyLog(path);
    assert.ok(res.ok, res.problems.slice(0, 3).join("; "));
    assert.equal(res.count, 30);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("append: fresh Recorder instance picks up existing chain head (cache fills from disk)", () => {
  const dir = mkdtempSync(join(tmpdir(), "halo-ts-"));
  const path = join(dir, "chain.jsonl");
  try {
    const r1 = new Recorder(path);
    r1.record("tool_call", "security", { tool: "a" });
    r1.record("tool_call", "security", { tool: "b" });
    const r2 = new Recorder(path);
    r2.record("tool_call", "security", { tool: "c" });
    const res = verifyLog(path);
    assert.ok(res.ok, res.problems.join("; "));
    assert.equal(res.count, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("provenance fields: principal/parentId/threats/pii_types populate and filter", () => {
  const r = build("read", "privacy", {
    tool: "t",
    toolInput: "mail to jane@acme.com",
    principal: { human_id: "u1", role_scope: "fin", bogus: "x" },
    parentId: "p1",
    threats: ["prompt_injection_indirect", { type: "policy_violation", ref: "R1" }, { ref: "drop" }],
    data: { region: "eu" },
  });
  assert.deepEqual(r["principal"], { human_id: "u1", role_scope: "fin" });
  assert.equal(r["parent_id"], "p1");
  assert.deepEqual(r["threats"], [
    { type: "prompt_injection_indirect" },
    { type: "policy_violation", ref: "R1" },
  ]);
  assert.deepEqual(r["data"], { region: "eu", pii_types: ["email"] });

  // back-compat: empty new fields are omitted entirely
  const r2 = build("read", "privacy", { tool: "t", toolInput: "no pii" });
  for (const k of ["principal", "parent_id", "threats", "data"]) {
    assert.ok(!(k in r2), `${k} must be absent when empty`);
  }
});
