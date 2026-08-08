import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { build, Recorder } from "../src/record.ts";
import { verifyLog, readLog } from "../src/verify.ts";

const WORKER = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "append_worker.ts");

function tempChain(): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "halo-conc-"));
  return { dir, path: join(dir, "audit.jsonl") };
}

test("two Recorder instances on one chain: head re-read, no fork", () => {
  const { dir, path } = tempChain();
  try {
    const a = new Recorder(path);
    const b = new Recorder(path);
    for (let i = 0; i < 6; i++) {
      const rec = i % 2 === 0 ? a : b;
      rec.append(build("tool_call", "reliability", { tool: "t", toolInput: { i } }));
    }
    const result = verifyLog(path);
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.equal(readLog(path).length, 6);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("concurrent processes appending to one chain: verifies, nothing lost", async () => {
  const { dir, path } = tempChain();
  const WORKERS = 4;
  const PER_WORKER = 25;
  try {
    const children = Array.from({ length: WORKERS }, (_, w) =>
      new Promise<number>((resolve, reject) => {
        const child = spawn(process.execPath, [WORKER, path, String(PER_WORKER), `worker-${w}`], {
          stdio: ["ignore", "ignore", "inherit"],
        });
        child.on("error", reject);
        child.on("close", (code) => resolve(code ?? -1));
      }),
    );
    const codes = await Promise.all(children);
    assert.deepEqual(codes, Array(WORKERS).fill(0));
    const result = verifyLog(path);
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.equal(readLog(path).length, WORKERS * PER_WORKER);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("append lock: released on success, stale holder reclaimed", () => {
  const { dir, path } = tempChain();
  const lockDir = path + ".lock.d";
  try {
    const rec = new Recorder(path);
    rec.append(build("tool_call", "reliability", { tool: "t" }));
    assert.equal(existsSync(lockDir), false, "lock dir must not survive a completed append");

    // A lock directory left by a crashed holder (old mtime) is reclaimed.
    mkdirSync(lockDir);
    const past = (Date.now() - 60_000) / 1000;
    utimesSync(lockDir, past, past);
    rec.append(build("tool_call", "reliability", { tool: "t" }));
    assert.equal(existsSync(lockDir), false);
    const result = verifyLog(path);
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.equal(readLog(path).length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
