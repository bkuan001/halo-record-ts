/* Conformance verification: schema validation + hash-chain integrity.
   Port of the Python verifier (verify.py); dependency-free. */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { GENESIS_PREV, computeHash } from "./canon.ts";
import type { HaloRecord } from "./record.ts";

const SCHEMA_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "halo-record.schema.json");

type Schema = Record<string, any>;

export function loadSchema(): Schema {
  return JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as Schema;
}

function typeOk(node: unknown, t: string): boolean {
  switch (t) {
    case "object": return node !== null && typeof node === "object" && !Array.isArray(node);
    case "array": return Array.isArray(node);
    case "string": return typeof node === "string";
    case "number": return typeof node === "number" && typeof node !== "boolean";
    case "integer": return typeof node === "number" && Number.isInteger(node);
    case "boolean": return typeof node === "boolean";
    case "null": return node === null;
    default: return true;
  }
}

function validate(node: unknown, schema: Schema, path: string, errors: string[]): void {
  if ("const" in schema && !deepEqual(node, schema["const"])) {
    errors.push(`${path}: expected const ${JSON.stringify(schema["const"])}, got ${JSON.stringify(node)}`);
  }
  if ("enum" in schema && !(schema["enum"] as unknown[]).some((v) => deepEqual(node, v))) {
    errors.push(`${path}: ${JSON.stringify(node)} not in enum ${JSON.stringify(schema["enum"])}`);
  }

  const t = schema["type"] as string | undefined;
  if (t) {
    if ((t === "number" || t === "integer") && typeof node === "boolean") {
      errors.push(`${path}: expected ${t}, got boolean`);
    } else if (!typeOk(node, t)) {
      errors.push(`${path}: expected ${t}, got ${Array.isArray(node) ? "array" : node === null ? "null" : typeof node}`);
      return;
    }
  }

  if (node !== null && typeof node === "object" && !Array.isArray(node)) {
    const obj = node as Record<string, unknown>;
    for (const req of (schema["required"] ?? []) as string[]) {
      if (!(req in obj)) errors.push(`${path}: missing required field ${JSON.stringify(req)}`);
    }
    const props = (schema["properties"] ?? {}) as Record<string, Schema>;
    for (const [key, val] of Object.entries(obj)) {
      if (key in props) validate(val, props[key], `${path}.${key}`, errors);
    }
  }

  if (Array.isArray(node) && "items" in schema) {
    node.forEach((item, i) => validate(item, schema["items"] as Schema, `${path}[${i}]`, errors));
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (typeof a !== "object") return false;
  return JSON.stringify(a) === JSON.stringify(b);
}

export function validateRecord(record: HaloRecord, schema?: Schema): string[] {
  const s = schema ?? loadSchema();
  const errors: string[] = [];
  validate(record, s, "record", errors);
  return errors;
}

export interface VerifyResult {
  ok: boolean;
  count: number;
  problems: string[];
}

/* Verify a list of already-parsed records: schema + chain. */
export function verifyRecords(records: HaloRecord[], schema?: Schema): VerifyResult {
  const s = schema ?? loadSchema();
  const problems: string[] = [];
  let prevHash = GENESIS_PREV;

  records.forEach((record, idx) => {
    const n = idx + 1;
    for (const err of validateRecord(record, s)) problems.push(`record ${n}: schema: ${err}`);

    const integ = (record["integrity"] ?? {}) as Record<string, unknown>;
    const declaredPrev = integ["prev_hash"] as string | undefined;
    const declaredHash = integ["hash"] as string | undefined;

    if (declaredPrev !== prevHash) {
      problems.push(`record ${n}: chain: prev_hash ${declaredPrev} does not match expected ${prevHash}`);
    }
    const recomputed = computeHash(record, prevHash);
    if (declaredHash !== recomputed) {
      problems.push(`record ${n}: chain: hash ${declaredHash} does not match recomputed ${recomputed}`);
    }
    prevHash = declaredHash || recomputed;
  });

  return { ok: problems.length === 0, count: records.length, problems };
}

export function readLog(path: string): HaloRecord[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((ln) => ln.trim())
    .map((ln) => JSON.parse(ln) as HaloRecord);
}

/* Verify a JSONL chain file. */
export function verifyLog(path: string, schema?: Schema): VerifyResult {
  return verifyRecords(readLog(path), schema);
}
