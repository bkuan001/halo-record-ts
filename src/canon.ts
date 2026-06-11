/* RFC 8785 (JSON Canonicalization Scheme) + SHA-256 hashing.
   Byte-for-byte compatible with the Python implementation (canon.py): same
   subset (integer-valued numbers only), same key ordering (UTF-16 code units,
   which equals Python's utf-16-be byte sort), same string escaping. */

import { createHash } from "node:crypto";

export const GENESIS_PREV = "0".repeat(64);

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export function canon(value: unknown): string {
  if (value === true) return "true";
  if (value === false) return "false";
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return canonString(value);
  if (typeof value === "number") return canonNumber(value);
  if (Array.isArray(value)) return "[" + value.map(canon).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => canonString(k) + ":" + canon(obj[k])).join(",") + "}";
  }
  throw new TypeError("cannot canonicalize " + typeof value);
}

function canonString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const o = ch.codePointAt(0) as number;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\r") out += "\\r";
    else if (o < 0x20) out += "\\u" + o.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

function canonNumber(n: number): string {
  if (!Number.isFinite(n)) throw new RangeError("non-finite number is not valid JSON");
  if (Number.isInteger(n)) return String(n);
  throw new RangeError(
    "non-integer float " + n + ": full RFC 8785 number formatting is out of scope; " +
    "the record format uses integer-valued numbers only"
  );
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/* A record's integrity.hash: set integrity.prev_hash, drop integrity.hash,
   canonicalize per RFC 8785, return the lowercase SHA-256 hex digest. */
export function computeHash(record: Record<string, unknown>, prevHash: string): string {
  const clone = JSON.parse(JSON.stringify(record)) as Record<string, unknown>;
  const integ = (clone["integrity"] ??= {}) as Record<string, unknown>;
  integ["prev_hash"] = prevHash;
  delete integ["hash"];
  return sha256Hex(canon(clone));
}

/* "sha256:" + SHA-256 of the canonical arguments, with a stable sorted-key
   fallback so a recorder embedded in a hook never crashes on an odd input. */
export function inputHash(value: unknown): string {
  let c: string;
  try {
    c = canon(value);
  } catch {
    c = stableStringify(value);
  }
  return "sha256:" + sha256Hex(c);
}

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : JSON.stringify(String(value));
  if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}";
  }
  return JSON.stringify(String(value));
}
