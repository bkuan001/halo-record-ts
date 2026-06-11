/* Completeness witnessing — checkpoints + verification against a neutral
   witness. Port of the Python anchor.py client-side surface. */

import { GENESIS_PREV, computeHash } from "./canon.ts";
import type { HaloRecord } from "./record.ts";

export interface Checkpoint {
  chain_root: string | null;
  subject: string | null;
  count: number;
  head: string;
  ts: string;
}

function nowZ(): string {
  return new Date().toISOString();
}

/* Stable identity of a chain: the hash of its first record. */
export function chainRoot(records: HaloRecord[]): string | null {
  if (records.length === 0) return null;
  const integ = (records[0]["integrity"] ?? {}) as Record<string, unknown>;
  return (integ["hash"] as string) ?? null;
}

/* The current chain head — the last record's hash, or genesis if empty. */
export function head(records: HaloRecord[]): string {
  if (records.length === 0) return GENESIS_PREV;
  const integ = (records[records.length - 1]["integrity"] ?? {}) as Record<string, unknown>;
  return (integ["hash"] as string) ?? GENESIS_PREV;
}

function subjectId(records: HaloRecord[]): string | null {
  for (const r of records) {
    const s = r["subject"];
    if (s && typeof s === "object" && (s as Record<string, unknown>)["id"]) {
      return String((s as Record<string, unknown>)["id"]);
    }
  }
  return null;
}

/* A witness of the chain's current state. */
export function checkpoint(records: HaloRecord[]): Checkpoint {
  return {
    chain_root: chainRoot(records),
    subject: subjectId(records),
    count: records.length,
    head: head(records),
    ts: nowZ(),
  };
}

/* Recompute the hash chain. Returns the index (1-based) of the first broken
   record, or 0 if intact. */
function chainIntact(records: HaloRecord[]): number {
  let prev = GENESIS_PREV;
  for (let i = 0; i < records.length; i++) {
    const integ = (records[i]["integrity"] ?? {}) as Record<string, unknown>;
    if (integ["prev_hash"] !== prev) return i + 1;
    const recomputed = computeHash(records[i], prev);
    if (integ["hash"] !== recomputed) return i + 1;
    prev = (integ["hash"] as string) || recomputed;
  }
  return 0;
}

function matches(cp: Checkpoint, records: HaloRecord[]): boolean {
  const subj = subjectId(records);
  if (subj !== null) return cp.subject === subj;
  return cp.chain_root === chainRoot(records);
}

export interface CompletenessResult {
  ok: boolean | null;
  why?: string;
  at?: number;
  have?: number;
  witnessed_count?: number;
  witnessed: number;
  latest_count?: number;
  head?: string;
}

/* Check a presented chain against what the notary independently witnessed.
   ok=null: no witnesses (unknown, not a failure). ok=false: a witnessed record
   is missing or altered. ok=true: every witnessed checkpoint still matches. */
export function verifyCompleteness(records: HaloRecord[], checkpoints: Checkpoint[]): CompletenessResult {
  const relevant = checkpoints.filter((c) => matches(c, records));
  if (relevant.length === 0) {
    return { ok: null, why: "no witnesses for this chain", witnessed: 0 };
  }

  const brokenAt = chainIntact(records);
  if (brokenAt) {
    return { ok: false, why: "chain integrity broken", at: brokenAt, witnessed: relevant.length };
  }

  const latest = Math.max(...relevant.map((c) => c.count));
  if (records.length < latest) {
    return {
      ok: false, why: "chain truncated below witnessed length",
      have: records.length, witnessed_count: latest, witnessed: relevant.length,
    };
  }

  for (const c of relevant) {
    const n = c.count;
    if (n < 1 || n > records.length) {
      return { ok: false, why: "witnessed count out of range", at: n, witnessed: relevant.length };
    }
    const integ = (records[n - 1]["integrity"] ?? {}) as Record<string, unknown>;
    if (integ["hash"] !== c.head) {
      return { ok: false, why: "record altered or dropped before witnessed point", at: n, witnessed: relevant.length };
    }
  }

  return { ok: true, witnessed: relevant.length, latest_count: latest, head: head(records) };
}
