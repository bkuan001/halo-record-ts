/* Completeness witnessing — checkpoints + verification against a neutral
   witness. Port of the Python anchor.py client-side surface. */

import { GENESIS_PREV, computeHash, canon, sha256Hex } from "./canon.ts";
import * as ts from "./timestamp.ts";
import type { HaloRecord } from "./record.ts";

/* An RFC 3161 time proof attached to a checkpoint. `gen_time` is a convenience
   cache; the authoritative time is always re-derived from `token_b64` on read. */
export interface TsaProof {
  url: string;
  digest: string;
  gen_time: string | null;
  token_b64: string;
}

export interface Checkpoint {
  chain_root: string | null;
  subject: string | null;
  count: number;
  head: string;
  ts: string;
  tsa?: TsaProof;
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

/* SHA-256 (hex) of a checkpoint's *state* — chain_root, subject, count, head —
   excluding the self-asserted `ts` and any attached `tsa`. This is what an
   RFC 3161 TSA timestamps: it binds this chain state to a time set by a party
   the operator does not control. */
export function checkpointDigest(cp: Checkpoint): string {
  const state = {
    chain_root: cp.chain_root ?? null,
    subject: cp.subject ?? null,
    count: cp.count,
    head: cp.head,
  };
  return sha256Hex(canon(state));
}

/* The TSA was unreachable, errored, or returned a token that does not cover this
   checkpoint. Raised so the caller can degrade to an un-timestamped checkpoint
   rather than losing it. */
export class TimestampError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimestampError";
  }
}

/* Fetch an RFC 3161 time proof over `checkpointDigest(cp)` from a TSA the
   operator doesn't control, and attach it as `cp.tsa`. A network call, made
   only on request (the witness anchor is the other opt-in reach-out). The raw
   token is stored base64 so it can be verified in full with `openssl ts -verify`
   (see timestamp.ts).

   Rejects with `TimestampError` on any TSA failure, or if the returned token
   does not actually cover our digest — a token that doesn't bind this checkpoint
   is worse than none, so it is never stored. The `gen_time` recorded here is a
   convenience cache: authoritative time is re-derived from the token on read
   (`checkpointVerifiedTime`). */
export async function attachTimestamp(cp: Checkpoint, tsaUrl?: string): Promise<Checkpoint> {
  const url = tsaUrl || ts.DEFAULT_TSA_URL;
  const digest = checkpointDigest(cp);
  let token: Buffer;
  try {
    token = await ts.requestToken(digest, url);
  } catch (e) {
    throw new TimestampError(`TSA ${url}: ${(e as Error).message}`);
  }
  const checked = ts.verify(token, digest);
  if (!checked.imprint_ok) {
    throw new TimestampError(`TSA ${url} returned a token that does not cover this checkpoint`);
  }
  return {
    ...cp,
    tsa: {
      url,
      digest,
      gen_time: checked.gen_time, // cache; re-derived on read
      token_b64: token.toString("base64"),
    },
  };
}

/* Re-derive a checkpoint's attested time from its stored RFC 3161 token — never
   from the (operator-editable) `tsa.gen_time` field. Returns the ISO time only
   if the token is present and its imprint matches this checkpoint's recomputed
   digest; otherwise null (a forged or missing token yields no time, so editing
   the JSON cannot fabricate an attestation). NOTE: this confirms the token binds
   this chain state and reads its claimed time; it does NOT validate the TSA's
   signature — run `openssl ts -verify` for that. */
export function checkpointVerifiedTime(cp: Checkpoint): string | null {
  const tsa = cp.tsa;
  if (!tsa || typeof tsa !== "object" || !tsa.token_b64) return null;
  let token: Buffer;
  try {
    token = Buffer.from(tsa.token_b64, "base64");
  } catch {
    return null;
  }
  const checked = ts.verify(token, checkpointDigest(cp));
  return checked.imprint_ok ? checked.gen_time : null;
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
  tsa_time?: string;
  tsa_time_status?: string;
  tsa_unverified?: number;
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

  const result: CompletenessResult = {
    ok: true, witnessed: relevant.length, latest_count: latest, head: head(records),
  };
  // Attested time is re-derived from each token (not the editable JSON field);
  // a checkpoint whose token is missing/forged/imprint-mismatched yields no time.
  const tsaTimes: string[] = [];
  let tsaUnverified = 0;
  for (const c of relevant) {
    if (c.tsa && typeof c.tsa === "object" && c.tsa.token_b64) {
      const t = checkpointVerifiedTime(c);
      if (t) tsaTimes.push(t);
      else tsaUnverified += 1;
    }
  }
  if (tsaTimes.length) {
    // upper bound: the chain reached this state no later than tsa_time. Time
    // only, not completeness — and the TSA signature must be checked
    // (openssl ts -verify) to trust the source.
    result.tsa_time = tsaTimes.reduce((a, b) => (b > a ? b : a));
    result.tsa_time_status = "claimed — verify the TSA signature with `openssl ts -verify`";
  }
  if (tsaUnverified) result.tsa_unverified = tsaUnverified; // a stored token that does not bind this state
  return result;
}
