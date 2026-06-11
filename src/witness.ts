/* Client for the hosted Halo witness. The checkpoint is computed LOCALLY and
   only {subject, count, head, chain_root} is sent — record contents never
   leave the vendor. Same wire protocol as the Python client (witness.py). */

import { checkpoint, type Checkpoint } from "./anchor.ts";
import type { HaloRecord } from "./record.ts";

/* Anchor a chain's current head to a hosted Halo witness. Returns the
   witness's receipt (the stored checkpoint with the server's timestamp). */
export async function anchorRemote(
  witnessUrl: string,
  key: string,
  records: HaloRecord[],
  opts: { timeoutMs?: number } = {},
): Promise<Checkpoint> {
  const cp = checkpoint(records);
  const body = JSON.stringify({
    subject: cp.subject,
    count: cp.count,
    head: cp.head,
    chain_root: cp.chain_root,
  });
  const resp = await fetch(witnessUrl.replace(/\/+$/, "") + "/anchor", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + key },
    body,
    signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
  });
  if (!resp.ok) throw new Error(`witness anchor failed: HTTP ${resp.status}`);
  const out = (await resp.json()) as { receipt?: Checkpoint } & Checkpoint;
  return out.receipt ?? out;
}

/* Fetch the witness's independently held checkpoints for a subject. */
export async function fetchCheckpoints(
  witnessUrl: string,
  subject?: string | null,
  opts: { timeoutMs?: number } = {},
): Promise<Checkpoint[]> {
  let url = witnessUrl.replace(/\/+$/, "") + "/v1/checkpoints";
  if (subject != null) url += "?" + new URLSearchParams({ subject }).toString();
  const resp = await fetch(url, { signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000) });
  if (!resp.ok) throw new Error(`witness fetch failed: HTTP ${resp.status}`);
  const out = (await resp.json()) as { checkpoints?: Checkpoint[] };
  return out.checkpoints ?? [];
}
