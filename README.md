# halo-record (TypeScript)

Tamper-evident audit trails for AI agents — the TypeScript recorder.

**Chain-format compatible with the Python `halo-record` package.** Records written here verify with either verifier, anchor via the same witness protocol, and render in the same Runtime Report. Canonicalization (RFC 8785 subset), hashing, redaction patterns, provenance tagging, and the witness wire protocol are ports of the Python implementation; cross-language interop is the package's defining test.

Zero runtime dependencies (Node ≥ 20, `node:crypto` / `node:fs`).

> **Using halo-record, or thinking about it?** Tell me who you are and what for → [Who's using halo-record?](https://github.com/bkuan001/halo-record/discussions/7)

## Why you can trust this code

You are being asked to put a recorder inside your agent. You should not take that on faith:

- **Zero runtime dependencies.** `npm install halo-record` installs exactly one package; framework adapters use structural typing and never import the frameworks.
- **Two opt-in network calls, and only these:** the witness anchor (sends only `{subject, count, head, chain_root}`) and the RFC 3161 timestamp (sends only a checkpoint's state hash to a Timestamp Authority). Both are off unless you call them; record contents never leave your infrastructure.
- **Raw inputs never enter a record.** Arguments are hashed and summarized through a redaction pass before writing.
- **Small enough to audit.** ~1,500 lines of TypeScript. Read all of it in an afternoon.
- **Apache-2.0.**

## Use

```ts
import { Recorder } from "halo-record";

const recorder = new Recorder("acme.jsonl");

recorder.record("tool_call", "privacy", {
  tool: "email.send",
  toolInput: { to: "alice@acme.com" },          // hashed + redacted summary; raw args never stored
  subject: "acme",                               // per-customer chain isolation
  source: "recorder",                            // provenance: captured vs ingested
  outcome: { status: "ok", summary: "sent" },    // redacted + scanned, same as input
});
```

One chain, one writer at a time: `Recorder` serializes appends within a process (fully synchronous) and across processes via a sidecar lock directory (`<chain>.lock.d`), held over the read-head-then-append sequence — so hook-style capture spawning one process per tool call cannot fork the chain. The Python package uses a different lock mechanism (`flock` on a `.lock` sidecar); the two do not interoperate, so writers in both languages sharing one chain should write per-process chains instead. [LIMITS.md section 9](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md#9-single-writer-chains) covers the full boundary.

If a guardrail or policy layer checked the action, its verdict can ride on the record — an optional block recording what the gate decided, sealed into the hash chain like every other field:

```ts
recorder.record("tool_call", "security", {
  tool: "payments.refund",
  verification: {
    status: "allowed", verifier: "gate/1.2",
    policy_ref: "sha256:1f3a...", checked_at: "2026-08-01T12:00:00Z",
  },
});
```

which seals into the record as:

```json
"verification": {"status": "allowed", "verifier": "gate/1.2", "policy_ref": "sha256:1f3a...", "checked_at": "2026-08-01T12:00:00Z"}
```

`status` is required within the block; `verifier`, `policy_ref`, and `checked_at` are optional. What each status means:

| Status | What the gate reports | Did the action execute? |
|---|---|---|
| `allowed` | it permitted the action | yes — the action proceeded |
| `blocked` | it denied the action | determined by the integration, not by this field — a record may still carry an outcome, and a block does not by itself prove non-execution |
| `modified` | it altered the action before execution — `action.input` describes the action **as executed**, post-modification | yes, in the altered form |
| `unverified` | it ran (or was consulted) but made no determination — distinct from an absent block, which means no verification claim was made at all | yes — the action proceeded without a verdict |

The block is supplied by the operator's integration code and records what it reports the gate said — the same trust posture as `principal` (see [LIMITS](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md#11-verification-status-is-the-gates-report-not-halos-finding)). Sealing proves the status was not edited after the fact; it does not prove the check occurred, that the verdict was correct, or that a blocked action did not execute. This is not independent verification.

For `policy_ref` to be usable as evidence, use a content hash of the ruleset and retain the ruleset artifact — an unresolvable label makes the field decorative.

Verify a chain (yours or one you received):

```ts
import { verifyLog, readLog, verifyCompleteness } from "halo-record";
import { fetchCheckpoints } from "halo-record";

const integrity = verifyLog("acme.jsonl");   // nothing edited (empty:true = nothing to attest, not a pass)
const cps = await fetchCheckpoints("https://witness.example", "acme");
const completeness = verifyCompleteness(readLog("acme.jsonl"), cps); // nothing omitted
```

Anchor to a witness (an opt-in network call; only `{subject, count, head, chain_root}` is sent, and record contents never leave your infrastructure):

```ts
import { anchorRemote, readLog } from "halo-record";
await anchorRemote("https://witness.example", VENDOR_KEY, readLog("acme.jsonl"));
```

Add an external RFC 3161 timestamp to a checkpoint — a Timestamp Authority the operator does not control signs the checkpoint's state hash, proving the chain reached that state no later than the attested time. Only the state hash is sent; the token stores base64 so a reviewer can verify it in full, independently, with `openssl` — this library does a light imprint/time check, not the TSA signature:

```ts
import { checkpoint, attachTimestamp, readLog } from "halo-record";

// Default TSA is the free freetsa.org — fine for evaluation. For production
// attestations point at a commercial TSA you trust (DigiCert / Sectigo / your own):
const cp = await attachTimestamp(checkpoint(readLog("acme.jsonl")), "https://your-tsa.example/tsr");
// cp.tsa.token_b64 → the verifiable RFC 3161 token; time is re-derived from it on read
```

**Verifying the token independently** (what you hand a security reviewer — they need nothing from this library):

```sh
# 1. decode the stored token to a standard .tsr file
node -e 'const cp=require("./cp.json");process.stdout.write(Buffer.from(cp.tsa.token_b64,"base64"))' > token.tsr

# 2. get the CA for the TSA that signed it (for the default freetsa.org):
curl -s -o tsa-ca.pem https://freetsa.org/files/cacert.pem

# 3. verify the token binds cp.tsa.digest at the attested time
openssl ts -verify -digest <cp.tsa.digest> -in token.tsr -CAfile tsa-ca.pem
# → "Verification: OK"
```

The CA in step 2 is specific to the TSA in `cp.tsa.url`; a commercial TSA publishes its own. `certReq` is set, so the token embeds the signing cert — no separate `-untrusted` file is needed.

Record a model call (the buyer's first question: "which model saw my data?"):

```ts
import { recordModelCall } from "halo-record";

recordModelCall(recorder, {
  provider: "anthropic", model: "claude-sonnet-4-6",
  zeroDataRetention: true, purpose: "draft support reply",
  subject: "acme",
});   // tool=model.generate, scope=model:anthropic; provider and retention terms, disclosed per call
```

## Framework adapters

All boundary-captured, all dependency-free (structural typing; the framework
packages are never imported):

```ts
import { createLangChainHandler } from "halo-record";   // LangChain.js / LangGraph.js callbacks
import { instrumentMcpClient, wrapMcpToolHandler } from "halo-record"; // MCP TS SDK, client or server side
import { createAgentsHooks } from "halo-record";        // OpenAI Agents SDK (JS) run hooks
import { wrapVercelTools, createStepRecorder } from "halo-record";    // Vercel AI SDK tools / onStepFinish
import { createClaudeAgentHook } from "halo-record";    // Claude Agent SDK PostToolUse hook
```

Every adapter funnels through the same core (`recordToolCall`), so
classification, scope, redaction, and provenance behave identically across
ecosystems, and identically to the Python adapters. Framework hook shapes are
structural; if a framework changes its callback signature, the adapter is a
small shim to update, not a rewrite.

## Personal data in the chain

The chain is append-only: anything sealed into a record stays there, because
removing it would break verification for everything after it. Tool arguments are
stored as a hash plus a redacted summary, never raw — but *redacted* is not
*removed*: a name or postal address has no reliable pattern, so neither is detected
nor masked. `subject` is also not the only field carrying text you supply —
`principal`, `approver`, `sessionId`, `agent`, `authority`, `data` and the summaries
all do.

The pattern that works: put a stable pseudonymous id in the chain and keep the
mapping to any individual in a system you can delete from, so an erasure request is
satisfied by deleting the mapping. Keep `subject` pointing at the tenant
organization, not a person. No setting enforces this — it is a discipline in how you
call the recorder, and the same discipline as the Python package.

Full field list, the reason the stored input fingerprint can confirm a guessable
value even after the mapping is gone, and the questions a reviewer should ask:
LIMITS.md section 13 in the
[halo-record](https://github.com/bkuan001/halo-record) repo.

## Test

```
node --test test/core.test.ts   # unit suite
npx tsc --noEmit                # typecheck (TS >= 5.8)
```

Cross-language checks (require the Python package):
- a TS-written chain passes `python -m halo_record.cli verify`
- a Python-written chain passes `verifyLog` here, including completeness against a Python witness log
- `canon()` output is byte-identical across both implementations

## Render the Runtime Report

The chain you write here renders with the Python CLI, same format by design (the report renderer ships in the Python package - this package has no CLI of its own):

```
pip install halo-record
halo report acme.jsonl -o acme.html
```

You end up looking at your agent's Runtime Report in a browser: every action, its provenance, the chain verdict, and (if anchored) the completeness verdict. Reference implementation and recorder internals: [halo-record (Python)](https://github.com/bkuan001/halo-record).

## License

Apache-2.0
