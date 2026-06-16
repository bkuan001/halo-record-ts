# halo-record (TypeScript)

Tamper-evident, hash-chained Runtime Records for AI agents: the TypeScript recorder.

**Chain-format compatible with the Python `halo-record` package.** Records written here verify with either verifier, anchor to the same hosted witness, and render in the same Runtime Report. Canonicalization (RFC 8785 subset), hashing, redaction patterns, provenance tagging, and the witness wire protocol are ports of the Python implementation; cross-language interop is the package's defining test.

Zero runtime dependencies (Node ≥ 20, `node:crypto` / `node:fs`).

## Why you can trust this code

You are being asked to put a recorder inside your agent. You should not take that on faith:

- **Zero runtime dependencies.** `npm install halo-record` installs exactly one package; framework adapters use structural typing and never import the frameworks.
- **One sanctioned network call:** the opt-in witness anchor, which sends only `{subject, count, head, chain_root}`. Record contents never leave your infrastructure.
- **Raw inputs never enter a record.** Arguments are hashed and summarized through a redaction pass before writing.
- **Small enough to audit.** ~1,400 lines of TypeScript. Read all of it in an afternoon.
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

Verify a chain (yours or one you received):

```ts
import { verifyLog, readLog, verifyCompleteness } from "halo-record";
import { fetchCheckpoints } from "halo-record";

const integrity = verifyLog("acme.jsonl");   // nothing edited
const cps = await fetchCheckpoints("https://witness.example", "acme");
const completeness = verifyCompleteness(readLog("acme.jsonl"), cps); // nothing omitted
```

Anchor to a witness (the one sanctioned network call; only `{subject, count, head, chain_root}` is sent, and record contents never leave your infrastructure):

```ts
import { anchorRemote, readLog } from "halo-record";
await anchorRemote("https://witness.example", VENDOR_KEY, readLog("acme.jsonl"));
```

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

The chain you write here renders with the Python CLI, same format by design:

```
pip install halo-record
halo report acme.jsonl -o acme.html
```

You end up looking at your agent's Runtime Report in a browser: every action, its provenance, the chain verdict, and (if anchored) the completeness verdict. Reference implementation and recorder internals: [halo-record (Python)](https://github.com/bkuan001/halo-record).

## License

Apache-2.0
