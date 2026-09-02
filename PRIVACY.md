# Privacy

halo-record is local-first by design. The full data-handling statement lives in the Python repo's [PRIVACY.md](https://github.com/bkuan001/halo-record/blob/main/PRIVACY.md) — everything there applies to this package too. The short version, with TypeScript specifics:

- **What a record stores:** one agent action — agent/model identifiers, action type and tool, authorization fields, the subject id you assign, timestamps, integrity hashes. Tool inputs are stored as a canonical hash plus a redacted summary capped at 200 characters — the complete raw value is never written, though a summary can carry fragments of it (redaction is best-effort). Scanner findings carry a type, severity, and a short redacted excerpt; `data.pii_types` lists detected *types* only. Passing `summaries: false` drops summaries, finding excerpts, and custom outcome fields, leaving hash-only records — though fields you supply yourself (an authority block, custom `data.*` keys, non-`sample` keys on your own findings) still seal as given; keep them payload-free.
- **Redaction is best-effort:** deterministic pattern matching plus a high-entropy catch-all — never a model judgment. Free-form personal data with no fixed shape (a name, a postal address) is not reliably detected; treat redaction as defense-in-depth, not a guarantee ([LIMITS §6](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)).
- **What leaves your machine:** nothing, unless your code calls the three opt-in network paths — the witness anchor (sends the subject id, a record count, and two chain fingerprints), the witness checkpoint fetch (sends the subject id being checked), or RFC 3161 timestamping (sends only a checkpoint's state hash to the Timestamp Authority you choose). The witness is a server you run or designate; there is no vendor-hosted or default endpoint. Record contents never leave your infrastructure.
- **What halo does not do:** no telemetry, no analytics, no accounts. Installing and running this package tells the maintainers nothing.
- **Retention:** records are plain JSONL files you control; halo imposes no retention. Editing records inside an established chain is visible on verification; detecting deletion outright requires a checkpoint held outside the chain ([LIMITS §1](https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)).

One note on authority snapshots: `build({ authority })` masks known secret formats at seal time, but hashes and refs pass through untouched and free-form text is not detected — keep the block to hashes and refs.

If this summary and the Python repo's PRIVACY.md ever disagree, the Python file governs.

Data-handling concern, or a pattern the redactor should know about? See [SECURITY.md](SECURITY.md).
