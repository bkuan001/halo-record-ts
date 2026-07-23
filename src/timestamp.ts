/* RFC 3161 trusted timestamping — an independence increment for checkpoints.
   Port of the Python timestamp.py; byte-identical DER requests and the same
   light verification (imprint match + attested time).

   A witness checkpoint records (chain_root, count, head, ts), but `ts` is the
   recorder's *own* clock — an operator can backdate it. RFC 3161 replaces that
   self-asserted time with a proof from a Timestamp Authority (TSA) the operator
   does not control: the TSA cryptographically binds the checkpoint's hash to a
   real time, so "this chain reached this head no later than T" becomes
   verifiable by a third party. No hosted infrastructure — a public TSA is enough.

   Consistent with the rest of the package this stays stdlib-only: it builds the
   ASN.1/DER TimeStampReq by hand, POSTs it over node:https/http, and does a light
   check (the returned token timestamps *our* digest, and at what time). It
   deliberately does NOT verify the TSA's signature or certificate chain — that
   belongs outside the zero-dependency core. The token is a standard artifact, so
   anyone can verify it in full with an off-the-shelf tool and never touch this
   library. base64-decode the token (`tsa.token_b64`) into a file (token.tsr) and:

       openssl ts -verify -digest <tsa.digest> -in token.tsr -CAfile tsa-ca.pem

   (`certReq` is set, so the token embeds the signing cert; a TSA that does not
   embed it needs an extra `-untrusted tsa.crt`.)

   This binds a checkpoint's *state* — it proves the chain reached that state no
   later than the attested time; individual records' `ts` fields stay
   self-asserted, and completeness is still the witness's job, not the clock's. */

import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";

export const DEFAULT_TSA_URL = "https://freetsa.org/tsr"; // free, RFC 3161; point
// at a commercial TSA (DigiCert / Sectigo / your own) for production.

// RFC 3161 tokens are a few KB. Cap the response read so a malicious or
// man-in-the-middled TSA cannot exhaust memory with a huge body.
export const MAX_TSA_RESPONSE = 1 << 21; // 2 MiB

const SHA256_OID = "2.16.840.1.101.3.4.2.1";

// --------------------------------------------------------------------------- //
// Minimal DER encoding (stdlib)
// --------------------------------------------------------------------------- //
export function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const out: number[] = [];
  while (n > 0) {
    out.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | out.length, ...out]);
}

export function tlv(tag: number, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
}

export function derInt(i: number): Buffer {
  let body: Buffer;
  if (i === 0) {
    body = Buffer.from([0x00]);
  } else {
    const b: number[] = [];
    while (i > 0) {
      b.unshift(i & 0xff);
      i = Math.floor(i / 256);
    }
    if (b[0] & 0x80) b.unshift(0); // keep it a positive integer
    body = Buffer.from(b);
  }
  return tlv(0x02, body);
}

export function derOid(oid: string): Buffer {
  const parts = oid.split(".").map((x) => parseInt(x, 10));
  const body: number[] = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    let p = part;
    const stack = [p & 0x7f];
    p = Math.floor(p / 128);
    while (p > 0) {
      stack.unshift((p & 0x7f) | 0x80);
      p = Math.floor(p / 128);
    }
    body.push(...stack);
  }
  return tlv(0x06, Buffer.from(body));
}

export function derSeq(...parts: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(parts));
}

/* MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }. */
export function messageImprint(digest: Buffer): Buffer {
  const algo = derSeq(derOid(SHA256_OID), tlv(0x05, Buffer.alloc(0))); // SHA-256, NULL params
  return derSeq(algo, tlv(0x04, digest));
}

/* A DER-encoded RFC 3161 TimeStampReq over `digest` (32 bytes, SHA-256).
   `certReq` asks the TSA to embed its certificate so the token verifies offline. */
export function buildRequest(digest: Buffer, certReq = true): Buffer {
  const parts = [derInt(1), messageImprint(digest)]; // version v1, imprint
  if (certReq) parts.push(tlv(0x01, Buffer.from([0xff]))); // certReq BOOLEAN TRUE
  return derSeq(...parts);
}

/* Ask `tsaUrl` to timestamp `digestHex` and resolve to the raw DER TimeStampResp
   (which carries the timeStampToken). A network call, made only when a caller
   opts into it (the witness anchor is the other opt-in reach-out). */
export function requestToken(
  digestHex: string,
  tsaUrl: string = DEFAULT_TSA_URL,
  timeout = 20000,
): Promise<Buffer> {
  const digest = Buffer.from(digestHex, "hex");
  const req = buildRequest(digest);
  const url = new URL(tsaUrl);
  const transport = url.protocol === "http:" ? httpRequest : httpsRequest;
  return new Promise<Buffer>((resolve, reject) => {
    const r = transport(
      url,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/timestamp-query",
          "Content-Length": String(req.length),
        },
        timeout,
      },
      (resp) => {
        const chunks: Buffer[] = [];
        let total = 0;
        resp.on("data", (c: Buffer) => {
          total += c.length;
          if (total > MAX_TSA_RESPONSE) {
            r.destroy();
            reject(new Error(`TSA response exceeds ${MAX_TSA_RESPONSE} bytes; refusing`));
            return;
          }
          chunks.push(c);
        });
        resp.on("end", () => resolve(Buffer.concat(chunks)));
        resp.on("error", reject);
      },
    );
    r.on("error", reject);
    r.on("timeout", () => r.destroy(new Error(`TSA ${tsaUrl}: request timed out`)));
    r.write(req);
    r.end();
  });
}

// --------------------------------------------------------------------------- //
// Light verification (stdlib) — imprint match + attested time
// --------------------------------------------------------------------------- //
function readTlv(data: Buffer, i: number): [number, Buffer, number] {
  const tag = data[i];
  let j = i + 1;
  let length = data[j];
  j += 1;
  if (length & 0x80) {
    const n = length & 0x7f;
    length = 0;
    for (let k = 0; k < n; k++) length = length * 256 + data[j + k];
    j += n;
  }
  return [tag, data.subarray(j, j + length), j + length];
}

/* GeneralizedTime 'YYYYMMDDHHMMSS[.fff]Z' → ISO-8601 UTC string. */
function parseGentime(raw: Buffer): string {
  let s = raw.toString("ascii").replace(/Z$/, "");
  let frac = "";
  if (s.includes(".")) {
    const dot = s.indexOf(".");
    frac = s.slice(dot + 1);
    s = s.slice(0, dot);
  }
  if (!/^\d{14}$/.test(s)) throw new Error("bad GeneralizedTime");
  const iso = `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`;
  if (!frac) return iso;
  return iso.slice(0, -1) + "." + frac.replace(/0+$/, "") + "Z";
}

export interface VerifyResult {
  imprint_ok: boolean;
  gen_time: string | null;
}

/* Light, dependency-free check of an RFC 3161 token:
   - imprint_ok: the token timestamps *exactly* our checkpoint digest (the TSA
     signed this chain state, not some other).
   - gen_time: the time the TSA attested (ISO-8601 UTC), or null.

   This does NOT validate the TSA's signature or certificate — that requires
   asymmetric crypto and is the job of `openssl ts -verify`. On its own this
   check confirms the token binds *our* chain state and reads its claimed time;
   only a full openssl verify against a trusted TSA turns that claim into a
   third-party proof. */
export function verify(tokenDer: Buffer, expectedDigestHex: string): VerifyResult {
  const digest = Buffer.from(expectedDigestHex, "hex");
  const imprint = messageImprint(digest);
  const idx = tokenDer.indexOf(imprint);
  if (idx < 0) return { imprint_ok: false, gen_time: null };
  // In TSTInfo the messageImprint is followed by serialNumber (INTEGER) then
  // genTime (GeneralizedTime, tag 0x18).
  let gen_time: string | null = null;
  try {
    const [tag, , afterSerial] = readTlv(tokenDer, idx + imprint.length);
    if (tag === 0x02) {
      const [tag2, body2] = readTlv(tokenDer, afterSerial);
      if (tag2 === 0x18) gen_time = parseGentime(body2);
    }
  } catch {
    /* malformed tail → no time, imprint still bound */
  }
  return { imprint_ok: true, gen_time };
}
