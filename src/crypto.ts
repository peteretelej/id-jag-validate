import { encode, encodeUtf8 } from "./base64url.js";
import type { ParsedToken } from "./types.js";

// Data-driven per-algorithm table. Ed25519 deliberately has no row; its RFC
// 8032 fixture vectors land now for the future fork.
interface AlgorithmRow {
  name: string;
  hash: string;
  jwk: { kty: string; crv?: string };
  usages: { verify: KeyUsage[]; sign: KeyUsage[] };
  /** Raw (IEEE P1363) signature length in bytes, where applicable. */
  signatureLength?: number;
}

const ALGORITHMS: Record<string, AlgorithmRow> = {
  RS256: {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    jwk: { kty: "RSA" },
    usages: { verify: ["verify"], sign: ["sign"] },
  },
  ES256: {
    name: "ECDSA",
    hash: "SHA-256",
    jwk: { kty: "EC", crv: "P-256" },
    usages: { verify: ["verify"], sign: ["sign"] },
    signatureLength: 64,
  },
};

export class UnsupportedAlgorithmError extends Error {
  constructor(alg: string) {
    super(`Unsupported algorithm "${alg}"; the engine implements RS256 and ES256 only.`);
    this.name = "UnsupportedAlgorithmError";
  }
}

export type SafeResult<T> = { ok: true; value: T } | { ok: false; reason: string };

// WebCrypto engines differ: a failed verification returns false in some hosts
// and throws in others. Wrapping every verify/sign keeps both as results so
// engine differences become verdicts, never crashes.
export async function safeCrypto<T>(op: string, fn: () => Promise<T>): Promise<SafeResult<T>> {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? `${op}: ${err.message}` : `${op} failed.` };
  }
}

function algorithmParams(row: AlgorithmRow): AlgorithmIdentifier | EcdsaParams {
  return row.name === "ECDSA" ? { name: "ECDSA", hash: row.hash } : { name: row.name, hash: row.hash };
}

export async function importKey(
  jwk: Record<string, unknown>,
  alg: string,
  usage: "verify" | "sign",
): Promise<CryptoKey> {
  const row = ALGORITHMS[alg];
  if (!row) throw new UnsupportedAlgorithmError(alg);
  if (jwk.kty !== row.jwk.kty) {
    throw new Error(`JWK "kty" must be "${row.jwk.kty}" for ${alg}; found "${String(jwk.kty ?? null)}".`);
  }
  if (row.jwk.crv && jwk.crv !== row.jwk.crv) {
    throw new Error(`JWK "crv" must be "${row.jwk.crv}" for ${alg}; found "${String(jwk.crv ?? null)}".`);
  }
  const keyAlgorithm: RsaHashedImportParams | EcKeyImportParams =
    row.name === "ECDSA" ? { name: "ECDSA", namedCurve: row.jwk.crv! } : { name: row.name, hash: row.hash };
  return crypto.subtle.importKey("jwk", jwk as JsonWebKey, keyAlgorithm, false, row.usages[usage]);
}

/**
 * Verify a parsed token's signature against a JWK. `alg` pinning comes from
 * the header: only RS256 and ES256 rows exist, so `alg: none` and every other
 * value are rejected here without ever being attempted as crypto.
 */
export async function verifyTokenSignature(
  token: ParsedToken,
  key: Record<string, unknown>,
): Promise<SafeResult<true>> {
  const alg = typeof token.header.alg === "string" ? token.header.alg : "";
  const row = ALGORITHMS[alg];
  if (!row) {
    return {
      ok: false,
      reason: `Header "alg" ${JSON.stringify(alg || null)} is not supported; only RS256 and ES256 can be verified.`,
    };
  }
  // Signature-format guard: DER-framed ES256 signatures (0x30 lead byte,
  // ~70-72 bytes) are the most common external-token failure. Reject with the
  // conversion path instead of a silent false.
  if (row.signatureLength !== undefined && token.signature.length !== row.signatureLength && token.signature[0] === 0x30) {
    return {
      ok: false,
      reason:
        "ES256 signature is DER-encoded (ASN.1 SEQUENCE). JWS requires the raw IEEE P1363 r|s form (64 bytes); convert DER to raw by splitting the (r, s) integers and left-padding each to 32 bytes.",
    };
  }
  const result = await safeCrypto("signature verification", async () => {
    const cryptoKey = await importKey(key, alg, "verify");
    return crypto.subtle.verify(algorithmParams(row), cryptoKey, token.signature, encodeUtf8(token.signingInput));
  });
  if (!result.ok) return result;
  return result.value ? { ok: true, value: true } : { ok: false, reason: "Signature verification failed against the supplied key." };
}

export async function signCompact(
  claims: Record<string, unknown>,
  jwk: Record<string, unknown>,
  alg: string,
  headerExtra: Record<string, unknown> = {},
): Promise<string> {
  const row = ALGORITHMS[alg];
  if (!row) throw new UnsupportedAlgorithmError(alg);
  const header = { alg, typ: "oauth-id-jag+jwt", ...headerExtra };
  const signingInput = `${encode(encodeUtf8(JSON.stringify(header)))}.${encode(encodeUtf8(JSON.stringify(claims)))}`;
  const signature = await crypto.subtle.sign(
    algorithmParams(row),
    await importKey(jwk, alg, "sign"),
    encodeUtf8(signingInput),
  );
  const bytes = new Uint8Array(signature);
  if (row.signatureLength !== undefined && bytes.length !== row.signatureLength) {
    throw new Error(`${alg} produced a ${bytes.length}-byte signature; expected raw ${row.signatureLength} bytes.`);
  }
  return `${signingInput}.${encode(bytes)}`;
}
