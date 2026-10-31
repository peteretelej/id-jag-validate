import { describe, expect, it } from "vitest";
import { decode, encode, decodeUtf8, encodeUtf8 } from "../src/base64url.js";
import { signCompact } from "../src/crypto.js";
import { demoKeys, positiveTokens } from "../src/fixtures.js";
import { mint } from "../src/mint.js";
import { parseToken, validateToken } from "../src/validate.js";

// Converts a raw IEEE P1363 r|s signature (64 bytes) into a DER SEQUENCE,
// simulating the most common external-token failure for ES256.
function rawToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const trim = (bytes: Uint8Array) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    return bytes.slice(start);
  };
  const pad = (bytes: Uint8Array) => (bytes[0]! & 0x80 ? new Uint8Array([0, ...bytes]) : bytes);
  const r = pad(trim(raw.slice(0, half)));
  const s = pad(trim(raw.slice(half)));
  return new Uint8Array([0x30, 2 + r.length + 2 + s.length, 0x02, r.length, ...r, 0x02, s.length, ...s]);
}

describe("crypto paths", () => {
  it("base64url codec round-trips and tolerates pasted tokens", () => {
    const bytes = encodeUtf8('{"alg":"ES256","typ":"oauth-id-jag+jwt"}');
    expect(decodeUtf8(decode(encode(bytes)))).toBe(decodeUtf8(bytes));
    // pasted-token artifacts: CRLF line wraps and stray trailing "=" padding
    const crlf = String.fromCharCode(13, 10);
    const pasted = encode(bytes).replace(/(.{8})/g, `$1${crlf}`) + "==";
    expect(decodeUtf8(decode(pasted))).toBe(decodeUtf8(bytes));
    expect(() => decode("abc!def")).toThrow();
  });

  it("a DER-framed ES256 signature yields an explanatory rejection, not a silent false", async () => {
    const fixture = positiveTokens.find((entry) => entry.id === "positive-es256-full")!;
    const parsed = parseToken(fixture.token);
    const token = `${parsed.signingInput}.${encode(rawToDer(parsed.signature))}`;
    const result = await validateToken(token, fixture.context);
    const signature = result.verdicts.find((verdict) => verdict.ruleId === "structure-signature");
    expect(signature?.status).toBe("invalid_grant");
    expect(signature?.message).toMatch(/DER/);
    expect(signature?.message).toMatch(/P1363/);
  });

  it("alg none is a rule outcome, never attempted as crypto", async () => {
    const fixture = positiveTokens.find((entry) => entry.id === "positive-rs256-example")!;
    const parsed = parseToken(fixture.token);
    const header = encode(encodeUtf8(JSON.stringify({ alg: "none", typ: "oauth-id-jag+jwt" })));
    const result = await validateToken(`${header}.${parsed.signingInput.split(".")[1]}.`, fixture.context);
    expect(result.parseError).toBeUndefined();
    const alg = result.verdicts.find((verdict) => verdict.ruleId === "structure-alg");
    expect(alg?.status).toBe("invalid_grant");
    expect(alg?.message).toMatch(/none/);
    expect(result.verdicts.find((verdict) => verdict.ruleId === "structure-signature")?.status).toBe("invalid_grant");
  });

  it("a wrong verification key maps to a failed verdict, not a crash", async () => {
    const fixture = positiveTokens.find((entry) => entry.id === "positive-rs256-example")!;
    const result = await validateToken(fixture.token, { ...fixture.context, key: demoKeys.attacker.publicKey });
    const signature = result.verdicts.find((verdict) => verdict.ruleId === "structure-signature");
    expect(signature?.status).toBe("invalid_grant");
    expect(signature?.message).toMatch(/failed/i);
  });

  it("algorithms outside the table are typed errors (Ed25519 has no row)", async () => {
    await expect(signCompact({}, {}, "Ed25519")).rejects.toThrow(/Unsupported algorithm/);
    await expect(mint({}, demoKeys.issuer.rs256.privateKey, { alg: "ES256" })).rejects.toThrow(/kty/);
  });

  it("a missing key renders the signature rule external, not failed", async () => {
    const fixture = positiveTokens.find((entry) => entry.id === "positive-rs256-example")!;
    const { key, ...contextWithoutKey } = fixture.context;
    const result = await validateToken(fixture.token, contextWithoutKey);
    const signature = result.verdicts.find((verdict) => verdict.ruleId === "structure-signature");
    expect(signature?.status).toBe("external");
  });
});
