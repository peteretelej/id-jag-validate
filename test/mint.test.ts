import { describe, expect, it } from "vitest";
import { signCompact } from "../src/crypto.js";
import { demoKeys } from "../src/fixtures.js";
import { mint } from "../src/mint.js";
import { validateToken } from "../src/validate.js";

const NOW = 1_900_000_000;

function roundTripClaims(jti: string) {
  return {
    iss: "https://acme.idp.example/",
    sub: "U019488227",
    aud: "https://acme.chat.example/",
    client_id: "f53f191f9311af35",
    jti,
    exp: NOW + 300,
    iat: NOW,
    email: "user@example.com",
    aud_sub: "u019488227-at-chat",
    resource: "https://acme.chat.example/api",
    scope: "chat.read",
  };
}

function roundTripContext() {
  return {
    now: NOW,
    expectedIssuer: "https://acme.idp.example/",
    expectedAudience: "https://acme.chat.example/",
    expectedClientId: "f53f191f9311af35",
  };
}

describe("mint round-trip", () => {
  it("mint then validate all-pass (RS256)", async () => {
    const token = await mint(roundTripClaims("roundtrip-rs256"), demoKeys.issuer.rs256.privateKey);
    const result = await validateToken(token, { ...roundTripContext(), key: demoKeys.issuer.rs256.publicKey });
    expect(result.revision).toBe("-05");
    expect(result.parseError).toBeUndefined();
    for (const verdict of result.verdicts) {
      if (verdict.status === "external") continue; // undecidable by design: needs RAS-side state
      expect(verdict.status, verdict.ruleId).toBe("pass");
    }
    expect(result.verdicts.some((verdict) => verdict.status === "external")).toBe(true);
  });

  it("mint then validate all-pass (ES256)", async () => {
    const token = await mint(roundTripClaims("roundtrip-es256"), demoKeys.issuer.es256.privateKey, { alg: "ES256" });
    const result = await validateToken(token, { ...roundTripContext(), key: demoKeys.issuer.es256.publicKey });
    expect(result.parseError).toBeUndefined();
    for (const verdict of result.verdicts) {
      if (verdict.status === "external") continue;
      expect(verdict.status, verdict.ruleId).toBe("pass");
    }
  });

  it("minted tokens can be deliberately broken via header overrides", async () => {
    const token = await mint(roundTripClaims("roundtrip-typ"), demoKeys.issuer.rs256.privateKey, { typ: "jwt" });
    const result = await validateToken(token, { ...roundTripContext(), key: demoKeys.issuer.rs256.publicKey });
    expect(result.verdicts.find((verdict) => verdict.ruleId === "structure-typ")?.status).toBe("invalid_grant");
  });

  it("signing rejects algorithms outside the table", async () => {
    await expect(signCompact({}, demoKeys.issuer.rs256.privateKey, "HS256")).rejects.toThrow(/Unsupported algorithm/);
  });
});
