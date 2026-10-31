// Regenerates the committed fixture set offline: synthetic demo key pairs,
// RFC 8032 Ed25519 test vectors (fixtures only - the algorithm has no verify/
// sign row in the engine), positive tokens (including the draft -05 Section
// 3.1 example claims signed by the demo issuer key), one negative token per
// breakage recipe, and the metadata fixtures. Never run at validation time;
// the outputs are committed openly as demo material.
//
// Usage: node scripts/regenerate-fixtures.mjs

import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const FIXTURES = join(ROOT, "fixtures");
mkdirSync(FIXTURES, { recursive: true });

const b64u = (bytes) =>
  Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const utf8 = (text) => new TextEncoder().encode(text);

async function signCompact(claims, jwk, alg, typ = "oauth-id-jag+jwt") {
  const header = { alg, typ };
  const signingInput = `${b64u(utf8(JSON.stringify(header)))}.${b64u(utf8(JSON.stringify(claims)))}`;
  const key = await crypto.subtle.importKey("jwk", jwk, algParams(alg), false, ["sign"]);
  const signature = await crypto.subtle.sign(algParams(alg), key, utf8(signingInput));
  return `${signingInput}.${b64u(new Uint8Array(signature))}`;
}

function algParams(alg) {
  if (alg === "RS256") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  if (alg === "ES256") return { name: "ECDSA", hash: "SHA-256", namedCurve: "P-256" };
  throw new Error(`unsupported algorithm: ${alg}`);
}

function generatePair(alg) {
  const keys =
    alg === "RS256"
      ? generateKeyPairSync("rsa", { modulusLength: 2048 })
      : generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { privateKey: keys.privateKey.export({ format: "jwk" }), publicKey: keys.publicKey.export({ format: "jwk" }) };
}

// Synthetic demo keys, regenerated on every run and committed openly.
const demoKeys = {
  issuer: { rs256: generatePair("RS256"), es256: generatePair("ES256") },
  client: generatePair("RS256"),
  attacker: generatePair("RS256"),
};

// RFC 8032 Section 7.1 test vectors (TEST 1-3).
const ed25519Vectors = {
  description: "RFC 8032 Section 7.1 Ed25519 test vectors; fixtures for a future fork, no algorithm row in the engine",
  vectors: [
    {
      name: "TEST 1",
      secretKey: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      message: "",
      signature:
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
      name: "TEST 2",
      secretKey: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      message: "72",
      signature:
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
      name: "TEST 3",
      secretKey: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      publicKey: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      message: "af82",
      signature:
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
  ],
};

const EXAMPLE_CLAIMS = {
  jti: "9e43f81b64a33f20116179",
  iss: "https://acme.idp.example/",
  sub: "U019488227",
  aud: "https://acme.chat.example/",
  client_id: "f53f191f9311af35",
  exp: 1311281270,
  iat: 1311280970,
  resource: "https://acme.chat.example/api",
  scope: "chat.read chat.history",
  auth_time: 1311280970,
  amr: ["mfa", "phrh", "hwk", "user"],
};

const CONTEXT = {
  now: 1311280980,
  expectedIssuer: "https://acme.idp.example/",
  expectedAudience: "https://acme.chat.example/",
  expectedClientId: "f53f191f9311af35",
};

const ES256_CLAIMS = {
  jti: "5c30e1f4db6a49c2bb8f7a21",
  iss: "https://acme.idp.example/",
  sub: "U019488227",
  aud: "https://acme.chat.example/",
  client_id: "f53f191f9311af35",
  exp: 1311281270,
  iat: 1311280970,
  email: "user@example.com",
  aud_sub: "u019488227-at-chat",
  resource: "https://acme.chat.example/api",
  scope: "chat.read chat.history",
};

const positive = [
  {
    id: "positive-rs256-example",
    description: "The draft -05 Section 3.1 example claims, signed by the demo issuer key (RS256).",
    token: await signCompact(EXAMPLE_CLAIMS, demoKeys.issuer.rs256.privateKey, "RS256"),
    context: { ...CONTEXT, keyRef: "issuer.rs256.publicKey" },
  },
  {
    id: "positive-es256-full",
    description: "A valid ID-JAG with subject-resolution claims (email, aud_sub), signed with ES256.",
    token: await signCompact(ES256_CLAIMS, demoKeys.issuer.es256.privateKey, "ES256"),
    context: { ...CONTEXT, keyRef: "issuer.es256.publicKey" },
  },
];

// One negative per breakage recipe; mutations mirror src/breakages.ts and are
// re-signed by the demo issuer key so only the content is broken.
function mutate(claims, header, mutateFn) {
  const payload = JSON.parse(JSON.stringify(claims));
  mutateFn({ header: { ...header }, payload });
  return payload;
}

const base = EXAMPLE_CLAIMS;
const negativeSpecs = [
  {
    id: "typ-wrong",
    description: "Header typ is wrong; the draft requires oauth-id-jag+jwt.",
    targetRuleId: "structure-typ",
    claims: mutate(base, {}, ({ header }) => {
      header.typ = "jwt";
    }),
    typ: "jwt",
  },
  {
    id: "expired",
    description: "The token expired before the evaluation time.",
    targetRuleId: "rejection-not-expired",
    claims: mutate(base, {}, ({ payload }) => {
      payload.exp = payload.exp - 100000;
    }),
  },
  {
    id: "missing-jti",
    description: "The REQUIRED jti claim is absent.",
    targetRuleId: "claims-required",
    claims: mutate(base, {}, ({ payload }) => {
      delete payload.jti;
    }),
  },
  {
    id: "aud-token-endpoint",
    description: "aud carries the token endpoint, the pre-bis RFC 7523 legacy value, instead of the RAS issuer.",
    targetRuleId: "semantics-aud-value",
    claims: mutate(base, {}, ({ payload }) => {
      payload.aud = "https://acme.chat.example/token";
    }),
  },
  {
    id: "aud-two-elements",
    description: "aud is a two-element array; exactly one RAS issuer element is allowed.",
    targetRuleId: "claims-aud-shape",
    claims: mutate(base, {}, ({ payload }) => {
      payload.aud = [payload.aud, "https://other.example/"];
    }),
  },
  {
    id: "client-id-mismatch",
    description: "client_id does not identify the authenticated client.",
    targetRuleId: "semantics-client-continuity",
    claims: mutate(base, {}, ({ payload }) => {
      payload.client_id = "0000000000000000";
    }),
  },
  {
    id: "subid-malformed",
    description: "sub_id is missing the REQUIRED nameid member.",
    targetRuleId: "subid-format",
    claims: mutate(base, {}, ({ payload }) => {
      payload.sub_id = { format: "saml-nameid", issuer: "https://acme.idp.example/saml" };
    }),
  },
  {
    id: "subid-nameid-only",
    description: "sub_id resolves on nameid alone without scoping members; the resolution trap.",
    targetRuleId: "subid-nameid-only",
    claims: mutate(base, {}, ({ payload }) => {
      payload.sub_id = { format: "saml-nameid", issuer: "https://acme.idp.example/saml", nameid: "foo@example.com" };
    }),
  },
];

const negative = [];
for (const spec of negativeSpecs) {
  negative.push({
    id: spec.id,
    description: spec.description,
    targetRuleId: spec.targetRuleId,
    token: await signCompact(spec.claims, demoKeys.issuer.rs256.privateKey, "RS256", spec.typ),
    context: { ...CONTEXT, keyRef: "issuer.rs256.publicKey" },
  });
}

const metadata = {
  positive: {
    id: "metadata-ras-well-formed",
    description: "A well-formed RAS advertisement: id-jag profile advertised with jwt-bearer in grant_types_supported.",
    kind: "ras",
    document: {
      issuer: "https://acme.chat.example/",
      grant_types_supported: ["urn:ietf:params:oauth:grant-type:authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
      authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"],
    },
  },
  negative: {
    id: "metadata-ras-coupling",
    description: "The id-jag profile is advertised without jwt-bearer in grant_types_supported; the coupling rule.",
    kind: "ras",
    targetRuleId: "metadata-ras-coupling",
    document: {
      issuer: "https://acme.chat.example/",
      grant_types_supported: ["urn:ietf:params:oauth:grant-type:authorization_code"],
      authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"],
    },
  },
};

writeFileSync(join(FIXTURES, "jwks-demo.json"), JSON.stringify(demoKeys, null, 2) + "\n");
writeFileSync(join(FIXTURES, "ed25519-vectors.json"), JSON.stringify(ed25519Vectors, null, 2) + "\n");
writeFileSync(join(FIXTURES, "tokens.json"), JSON.stringify({ positive, negative }, null, 2) + "\n");
writeFileSync(join(FIXTURES, "metadata.json"), JSON.stringify(metadata, null, 2) + "\n");

console.log(`fixtures written to ${FIXTURES}`);
