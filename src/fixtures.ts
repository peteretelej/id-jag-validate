import ed25519VectorsJson from "../fixtures/ed25519-vectors.json" with { type: "json" };
import jwksDemoJson from "../fixtures/jwks-demo.json" with { type: "json" };
import metadataJson from "../fixtures/metadata.json" with { type: "json" };
import tokensJson from "../fixtures/tokens.json" with { type: "json" };
import type { ValidationContext } from "./types.js";

export interface DemoKeyPair {
  privateKey: Record<string, unknown>;
  publicKey: Record<string, unknown>;
}

export interface DemoKeys {
  issuer: { rs256: DemoKeyPair; es256: DemoKeyPair };
  client: DemoKeyPair;
  attacker: DemoKeyPair;
}

export const demoKeys = jwksDemoJson as DemoKeys;

export interface Ed25519Vector {
  name: string;
  secretKey: string;
  publicKey: string;
  message: string;
  signature: string;
}

export const ed25519TestVectors: Ed25519Vector[] = ed25519VectorsJson.vectors;

export interface MetadataFixture {
  id: string;
  description: string;
  kind: "idp" | "ras" | "client";
  targetRuleId?: string;
  document: Record<string, unknown>;
}

interface RawTokenFixture {
  id: string;
  description: string;
  targetRuleId?: string;
  token: string;
  context: Omit<ValidationContext, "key"> & { keyRef?: string };
}

export interface TokenFixture {
  id: string;
  description: string;
  targetRuleId?: string;
  token: string;
  context: ValidationContext;
}

function resolveKeyRef(ref: string): Record<string, unknown> {
  let node: unknown = demoKeys;
  for (const part of ref.split(".")) {
    node = (node as Record<string, unknown>)[part];
  }
  return node as Record<string, unknown>;
}

function resolveFixtures(list: RawTokenFixture[]): TokenFixture[] {
  return list.map(({ context, ...rest }) => {
    const { keyRef, ...restContext } = context;
    return { ...rest, context: keyRef ? { ...restContext, key: resolveKeyRef(keyRef) } : restContext };
  });
}

export const positiveTokens: TokenFixture[] = resolveFixtures(tokensJson.positive);
export const negativeTokens: TokenFixture[] = resolveFixtures(tokensJson.negative);

export const metadataPositive: MetadataFixture = metadataJson.positive as MetadataFixture;
export const metadataNegative: MetadataFixture = metadataJson.negative as MetadataFixture;
