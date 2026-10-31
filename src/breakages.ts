import type { Family } from "./types.js";

export interface BreakageRecipe {
  id: string;
  family: Family;
  targetRuleId: string;
  /**
   * True when the Mint tab exposes this recipe as one toggle per family; the
   * console-check suite asserts each toggle flips exactly its target rule row.
   */
  mintToggle: boolean;
  /**
   * Produces the breakage from a cloned {header, payload} pair (mutates in
   * place); callers re-sign afterwards. Absent for metadata recipes.
   */
  mutate?: (parts: { header: Record<string, unknown>; payload: Record<string, unknown> }) => void;
}

export const breakageRecipes: BreakageRecipe[] = [
  {
    id: "typ-wrong",
    family: "structure",
    targetRuleId: "structure-typ",
    mintToggle: true,
    mutate: ({ header }) => {
      header.typ = "jwt";
    },
  },
  {
    id: "expired",
    family: "rejection",
    targetRuleId: "rejection-not-expired",
    mintToggle: true,
    mutate: ({ payload }) => {
      payload.exp = (payload.exp as number) - 100000;
    },
  },
  {
    id: "missing-jti",
    family: "claims",
    targetRuleId: "claims-required",
    mintToggle: true,
    mutate: ({ payload }) => {
      delete payload.jti;
    },
  },
  {
    id: "aud-token-endpoint",
    family: "semantics",
    targetRuleId: "semantics-aud-value",
    mintToggle: true,
    mutate: ({ payload }) => {
      payload.aud = "https://acme.chat.example/token";
    },
  },
  {
    id: "aud-two-elements",
    family: "claims",
    targetRuleId: "claims-aud-shape",
    mintToggle: true,
    mutate: ({ payload }) => {
      payload.aud = [payload.aud as string, "https://other.example/"];
    },
  },
  {
    id: "client-id-mismatch",
    family: "semantics",
    targetRuleId: "semantics-client-continuity",
    mintToggle: true,
    mutate: ({ payload }) => {
      payload.client_id = "0000000000000000";
    },
  },
  {
    id: "subid-malformed",
    family: "subid",
    targetRuleId: "subid-format",
    mintToggle: true,
    mutate: ({ payload }) => {
      payload.sub_id = { format: "saml-nameid", issuer: "https://acme.idp.example/saml" };
    },
  },
  {
    id: "subid-nameid-only",
    family: "subid",
    targetRuleId: "subid-nameid-only",
    mintToggle: true,
    mutate: ({ payload }) => {
      payload.sub_id = { format: "saml-nameid", issuer: "https://acme.idp.example/saml", nameid: "foo@example.com" };
    },
  },
  {
    id: "metadata-ras-coupling",
    family: "metadata",
    targetRuleId: "metadata-ras-coupling",
    mintToggle: false,
  },
];
