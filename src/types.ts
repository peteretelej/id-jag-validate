export type Revision = "-04" | "-05";

/** The A-G check families from the draft's processing rules. */
export type Family =
  | "structure"
  | "claims"
  | "semantics"
  | "subid"
  | "metadata"
  | "mint"
  | "rejection";

export type Keyword =
  | "MUST"
  | "MUST NOT"
  | "SHOULD"
  | "SHOULD NOT"
  | "MAY"
  | "RECOMMENDED"
  | "REQUIRED"
  | "OPTIONAL";

/**
 * How a rule failure is graded: `invalid_grant` for rejection-grade
 * failures, `informational` for advisory outcomes, `external` for rules a
 * single token cannot decide alone (they need Resource-Server-side state).
 */
export type FailGrade = "invalid_grant" | "informational" | "external";

export type VerdictStatus = "pass" | FailGrade | "error";

export interface RuleDescriptor {
  id: string;
  revision: Revision;
  family: Family;
  /** The normative keyword from the draft. */
  keyword: Keyword;
  /** Section reference exactly as citable against the draft. */
  cite: string;
  /** Name of a check primitive in `src/checks.ts`. */
  check: string;
  /** Static arguments for the check primitive. */
  params?: Record<string, unknown>;
  fail: FailGrade;
  /** One-sentence public-safe statement of the rule. */
  summary: string;
}

export interface Verdict {
  ruleId: string;
  family: Family;
  keyword: Keyword;
  cite: string;
  status: VerdictStatus;
  message: string;
}

export interface ParsedToken {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Uint8Array<ArrayBuffer>;
  signingInput: string;
}

export interface ValidationContext {
  revision?: Revision;
  /** Evaluation time as a Unix timestamp in seconds; defaults to the host clock. */
  now?: number;
  /** The trusted IdP issuer expected in `iss`. Absent: the iss-trust rule renders external. */
  expectedIssuer?: string;
  /** The RAS issuer expected in `aud`. */
  expectedAudience?: string;
  /** The authenticated client expected in `client_id`. */
  expectedClientId?: string;
  /** Issuer public JWK for signature verification (pasted JWKS or mint fixtures). */
  key?: Record<string, unknown>;
  /** Which metadata flavor a document is for; defaults to "ras" in validateMetadata. */
  kind?: "idp" | "ras" | "client";
}

export interface TokenValidationResult {
  revision: Revision;
  /** Set when the token did not parse; verdicts are empty in that case. */
  parseError?: string;
  verdicts: Verdict[];
}

export interface MetadataValidationResult {
  revision: Revision;
  verdicts: Verdict[];
}
