import { verifyTokenSignature } from "./crypto.js";
import type { ParsedToken, ValidationContext } from "./types.js";

export interface CheckResult {
  ok: boolean;
  message?: string;
  /** Advisory carried on a passing verdict. */
  note?: string;
  /**
   * Overrides the descriptor's fail grade for this outcome. Used when a rule
   * is undecidable rather than failed (e.g. no key supplied for signature
   * verification): the verdict renders external instead of invalid_grant.
   */
  grade?: "informational" | "external";
}

export interface CheckInput {
  /** Parsed token; null for metadata rules and parse failures. */
  token: ParsedToken | null;
  /** Metadata document; null for token rules. */
  document: Record<string, unknown> | null;
  params: Record<string, unknown>;
  context: ValidationContext;
  now: number;
}

export type Check = (input: CheckInput) => CheckResult | Promise<CheckResult>;

function payloadOf(input: CheckInput): Record<string, unknown> {
  return input.token?.payload ?? {};
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

const typEquals: Check = ({ token, params }) => {
  const value = params.value as string;
  if (token?.header.typ === value) return { ok: true };
  return { ok: false, message: `Header "typ" must be "${value}"; found ${JSON.stringify(token?.header.typ ?? null)}.` };
};

const algPinned: Check = ({ token, params }) => {
  const values = params.values as string[];
  const alg = token?.header.alg;
  if (typeof alg === "string" && values.includes(alg)) return { ok: true };
  return {
    ok: false,
    message: `Header "alg" must be one of ${values.join(", ")}; found ${JSON.stringify(alg ?? null)}. "none" and every other value are rejected without attempting crypto.`,
  };
};

const signatureVerifies: Check = async ({ token, context }) => {
  if (!token) return { ok: false, message: "Token did not parse; the signature was not evaluated." };
  if (!context.key) {
    return {
      ok: false,
      grade: "external",
      message:
        "Signature verification needs the issuer's public JWK in context.key; without it the engine cannot decide this rule.",
    };
  }
  const result = await verifyTokenSignature(token, context.key);
  return result.ok ? { ok: true } : { ok: false, message: result.reason };
};

const requiredClaims: Check = (input) => {
  const claims = input.params.claims as string[];
  const payload = payloadOf(input);
  const missing = claims.filter((name) => payload[name] === undefined || payload[name] === null);
  if (missing.length === 0) return { ok: true };
  return { ok: false, message: `Missing required claim${missing.length > 1 ? "s" : ""}: ${missing.join(", ")}.` };
};

function shapeProblem(value: unknown, shape: string): string | null {
  switch (shape) {
    case "string":
      return typeof value === "string" ? null : "must be a JSON string";
    case "numericDate":
      return typeof value === "number" && Number.isFinite(value) ? null : "must be a NumericDate (a number of seconds)";
    case "stringOrSingleArray": {
      if (typeof value === "string") return null;
      if (Array.isArray(value) && value.length === 1 && typeof value[0] === "string") return null;
      return "must be a string or an array containing exactly one string";
    }
    case "stringOrNonEmptyUniqueStringArray": {
      if (typeof value === "string") return null;
      if (
        Array.isArray(value) &&
        value.length > 0 &&
        value.every((entry) => typeof entry === "string") &&
        new Set(value).size === value.length
      ) {
        return null;
      }
      return "must be a string or a non-empty array of unique strings";
    }
    case "objectArray": {
      if (Array.isArray(value) && value.every((entry) => asRecord(entry) !== null)) return null;
      return "must be a JSON array of objects";
    }
    default:
      return null;
  }
}

const claimShape: Check = (input) => {
  const names = (input.params.claims ?? [input.params.claim]) as string[];
  const shape = input.params.shape as string;
  const payload = payloadOf(input);
  for (const name of names) {
    const value = payload[name];
    if (value === undefined) continue;
    const problem = shapeProblem(value, shape);
    if (problem) return { ok: false, message: `Claim "${name}" ${problem}; found ${JSON.stringify(value)}.` };
  }
  return { ok: true };
};

// Value equality against the context. When the claim's shape itself is broken
// (e.g. a multi-element aud) and the descriptor opts in via deferBrokenShape
// (aud is the only context-matched claim with a shape rule), this check defers
// so exactly one rule row carries the failure. Well-shaped but wrong values,
// and claims without a paired shape rule, fail here. Without the expected
// context value the rule is undecidable, not failed.
const claimEqualsContext: Check = (input) => {
  const claimName = input.params.claim as string;
  const contextField = input.params.contextField as keyof ValidationContext;
  const expected = input.context[contextField];
  const value = payloadOf(input)[claimName];
  if (typeof expected !== "string") {
    return {
      ok: false,
      grade: "external",
      message: `Deciding "${claimName}" needs "${String(contextField)}" in the validation context: ${input.params.requirement as string}`,
    };
  }
  const comparable = Array.isArray(value) && value.length === 1 ? value[0] : value;
  if (comparable === expected) return { ok: true };
  const shapeBroken = Array.isArray(value) && (value.length !== 1 || typeof value[0] !== "string");
  if (shapeBroken && input.params.deferBrokenShape === true) {
    return { ok: true, note: `"${claimName}" shape is invalid; the shape rule carries this failure.` };
  }
  return {
    ok: false,
    message: `Claim "${claimName}" must be ${input.params.label as string} (${JSON.stringify(expected)}); found ${JSON.stringify(value)}.`,
  };
};

const notExpired: Check = (input) => {
  const exp = payloadOf(input).exp;
  if (typeof exp !== "number" || !Number.isFinite(exp)) {
    return { ok: false, message: `Claim "exp" must be a NumericDate to evaluate expiry.` };
  }
  if (exp > input.now) return { ok: true };
  return { ok: false, message: `Token expired: "exp" ${exp} is not after the evaluation time ${input.now}.` };
};

// sub and sub_id, when both present, MUST identify the same End-User. The
// engine cannot verify identity equality, so it flags the pair informationally.
const subSubIdSameUser: Check = (input) => {
  const payload = payloadOf(input);
  if (payload.sub === undefined || payload.sub_id === undefined) return { ok: true };
  return {
    ok: false,
    message:
      "Both sub and sub_id are present: they MUST identify the same End-User. The engine cannot verify identity equality; confirm the pair before trusting the grant.",
  };
};

// Requirement-state rules: the engine states the rule with its keyword and
// cite; deciding it needs Resource-Server-side state the engine does not take.
const requirement: Check = (input) => ({ ok: false, message: (input.params.requirement as string) ?? "" });

const clientIdUrl: Check = (input) => {
  const clientId = payloadOf(input).client_id;
  if (typeof clientId === "string" && /^https?:\/\//.test(clientId)) {
    return {
      ok: false,
      message: `client_id ${JSON.stringify(clientId)} is a URL: under Client-ID Metadata Documents the URL is a global client identifier resolved out of band; confirm the document at that URL and the mapping between IdP and Resource Authorization Server.`,
    };
  }
  return { ok: true };
};

const subIdFormat: Check = (input) => {
  const subId = payloadOf(input).sub_id;
  if (subId === undefined) return { ok: true, note: "No sub_id claim; nothing to format-check." };
  const record = asRecord(subId);
  if (!record) {
    return { ok: false, message: `Claim "sub_id" must be a JSON object (Subject Identifier per RFC 9493); found ${JSON.stringify(subId)}.` };
  }
  const formatValue = input.params.format as string;
  const required = input.params.required as string[];
  const optional = (input.params.optional ?? []) as string[];
  if (record.format !== formatValue) {
    return {
      ok: false,
      message: `sub_id "format" must be "${formatValue}"; found ${JSON.stringify(record.format ?? null)}. A Subject Identifier Format the RAS does not support is rejected with invalid_grant.`,
    };
  }
  const missing = required.filter((member) => typeof record[member] !== "string" || record[member] === "");
  if (missing.length > 0) {
    return {
      ok: false,
      message: `sub_id (${formatValue}) is malformed: required member${missing.length > 1 ? "s" : ""} ${missing.join(", ")} must be non-empty strings.`,
    };
  }
  const known = [...required, ...optional];
  const unknownMembers = Object.keys(record).filter((member) => !known.includes(member));
  if (unknownMembers.length > 0) {
    return {
      ok: false,
      message: `sub_id carries members outside the ${formatValue} format: ${unknownMembers.map((member) => JSON.stringify(member)).join(", ")}.`,
    };
  }
  return { ok: true };
};

const subIdTransient: Check = (input) => {
  const record = asRecord(payloadOf(input).sub_id);
  if (!record) return { ok: true, note: "No sub_id object; nothing to check." };
  const forbidden = input.params.forbidden as string;
  if (record.nameid_format === forbidden) {
    return {
      ok: false,
      message: `SAML <NameID> Format ${JSON.stringify(forbidden)} (transient) MUST NOT be used: transient values change across sessions and cannot serve as a cross-trust-domain identifier.`,
    };
  }
  return { ok: true };
};

const subIdScope: Check = (input) => {
  const record = asRecord(payloadOf(input).sub_id);
  if (!record || record.nameid === undefined) return { ok: true, note: "No nameid member; nothing to scope-check." };
  const requireAny = input.params.requireAny as string[];
  if (requireAny.some((member) => record[member] !== undefined)) return { ok: true };
  return {
    ok: false,
    message:
      "sub_id carries a nameid without scoping members (name_qualifier or sp_name_qualifier). A RAS MUST NOT resolve the subject using only the nameid value unless local policy defines nameid alone for this issuer; with no policy input this validator rejects it.",
  };
};

const metadataStringArray: Check = (input) => {
  const member = input.params.member as string;
  const value = input.document?.[member];
  if (value === undefined) return { ok: true, note: `"${member}" is not advertised; nothing to shape-check.` };
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) return { ok: true };
  return { ok: false, message: `Metadata member "${member}" MUST be a JSON array of strings; found ${JSON.stringify(value)}.` };
};

const metadataUrn: Check = (input) => {
  const member = input.params.member as string;
  const urn = input.params.urn as string;
  const value = input.document?.[member];
  if (value === undefined) {
    return { ok: false, message: `"${member}" is not advertised; the draft recommends advertising ${urn}.` };
  }
  if (Array.isArray(value) && value.includes(urn)) return { ok: true };
  return { ok: false, message: `"${member}" does not include ${urn}; found ${JSON.stringify(value)}.` };
};

const metadataCoupling: Check = (input) => {
  const profileMember = input.params.profileMember as string;
  const profileUrn = input.params.profileUrn as string;
  const grantMember = input.params.grantMember as string;
  const requiredUrns = input.params.requiredUrns as string[];
  const profiles = input.document?.[profileMember];
  if (!(Array.isArray(profiles) && profiles.includes(profileUrn))) {
    return { ok: true, note: `${profileUrn} is not advertised in "${profileMember}"; the coupling requirement is not triggered.` };
  }
  const grants = input.document?.[grantMember];
  const missing = requiredUrns.filter((urn) => !(Array.isArray(grants) && grants.includes(urn)));
  if (missing.length === 0) return { ok: true };
  return {
    ok: false,
    message: `"${profileMember}" advertises ${profileUrn}, so "${grantMember}" MUST include ${missing.join(", ")}; found ${JSON.stringify(grants ?? null)}.`,
  };
};

const metadataAlgIncludes: Check = (input) => {
  const member = input.params.member as string;
  const value = input.document?.[member];
  if (value === undefined) return { ok: true, note: `"${member}" is not advertised; nothing to check.` };
  const alg = input.params.alg as string;
  if (Array.isArray(value) && value.includes(alg)) return { ok: true };
  return { ok: false, message: `"${member}", when present, MUST include "${alg}"; found ${JSON.stringify(value)}.` };
};

const claimPresentAny: Check = (input) => {
  const claims = input.params.claims as string[];
  const payload = payloadOf(input);
  if (claims.some((name) => payload[name] !== undefined)) return { ok: true };
  return {
    ok: false,
    message: `None of ${claims.join(", ")} is present; the draft recommends including at least one for subject resolution.`,
  };
};

const actorClaim: Check = (input) => {
  const act = payloadOf(input).act;
  if (act === undefined) return { ok: true };
  return {
    ok: false,
    message:
      "act claim present: the engine surfaces actor context informationally and does not evaluate delegation (RFC 8693 Section 4.1; the draft leaves actor_token processing to future profiles).",
  };
};

export const CHECKS: Record<string, Check> = {
  typEquals,
  algPinned,
  signatureVerifies,
  requiredClaims,
  claimShape,
  claimEqualsContext,
  notExpired,
  subSubIdSameUser,
  requirement,
  clientIdUrl,
  subIdFormat,
  subIdTransient,
  subIdScope,
  metadataStringArray,
  metadataUrn,
  metadataCoupling,
  metadataAlgIncludes,
  claimPresentAny,
  actorClaim,
};
