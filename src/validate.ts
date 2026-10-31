import { decode, decodeUtf8 } from "./base64url.js";
import { CHECKS, type Check, type CheckInput } from "./checks.js";
import { defaultRevision, getRuleset } from "./rules/index.js";
import type {
  MetadataValidationResult,
  ParsedToken,
  Revision,
  RuleDescriptor,
  TokenValidationResult,
  ValidationContext,
  Verdict,
} from "./types.js";

// Families a single ID-JAG can be evaluated against; mint rules describe the
// token-exchange request and metadata rules evaluate documents, so neither
// runs in token validation.
const TOKEN_FAMILIES = new Set(["structure", "claims", "semantics", "subid", "rejection"]);

export function parseToken(token: string): ParsedToken {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new Error(`A JWS compact serialization has exactly three dot-separated parts; found ${parts.length}.`);
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  if (!headerPart || !payloadPart) throw new Error("JWT header and payload parts must be non-empty.");
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(decodeUtf8(decode(headerPart)));
    payload = JSON.parse(decodeUtf8(decode(payloadPart)));
  } catch (err) {
    throw new Error(`JWT header and payload must be base64url-encoded JSON (${err instanceof Error ? err.message : "decode failed"}).`);
  }
  if (typeof header !== "object" || header === null || Array.isArray(header)) {
    throw new Error("JWT header must be a JSON object.");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new Error("JWT payload must be a JSON object.");
  }
  return {
    header: header as Record<string, unknown>,
    payload: payload as Record<string, unknown>,
    signature: decode(signaturePart ?? ""),
    signingInput: `${headerPart}.${payloadPart}`,
  };
}

function baseVerdict(rule: RuleDescriptor) {
  return { ruleId: rule.id, family: rule.family, keyword: rule.keyword, cite: rule.cite };
}

async function evaluateRule(rule: RuleDescriptor, input: CheckInput): Promise<Verdict> {
  const check: Check | undefined = CHECKS[rule.check];
  if (!check) {
    return { ...baseVerdict(rule), status: "error", message: `No check primitive named "${rule.check}".` };
  }
  try {
    const result = await check(input);
    if (result.ok) {
      return { ...baseVerdict(rule), status: "pass", message: result.note ?? "Satisfied." };
    }
    const status = result.grade ?? rule.fail;
    return { ...baseVerdict(rule), status, message: result.message || rule.summary };
  } catch (err) {
    return {
      ...baseVerdict(rule),
      status: "error",
      message: err instanceof Error ? err.message : "Check primitive failed.",
    };
  }
}

/**
 * Validate an ID-JAG against a draft revision, returning one verdict per
 * applicable rule. Undecidable rules (uniqueness, tenant trust, replay)
 * render external verdicts stating their requirement; the engine never takes
 * Resource-Server-side state in v1.
 */
export async function validateToken(token: string, context: ValidationContext = {}): Promise<TokenValidationResult> {
  const revision: Revision = context.revision ?? defaultRevision;
  // NumericDate claims are seconds; the default evaluation time must be too.
  const now = context.now ?? Math.floor(Date.now() / 1000);
  let parsed: ParsedToken;
  try {
    parsed = parseToken(token);
  } catch (err) {
    return {
      revision,
      parseError: err instanceof Error ? err.message : String(err),
      verdicts: [],
    };
  }
  const base: CheckInput = { token: parsed, document: null, params: {}, context, now };
  const verdicts: Verdict[] = [];
  for (const rule of getRuleset(revision)) {
    if (!TOKEN_FAMILIES.has(rule.family)) continue;
    verdicts.push(await evaluateRule(rule, { ...base, params: rule.params ?? {} }));
  }
  return { revision, verdicts };
}

/**
 * Validate a supplied metadata document (no fetching; the host fetches) for a
 * draft revision. kind selects the flavor: idp, ras (default), or client.
 */
export async function validateMetadata(
  metadata: Record<string, unknown>,
  context: ValidationContext = {},
): Promise<MetadataValidationResult> {
  const revision: Revision = context.revision ?? defaultRevision;
  const kind = context.kind ?? "ras";
  const base: CheckInput = { token: null, document: metadata, params: {}, context: { ...context, kind }, now: context.now ?? Math.floor(Date.now() / 1000) };
  const verdicts: Verdict[] = [];
  for (const rule of getRuleset(revision)) {
    if (rule.family !== "metadata") continue;
    const kinds = rule.params?.kinds as string[] | undefined;
    if (kinds && !kinds.includes(kind)) continue;
    verdicts.push(await evaluateRule(rule, { ...base, params: rule.params ?? {} }));
  }
  return { revision, verdicts };
}
