import { signCompact } from "./crypto.js";

export interface MintOptions {
  /** Signing algorithm; defaults to RS256. */
  alg?: "RS256" | "ES256";
  /** Header "typ" override; defaults to "oauth-id-jag+jwt". */
  typ?: string;
}

/**
 * Mint an ID-JAG: sign claims with an imported private JWK and produce a
 * compact JWS. The claims are signed exactly as given; timestamps are the
 * caller's responsibility (no ambient clock here).
 */
export async function mint(
  claims: Record<string, unknown>,
  key: Record<string, unknown>,
  options: MintOptions = {},
): Promise<string> {
  const alg = options.alg ?? "RS256";
  const headerExtra = options.typ === undefined ? {} : { typ: options.typ };
  return signCompact(claims, key, alg, headerExtra);
}
