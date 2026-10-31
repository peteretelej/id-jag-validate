import type { RuleDescriptor } from "../types.js";

// Seeded from the -04 extraction (labsite-structure-prep section 4), keeping
// its section cites. The -05 text is the accuracy authority for the -05
// ruleset; this ruleset is the version-pinned seed. Unlike -05, draft -04
// carries no explicit RS256/ES256 algorithm-restriction language, no
// id_jag_signing_alg_values_supported metadata member, and no SAML NameID
// stability (transient), identifier-scope/pairwise-mapping, or error-response/
// refresh-token processing additions; those enter with -05.

export const rules: RuleDescriptor[] = [
  // Structure (Sections 3.1, 4.4.1)
  {
    id: "structure-typ",
    revision: "-04",
    family: "structure",
    keyword: "MUST",
    cite: "Section 3.1",
    check: "typEquals",
    params: { value: "oauth-id-jag+jwt" },
    fail: "invalid_grant",
    summary: 'The JWT header "typ" MUST be "oauth-id-jag+jwt" (explicit typing per RFC 8725 Section 3.11).',
  },
  {
    id: "structure-alg",
    revision: "-04",
    family: "structure",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "algPinned",
    params: { values: ["RS256", "ES256"] },
    fail: "invalid_grant",
    summary:
      "The signature MUST be validated as required by RFC 7521 Section 5.2 with an allow-listed algorithm; the engine pins verification to RS256 and ES256 and rejects alg none and every other value as rule outcomes.",
  },
  {
    id: "structure-signature",
    revision: "-04",
    family: "structure",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "signatureVerifies",
    fail: "invalid_grant",
    summary:
      "The ID-JAG signature MUST verify against the issuing IdP's published keys; the engine verifies a supplied JWK, and key discovery is a host concern.",
  },

  // Claims presence and shapes (Section 3.1)
  {
    id: "claims-required",
    revision: "-04",
    family: "claims",
    keyword: "REQUIRED",
    cite: "Section 3.1",
    check: "requiredClaims",
    params: { claims: ["iss", "sub", "aud", "client_id", "jti", "exp", "iat"] },
    fail: "invalid_grant",
    summary: "iss, sub, aud, client_id, jti, exp, and iat are REQUIRED claims of the ID-JAG.",
  },
  {
    id: "claims-aud-shape",
    revision: "-04",
    family: "claims",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "claimShape",
    params: { claim: "aud", shape: "stringOrSingleArray" },
    fail: "invalid_grant",
    summary:
      "The aud claim MUST be a string or a single-element array whose element is the RAS issuer identifier; anything else is rejected (this prevents audience injection attacks).",
  },
  {
    id: "claims-resource-shape",
    revision: "-04",
    family: "claims",
    keyword: "MUST",
    cite: "Section 3.1",
    check: "claimShape",
    params: { claim: "resource", shape: "stringOrNonEmptyUniqueStringArray" },
    fail: "invalid_grant",
    summary: "When present, resource is a string or a non-empty JSON array of unique strings (RFC 8707 resource identifiers).",
  },
  {
    id: "claims-authorization-details-shape",
    revision: "-04",
    family: "claims",
    keyword: "MUST",
    cite: "Section 3.1",
    check: "claimShape",
    params: { claim: "authorization_details", shape: "objectArray" },
    fail: "invalid_grant",
    summary: "When present, authorization_details MUST be a JSON array of authorization detail objects (RFC 9396).",
  },
  {
    id: "claims-string-claims-shape",
    revision: "-04",
    family: "claims",
    keyword: "MUST",
    cite: "Section 3.1",
    check: "claimShape",
    params: { claims: ["scope", "tenant", "aud_tenant", "aud_sub", "email"], shape: "string" },
    fail: "invalid_grant",
    summary: "When present, scope, tenant, aud_tenant, aud_sub, and email MUST each be a JSON string.",
  },
  {
    id: "claims-numeric-dates",
    revision: "-04",
    family: "claims",
    keyword: "MUST",
    cite: "RFC 7519 Sections 4.1.4 and 4.1.6",
    check: "claimShape",
    params: { claims: ["exp", "iat"], shape: "numericDate" },
    fail: "invalid_grant",
    summary: "exp and iat MUST be NumericDate values (numbers of seconds).",
  },
  {
    id: "claims-subject-resolution-recommended",
    revision: "-04",
    family: "claims",
    keyword: "RECOMMENDED",
    cite: "Section 3.1",
    check: "claimPresentAny",
    params: { claims: ["email", "aud_sub"] },
    fail: "informational",
    summary:
      "It is RECOMMENDED that the ID-JAG contain an email and/or aud_sub claim (subject resolution plus JIT provisioning).",
  },
  {
    id: "claims-act-informational",
    revision: "-04",
    family: "claims",
    keyword: "OPTIONAL",
    cite: "Section 3.1",
    check: "actorClaim",
    fail: "informational",
    summary:
      "act is OPTIONAL (RFC 8693 Section 4.1); the engine surfaces actor context informationally and never renders a verdict on it.",
  },

  // Claim semantics (Sections 3.1, 4.4.1, 5, 6.3)
  {
    id: "semantics-aud-value",
    revision: "-04",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "claimEqualsContext",
    params: {
      claim: "aud",
      contextField: "expectedAudience",
      label: "this Resource Authorization Server's issuer identifier",
      requirement:
        "the RAS MUST reject the ID-JAG with invalid_grant unless aud carries its own issuer identifier; supply the expected audience to decide this rule.",
    },
    fail: "invalid_grant",
    summary:
      "The aud claim MUST contain the issuer identifier of the Resource Authorization Server; a mismatch is rejected with invalid_grant.",
  },
  {
    id: "semantics-iss-trust",
    revision: "-04",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "claimEqualsContext",
    params: {
      claim: "iss",
      contextField: "expectedIssuer",
      label: "a trusted IdP Authorization Server issuer identifier",
      requirement:
        "the RAS MUST reject the ID-JAG with invalid_grant if iss does not identify an IdP Authorization Server it trusts; supply the trusted issuer to decide this rule.",
    },
    fail: "invalid_grant",
    summary: "The RAS MUST reject the ID-JAG with invalid_grant if iss does not identify an IdP Authorization Server it trusts.",
  },
  {
    id: "semantics-client-continuity",
    revision: "-04",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "claimEqualsContext",
    params: {
      claim: "client_id",
      contextField: "expectedClientId",
      label: "the authenticated client's identifier",
      requirement:
        "the RAS MUST reject the request with invalid_grant unless the client_id claim identifies the same client as the request's client authentication (client continuity, not actor authentication); supply the authenticated client to decide this rule.",
    },
    fail: "invalid_grant",
    summary:
      "The client_id claim MUST identify the same client as the request's client authentication; a mismatch is client-continuity failure, rejected with invalid_grant.",
  },
  {
    id: "semantics-sub-sub-id-same-user",
    revision: "-04",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 3.1",
    check: "subSubIdSameUser",
    fail: "informational",
    summary: "When both sub and sub_id are present, they MUST identify the same End-User; the engine flags the pair for confirmation.",
  },
  {
    id: "semantics-sub-uniqueness",
    revision: "-04",
    family: "semantics",
    keyword: "MUST",
    cite: "Sections 3.1, 6.3",
    check: "requirement",
    params: {
      requirement:
        "A public sub MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer and when scoped with issuer and tenant (iss+tenant+sub) for a multi-tenant issuer; deciding this needs the RAS's subject state, which the engine does not take in v1.",
    },
    fail: "external",
    summary: "Subject identifiers MUST be unique when scoped with issuer (and tenant for multi-tenant issuers); requires RAS-side state.",
  },
  {
    id: "semantics-aud-sub-uniqueness",
    revision: "-04",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 3.1",
    check: "requirement",
    params: {
      requirement:
        "The combination of aud + aud_tenant and aud_sub MUST be unique within the Resource Authorization Server; deciding this needs the RAS's subject state, which the engine does not take in v1.",
    },
    fail: "external",
    summary: "aud + aud_tenant and aud_sub MUST be unique within the Resource Authorization Server; requires RAS-side state.",
  },
  {
    id: "semantics-tenant-required",
    revision: "-04",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 6.3",
    check: "requirement",
    params: {
      requirement:
        "When the RAS is multi-tenant the IdP MUST include the tenant claim, and the RAS MUST reject the ID-JAG with invalid_grant unless it trusts iss and tenant together; the engine does not know whether a deployment is multi-tenant, so this needs deployment input.",
    },
    fail: "external",
    summary: "When the RAS is multi-tenant the IdP MUST include the tenant claim; needs deployment input.",
  },
  {
    id: "semantics-client-id-cimd",
    revision: "-04",
    family: "semantics",
    keyword: "MAY",
    cite: "Section 5",
    check: "clientIdUrl",
    fail: "informational",
    summary:
      "The IdP must know the client_id relationship, maintained out of band; when clients use Client-ID Metadata Documents the URL client_id acts as a shared global namespace and removes the mapping.",
  },

  // SAML NameID sub_id (Sections 3.2.1, 3.2.2)
  {
    id: "subid-format",
    revision: "-04",
    family: "subid",
    keyword: "MUST",
    cite: "Section 3.2.1",
    check: "subIdFormat",
    params: {
      format: "saml-nameid",
      required: ["format", "issuer", "nameid"],
      optional: ["nameid_format", "name_qualifier", "sp_name_qualifier", "sp_provided_id"],
    },
    fail: "invalid_grant",
    summary:
      "A sub_id in the SAML NameID Subject Identifier Format MUST contain format (saml-nameid), issuer, and nameid, and MAY contain nameid_format, name_qualifier, sp_name_qualifier, and sp_provided_id; a malformed or unsupported format is rejected with invalid_grant.",
  },
  {
    id: "subid-nameid-only",
    revision: "-04",
    family: "subid",
    keyword: "MUST NOT",
    cite: "Section 3.2.2",
    check: "subIdScope",
    params: { requireAny: ["name_qualifier", "sp_name_qualifier"] },
    fail: "invalid_grant",
    summary:
      "The RAS MUST compare every member it uses for that issuer's subject resolution and MUST NOT resolve on the nameid value alone unless local policy says so; a nameid without scoping members is the resolution trap.",
  },
  {
    id: "subid-construction",
    revision: "-04",
    family: "subid",
    keyword: "MUST",
    cite: "Section 3.2.2",
    check: "requirement",
    params: {
      requirement:
        "The SAML NameID sub_id members MUST derive from the SAML Assertion Subject <NameID> the IdP would issue for SSO to that RAS, each optional field present exactly when the corresponding attribute is present, and the sub_id MUST identify the same subject as sub; verifying this needs IdP-side SSO state.",
    },
    fail: "external",
    summary: "sub_id members MUST derive from the SSO <NameID> for that RAS, with optional fields present exactly when the attributes are; needs IdP-side state.",
  },
  {
    id: "subid-required-policy",
    revision: "-04",
    family: "subid",
    keyword: "MUST",
    cite: "Section 3.2.2",
    check: "requirement",
    params: {
      requirement:
        "The RAS MUST reject the token request with invalid_grant when the sub_id claim is missing when required, malformed or of an unsupported format, or not authorized by policy for that issuer; whether sub_id is required is RAS-local policy the engine does not take in v1.",
    },
    fail: "external",
    summary: "The RAS MUST reject with invalid_grant when sub_id is missing when required, malformed, or unauthorized; policy input decides.",
  },

  // Discovery and metadata (Sections 7, 8)
  {
    id: "metadata-idp-token-type",
    revision: "-04",
    family: "metadata",
    keyword: "SHOULD",
    cite: "Section 7",
    check: "metadataUrn",
    params: {
      member: "identity_chaining_requested_token_types_supported",
      urn: "urn:ietf:params:oauth:token-type:id-jag",
      kinds: ["idp"],
    },
    fail: "informational",
    summary:
      "An IdP Authorization Server SHOULD include urn:ietf:params:oauth:token-type:id-jag in identity_chaining_requested_token_types_supported.",
  },
  {
    id: "metadata-grant-profiles-shape",
    revision: "-04",
    family: "metadata",
    keyword: "MUST",
    cite: "Sections 7 and 8",
    check: "metadataStringArray",
    params: { member: "authorization_grant_profiles_supported", kinds: ["ras", "client"] },
    fail: "invalid_grant",
    summary: "authorization_grant_profiles_supported MUST be a JSON array of strings, each naming a supported grant profile.",
  },
  {
    id: "metadata-ras-profile",
    revision: "-04",
    family: "metadata",
    keyword: "SHOULD",
    cite: "Section 7",
    check: "metadataUrn",
    params: {
      member: "authorization_grant_profiles_supported",
      urn: "urn:ietf:params:oauth:grant-profile:id-jag",
      kinds: ["ras"],
    },
    fail: "informational",
    summary:
      "A Resource Authorization Server SHOULD include urn:ietf:params:oauth:grant-profile:id-jag in authorization_grant_profiles_supported (advertisement means the processing rules are implemented).",
  },
  {
    id: "metadata-ras-coupling",
    revision: "-04",
    family: "metadata",
    keyword: "MUST",
    cite: "Section 7",
    check: "metadataCoupling",
    params: {
      profileMember: "authorization_grant_profiles_supported",
      profileUrn: "urn:ietf:params:oauth:grant-profile:id-jag",
      grantMember: "grant_types_supported",
      requiredUrns: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
      kinds: ["ras"],
    },
    fail: "invalid_grant",
    summary:
      "A RAS advertising urn:ietf:params:oauth:grant-profile:id-jag MUST also include urn:ietf:params:oauth:grant-type:jwt-bearer in grant_types_supported.",
  },
  {
    id: "metadata-client-profile",
    revision: "-04",
    family: "metadata",
    keyword: "SHOULD",
    cite: "Section 8",
    check: "metadataUrn",
    params: {
      member: "authorization_grant_profiles_supported",
      urn: "urn:ietf:params:oauth:grant-profile:id-jag",
      kinds: ["client"],
    },
    fail: "informational",
    summary: "A client SHOULD include urn:ietf:params:oauth:grant-profile:id-jag in its authorization_grant_profiles_supported.",
  },
  {
    id: "metadata-client-grant-types",
    revision: "-04",
    family: "metadata",
    keyword: "MUST",
    cite: "Section 8",
    check: "metadataCoupling",
    params: {
      profileMember: "authorization_grant_profiles_supported",
      profileUrn: "urn:ietf:params:oauth:grant-profile:id-jag",
      grantMember: "grant_types",
      requiredUrns: [
        "urn:ietf:params:oauth:grant-type:token-exchange",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
      ],
      kinds: ["client"],
    },
    fail: "invalid_grant",
    summary:
      "A client advertising the id-jag profile MUST include both urn:ietf:params:oauth:grant-type:token-exchange and urn:ietf:params:oauth:grant-type:jwt-bearer in its grant_types.",
  },

  // Mint side: token-exchange processing at the IdP (Sections 4.3, 4.3.3).
  // These rules are registry-only: they describe the exchange request, not
  // the ID-JAG, so validateToken does not evaluate them.
  {
    id: "mint-requested-token-type",
    revision: "-04",
    family: "mint",
    keyword: "REQUIRED",
    cite: "Section 4.3",
    check: "requirement",
    params: {
      requirement:
        "The Token Exchange request REQUIRED requested_token_type is urn:ietf:params:oauth:token-type:id-jag; the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "requested_token_type is REQUIRED and must be urn:ietf:params:oauth:token-type:id-jag.",
  },
  {
    id: "mint-audience",
    revision: "-04",
    family: "mint",
    keyword: "REQUIRED",
    cite: "Section 4.3",
    check: "requirement",
    params: {
      requirement:
        "The Token Exchange request REQUIRED audience identifies the Resource Authorization Server (implementation-specific URNs MAY be resolved by the IdP); the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "audience is REQUIRED and identifies the Resource Authorization Server for the ID-JAG.",
  },
  {
    id: "mint-subject-token",
    revision: "-04",
    family: "mint",
    keyword: "MUST",
    cite: "Section 4.3",
    check: "requirement",
    params: {
      requirement:
        "subject_token is REQUIRED; implementations MUST accept Identity Assertions (id_token, saml2) and MAY additionally accept refresh tokens; the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "Implementations MUST accept Identity Assertions as subject_token and MAY accept refresh tokens.",
  },
  {
    id: "mint-subject-token-type",
    revision: "-04",
    family: "mint",
    keyword: "REQUIRED",
    cite: "Section 4.3",
    check: "requirement",
    params: {
      requirement:
        "subject_token_type is REQUIRED and must be consistent with the subject token (id_token, saml2, or refresh_token); the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "subject_token_type is REQUIRED and must be consistent with the subject_token.",
  },
  {
    id: "mint-assertion-audience",
    revision: "-04",
    family: "mint",
    keyword: "MUST",
    cite: "Section 4.3.3",
    check: "requirement",
    params: {
      requirement:
        "The IdP MUST validate the assertion and MUST check that the assertion's audience matches the client_id of the request's client authentication; the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "The IdP MUST validate the subject assertion and check its audience against the authenticated client_id.",
  },
  {
    id: "mint-refresh-validation",
    revision: "-04",
    family: "mint",
    keyword: "MUST",
    cite: "Section 4.3.3",
    check: "requirement",
    params: {
      requirement:
        "A refresh-token subject token gets standard refresh-grant validation at the IdP (issued by the IdP, bound to the authenticated client, unexpired, not revoked); the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "Refresh-token subject tokens get standard refresh-grant validation at the IdP.",
  },
  {
    id: "mint-refresh-assembly",
    revision: "-04",
    family: "mint",
    keyword: "SHOULD",
    cite: "Section 4.3.3",
    check: "requirement",
    params: {
      requirement:
        "A refresh-token subject token SHOULD have the IdP re-assemble current subject claims so the issued ID-JAG reflects them; the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "A refresh-token exchange SHOULD re-assemble current subject claims for the issued ID-JAG.",
  },
  {
    id: "mint-granted-values",
    revision: "-04",
    family: "mint",
    keyword: "MUST",
    cite: "Section 4.3.3",
    check: "requirement",
    params: {
      requirement:
        "The resource/scope/authorization_details processed per RFC 8707, RFC 6749 Section 3.3, and RFC 9396 (with policy narrowing MAY) MUST be reflected in the issued ID-JAG as granted; the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "Granted resource, scope, and authorization_details values MUST be reflected in the issued ID-JAG.",
  },
  {
    id: "mint-actor-token",
    revision: "-04",
    family: "mint",
    keyword: "OPTIONAL",
    cite: "Section 4.3",
    check: "requirement",
    params: {
      requirement:
        "actor_token is OPTIONAL and its processing is out of scope; the validator surfaces act as informational, never as a verdict; the engine never renders a verdict on it.",
    },
    fail: "external",
    summary: "actor_token is OPTIONAL and its processing is out of scope.",
  },

  // RAS rejection behaviors (Section 4.4.1 + RFC 7521 Section 5.2)
  {
    id: "rejection-not-expired",
    revision: "-04",
    family: "rejection",
    keyword: "MUST",
    cite: "RFC 7521 Section 5.2",
    check: "notExpired",
    fail: "invalid_grant",
    summary: "An expired assertion MUST be rejected with invalid_grant (RFC 7521 Section 5.2).",
  },
];
