import type { RuleDescriptor } from "../types.js";

// Known non-rules in draft -05: content that is explainer material rather
// than token/metadata/mint rules, recorded so the -04 -> -05 delta stays
// auditable.
//
// - Section 9 (all of it): security-consideration prose - 9.1 client
//   authentication trade-offs, 9.2 storage of subject tokens, 9.3 step-up
//   authentication, 9.4 cross-domain use, 9.5/9.6 authorization-server and
//   protected-resource metadata validation, 9.7 metadata disclosure, 9.8/9.9
//   subject identifier trust and disclosure, 9.10 actor delegation extensions,
//   9.11 sender-constrained tokens (DPoP key binding 9.11.1, mTLS certificate
//   binding 9.11.2, cnf proof-of-possession processing).
// - Section 4.5: SAML 2.0 subject-token interoperability (assertion-to-
//   refresh-token exchange; no ID-JAG token or metadata surface to check).
// - Section 7.1: "The IdP Authorization Server SHOULD sign ID-JAGs with a key
//   published at the jwks_uri" - signing behavior, not a document or token
//   property the engine can check (jwks_uri presence is generic AS metadata).
// - RFC 8725 requirements beyond the draft's own cites are deliberately not
//   imported; the draft cites RFC 8725 Section 3.11 for the typ header only.

export const rules: RuleDescriptor[] = [
  // Structure (Sections 3, 3.1, 4.4.1)
  {
    id: "structure-typ",
    revision: "-05",
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
    revision: "-05",
    family: "structure",
    keyword: "MUST",
    cite: "Section 3",
    check: "algPinned",
    params: { values: ["RS256", "ES256"] },
    fail: "invalid_grant",
    summary:
      "RS256 is mandatory to implement and the header algorithm MUST match the supplied key; the engine also accepts ES256 and rejects alg none and every other value as rule outcomes.",
  },
  {
    id: "structure-signature",
    revision: "-05",
    family: "structure",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "signatureVerifies",
    fail: "invalid_grant",
    summary:
      "The ID-JAG signature MUST be validated against the trusted issuer's keys (from jwks_uri) as required by RFC 7521 Section 5.2.",
  },

  // Claims presence and shapes (Section 3.1)
  {
    id: "claims-required",
    revision: "-05",
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
    revision: "-05",
    family: "claims",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "claimShape",
    params: { claim: "aud", shape: "stringOrSingleArray" },
    fail: "invalid_grant",
    summary:
      "The aud claim MUST be a string containing the RAS issuer identifier, or an array containing exactly that one element; anything else is rejected (this prevents audience injection attacks).",
  },
  {
    id: "claims-resource-shape",
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
    family: "claims",
    keyword: "RECOMMENDED",
    cite: "Section 3.1",
    check: "claimPresentAny",
    params: { claims: ["email", "aud_sub"] },
    fail: "informational",
    summary:
      "It is RECOMMENDED that the ID-JAG contain an email and/or aud_sub claim so the RAS can perform subject resolution, including JIT provisioning.",
  },
  {
    id: "claims-act-informational",
    revision: "-05",
    family: "claims",
    keyword: "OPTIONAL",
    cite: "Section 3.1",
    check: "actorClaim",
    fail: "informational",
    summary:
      "act is OPTIONAL (RFC 8693 Section 4.1); the engine surfaces actor context informationally and never renders a verdict on it.",
  },

  // Claim semantics (Sections 3.1, 4.4.1, 5.1, 6.1, 6.3)
  {
    id: "semantics-aud-value",
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 4.4.1",
    check: "claimEqualsContext",
    params: {
      claim: "client_id",
      contextField: "expectedClientId",
      label: "the authenticated client's identifier",
      requirement:
        "when the client authenticates, the RAS MUST reject the request with invalid_grant unless client_id identifies the authenticated client (client continuity, not actor authentication); supply the authenticated client to decide this rule.",
    },
    fail: "invalid_grant",
    summary:
      "If the client authenticates, the RAS MUST reject the request with invalid_grant unless the client_id claim identifies the authenticated client.",
  },
  {
    id: "semantics-sub-sub-id-same-user",
    revision: "-05",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 3.1",
    check: "subSubIdSameUser",
    fail: "informational",
    summary: "When both sub and sub_id are present, they MUST identify the same End-User; the engine flags the pair for confirmation.",
  },
  {
    id: "semantics-sub-uniqueness",
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
    family: "semantics",
    keyword: "MUST",
    cite: "Section 6.1",
    check: "requirement",
    params: {
      requirement:
        "When the issuer is multi-tenant the ID-JAG MUST include the tenant claim, and the RAS MUST reject the ID-JAG with invalid_grant unless it trusts iss and tenant together; the engine does not know whether an issuer is multi-tenant, so this needs deployment input.",
    },
    fail: "external",
    summary: "A multi-tenant issuer MUST include the tenant claim, and the RAS MUST trust iss and tenant together; needs deployment input.",
  },
  {
    id: "semantics-client-id-cimd",
    revision: "-05",
    family: "semantics",
    keyword: "MAY",
    cite: "Section 5.1",
    check: "clientIdUrl",
    fail: "informational",
    summary:
      "The client_id relationship may be mapped out of band; when clients use Client-ID Metadata Documents the URL client_id acts as a shared global namespace and removes the mapping.",
  },

  // SAML NameID sub_id (Sections 3.2.1, 3.2.2)
  {
    id: "subid-format",
    revision: "-05",
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
    id: "subid-transient-nameid",
    revision: "-05",
    family: "subid",
    keyword: "MUST NOT",
    cite: "Section 3.2.2",
    check: "subIdTransient",
    params: { forbidden: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" },
    fail: "invalid_grant",
    summary:
      "Transient SAML NameID Formats (such as urn:oasis:names:tc:SAML:2.0:nameid-format:transient) MUST NOT be used: their values change across sessions and cannot serve as a cross-trust-domain identifier.",
  },
  {
    id: "subid-nameid-only",
    revision: "-05",
    family: "subid",
    keyword: "MUST NOT",
    cite: "Section 3.2.2",
    check: "subIdScope",
    params: { requireAny: ["name_qualifier", "sp_name_qualifier"] },
    fail: "invalid_grant",
    summary:
      "The RAS MUST NOT resolve the subject using only the nameid value unless local policy defines nameid alone as the subject identifier for that SAML issuer; a nameid without scoping members is the resolution trap.",
  },
  {
    id: "subid-pairwise-mapping",
    revision: "-05",
    family: "subid",
    keyword: "MUST",
    cite: "Section 3.2.2",
    check: "requirement",
    params: {
      requirement:
        "When pairwise NameIDs are issued, the nameid MUST be the value the IdP would issue to the SAML Service Provider corresponding to the target Resource Authorization Server, the IdP MUST maintain the client_id-to-SP-entity-ID mapping, and it MUST NOT assume a nameid identifies the same End-User across Service Providers without the qualifying scope members; deciding this needs IdP-side SSO state.",
    },
    fail: "external",
    summary: "Pairwise nameid values MUST be scoped to the Service Provider of the target RAS, with the mapping maintained; needs IdP-side state.",
  },
  {
    id: "subid-construction",
    revision: "-05",
    family: "subid",
    keyword: "MUST",
    cite: "Section 3.2.2",
    check: "requirement",
    params: {
      requirement:
        "The SAML NameID sub_id MUST be derived from the SAML Assertion Subject <NameID> the IdP would use for SSO to the target RAS (or an equivalent configured mapping), each optional field MUST be included exactly when the corresponding attribute is present, and the sub_id MUST identify the same subject as sub; verifying this needs IdP-side SSO state.",
    },
    fail: "external",
    summary: "sub_id members MUST derive from the SSO <NameID> for that RAS, with optional fields present exactly when the attributes are; needs IdP-side state.",
  },
  {
    id: "subid-required-policy",
    revision: "-05",
    family: "subid",
    keyword: "MUST",
    cite: "Section 3.2.2",
    check: "requirement",
    params: {
      requirement:
        "If the RAS requires a SAML NameID Subject Identifier for subject resolution, it MUST reject the token request with invalid_grant when the ID-JAG lacks a sub_id using that format, when the claim is malformed or unsupported, or when it is not authorized by local policy for the issuer; whether sub_id is required is RAS-local policy the engine does not take in v1.",
    },
    fail: "external",
    summary: "A RAS requiring the SAML NameID sub_id MUST reject with invalid_grant when it is missing, malformed, or unauthorized; policy input decides.",
  },

  // Metadata (Sections 7.1, 7.2, 8)
  {
    id: "metadata-idp-token-type",
    revision: "-05",
    family: "metadata",
    keyword: "SHOULD",
    cite: "Section 7.1",
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
    id: "metadata-idp-signing-alg",
    revision: "-05",
    family: "metadata",
    keyword: "MUST",
    cite: "Section 7.1",
    check: "metadataAlgIncludes",
    params: { member: "id_jag_signing_alg_values_supported", alg: "RS256", kinds: ["idp"] },
    fail: "invalid_grant",
    summary: "id_jag_signing_alg_values_supported, when present, MUST include RS256.",
  },
  {
    id: "metadata-grant-profiles-shape",
    revision: "-05",
    family: "metadata",
    keyword: "MUST",
    cite: "Sections 7.2 and 8",
    check: "metadataStringArray",
    params: { member: "authorization_grant_profiles_supported", kinds: ["ras", "client"] },
    fail: "invalid_grant",
    summary: "authorization_grant_profiles_supported MUST be a JSON array of strings, each naming a supported grant profile.",
  },
  {
    id: "metadata-ras-profile",
    revision: "-05",
    family: "metadata",
    keyword: "SHOULD",
    cite: "Section 7.2",
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
    revision: "-05",
    family: "metadata",
    keyword: "MUST",
    cite: "Section 7.2",
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
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
    family: "mint",
    keyword: "REQUIRED",
    cite: "Section 4.3",
    check: "requirement",
    params: {
      requirement:
        "The Token Exchange request REQUIRED audience identifies the Resource Authorization Server (exactly one value; implementation-specific URNs MAY be resolved by the IdP); the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "audience is REQUIRED and must carry exactly one Resource Authorization Server identifier.",
  },
  {
    id: "mint-subject-token",
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
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
    revision: "-05",
    family: "mint",
    keyword: "MUST",
    cite: "Section 4.3.3",
    check: "requirement",
    params: {
      requirement:
        "A refresh-token subject token MUST be validated the same way as a standard refresh_token grant (issued by the IdP, bound to the authenticated client, unexpired, not revoked); the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "Refresh-token subject tokens get standard refresh-grant validation at the IdP.",
  },
  {
    id: "mint-refresh-assembly",
    revision: "-05",
    family: "mint",
    keyword: "SHOULD",
    cite: "Section 4.3.3",
    check: "requirement",
    params: {
      requirement:
        "When a refresh token is the subject token, the IdP SHOULD assemble the subject's claims the way it would for a new Identity Assertion, so the ID-JAG reflects current subject attributes and policy; the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "A refresh-token exchange SHOULD re-assemble current subject claims for the issued ID-JAG.",
  },
  {
    id: "mint-granted-values",
    revision: "-05",
    family: "mint",
    keyword: "MUST",
    cite: "Section 4.3.3",
    check: "requirement",
    params: {
      requirement:
        "The IdP MUST include the granted resource, scope, and authorization_details values in the issued ID-JAG, each granted resource identifier exactly as the client sent it; the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "Granted resource, scope, and authorization_details values MUST be reflected in the issued ID-JAG.",
  },
  {
    id: "mint-policy-narrowing",
    revision: "-05",
    family: "mint",
    keyword: "MAY",
    cite: "Section 4.3.3",
    check: "requirement",
    params: {
      requirement:
        "The IdP MAY grant a subset of the requested resources or scopes, and MAY modify, filter, or omit authorization details based on policy; the engine does not see the exchange request.",
    },
    fail: "external",
    summary: "The IdP MAY narrow requested resources, scopes, or authorization details by policy.",
  },
  {
    id: "mint-actor-token",
    revision: "-05",
    family: "mint",
    keyword: "OPTIONAL",
    cite: "Section 4.3",
    check: "requirement",
    params: {
      requirement:
        "actor_token is OPTIONAL and its processing is outside the scope of this specification; future profiles MAY define validation and whether an act claim results; the engine never renders a verdict on it.",
    },
    fail: "external",
    summary: "actor_token is OPTIONAL; its processing is out of scope for this specification.",
  },

  // RAS rejection behaviors (RFC 7521 Section 5.2; Sections 4.4.1, 4.4.3, 4.4.4)
  {
    id: "rejection-not-expired",
    revision: "-05",
    family: "rejection",
    keyword: "MUST",
    cite: "RFC 7521 Section 5.2",
    check: "notExpired",
    fail: "invalid_grant",
    summary: "An expired assertion MUST be rejected with invalid_grant (RFC 7521 Section 5.2).",
  },
  {
    id: "rejection-error-mapping",
    revision: "-05",
    family: "rejection",
    keyword: "MUST",
    cite: "Section 4.4.3",
    check: "requirement",
    params: {
      requirement:
        "The RAS profiles two error codes: invalid_grant when the ID-JAG fails a validation rule (signature, aud, client_id, exp, typ, decryption, or cnf binding), and access_denied when the ID-JAG is valid but the End-User or Client is not authorized; deciding which needs RAS-side entitlement state.",
    },
    fail: "external",
    summary: "Validation failures map to invalid_grant; authorization denials map to access_denied.",
  },
  {
    id: "rejection-no-refresh-token",
    revision: "-05",
    family: "rejection",
    keyword: "SHOULD NOT",
    cite: "Section 4.4.4",
    check: "requirement",
    params: {
      requirement:
        "The RAS SHOULD NOT return a refresh token when an ID-JAG is exchanged for an access token; the ID-JAG replaces the refresh token, and clients MAY re-submit it until it expires; the engine does not see the token response.",
    },
    fail: "external",
    summary: "The RAS SHOULD NOT return a refresh token on an ID-JAG exchange; the ID-JAG itself is re-submittable.",
  },
  {
    id: "rejection-jti-single-use",
    revision: "-05",
    family: "rejection",
    keyword: "MAY",
    cite: "Section 4.4.4",
    check: "requirement",
    params: {
      requirement:
        "The RAS MAY accept each ID-JAG only once by tracking its jti, and MAY reject an ID-JAG whose exp exceeds its policy; replay tracking is RAS-side state the engine does not take in v1.",
    },
    fail: "external",
    summary: "The RAS MAY enforce single use by tracking jti and MAY cap exp by policy; replay tracking needs RAS-side state.",
  },
];
