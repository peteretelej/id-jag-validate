import { describe, expect, it } from "vitest";
import { metadataNegative, metadataPositive } from "../src/fixtures.js";
import { validateMetadata } from "../src/validate.js";

const invalidGrants = (verdicts: Awaited<ReturnType<typeof validateMetadata>>["verdicts"]) =>
  verdicts.filter((verdict) => verdict.status === "invalid_grant");

describe("metadata checks", () => {
  it("the coupling negative fails exactly the coupling rule", async () => {
    const result = await validateMetadata(metadataNegative.document, { kind: metadataNegative.kind });
    expect(invalidGrants(result.verdicts).map((verdict) => verdict.ruleId)).toEqual([
      metadataNegative.targetRuleId,
    ]);
    const coupling = invalidGrants(result.verdicts)[0]!;
    expect(coupling.cite).toBeTruthy();
    expect(coupling.message).toMatch(/jwt-bearer/);
  });

  it("a well-formed RAS advertisement passes", async () => {
    const result = await validateMetadata(metadataPositive.document, { kind: metadataPositive.kind });
    expect(result.verdicts.length).toBeGreaterThan(0);
    expect(result.verdicts.filter((verdict) => verdict.status === "error")).toEqual([]);
    expect(invalidGrants(result.verdicts)).toEqual([]);
  });

  it("a client advertising the profile must include both grant type URNs", async () => {
    const result = await validateMetadata(
      {
        authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"],
        grant_types: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
      },
      { kind: "client" },
    );
    expect(invalidGrants(result.verdicts).map((verdict) => verdict.ruleId)).toEqual(["metadata-client-grant-types"]);
  });

  it("a non-array authorization_grant_profiles_supported fails the shape rule", async () => {
    const result = await validateMetadata(
      {
        authorization_grant_profiles_supported: "urn:ietf:params:oauth:grant-profile:id-jag",
        grant_types_supported: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
      },
      { kind: "ras" },
    );
    expect(invalidGrants(result.verdicts).map((verdict) => verdict.ruleId)).toEqual(["metadata-grant-profiles-shape"]);
  });

  it("id_jag_signing_alg_values_supported must include RS256 when advertised", async () => {
    const result = await validateMetadata(
      {
        identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"],
        id_jag_signing_alg_values_supported: ["ES256"],
      },
      { kind: "idp" },
    );
    expect(invalidGrants(result.verdicts).map((verdict) => verdict.ruleId)).toEqual(["metadata-idp-signing-alg"]);
  });
});
