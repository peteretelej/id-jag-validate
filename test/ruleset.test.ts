import { describe, expect, it } from "vitest";
import { defaultRevision, getRuleset } from "../src/rules/index.js";

const REVISIONS = ["-04", "-05"] as const;

describe("ruleset registry", () => {
  it("exposes both rulesets with revision-consistent, fully-cited descriptors", () => {
    for (const revision of REVISIONS) {
      const rules = getRuleset(revision);
      expect(rules.length).toBeGreaterThan(0);
      for (const rule of rules) {
        expect(rule.revision, rule.id).toBe(revision);
        expect(rule.keyword, rule.id).toBeTruthy();
        expect(rule.cite, rule.id).toBeTruthy();
        expect(rule.summary, rule.id).toBeTruthy();
        expect(rule.fail, rule.id).toBeTruthy();
      }
    }
  });

  it("defaults to -05", () => {
    expect(defaultRevision).toBe("-05");
  });

  it("throws on an unknown revision", () => {
    expect(() => getRuleset("-03" as never)).toThrow(/Unknown revision/);
  });

  it("sampled -05 descriptors match the fetched -05 text (keyword + cite)", () => {
    const byId = new Map(getRuleset("-05").map((rule) => [rule.id, rule]));
    expect(byId.get("structure-typ")).toMatchObject({ keyword: "MUST", cite: "Section 3.1" });
    expect(byId.get("claims-required")).toMatchObject({ keyword: "REQUIRED", cite: "Section 3.1" });
    expect(byId.get("subid-format")).toMatchObject({ keyword: "MUST", cite: "Section 3.2.1" });
    expect(byId.get("subid-transient-nameid")).toMatchObject({ keyword: "MUST NOT", cite: "Section 3.2.2" });
    expect(byId.get("metadata-ras-coupling")).toMatchObject({ keyword: "MUST", cite: "Section 7.2" });
    expect(byId.get("rejection-not-expired")).toMatchObject({ keyword: "MUST", cite: "RFC 7521 Section 5.2" });
  });

  it("keeps the -05 additions out of -04", () => {
    const ids04 = new Set(getRuleset("-04").map((rule) => rule.id));
    for (const added of [
      "subid-transient-nameid",
      "subid-pairwise-mapping",
      "metadata-idp-signing-alg",
      "rejection-error-mapping",
      "rejection-no-refresh-token",
      "rejection-jti-single-use",
    ]) {
      expect(ids04.has(added)).toBe(false);
      expect(getRuleset("-05").some((rule) => rule.id === added), added).toBe(true);
    }
  });
});
