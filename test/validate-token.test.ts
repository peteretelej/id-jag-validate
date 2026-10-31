import { describe, expect, it } from "vitest";
import { breakageRecipes } from "../src/breakages.js";
import { demoKeys, negativeTokens, positiveTokens } from "../src/fixtures.js";
import { signCompact } from "../src/crypto.js";
import { getRuleset } from "../src/rules/index.js";
import { parseToken, validateToken } from "../src/validate.js";

const invalidGrants = (verdicts: Awaited<ReturnType<typeof validateToken>>["verdicts"]) =>
  verdicts.filter((verdict) => verdict.status === "invalid_grant");

describe("token validation outcomes", () => {
  it("positive fixtures produce no failing verdict and a verified signature", async () => {
    for (const fixture of positiveTokens) {
      const result = await validateToken(fixture.token, fixture.context);
      expect(result.parseError, fixture.id).toBeUndefined();
      expect(invalidGrants(result.verdicts).map((v) => v.ruleId), fixture.id).toEqual([]);
      expect(
        result.verdicts.filter((v) => v.status === "error").map((v) => v.ruleId),
        fixture.id,
      ).toEqual([]);
      expect(
        result.verdicts.find((v) => v.ruleId === "structure-signature")?.status,
        fixture.id,
      ).toBe("pass");
    }
  });

  it("each negative fixture fails exactly its target rule with invalid_grant and renders its cite", async () => {
    for (const fixture of negativeTokens) {
      const result = await validateToken(fixture.token, fixture.context);
      expect(result.parseError, fixture.id).toBeUndefined();
      const invalid = invalidGrants(result.verdicts);
      expect(invalid.map((v) => v.ruleId), fixture.id).toEqual([fixture.targetRuleId]);
      expect(invalid[0]!.cite, fixture.id).toBeTruthy();
      expect(invalid[0]!.keyword, fixture.id).toBeTruthy();
      expect(invalid[0]!.message, fixture.id).toBeTruthy();
    }
  });

  it("negative fixtures cover the breakage recipes one-to-one and target live rules", () => {
    const tokenRecipes = breakageRecipes.filter((recipe) => recipe.family !== "metadata");
    expect(negativeTokens.map((fixture) => fixture.id).sort()).toEqual(
      tokenRecipes.map((recipe) => recipe.id).sort(),
    );
    for (const recipe of breakageRecipes) {
      expect(getRuleset("-05").some((rule) => rule.id === recipe.targetRuleId), recipe.id).toBe(true);
    }
  });

  it("recipe mutations reproduce the committed negative fixtures", async () => {
    const positive = positiveTokens.find((fixture) => fixture.id === "positive-rs256-example")!;
    const parsed = parseToken(positive.token);
    for (const recipe of breakageRecipes) {
      if (!recipe.mutate) continue;
      const header = { ...parsed.header };
      const payload = structuredClone(parsed.payload);
      recipe.mutate({ header, payload });
      const token = await signCompact(payload, demoKeys.issuer.rs256.privateKey, "RS256", {
        typ: header.typ as string,
      });
      const negative = negativeTokens.find((fixture) => fixture.id === recipe.id);
      expect(negative, recipe.id).toBeDefined();
      const mutated = await validateToken(token, negative!.context);
      const committed = await validateToken(negative!.token, negative!.context);
      expect(invalidGrants(mutated.verdicts).map((v) => v.ruleId), recipe.id).toEqual([recipe.targetRuleId]);
      expect(invalidGrants(committed.verdicts).map((v) => v.ruleId), recipe.id).toEqual([recipe.targetRuleId]);
    }
  });
});
