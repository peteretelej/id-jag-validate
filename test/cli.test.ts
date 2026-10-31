import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it, describe } from "vitest";
import { negativeTokens, positiveTokens, type TokenFixture } from "../src/fixtures.js";

// The CLI contract is the spawned public bin; these tests exercise it as a
// child process, so they must not run in the browser project (see
// vitest.config.ts, which excludes this file there). Requires `npm run build`.
// The bin lives at dist/src/cli.js: the JSON fixture imports put the emit
// rootDir at the project root.
const CLI = fileURLToPath(new URL("../dist/src/cli.js", import.meta.url));

const positive = positiveTokens.find((f) => f.id === "positive-rs256-example");
const expired = negativeTokens.find((f) => f.id === "expired");
const typWrong = negativeTokens.find((f) => f.id === "typ-wrong");

function assertFixture(fixture: TokenFixture | undefined): TokenFixture {
  if (!fixture) throw new Error("Expected fixture missing from fixtures/tokens.json");
  return fixture;
}

function contextArgs(fixture: TokenFixture): string[] {
  const args: string[] = [];
  const { context } = fixture;
  if (context.expectedIssuer) args.push("--issuer", context.expectedIssuer);
  if (context.expectedAudience) args.push("--audience", context.expectedAudience);
  if (context.expectedClientId) args.push("--client-id", context.expectedClientId);
  if (context.now !== undefined) args.push("--now", new Date(context.now * 1000).toISOString());
  return args;
}

function run(args: string[], input?: string) {
  return spawnSync(process.execPath, [CLI, ...args], { input, encoding: "utf8" });
}

describe("id-jag-validate CLI", () => {
  it("exits 0 on a valid fixture and renders one line per verdict", () => {
    const fixture = assertFixture(positive);
    const result = run(["validate", ...contextArgs(fixture), fixture.token]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/MUST.*pass/);
    const lines = result.stdout.trim().split("\n");
    expect(lines.length).toBeGreaterThan(5);
  });

  it("exits 1 on a rejection-grade fixture piped through stdin", () => {
    const fixture = assertFixture(expired);
    const result = run(["validate", ...contextArgs(fixture), "-"], fixture.token);
    expect(result.status).toBe(1);
    expect(result.stdout).toMatch(/FAIL/);
  });

  it("exits 2 on malformed argv and on empty input", () => {
    const unknownFlag = run(["validate", "--bogus"]);
    expect(unknownFlag.status).toBe(2);
    const noInput = run(["validate"], "");
    expect(noInput.status).toBe(2);
  });

  it("--json emits parseable verdict JSON containing rule id and cite for a failing fixture", () => {
    const fixture = assertFixture(typWrong);
    const result = run(["validate", "--json", fixture.token]);
    expect(result.status).toBe(1);
    const parsed = JSON.parse(result.stdout) as {
      revision: string;
      verdicts: Array<{ ruleId: string; cite: string; status: string }>;
    };
    expect(parsed.revision).toBe("-05");
    expect(Array.isArray(parsed.verdicts)).toBe(true);
    const failing = parsed.verdicts.find((v) => v.status === "invalid_grant");
    expect(failing?.ruleId).toBe("structure-typ");
    expect(typeof failing?.cite).toBe("string");
    expect(failing?.cite.length).toBeGreaterThan(0);
  });

  it("--revision=-04 selects the -04 ruleset", () => {
    const fixture = assertFixture(positive);
    const args = [...contextArgs(fixture)];
    const as04 = run(["validate", "--revision=-04", "--json", ...args, fixture.token]);
    expect(as04.status).toBe(0);
    const defaultRun = run(["validate", "--json", ...args, fixture.token]);
    expect(defaultRun.status).toBe(0);
    const ids04 = (JSON.parse(as04.stdout) as { verdicts: Array<{ ruleId: string }> }).verdicts.map((v) => v.ruleId);
    const idsDefault = (JSON.parse(defaultRun.stdout) as { verdicts: Array<{ ruleId: string }> }).verdicts.map((v) => v.ruleId);
    // rejection-jti-single-use exists only in the -05 ruleset.
    expect(idsDefault).toContain("rejection-jti-single-use");
    expect(ids04).not.toContain("rejection-jti-single-use");
    expect(ids04.length).toBeLessThan(idsDefault.length);
  });
});
