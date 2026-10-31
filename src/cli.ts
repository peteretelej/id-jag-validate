#!/usr/bin/env node
// CLI over the validation engine. node:util.parseArgs only - the package
// keeps zero runtime dependencies.
import { parseArgs } from "node:util";
import { defaultRevision } from "./rules/index.js";
import { validateMetadata, validateToken } from "./validate.js";
import type { Revision, ValidationContext, Verdict, VerdictStatus } from "./types.js";

const USAGE = `id-jag-validate - rule-by-rule ID-JAG validation with draft section citations

Usage:
  id-jag-validate validate [options] [<token>]

  Pass the compact-serialized ID-JAG as an argument, or pipe it through
  stdin (pass "-" to read stdin explicitly). With --metadata the input is
  an AS metadata document instead of a JWT, validated as a Resource
  Authorization Server advertisement.

Options:
  --json              Print machine-readable JSON (the full validation result)
  --revision <rev>    Draft ruleset to validate against: -04 or -05
                      (default: ${defaultRevision}). Dash-leading values require
                      equals syntax: --revision=-04
  --metadata          Treat the input as an AS metadata document (JSON)
  --issuer <url>      Expected issuer (trusted IdP for iss)
  --audience <url>    Expected Resource Authorization Server audience (aud)
  --client-id <id>    Expected authenticated client (client_id)
  --now <iso>         Evaluation time as an ISO 8601 timestamp (default: now)
  -h, --help          Show this help

Exit codes:
  0  evaluated, no rejection-grade failures
  1  one or more invalid_grant-grade rule failures, or a rule the engine
     could not evaluate (error)
  2  usage, parse, or unreadable-input error`;

const TAGS: Record<VerdictStatus, string> = {
  pass: "pass",
  invalid_grant: "FAIL",
  informational: "info",
  external: "external",
  error: "error",
};

function renderVerdict(verdict: Verdict): string {
  return `${verdict.keyword.padEnd(11)} ${verdict.cite.padEnd(6)} ${TAGS[verdict.status].padEnd(8)} ${verdict.message}`;
}

// Exit 0 must mean "evaluated, no rejection-grade failures": a verdict the
// engine could not produce (error) counts as failure-grade for CI gating.
function exitCode(verdicts: Verdict[]): number {
  return verdicts.some((v) => v.status === "invalid_grant" || v.status === "error") ? 1 : 0;
}

async function readStdin(): Promise<string> {
  let text = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) text += String(chunk);
  return text;
}

function usageError(message: string): number {
  console.error(`id-jag-validate: ${message}\n\n${USAGE}`);
  return 2;
}

async function main(): Promise<number> {
  let values: {
    json: boolean;
    metadata: boolean;
    revision?: string;
    issuer?: string;
    audience?: string;
    "client-id"?: string;
    now?: string;
    help: boolean;
  };
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: process.argv.slice(2),
      options: {
        json: { type: "boolean", default: false },
        metadata: { type: "boolean", default: false },
        revision: { type: "string" },
        issuer: { type: "string" },
        audience: { type: "string" },
        "client-id": { type: "string" },
        now: { type: "string" },
        help: { type: "boolean", short: "h", default: false },
      },
      allowPositionals: true,
    }));
  } catch (err) {
    return usageError(err instanceof Error ? err.message : "invalid arguments");
  }

  if (values.help) {
    console.log(USAGE);
    return 0;
  }

  const [subcommand, tokenArg] = positionals;
  if (subcommand !== "validate") {
    return usageError(`expected the "validate" subcommand; got ${JSON.stringify(subcommand ?? null)}`);
  }

  const revision = (values.revision ?? defaultRevision) as Revision;
  if (revision !== "-04" && revision !== "-05") {
    return usageError(`unknown revision ${JSON.stringify(revision)}; available: -04, -05 (dash-leading values need equals syntax: --revision=-04)`);
  }

  let now: number | undefined;
  if (values.now !== undefined) {
    const ms = Date.parse(values.now);
    if (Number.isNaN(ms)) {
      return usageError(`--now must be an ISO 8601 timestamp; got ${JSON.stringify(values.now)}`);
    }
    now = Math.floor(ms / 1000);
  }

  let input = tokenArg;
  if (!input || input === "-") {
    if (process.stdin.isTTY) {
      return usageError("no input; pass a token (or a JSON document with --metadata) as an argument, or pipe it through stdin");
    }
    input = (await readStdin()).trim();
  }
  if (!input) {
    return usageError("input is empty");
  }

  const context: ValidationContext = {
    revision,
    ...(values.issuer !== undefined && { expectedIssuer: values.issuer }),
    ...(values.audience !== undefined && { expectedAudience: values.audience }),
    ...(values["client-id"] !== undefined && { expectedClientId: values["client-id"] }),
    ...(now !== undefined && { now }),
  };

  if (values.metadata) {
    let document: unknown;
    try {
      document = JSON.parse(input);
    } catch (err) {
      return usageError(`input is not valid JSON: ${err instanceof Error ? err.message : "parse failed"}`);
    }
    if (typeof document !== "object" || document === null || Array.isArray(document)) {
      return usageError("a metadata document must be a JSON object");
    }
    const result = await validateMetadata(document as Record<string, unknown>, context);
    if (values.json) console.log(JSON.stringify(result, null, 2));
    else for (const verdict of result.verdicts) console.log(renderVerdict(verdict));
    return exitCode(result.verdicts);
  }

  const result = await validateToken(input, context);
  if (values.json) {
    console.log(JSON.stringify(result, null, 2));
  } else if (result.parseError) {
    return usageError(result.parseError);
  } else {
    for (const verdict of result.verdicts) console.log(renderVerdict(verdict));
  }
  return result.parseError ? 2 : exitCode(result.verdicts);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error(err instanceof Error ? (err.stack ?? err.message) : err);
    process.exitCode = 2;
  },
);
