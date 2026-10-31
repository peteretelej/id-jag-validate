# id-jag-validate

Rule-by-rule validation for OAuth **ID-JAG** (Identity Assertion JWT
Authorization Grant) tokens per
`draft-ietf-oauth-identity-assertion-authz-grant`. Every rule returns a
verdict carrying its normative keyword and draft section citation, so a
failure tells you exactly which line of the draft it comes from. Works
as a library and as a CLI.

## What it validates

Version-pinned rule sets for the two current draft revisions:

- `-04`: 40 rules
- `-05`: 46 rules (default)

Token validation covers the structure, claims, semantics, sub_id, and
rejection families; metadata validation covers the AS metadata
families (draft Section 7/8 documents); the mint family describes the
token-exchange request. Signatures verify with RS256 or ES256 through
WebCrypto; `alg` values other than those two are rejected without
attempting crypto.

Verdict statuses:

- `pass`: the rule is satisfied
- `invalid_grant`: rejection-grade failure; the token MUST be rejected
- `informational`: advisory outcome (for example a RECOMMENDED claim that is absent)
- `external`: the rule needs Resource-Server-side or IdP-side state a single
  token cannot carry, so the verdict states the requirement instead
- `error`: the check could not run (for example malformed key material)

## Install

```
npm install id-jag-validate
```

The package is ESM-only with zero runtime dependencies. On Node.js it
needs >= 20.19 (the first LTS line where `require(esm)` works, so both
`import` and `require` load it there); in browsers, load it through a
bundler. All crypto goes through the platform's WebCrypto.

## Library usage

```js
import { validateToken } from "id-jag-validate";

const result = await validateToken(token, {
  revision: "-05",                             // or "-04"
  expectedIssuer: "https://idp.example.com/",  // trusted IdP for iss
  expectedAudience: "https://ras.example.com/",// expected RAS audience
  expectedClientId: "my-client",               // authenticated client
  now: 1760000000,                             // optional Unix seconds; defaults to the host clock
  key: issuerPublicJwk,                        // optional; enables signature verification
});

if (result.parseError) throw new Error(result.parseError);
for (const v of result.verdicts) {
  console.log(`${v.keyword} [${v.cite}] ${v.status}: ${v.message}`);
}
```

Without `key`, the signature rule renders an `external` verdict asking
for the issuer's public JWK; pass the JWK (from a JWKS or your own key
pipeline) to get a real cryptographic decision.

Metadata documents validate the same way, with the document supplied
by you (the engine never fetches):

```js
import { validateMetadata } from "id-jag-validate";

const result = await validateMetadata(document, { revision: "-05" });
```

`validateToken` and `validateMetadata` default `revision` to `-05`.
To select the rules for a revision without validating, use the
rules subpath: `getRuleset("-04")` returns the rule descriptors
(`id`, `keyword`, `cite`, `summary`) for CI reporting or docs
generation. `parseToken(token)` is also exported for inspecting the
decoded header and payload without running validation.

Additional subpath exports: `id-jag-validate/crypto` (verify/sign
helpers), `id-jag-validate/mint` (mint a demo ID-JAG), and
`id-jag-validate/fixtures` (synthetic demo keys and the committed test
fixtures, handy for trying the library end to end).

## CLI usage

```
npx id-jag-validate validate <token> --issuer https://idp.example.com/ \
  --audience https://ras.example.com/ --client-id my-client \
  --now 2026-10-31T00:00:00Z
```

Each rule prints one line: keyword, citation, outcome, and message.
Flags:

| Flag | Meaning |
|------|---------|
| `--json` | Print the full validation result as JSON |
| `--revision <rev>` | Validate against `-04` or `-05` (default `-05`) |
| `--metadata` | Treat the input as an AS metadata document (JSON) instead of a JWT |
| `--issuer <url>` | Expected issuer (`iss`) |
| `--audience <url>` | Expected Resource Authorization Server audience (`aud`) |
| `--client-id <id>` | Expected authenticated client (`client_id`) |
| `--now <iso>` | Evaluation time as an ISO 8601 timestamp |
| `-h, --help` | Show help |

The token can be an argument or piped through stdin (use `-` to read
stdin explicitly). Dash-leading revision values require equals syntax,
because a separate `-04` token would parse as an option:

```
id-jag-validate validate --revision=-04 <token>
```

Validate a metadata document from a file:

```
id-jag-validate validate --metadata < metadata.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No rejection-grade failures |
| `1` | One or more `invalid_grant`-grade rule failures |
| `2` | Usage, parse, or unreadable-input error |

### CI example

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: 24
  - run: npm install id-jag-validate
  - name: Validate the pinned ID-JAG
    run: |
      npx id-jag-validate validate "$(cat id-jag.txt)" \
        --issuer https://idp.example.com/ \
        --audience https://ras.example.com/ \
        --client-id my-client
```

The step fails when the token has rejection-grade failures (exit 1);
input problems surface distinctly as exit 2. Add `--json` and pipe
through `jq` when you need per-rule results in the job summary.

## License

MIT
