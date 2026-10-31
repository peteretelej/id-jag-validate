# id-jag-validate

Validation for OAuth ID-JAG (Identity and Authorization Assertion
Grant) tokens per `draft-ietf-oauth-id-jag`: rule-by-rule verdicts
with section citations, usable as a library and from the CLI.

**Work in progress.** This package reserves the npm name. The 0.0.1
line carries the isomorphic validation engine: rule descriptors for
draft revisions -04 and -05 with `getRuleset`, RS256/ES256 WebCrypto
verify and mint, `validateToken` and `validateMetadata`, and the
committed fixture set - proven by vitest suites in node and browser
mode. The CLI and the published package are still ahead; do not
depend on it yet.
