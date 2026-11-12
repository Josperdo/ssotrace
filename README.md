# ssotrace

[![CI](https://github.com/Josperdo/ssotrace/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Josperdo/ssotrace/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/Josperdo/ssotrace)](https://github.com/Josperdo/ssotrace/commits/main)

Diagnose failed SSO logins from a HAR file, and redact it so it's safe to share.

Status: pre-release, under active development.

> [!CAUTION]
> **HAR files contain live session tokens.** A browser HAR export includes cookies, bearer tokens, SAML assertions, and OAuth codes that can let someone sign in as you. Never share one unredacted.

## Build from source

Requires Go (see `go.mod` for the version) and `make`.

```sh
git clone https://github.com/Josperdo/ssotrace.git
cd ssotrace
make build
./bin/ssotrace version
```

The result is a single static binary with no runtime dependencies.

## Usage

```
ssotrace diagnose <file.har> [--format text|json|markdown] [--no-color] [--max-size SIZE]
                  [--clock-skew DURATION] [--idp-cert FILE] [--sp-entity-id ID]
ssotrace redact   <file.har> -o <out.har> [--force] [--keep-bodies] [--max-size SIZE]
ssotrace scan     <file.har> [--format text|json] [--no-color] [--max-size SIZE]
ssotrace version
ssotrace help
```

HAR files larger than 256 MiB are refused by default. Raise the limit with `--max-size`, for example `--max-size 1GiB`.

Time checks allow 3 minutes of clock difference between the identity provider and the service provider, a common SP default. Match your SP with `--clock-skew`, for example `--clock-skew 5m`, or use `--clock-skew 0` for a strict check.

By default a valid signature proves only that a message was not altered after signing. To check who signed it, pass the IdP's signing certificate with `--idp-cert idp.pem`, taken from the IdP's metadata or admin console. A PEM file with several certificates is accepted, for rollovers. For IdP-initiated logins, where the capture has no request to learn the SP from, pass `--sp-entity-id` so the audience can be checked.

Output is plain text for people by default, grouped by login attempt with problems first. Use `--format markdown` to paste into a ticket, or `--format json` for scripts (it carries `"schema_version": 1` and every check, including passes). Colors are used only on a terminal; `--no-color` or `NO_COLOR=1` turns them off.

### Sharing a HAR safely

`ssotrace scan file.har` lists the secrets in a capture (session cookies, credential headers, tokens and authorization codes, passwords, SAML signatures and user identities, email addresses) without changing it, showing each only as a short preview or a length. It exits `1` if it finds any, so a script can refuse to attach the file.

`ssotrace redact file.har -o file.redacted.har` writes a copy that is safe to share and still diagnoses the same way:

- Cookies and headers keep their names and attributes; their values are removed.
- Token, code, and password parameters are removed; parameters that only describe the request (`client_id`, `scope`, standard `error` values) are kept.
- SAML messages keep issuers, audiences, URLs, times, algorithms, and the signing certificate. Signature and digest values are removed, and user identifiers are replaced with salted hashes, so two messages about the same user still match.
- JWTs keep the claims that explain a rejection (`iss`, `aud`, `exp`, …) and lose the rest and their signature.
- Response bodies are removed, except for any identity provider error codes. Keep them with `--keep-bodies`.
- A summary of the original diagnosis is written into the file's `log.comment`.

Before writing, ssotrace scans its own output; if anything secret-looking remains, it writes nothing. The output is created with `0600` permissions, never overwrites the input, and replaces an existing file only with `--force`. Redaction is careful but not magic: review the output before sharing it.

Exit codes: `0` no failures (or, for `scan`, no secrets) found, `1` at least one failure (or secret) found, `2` usage or input error.

ssotrace works offline. It makes no network requests unless you pass a flag that explicitly says it will, and it sends no telemetry.

## Security

See [SECURITY.md](SECURITY.md) for the security model and how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
