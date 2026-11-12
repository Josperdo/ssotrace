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
ssotrace redact   <file.har> -o <out.har> [--max-size SIZE]
ssotrace scan     <file.har> [--max-size SIZE]
ssotrace version
ssotrace help
```

HAR files larger than 256 MiB are refused by default. Raise the limit with `--max-size`, for example `--max-size 1GiB`.

Time checks allow 3 minutes of clock difference between the identity provider and the service provider, a common SP default. Match your SP with `--clock-skew`, for example `--clock-skew 5m`, or use `--clock-skew 0` for a strict check.

By default a valid signature proves only that a message was not altered after signing. To check who signed it, pass the IdP's signing certificate with `--idp-cert idp.pem`, taken from the IdP's metadata or admin console. A PEM file with several certificates is accepted, for rollovers. For IdP-initiated logins, where the capture has no request to learn the SP from, pass `--sp-entity-id` so the audience can be checked.

Exit codes: `0` no failures found, `1` at least one failure found, `2` usage or input error.

ssotrace works offline. It makes no network requests unless you pass a flag that explicitly says it will, and it sends no telemetry.

## Security

See [SECURITY.md](SECURITY.md) for the security model and how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
