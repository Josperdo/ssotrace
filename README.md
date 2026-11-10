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
ssotrace diagnose <file.har> [--format text|json|markdown] [--no-color]
ssotrace redact   <file.har> -o <out.har>
ssotrace scan     <file.har>
ssotrace version
ssotrace help
```

Exit codes: `0` no failures found, `1` at least one failure found, `2` usage or input error.

ssotrace works offline. It makes no network requests unless you pass a flag that explicitly says it will, and it sends no telemetry.

## Security

See [SECURITY.md](SECURITY.md) for the security model and how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
