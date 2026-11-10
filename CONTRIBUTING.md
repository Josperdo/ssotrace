# Contributing to ssotrace

Thanks for helping. Please read [SECURITY.md](SECURITY.md) first: this tool handles files full of credentials, and that shapes most of the rules below.

## Development setup

You need:

- **Go**, at the version in `go.mod`
- **golangci-lint** v2: `brew install golangci-lint`
- **govulncheck**: `go install golang.org/x/vuln/cmd/govulncheck@latest`
- **Docker** with Compose, only if you use the local Keycloak lab (see [`lab/README.md`](lab/README.md))

Then install the git hooks:

```sh
make hooks
```

The pre-commit hook refuses to commit HAR files outside `testdata/` and lab credentials.

## Before opening a pull request

```sh
make check
```

This formats, vets, lints, runs tests with the race detector, and checks for known vulnerabilities. CI runs the same steps.

New behavior needs tests, including at least one passing and one failing case.

## Test fixtures

Fixtures must be synthetic. No real HAR files, tokens, emails, or tenant IDs, ever. See [`testdata/README.md`](testdata/README.md) for the full rules.

## Rule IDs

Rules are identified as `HAR001`, `SAML001`, `OIDC001`, and so on.

- IDs are stable and are **never reused**, even after a rule is removed.
- Every rule has an entry in [`docs/rules.md`](docs/rules.md), using the template there.
- Every rule ships with at least one passing and one failing fixture.

## Dependencies

ssotrace uses the Go standard library wherever it can, which keeps the binary small and the supply chain short. **Do not add a new dependency without discussing it in an issue first.** Explain what it does and why the standard library isn't enough.

## Reporting security issues

Do not open a public issue. Use private reporting as described in [SECURITY.md](SECURITY.md).
