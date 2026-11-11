# testdata

Test fixtures and golden files. Everything here is public, so everything here must be **synthetic**.

## Fixture rules

- **Generated keys and certificates only.** Create throwaway keys for tests; never copy a key or certificate from a real identity provider.
- **Reserved domains only:** `example.com`, `example.org`, `example.net`, and their subdomains.
- **Fake identifiers.** GUIDs, tenant IDs, and client IDs must be obviously fake (for example `00000000-0000-0000-0000-000000000001`).
- **No real tokens, cookies, or emails.** Use addresses like `alice@example.com`.
- **No real HAR files**, not even from the local lab. Captures stay in `lab/captures/` (gitignored).

If you need a fixture that resembles a real capture, rebuild it by hand or in code with synthetic values. Do not edit a real capture down.

For SAML fixtures, prefer generating them in the test with `internal/testutil` (for example `testutil.NewSAMLLogin`). It creates a fresh key and certificate each run, so there is no key material to commit.

## Golden files

Expected rendered output lives in `testdata/golden/`. Regenerate it after an intentional output change with:

```sh
go test ./... -update
```

Review the diff before committing: a golden file change is a user-visible output change.
