# Architecture

ssotrace is a pipeline. Each stage is one package under `internal/`, and data flows in one direction.

```
HAR file → har.Load (bounded) → flow.Build (correlate) → diagnose.Run (rules) → report.Render (text|json|md)
                                                     ↘ redact.Apply → redact.Scan (verify) → write 0600
```

## Packages

| Package | Responsibility |
|---------|----------------|
| `cmd/ssotrace` | Process entry point: wires arguments, output streams, version stamps, and the exit code to `internal/cli`. |
| `internal/cli` | Parses subcommands and flags and maps results to exit codes (`0` no failures, `1` failures found, `2` usage or input error). |
| `internal/har` | HAR 1.2 types and a loader that enforces size limits on untrusted input. |
| `internal/saml` | Decodes SAML messages from the POST and Redirect bindings, models them, and verifies signatures. |
| `internal/oidc` | Parses OAuth 2.0 and OpenID Connect requests, callbacks, and tokens. |
| `internal/flow` | Correlates HAR entries into SSO flows, pairing each request with its response. |
| `internal/diagnose` | The rule engine: severities, findings, the `Rule` interface, and the rule registry. |
| `internal/redact` | Removes credentials from a HAR with SSO-aware rules, then scans the result for leaks. |
| `internal/report` | Renders findings as text, JSON, or Markdown. |
| `internal/kb` | Maps vendor error codes to plain-English causes and fixes, from data embedded in the binary. |
| `internal/secret` | Produces safe previews (short prefix plus length) of secret values for display. |

## Boundaries

- **Rules are pure.** A rule reads the parsed flow and a reference time from its `Context` and returns findings. Rules do no I/O and never read the system clock, so a given HAR always produces the same diagnosis.
- **Secrets cross into output only through `internal/secret`.** Evidence values are made display-safe before they reach a renderer.
- **Redaction verifies itself.** `redact.Apply` output always goes through `redact.Scan`; if the scan finds a leak, nothing is written.
- **Nothing is public API.** Everything lives under `internal/`, so package boundaries can change without breaking anyone.
