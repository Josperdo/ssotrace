# Architecture

ssotrace is a pipeline. Each stage is one package under `internal/`, and data flows in one direction.

```
HAR file → har.Load (bounded) → flow.TraceSAML (decode + correlate) → diagnose.Run (rules) → report.Render (text|json|md)
                                                     ↘ redact.Apply → redact.Scan (verify) → write 0600
```

## Packages

| Package | Responsibility |
|---------|----------------|
| `cmd/ssotrace` | Process entry point: wires arguments, output streams, version stamps, and the exit code to `internal/cli`. |
| `internal/cli` | Parses subcommands and flags and maps results to exit codes (`0` no failures, `1` failures found, `2` usage or input error). |
| `internal/har` | HAR 1.2 types, a streaming loader that enforces size limits on untrusted input, and header, query, and form lookups that smooth over differences between browser exports. |
| `internal/saml` | Decodes SAML messages from the POST and Redirect bindings (with an inflate cap), parses them with a depth limit and no DOCTYPE, models AuthnRequests and Responses, and verifies enveloped signatures. Signed content is read only from the element the validator returns. |
| `internal/oidc` | Parses OAuth 2.0 and OpenID Connect requests, callbacks, and tokens. |
| `internal/flow` | Recognizes which HAR entries carry SAML or OAuth/OIDC messages, records where and when each SAML message was sent, and pairs AuthnRequests with Responses by `InResponseTo`. |
| `internal/diagnose` | The rule engine: severities, findings, the `Rule` interface, and the rule registry. |
| `internal/redact` | Removes credentials from a HAR with SSO-aware rules, then scans the result for leaks. |
| `internal/report` | Renders findings and flows. JSON output carries `"schema_version": 1`. |
| `internal/kb` | Maps vendor error codes to plain-English causes and fixes, from data embedded in the binary. |
| `internal/secret` | Produces safe previews (short prefix plus length) of secret values for display. |
| `internal/testutil` | Test-only. Builds synthetic fixtures at test time: throwaway RSA keys and self-signed certificates, signed SAML Responses, AuthnRequests in the Redirect binding, and HAR entries that carry them. Never linked into the binary. |

## Boundaries

- **Rules are pure.** A rule reads only its `Context` (the loaded HAR) and returns findings. Rules do no I/O and never read the system clock, so a given HAR always produces the same diagnosis.
- **Input is bounded before it is trusted.** `har.Load` rejects oversized files before reading them and counts bytes while decoding. Error messages describe what was wrong without echoing file content.
- **Signature checks are integrity, not trust.** Without a pinned certificate, a valid signature only proves the message was not altered after signing; output says which certificate vouched for it. Certificate validity is judged at the HAR timestamp, not today.
- **Secrets cross into output only through `internal/secret`.** Evidence values are made display-safe before they reach a renderer.
- **Redaction verifies itself.** `redact.Apply` output always goes through `redact.Scan`; if the scan finds a leak, nothing is written.
- **Nothing is public API.** Everything lives under `internal/`, so package boundaries can change without breaking anyone.
- **Fixtures are generated, not captured.** Tests build signed SAML traffic with `internal/testutil`, so no key or real capture is ever committed. The `lab/` environment (its own Go module) produces real captures for manual testing; they stay out of the repository.
