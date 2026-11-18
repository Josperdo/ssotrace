# Architecture

ssotrace is a pipeline. Each stage is one package under `internal/`, and data flows in one direction.

```
HAR file → har.Load (bounded) → flow.TraceSAML + flow.TraceOIDC (decode + correlate) → diagnose.Run (rules) → report.Render (text|json|md)
                                                     ↘|json|md)
                                                     ↘ redact.Apply → redact.Scan (verify) → write 0600
```

## Packages

| Package | Responsibility |
|---------|----------------|
| `cmd/ssotrace` | Process entry point: wires arguments, output streams, version stamps, and the exit code to `internal/cli`. |
| `internal/cli` | Parses subcommands and flags and maps results to exit codes (`0` no failures, `1` failures found, `2` usage or input error). |
| `internal/har` | HAR 1.2 types, a streaming loader that enforces size limits on untrusted input, and header, query, and form lookups that smooth over differences between browser exports. |
| `internal/saml` | Decodes SAML messages from the POST and Redirect bindings (with an inflate cap), parses them with a depth limit and no DOCTYPE, models AuthnRequests and Responses, and verifies enveloped signatures. Signed content is read only from the element the validator returns. |
| `internal/oidc` | Models OAuth/OIDC authorization requests, callbacks, and token calls, and decodes JWTs (header and the registered/OIDC claims) with the standard library only, without verifying them. Codes, `state`, `nonce`, and tokens are kept for comparison but serialized only as previews or presence flags. |
| `internal/flow` | Recognizes which HAR entries carry SAML or OAuth/OIDC messages and records where and when each was sent. Pairs SAML AuthnRequests with Responses by `InResponseTo`, and OAuth/OIDC authorization requests with callbacks by `state` (falling back to `redirect_uri`) and callbacks with token calls by authorization code. Fragment callbacks are read from the redirect that carried them. |
| `internal/diagnose` | The rule engine: severities, findings, the `Rule` interface, and the rule registry. |
| `internal/redact` | Builds a shareable copy of a HAR from an allowlist (names kept, secret values removed, SAML identities and OAuth codes, `state`, and `nonce` masked with salted hashes, signatures replaced with a record of their result, token endpoint responses filtered rather than dropped), then proves it clean with the same leak scanner `ssotrace scan` uses. Writes atomically with `0600` permissions and never over the input. |
| `internal/report` | Renders findings and flows. JSON output carries `"schema_version": 1`. |
| `internal/kb` | Placeholder for explanations of vendor error codes. Empty in this version: HAR004 reports the raw codes. |
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
