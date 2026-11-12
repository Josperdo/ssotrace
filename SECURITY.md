# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security tab → Report a vulnerability**. Do not open a public issue.

- You should receive an acknowledgement within 7 days.
- ssotrace is maintained by one person in their spare time. Confirmed security issues are prioritized over all feature work.
- **Never attach a real HAR file to a report.** Reproduce the issue with a synthetic or redacted file.

## Supported versions

Only the latest release receives security fixes.

## Security model

HAR files routinely contain live credentials: session cookies, bearer tokens, SAML assertions, and OAuth authorization codes. ssotrace assumes every input file is sensitive and potentially hostile.

### What ssotrace is designed to guarantee

- **Offline by default.** ssotrace makes no network requests unless you pass an explicit flag that says it will.
- **No telemetry.** Nothing about you or your files leaves your machine.
- **Secrets are never printed in full.** Diagnostic output shows a short preview and length, never a complete token, cookie, or signature.
- **Redaction fails closed.** Values that might be credentials are removed when in doubt. Redacted output is re-scanned for leaks before it is written; if the scan finds anything, no file is written.
- **Bounded input.** File size, decompressed payload size, and XML depth are capped to resist resource-exhaustion attacks from crafted files.
- **Safe file handling.** Output files are created with owner-only permissions (`0600`) and written atomically, so a failed run never leaves a partial file. The input file is never modified or overwritten, including through a symlink or hard link, and an existing output file is replaced only with `--force`.
- **Untrusted text is shown inert.** Text copied from a HAR into a report has control characters and Unicode direction overrides replaced, so a crafted file cannot inject terminal escape sequences or disguise text. Markdown output shows such values as code, so they cannot become links or HTML.
- **Masked identifiers cannot be reversed.** User identifiers are replaced with salted hashes. The salt is random for each run and never stored, so a masked value cannot be confirmed by hashing guesses. Digest values, which would allow the same kind of guessing, are removed.

### What ssotrace does not guarantee

- **Redaction is best-effort.** Application-specific secrets in unusual fields or formats can be missed. Review redacted output before sharing it.
- **Redaction does not revoke anything.** If an unredacted HAR has already been shared, sign the affected users out and revoke their sessions and tokens at the identity provider.
- **"Signature valid" is not "trusted."** Unless you provide the identity provider's certificate or metadata, a valid signature only proves the message was not altered after signing, not that the expected party signed it.
- **A redacted file's signature results are a record, not proof.** Redaction removes signature values, so they cannot be checked again. The redacted file records whether each signature verified before removal, and ssotrace reports that record as such. Anyone can edit a file; for proof, check the original capture.
- **ssotrace is not a substitute for identity provider logs.** A HAR shows only what passed through the browser.

## Scope

**In scope**
- Secrets leaking through diagnostic output or surviving redaction
- Crashes, hangs, or excessive resource use caused by crafted input files
- Incorrect signature validation results
- Unsafe file creation or path handling

**Out of scope**
- Attacks that require control of the user's local machine
- The `lab/` directory, which is an intentionally insecure local test environment
