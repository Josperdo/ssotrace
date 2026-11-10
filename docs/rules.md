# Rules reference

Every finding ssotrace reports comes from a rule. This page lists every rule, what it means, and how to fix the problem it describes.

## Rule IDs

| Prefix | Covers |
|--------|--------|
| `HAR`  | The capture itself: missing traffic, stripped bodies, redirect loops |
| `SAML` | SAML 2.0 requests, responses, assertions, and signatures |
| `OIDC` | OAuth 2.0 and OpenID Connect requests, callbacks, and tokens |

IDs are stable. A rule keeps its ID for life, and a removed rule's ID is never reused, so scripts and saved reports that reference an ID keep meaning the same thing.

## Severity levels

| Severity | Meaning | Affects exit code |
|----------|---------|-------------------|
| `FAIL` | This breaks the login. | Yes: any FAIL makes ssotrace exit `1` |
| `WARN` | Works today but is risky, deprecated, or likely to break. | No |
| `INFO` | Context that helps explain the flow. | No |
| `PASS` | The check ran and found nothing wrong. | No |

## Entry template

```
### SAML000 — Title
Severity: FAIL | WARN | INFO
What it means:
Common causes:
How to fix:
```

## Rules

### HAR001 — No SSO traffic found
Severity: FAIL

What it means:
None of the requests in the file carries a SAML message (`SAMLRequest`, `SAMLResponse`, or `SAMLart`) or an OAuth/OIDC authorization request, callback, or token request. Without that traffic there is nothing to diagnose.

Common causes:
- "Preserve log" was off, so the browser cleared the Network tab on one of the redirects between the application and the identity provider.
- Recording started after the sign-in had already happened.
- The file was captured on the wrong tab or window.

How to fix:
Capture again. Open the browser's developer tools, go to the Network tab, and turn on "Preserve log" (Firefox: "Persist Logs") before starting. Start the sign-in from the beginning, ideally in a private window, and export the HAR once the error appears.

### HAR002 — Request bodies missing
Severity: WARN

What it means:
One or more requests report sending a body (`bodySize` greater than 0), but the HAR does not contain it. SAML responses, OIDC `form_post` callbacks, and token requests travel in request bodies, so ssotrace cannot check them.

Common causes:
- The file was run through a HAR sanitizer or other redaction tool that removed request content.
- The browser did not record request content for those requests.

How to fix:
Export the HAR again directly from the browser's developer tools and run ssotrace on that original file. To share it safely afterwards, use `ssotrace redact`, which keeps the SSO messages needed for diagnosis.
