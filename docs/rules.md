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

No rules are defined yet.
