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

### HAR003 — Redirect loop between the application and the IdP
Severity: FAIL

What it means:
The same sign-in request (a request answered with a redirect, or one carrying a SAML or OAuth message) was made 3 or more times within 30 seconds. The IdP keeps completing the login and the application keeps sending the user back. Requests are compared without their query string, and ordinary page loads and polling are ignored, as are retries spread out over more than 30 seconds.

Common causes:
- The application's session cookie lacks `SameSite=None; Secure` and is dropped on the cross-site POST from the IdP.
- The cookie is marked `Secure` but the site is served over http, or its domain or path does not match.
- The application rejects the login (see other findings) and silently starts a new one.

How to fix:
Check the response to the login callback: it must set the session cookie, and the next request must send it back.

### HAR004 — IdP error code found
Severity: WARN

What it means:
An identity provider's own error code appears in a URL, redirect target, form body, or HTML, JSON, XML, or text response body. ssotrace recognizes Microsoft Entra ID (`AADSTS` plus 5 or 6 digits), AD FS (`MSIS` plus 4 digits), Okta (`E0000` plus 3 digits), and the standard OAuth 2.0 and OpenID Connect `error` values. JavaScript files are not searched, because login pages ship scripts that list every code they might display. Each code is reported once, with where it first appeared.

Common causes:
The IdP refused the login and said why in its own terms.

How to fix:
Look up the code in the identity provider's documentation, or search the IdP's sign-in logs for it at the time of the capture.

### SAML001 — IdP returned an error instead of a login
Severity: FAIL

What it means:
The SAML Response's status is not `Success`, so the IdP did not log the user in. The first-level code says whose side the problem is on (`Requester` = the SP's request, `Responder` = the IdP). The second-level code, when present, says what went wrong. ssotrace explains these second-level codes: `AuthnFailed`, `RequestDenied`, `NoPassive`, `InvalidNameIDPolicy`, `NoAuthnContext`, `UnknownPrincipal`, `UnsupportedBinding`, `RequestUnsupported`, `NoAvailableIDP`, `NoSupportedIDP`, `InvalidAttrNameOrValue`, and the version codes.

Common causes:
- The user is not assigned to the application in the IdP (`RequestDenied`).
- Wrong password, failed MFA, or a locked account (`AuthnFailed`).
- The SP asks for a NameID format or authentication method the IdP does not provide (`InvalidNameIDPolicy`, `NoAuthnContext`).

How to fix:
Follow the fix for the second-level code in the finding. The IdP's sign-in logs for the same user and time usually name the exact reason.

### SAML002 — Assertion audience does not match the SP
Severity: FAIL (INFO when it cannot be checked)

What it means:
The assertion's `Audience` is not the SP's entity ID, so the SP will reject it. ssotrace takes the SP's entity ID from `--sp-entity-id` if you supply it, otherwise from the `Issuer` of the AuthnRequest the Response answers, or, for IdP-initiated logins, from another AuthnRequest in the capture that used the same ACS URL. If there is none, the finding is INFO: the audience is shown but cannot be checked. Pass `--sp-entity-id` to check IdP-initiated logins.

Common causes:
- The IdP application was set up with the wrong Entity ID / Identifier / Audience URI, often an old, staging, or `http` vs `https` value.
- The login went to the wrong application in the IdP (two apps for the same SP).

How to fix:
Set the Audience in the IdP's settings for this application to exactly the SP entity ID shown in the finding.

### SAML003 — Response Destination does not match where it was sent
Severity: FAIL

What it means:
The Response's `Destination` is not the URL the browser actually posted it to. URLs are compared with scheme and host case-insensitive, default ports ignored, and the path exact.

Common causes:
- The SP sits behind a TLS-terminating proxy and advertises its internal `http://` URL.
- The IdP has an old hostname or path for the SP's Assertion Consumer Service.

How to fix:
Set the ACS / Reply URL in the IdP to exactly the URL the browser posted to. If a proxy is involved, configure the SP with its public URL.

### SAML004 — Assertion Recipient does not match where it was sent
Severity: FAIL

What it means:
The bearer `SubjectConfirmationData` `Recipient` inside the assertion is not the URL the browser posted to. Because Recipient is inside the signed assertion, SPs rely on this check even more than on Destination.

Common causes:
Same as SAML003: a wrong ACS URL at the IdP, or a proxy that changes the scheme, host, or port.

How to fix:
Set the ACS / Reply URL in the IdP to exactly the URL the browser posted to.

### SAML005 — Request and response do not pair up
Severity: FAIL, WARN, or INFO depending on the case

What it means:
ssotrace pairs each AuthnRequest with the Response whose `InResponseTo` names its ID. This rule reports when that fails:
- **FAIL:** an AuthnRequest got an HTTP error from the IdP and no Response.
- **WARN:** an AuthnRequest got no Response at all, or a Response answers a request that is not in the capture.
- **INFO:** a Response has no `InResponseTo`, meaning the login was IdP-initiated.

Common causes:
- The IdP rejected the request: the ACS URL is not registered for the application ("invalid redirect URI"), or the SP's entity ID is unknown to the IdP.
- Recording started after the login began, or stopped before it finished.
- The SP lost its session during the cross-site POST back from the IdP (a `SameSite` cookie problem).

How to fix:
For an IdP rejection, check the IdP's logs and the application's registered ACS URLs. Otherwise capture again from the very start with "Preserve log" on.

### SAML006 — Assertion delivered outside its validity window
Severity: FAIL (WARN when within the clock-skew tolerance)

What it means:
The browser delivered the assertion before its `NotBefore` time or after its `NotOnOrAfter` time. ssotrace checks the assertion's `Conditions` and each bearer `SubjectConfirmationData` `NotOnOrAfter`, against the time the browser sent the Response (from the HAR, so from the user's clock). If the assertion is outside the window by less than the clock-skew tolerance (default 3 minutes, set with `--clock-skew`), the finding is a WARN: the SP probably accepts it today, but only just. When the assertion's `IssueInstant` is later than the time the browser sent it, ssotrace reports the minimum clock difference, since an assertion cannot be issued after it was delivered. An unreadable timestamp is a WARN. An assertion whose own timestamps contradict each other (it expires at or before its `IssueInstant` or `NotBefore`) is also a WARN: its validity window is empty, so only clock-skew tolerance lets an SP accept it.

Common causes:
- The IdP's or SP's clock is wrong (no NTP).
- The user waited a long time between the IdP issuing the assertion and the browser posting it.
- The clock on the user's machine is wrong, which shifts every HAR timestamp.

How to fix:
Synchronize the IdP and SP clocks with NTP. If the clocks are right and logins are slow, lengthen the assertion lifetime in the IdP.

### SAML007 — Assertion is not signed
Severity: FAIL

What it means:
Neither the Response nor the assertion carries a signature, so nothing proves the IdP wrote it. Without a signature anyone could forge a login, and SPs reject it.

Common causes:
Signing was turned off in the IdP's settings for the application.

How to fix:
Turn on assertion signing (and optionally Response signing) in the IdP.

### SAML008 — Signature is invalid
Severity: FAIL

What it means:
A signature on the AuthnRequest, Response, or assertion does not verify against the certificate embedded in it: the content changed after signing, or it was signed with a different key. A signature that does verify proves only that the content is unchanged (integrity), not that the signer is the IdP you expect (trust). Certificate expiry is reported separately and does not cause this finding.
A signature that does not embed its certificate is reported as INFO ("could not be checked"), not FAIL: some IdPs leave the certificate out on purpose because the SP already has it.
In a file produced by `ssotrace redact`, signature values have been replaced with a record of whether they verified before removal. A recorded pass counts as a pass, and the finding says it is a record that cannot be re-checked; a recorded failure is still a FAIL.

Common causes:
- A proxy, WAF, or browser extension rewrote the message.
- The HAR was edited or run through a sanitizer.
- The IdP is misconfigured and signs with a key that does not match the certificate it embeds.

How to fix:
Capture again directly from the browser. If it still fails, compare the IdP's current signing certificate with the one in the finding.

### SAML009 — IdP signing certificate expired or expiring
Severity: WARN

What it means:
The certificate embedded in a signature was expired or not yet valid when the message was sent, or expires within 30 days of it. Each certificate is reported once. It is a WARN because SPs differ: many pin the certificate and ignore its dates, while others reject an expired one.

Common causes:
- The IdP's signing certificate reached the end of its life and has not been rolled over.
- A clock on the IdP or the user's machine is wrong (for "not yet valid").

How to fix:
Create the new signing certificate in the IdP and give it, or the IdP's updated metadata, to the SP before switching the IdP over. Many SPs accept two certificates at once, which allows a rollover without downtime.

### SAML010 — Weak signature algorithm
Severity: WARN

What it means:
A signature uses SHA-1 or MD5 for its signature or digest algorithm. These are deprecated, and many SPs reject them.

Common causes:
An old IdP application configuration that still defaults to RSA-SHA1.

How to fix:
Set the signature algorithm to RSA-SHA256 and the digest to SHA-256 in the IdP.

### SAML011 — Assertion is encrypted
Severity: INFO

What it means:
The assertion is encrypted for the SP, so ssotrace cannot read it. It can still check the Response status, Destination, and the Response's own signature, but not the NameID, audience, validity times, or attributes.

Common causes:
Assertion encryption is turned on, which is good practice.

How to fix:
No fix is needed. For a full diagnosis, turn encryption off temporarily in a test environment, or check the SP's logs.

### SAML012 — NameID missing or in the wrong format
Severity: FAIL (format differs) or WARN (missing)

What it means:
The assertion has no `NameID`, or its format differs from the `NameIDPolicy` format the SP requested. A requested format of `unspecified` accepts anything.

Common causes:
- The IdP sends `emailAddress` while the SP asks for `persistent`, or the reverse.
- No NameID source is configured in the IdP application.

How to fix:
Make the IdP's NameID format match the SP's request, or have the SP request the format the IdP sends (or `unspecified`).

### SAML013 — Signed by a different certificate than the one you trust
Severity: FAIL (INFO without `--idp-cert`)

What it means:
With `--idp-cert`, ssotrace compares the SHA-256 fingerprint of every signing certificate in the capture with the certificates you supplied. A mismatch means the message was signed by a certificate you did not say you trust. Without `--idp-cert`, the finding is INFO and says that signatures were checked for integrity only: a valid signature proves the content was not altered, not who signed it.

Common causes:
- The IdP rolled over to a new signing certificate and the SP still has the old one.
- Less often, the message did not come from your IdP.

How to fix:
Get the IdP's current signing certificate from its metadata or admin console, not from the capture. If the signer is the IdP's new certificate, update the SP. During a rollover, pass a PEM file containing both the old and new certificate. If the IdP does not recognize the certificate, treat the message as forged.

### SAML014 — Response contains more than one assertion
Severity: WARN

What it means:
The Response carries more than one assertion, plain or encrypted. IdPs normally send exactly one, and extra assertions are the core of XML signature wrapping attacks. The finding shows how many of the readable assertions a signature covers.

Common causes:
- Something modified the Response in transit.
- Rarely, an IdP or proxy that deliberately sends several assertions.

How to fix:
Treat an unexpected case as suspicious and find where the Response was modified. Make sure the SP accepts exactly one assertion and reads only the one its signature check validated.
