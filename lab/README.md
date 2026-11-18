# ssotrace lab

A local Keycloak identity provider (IdP), a minimal SAML service provider (SP), and a small OIDC single-page app for producing real-shaped SSO traffic.

> **Intentionally insecure. Local testing only.** Keycloak runs in dev mode over plain HTTP. The SP never verifies signatures. Both listen on `127.0.0.1` only. Do not expose them or reuse their credentials.

| Service  | URL                          | What it is                                             |
|----------|------------------------------|--------------------------------------------------------|
| Keycloak | <http://127.0.0.1:8080/>     | IdP. Realm `ssotrace-lab`, user `alice`, SAML clients and the OIDC client `lab-spa` |
| SP       | <http://127.0.0.1:8081/>     | Stdlib-only Go SP in [`sp/`](sp/) (its own Go module), plus the OIDC single-page app at `/oidc/` |

## Requirements

Docker with the Compose plugin.

## Start and stop

```sh
cp lab/.env.example lab/.env   # first time only; edit the values
make lab-up                     # build the SP, start both containers
make lab-down                   # stop and remove them
```

Keycloak takes 20–60 seconds to start. Follow progress with:

```sh
docker compose -f lab/docker-compose.yml --env-file lab/.env logs -f
```

The realm, user, and SAML client come from [`realm/ssotrace-lab.json`](realm/ssotrace-lab.json), imported at startup. Keycloak uses an in-memory database, so anything you change in the admin console is lost on `make lab-down`. That is the point: every start is a clean baseline.

- **Admin console:** <http://127.0.0.1:8080/admin/>, credentials from `KC_BOOTSTRAP_ADMIN_*` in `lab/.env` (sign in to the `master` realm).
- **Test user:** `alice`, password from `LAB_USER_PASSWORD` in `lab/.env`.
- **SAML client:** *Clients → `http://127.0.0.1:8081/saml/metadata`* in the `ssotrace-lab` realm.

## Capture a login

1. Open <http://127.0.0.1:8081/> in a private window.
2. Open DevTools → **Network** and tick **Preserve log** (Firefox: **Persist Logs**).
3. Click **Log in with Keycloak** and sign in as `alice`.
4. The SP shows the decoded Response. Export the HAR to `lab/captures/`.

The capture holds two SAML messages:

- `GET /realms/ssotrace-lab/protocol/saml?SAMLRequest=…` is the AuthnRequest (HTTP-Redirect binding: deflated, base64, in the URL).
- `POST /saml/acs` with a `SAMLResponse` form field is the signed Response (HTTP-POST binding: base64 in the body).

### SP-initiated vs IdP-initiated

- **SP-initiated** (above): the user starts at the SP, which sends an AuthnRequest. The Response's `InResponseTo` names that request's ID, so the SP can match them up.
- **IdP-initiated:** the user starts at the IdP and there is no AuthnRequest, so the Response has no `InResponseTo`. Browse to <http://127.0.0.1:8080/realms/ssotrace-lab/protocol/saml/clients/lab-sp> to try it.

## Break it on purpose

Settings below live in the admin console under *ssotrace-lab realm → Clients → `http://127.0.0.1:8081/saml/metadata`*. After each scenario, `make lab-down && make lab-up` resets everything.

| Scenario | How to cause it | What the HAR shows | What ssotrace reports |
|---|---|---|---|
| **Wrong audience** | Nothing to change. Browse to <http://127.0.0.1:8080/realms/ssotrace-lab/protocol/saml/clients/wrong-audience>. A second, pre-built client posts to the lab SP under a different entity ID. | `Audience` is `urn:example:ssotrace-lab:wrong-audience`, not the SP's entity ID | IdP-initiated, so there is no request to learn the SP from: SAML002 INFO. Run with `--sp-entity-id http://127.0.0.1:8081/saml/metadata` (or log in from the SP first in the same capture) for SAML002 FAIL |
| **Wrong ACS URL** | *Settings → Valid redirect URIs* → `http://127.0.0.1:9999/*` | AuthnRequest asks for `…:8081/saml/acs`; Keycloak answers HTTP 400 and no `SAMLResponse` | SAML005 FAIL (IdP rejected the login request) |
| **Expired assertion / clock skew** | *Advanced → Assertion Lifespan* → 1 second. Then in DevTools, *Command menu → Disable JavaScript*, log in, wait on Keycloak's **Continue** page, and click it. | POST timestamp is after `NotOnOrAfter`: the same symptom a skewed IdP clock causes | SAML006 WARN if the wait was within the 3-minute default tolerance; FAIL with `--clock-skew 0` or a wait over 3 minutes. Keycloak also stamps `NotOnOrAfter` before `IssueInstant` at a 1-second lifespan, which is its own SAML006 WARN |
| **Rotated cert** | Save the current certificate first: copy the `X509Certificate` value from <http://127.0.0.1:8080/realms/ssotrace-lab/protocol/saml/descriptor> into `lab/captures/old-idp.cert`. Then *Realm settings → Keys → Add provider → rsa-generated* with a higher priority than the existing key, and capture. | The Response is signed with a certificate the saved one does not match | SAML013 FAIL with `--idp-cert lab/captures/old-idp.cert` (INFO without it) |
| **Unsigned assertion** | *Settings → Signature and Encryption*: turn off **Sign documents** and **Sign assertions** | No `<ds:Signature>` anywhere in the Response | SAML007 FAIL |

> These steps were written against Keycloak 26.8. If a menu has moved, the setting names are the same in the realm JSON (`saml.assertion.signature`, `saml.server.signature`, `redirectUris`, …).

## OIDC

The SP also serves a small single-page app at <http://127.0.0.1:8081/oidc/> (one static page, [`sp/oidc.html`](sp/oidc.html)). It signs in with the authorization code flow and PKCE through the public client `lab-spa`, and it redeems the code from the browser. That is the point: an app that exchanges the code on its server would leave the token request out of the HAR.

> **Intentionally insecure.** The page decodes the ID token for display but never verifies it, and it has links that break the sign-in on purpose.

### Capture an OIDC sign-in

1. Open <http://127.0.0.1:8081/oidc/> in a private window.
2. Open DevTools → **Network** and tick **Preserve log**.
3. Click **Normal sign-in** and sign in as `alice`.
4. The page shows the token endpoint's answer and the decoded ID token claims. Export the HAR to `lab/captures/`.

The capture holds the authorization request (`GET …/protocol/openid-connect/auth?client_id=lab-spa&…`), the callback (`GET /oidc/callback?state=…&code=…`), and the browser's own token request (`POST …/protocol/openid-connect/token`) with the ID token in its response. Check signatures against the lab's keys with:

```sh
ssotrace diagnose lab/captures/oidc.har --fetch-jwks http://127.0.0.1:8080/realms/ssotrace-lab/protocol/openid-connect/certs
```

Plain http is accepted here only because the URL is on `127.0.0.1`.

### Break it on purpose

Scenarios marked *page* need only a link on the SPA page. The others change the `lab-spa` client under *ssotrace-lab realm → Clients → `lab-spa`*; `make lab-down && make lab-up` resets them.

| Scenario | How to cause it | What ssotrace reports |
|---|---|---|
| **Baseline** | *page:* Normal sign-in | Every OIDC rule passes; OIDC009 INFO without keys, PASS with `--fetch-jwks` |
| **Silent sign-in without a session** | *page:* Silent sign-in, in a fresh private window | OIDC001 INFO (`login_required` after `prompt=none`) |
| **User declines consent** | *Settings → Login settings → Consent required* on; sign in and click **No** | OIDC001 FAIL (`access_denied`) |
| **redirect_uri not registered** | *Settings → Valid redirect URIs* → `http://127.0.0.1:9999/*`; *page:* Normal sign-in | Keycloak shows its "Invalid parameter: redirect_uri" page: OIDC001 FAIL and OIDC003 FAIL |
| **redirect_uri differs in the token request** | *page:* Different redirect_uri | OIDC003 FAIL (shows both URIs and "only a trailing slash differs") and OIDC007 FAIL (`invalid_grant`) |
| **Code redeemed twice** | *page:* Redeem the code twice | OIDC007 FAIL on the second token request (`invalid_grant`) |
| **PKCE verifier missing** | *page:* PKCE, but no code_verifier | OIDC007 FAIL, with evidence that the request sent a `code_challenge` but the token request has no `code_verifier` |
| **Confidential client** | *Settings → Capability config → Client authentication* on; *page:* Normal sign-in | OIDC007 FAIL (`invalid_client`: the browser has no secret to send) |
| **CORS blocked** | *Settings → Web origins* → remove `http://127.0.0.1:8081`; *page:* Normal sign-in | Keycloak answers HTTP 403 without `Access-Control-Allow-Origin`, and the browser records an empty body: OIDC007 FAIL ("Browser blocked the token response"), showing the page origin. A browser that records no response at all (status 0) gives an OIDC007 WARN that points at CORS instead |
| **No PKCE** | *page:* No PKCE | OIDC008 WARN (browser app without PKCE) |
| **PKCE plain** | *page:* PKCE with the plain method | OIDC008 WARN |
| **Client secret in the browser** | *page:* Send a client_secret | OIDC008 WARN |
| **Implicit flow** | *Settings → Capability config → Implicit flow* on; *page:* Implicit flow | OIDC008 WARN. The tokens come back in the URL fragment, which ssotrace reads from Keycloak's redirect |
| **Rotated signing key** | Save the current keys first: `curl -s http://127.0.0.1:8080/realms/ssotrace-lab/protocol/openid-connect/certs > lab/captures/old-jwks.json`. Then *Realm settings → Keys → Add provider → rsa-generated* with a higher priority, and capture a normal sign-in | OIDC009 INFO with `--jwks lab/captures/old-jwks.json` (signed by a key not in the key set); PASS with `--fetch-jwks` |

### Run every scenario at once

```sh
make lab-up      # if the lab is not running yet
make lab-oidc
```

[`oidcrun/`](oidcrun/) (its own Go module, standard library only) plays the browser for every row above except **CORS blocked**. It signs in as `alice` through Keycloak's real login pages, follows each redirect, redeems the code the way the page does, and saves each scenario as a HAR in `lab/captures/oidcrun/`. Admin-side changes go through Keycloak's admin REST API and are undone after each scenario. It then runs `ssotrace diagnose` on each HAR and prints a table of what happened, what ssotrace reported, and whether that matches this table. It exits non-zero on any mismatch.

**CORS blocked** stays a manual check, because how the browser records a blocked response is the point of that row.

Some rules cannot be triggered through an honest identity provider, because the mismatch they catch comes from an application, a proxy, or a clock: **OIDC002** (state mismatch), **OIDC004** (nonce mismatch), **OIDC005** (audience or `azp` names another client), and **OIDC006** (token outside its validity window). They are covered by the synthetic fixtures in `internal/diagnose` and `internal/redact` instead.

> These steps were written against Keycloak 26.8. If a menu has moved, the setting names are the same in the realm JSON (`publicClient`, `implicitFlowEnabled`, `consentRequired`, `redirectUris`, `webOrigins`).

## Captures

Save HAR exports to `lab/captures/`. That directory is gitignored, and the pre-commit hook blocks `.har` files anywhere outside `testdata/`.

> **Never move a capture into `testdata/`.** Even lab captures contain real signatures, session cookies, and generated IDs. Test fixtures are generated in code by `internal/testutil`; see [`testdata/README.md`](../testdata/README.md).
