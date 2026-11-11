# ssotrace lab

A local Keycloak identity provider (IdP) and a minimal SAML service provider (SP) for producing real-shaped SSO traffic.

> **Intentionally insecure. Local testing only.** Keycloak runs in dev mode over plain HTTP. The SP never verifies signatures. Both listen on `127.0.0.1` only. Do not expose them or reuse their credentials.

| Service  | URL                          | What it is                                             |
|----------|------------------------------|--------------------------------------------------------|
| Keycloak | <http://127.0.0.1:8080/>     | IdP. Realm `ssotrace-lab`, user `alice`, one SAML client |
| SP       | <http://127.0.0.1:8081/>     | Stdlib-only Go SP in [`sp/`](sp/) (its own Go module)   |

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

| Scenario | How to cause it | What the HAR shows |
|---|---|---|
| **Wrong audience** | Nothing to change. Browse to <http://127.0.0.1:8080/realms/ssotrace-lab/protocol/saml/clients/wrong-audience>. A second, pre-built client posts to the lab SP under a different entity ID. | `Audience` is `urn:example:ssotrace-lab:wrong-audience`, not the SP's entity ID |
| **Wrong ACS URL** | *Settings → Valid redirect URIs* → `http://127.0.0.1:9999/*` | AuthnRequest asks for `…:8081/saml/acs`; Keycloak answers with an error page and no `SAMLResponse` |
| **Expired assertion / clock skew** | *Advanced → Assertion Lifespan* → 1 second. Then in DevTools, *Command menu → Disable JavaScript*, log in, wait 5 seconds on Keycloak's **Continue** page, and click it. | POST timestamp is after `NotOnOrAfter`: the same symptom a skewed IdP clock causes |
| **Rotated cert** | Capture once. Then *Realm settings → Keys → Add provider → rsa-generated* with a higher priority than the existing key, and capture again. | The second Response is signed with a certificate the first capture never saw |
| **Unsigned assertion** | *Settings → Signature and Encryption*: turn off **Sign documents** and **Sign assertions** | No `<ds:Signature>` anywhere in the Response |

> These steps were written against Keycloak 26.8. If a menu has moved, the setting names are the same in the realm JSON (`saml.assertion.signature`, `saml.server.signature`, `redirectUris`, …).

## Captures

Save HAR exports to `lab/captures/`. That directory is gitignored, and the pre-commit hook blocks `.har` files anywhere outside `testdata/`.

> **Never move a capture into `testdata/`.** Even lab captures contain real signatures, session cookies, and generated IDs. Test fixtures are generated in code by `internal/testutil`; see [`testdata/README.md`](../testdata/README.md).
