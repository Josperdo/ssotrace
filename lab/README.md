# ssotrace lab

A local Keycloak identity provider for producing real-shaped SSO traffic.

> **Intentionally insecure. Local testing only.** Keycloak runs in dev mode over plain HTTP and listens on `127.0.0.1` only. Do not expose it or reuse its credentials.

## Requirements

Docker with the Compose plugin.

## Start and stop

```sh
cp lab/.env.example lab/.env   # first time only; edit the values
make lab-up                     # start Keycloak in the background
make lab-down                   # stop and remove the container
```

Keycloak takes 20–60 seconds to start. Follow progress with:

```sh
docker compose -f lab/docker-compose.yml --env-file lab/.env logs -f keycloak
```

## Admin console

Open <http://127.0.0.1:8080/admin/> and sign in with the username and password from `lab/.env`.

The container uses an in-memory database, so `make lab-down` discards all realms, clients, and users.

## Captures

Save HAR exports from the lab to `lab/captures/`. That directory is gitignored, and the pre-commit hook blocks `.har` files anywhere outside `testdata/`.

> **Never move a capture into `testdata/`.** Even lab captures contain real signatures, session cookies, and generated IDs. Test fixtures must be synthetic and generated from scratch; see [`testdata/README.md`](../testdata/README.md).
