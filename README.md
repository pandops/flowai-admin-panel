# admin-panel

HTTP backend for the administrator routes. It verifies the external admin
JWT and calls the services that own the data over NATS. It has no web
interface and no storage beyond its configuration.

| Route                                 | Owner request (`team: admin`)       |
| ------------------------------------- | ----------------------------------- |
| `POST /admin/teams`                   | `team-registry.admin.create.pub`    |
| `GET /admin/teams/{team_id}`          | `team-registry.admin.get.pub`       |
| `PATCH /admin/teams/{team_id}`        | `team-registry.admin.update.pub`    |
| `POST /admin/teams/{team_id}/archive` | `team-registry.admin.archive.pub`   |
| `GET /admin/tags`                     | `flow-registry.admin.tags.pub`      |
| `GET /admin/tasks`                    | `task-manager.admin.list-tasks.pub` |

A team name is set once by `POST /admin/teams` and cannot be changed.
`PATCH /admin/teams/{team_id}` changes only `default_image`; team-registry
answers an update that carries `team_name` with `400 team_name_immutable`,
and admin-panel returns that answer unchanged.

Probes: `GET /v1/livez` (always 200) and `GET /v1/readyz` (503 while the
NATS connection is down). Every other path answers 404.

## Request handling

1. **Authentication.** The bearer admin JWT must pass the configured
   issuer, audience, RSA algorithm allowlist, signature (JWKS, refreshed for
   an unknown `kid` within `admin_jwks_timeout`), `iat`/`exp`, clock skew
   and `admin_token_max_age`, and carry the exact role
   `flowai-system-admin` at `role_claim_pointer`. Failures: `401
invalid_admin_token`, `403 insufficient_admin_role`, `502
admin_identity_provider_unavailable`. Caller headers such as
   `X-FlowAI-Role` are never an identity.
2. **admin-panel's own checks.** Identifiers in the path, the `team_id` and
   `flow_id` filters and top-level `*_id` body fields must be positive
   decimal int64 values (`400 invalid_request`); `flow_id` needs `team_id`
   on `/admin/tasks`; `limit` is 1–200 (default 50) and the cursor must
   verify (`400 invalid_pagination`). Team routes get no other validation.
3. **Rejection audit.** A rejection after authentication (403 and the 400s
   above) is published to `admin-panel.audit.<action>.pub` (header
   `team: admin`, `Nats-Msg-Id: admin-panel-<publisher_seq>`) and the HTTP
   answer is sent only after the JetStream acknowledgement; without one
   within the request timeout the answer is `503 service_unavailable`.
   `401` and `502` are not audited. Forwarded requests are audited by their
   owners. Schemas: `schemas/audit.<action>.schema.json`, one per
   action (`team-create`, `team-get`, `team-update`, `team-archive`,
   `tags-list`, `tasks-list`), sharing `schemas/defs.schema.json`.
4. **Forwarding.** The request body is `{"params": {...}, "body": ...}`:
   `params` holds the path and query values (identifiers as JSON numbers,
   `limit` always set on lists), `body` the REST body unchanged, or on a
   list page after the first `{"after": <owner position>}`. Headers:
   `team: admin`, `admin_subject` (JWT subject), `request_id` (random
   positive 63-bit integer) and `If-Match` when present. The owner's
   `status` header and body are returned unchanged with `ETag`, `Location`
   and `Retry-After`. No responder or no reply within `request_timeout`
   gives `503 service_unavailable`; a disconnected broker gives `503
broker_unavailable`.
5. **Pagination.** Owners reply `{items, next}`. admin-panel keeps exactly
   the documented entry fields in order and wraps `next` in an HMAC cursor
   `<key_id>.<payload>.<mac>` bound to the endpoint, the
   `flowai-system-admin` scope, the filter tuple, the ordering and the
   forward direction. Response: `{items, page: {next_cursor, count}}`.

`publisher_seq` is an in-memory counter that starts at the process start
time in Unix microseconds and takes `max(previous + 1, now)` per message,
so it keeps increasing across restarts.

## Configuration

`admin-panel --config /etc/flowai/config.yaml`; every key is listed in
[`config.example.yaml`](config.example.yaml). Startup fails on a missing or
unsafe trust setting: no TLS NATS URL, CA or `.creds` file, a missing admin
trust field, a symmetric algorithm, a non-positive `admin_jwks_timeout` or
`admin_token_max_age`, or no cursor key.

Admin Panel owns the external administrator JWT trust settings under
`admin`, including the issuer, audience, JWKS URL and role claim pointer.
The API Gateway's operator OIDC client and sessions are configured
separately. The runtime receives its YAML, NATS CA and user credentials, and
cursor key files through external mounts.

## Build and test

```sh
go test -mod=readonly -count=1 -coverpkg=./... ./...
podman build --platform linux/amd64 -f Containerfile .
```

Set `FLOWAI_CONTRACT_FIXTURE_DIR` to an absolute directory holding the
pinned Team Registry, Flow Registry and Task Manager schemas under
`svc/<publisher>/schemas/`. The manual qualification workflow lists the exact
paths and expected hashes and stages them outside the checkout. The
declaration test uses the relevant entries from Gitea's schema ownership
map, preserved in `qualification/admin-panel-declarations.json`.

The tests fake the JWKS endpoint and broker in process. The service has no
external-dependency integration suite.
