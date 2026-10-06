# Education sign-in reference application

This synthetic example consumes its own registered Education verifier over protected
HTTP. The runtime verifies credential protocols. The application checks enrolment and
institution, then maps the exact authenticated `(issuer, student_id)` pair to a random
application account ID. A verified signature alone never creates a login.

Eligibility is separate. It requests only `credentialSubject.enrolled` and
`credentialSubject.institution_id`, creates no account and does not sign in. Sign-in
also requests `credentialSubject.student_id`. Services receiving the same stable ID
can correlate visits. Use eligibility when account continuity is unnecessary.

## Prerequisites and configuration

First follow the [partner runtime setup](../partner-runtime/README.md): create a project,
prove endpoint/key ownership, obtain signed permissions for both fixed Education profiles,
bootstrap a persistent identity, configure independently pinned trust/status evidence and
serve the public runtime at reachable HTTPS. Obtain holder-bound synthetic Education through
the issuer's existing Government enrolment prerequisite. The application integrates only
Education, not Government Identity. No operator host-table edit or new credential crypto is
needed. Project-owned code is Apache-2.0 under the root LICENSE. Public checkout/export, exact signed artifact selection and public-release approval remain under #338;
#349 delivers the kit, and #348 tracks the later Release B gate.

Use installed pnpm/Node tooling and **a dedicated application Postgres database**. Never point
the app at the ecosystem registry/issuer database: its Drizzle migration ledger is independent.
The built-in Drizzle migrator applies the bundled `drizzle/0000` at startup. No drizzle-kit
runtime dependency or custom migration engine is needed. Bootstrap one app instance at a time.
The exact issuer/student ID unique constraint preserves accounts across app/container restart.
Back up this operator-owned database; loss of it loses account continuity. Browser sessions
and interactions are bounded in memory and restart logs them out.

Required environment:

| Variable | Meaning |
| --- | --- |
| `EDUCATION_APP_ORIGIN` | Exact browser HTTPS origin, without path/query/fragment |
| `EDUCATION_APP_DATABASE_URL` | Dedicated app Postgres connection string |
| `EDUCATION_RUNTIME_MANAGEMENT` | Exact loopback `http://127.0.0.1:<port>` runtime management origin |
| `PARTNER_MANAGEMENT_TOKEN` | Runtime management bearer secret, server-side only |
| `EDUCATION_TRUSTED_ISSUER` | Explicit accepted Education issuer DID |
| `EDUCATION_VERIFIER_DID` | Explicit registered runtime DID |
| `EDUCATION_INSTITUTION` | Exact institution value allowed by this application's policy |
| `EDUCATION_APP_PORT` | Internal listener port, default 3082 |

```sh
pnpm install --frozen-lockfile
just education-sign-in
```

The CLI binds the container interface. Expose it only through correctly configured HTTPS
ingress. `just education-sign-in` tees claim-free readiness/failure output to
`.logs/education-sign-in.log`. It never logs browser cookies, credentials, claims, activation
URIs, result capabilities or raw runtime diagnostics. Readiness errors are fixed codes.

## Browser and result contract

`GET /api/session` creates a 30-minute opaque `__Host-education` cookie with Secure,
HttpOnly, SameSite=Strict and Path=/. It returns the synchronizer CSRF token and anonymous
or signed-in status. POSTs require the exact configured Origin, the initiating cookie and
`X-CSRF-Token`, plus `application/json`. Browser URLs and JavaScript never receive the
management token or result capability. The app stores session ID, correlation capability,
original interaction ID, profile and retention deadline server-side.

`POST /api/interactions` accepts exactly `{"profile":"education_sign_in"}` or
`{"profile":"education_eligibility"}`. The 201 response includes an opaque application
interaction ID and actual runtime activation/request URI. Open the activation link in the
Android browser to launch the wallet; on another device, transfer the link to the phone's
browser. Buildprod has no development paste control. Review the real recipient, purpose,
instance and requested values in the wallet and use normal hardware authorization.

`POST /api/interactions/<id>/complete` accepts exactly `{}` and consumes the protected
runtime result using the server-held capability. A pending result returns 409 RESULT_PENDING
and can be checked again. One admitted completion claims the app interaction before I/O.
Uncertain upstream delivery fails closed and consumes it. A different browser gets 404
INTERACTION_NOT_FOUND. Replay gets 409 INTERACTION_CONSUMED; competing admitted interactions
cannot rotate the same browser twice. Rotation invalidates remaining pending interactions.

The application requires verified status, exact original interaction, configured issuer and
verifier, Education type, definition `urn:credworks:education` version 1, exact fixed profile
and complete paths, enrolled===true, exact configured institution and a bounded nonblank
student ID for sign-in. It retains the runtime's immutable fractional `evidence.expires_at`.
Browser expiry, original runtime retention at creation plus 240 seconds and evidence expiry are
rechecked after network/account I/O. Equality is expired; no refresh extends these bounds.
The runtime's 120-second presentation deadline is separate from its 240-second result retention.

Successful sign-in returns `{"status":"signed_in","account_id":"<app UUID>"}` and
rotates the cookie/CSRF secret. Eligibility returns `{"status":"eligible"}` without a
new cookie/account. Refusal never replaces an existing login. Neither route returns student
ID, holder keys or credential instance IDs. The public runtime `{"status":"accepted"}`
acknowledges delivery only. The app uses the separately authenticated protected result.

The source includes [OpenAPI](src/public/openapi.json) and serves it at `/openapi.json`.
A minimal same-browser curl sequence against your normal HTTPS ingress:

```sh
APP=https://app.example
curl --fail-with-body -c browser.cookies "$APP/api/session" > browser-session.json
# Read csrf locally from browser-session.json. Keep it and browser.cookies private.
curl --fail-with-body -b browser.cookies -c browser.cookies "$APP/api/interactions" \
  -H "Origin: $APP" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  --data '{"profile":"education_sign_in"}' > interaction.json
# Open the returned activation_uri and finish the wallet ceremony.
curl --fail-with-body -b browser.cookies -c browser.cookies "$APP/api/interactions/$INTERACTION_ID/complete" \
  -H "Origin: $APP" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' --data '{}'
# Refresh /api/session after cookie rotation to obtain the new CSRF token.
```

Bodies are capped at 4 KiB; protected responses at 16 KiB. Headers/body connections are bounded
by 10 seconds, runtime fetch/streaming by 5 seconds, and DB connection/statement/query waits
by 3/3/4 seconds. At most 100 browser records and five reserved interactions per browser are
retained. JSON errors contain only `error.code`. Stable codes include REQUEST_BAD_REQUEST,
REQUEST_TOO_LARGE, CSRF_REFUSED, BROWSER_REQUIRED/EXPIRED/RETIRED/CAPACITY,
INTERACTION_NOT_FOUND/CONSUMED/EXPIRED/CAPACITY, RESULT_PENDING/INVALID/UNAVAILABLE,
VERIFICATION_REFUSED, EVIDENCE_STALE, ENROLMENT_REQUIRED, INSTITUTION_NOT_ALLOWED,
STUDENT_ID_INVALID, RUNTIME_UNAVAILABLE and APPLICATION_UNAVAILABLE. No raw exception
or upstream response body is returned.

## Private container setup

Build a source-pinned app image without Rust or fixture signing material:

```sh
REVISION=$(git rev-parse HEAD)
docker build --build-arg SOURCE_REVISION="$REVISION" -f apps/education-sign-in/Dockerfile \
  -t "education-sign-in:$REVISION" .
```

Use `infra/education-sign-in/compose.yml` with explicit revision-tagged
`EDUCATION_APP_IMAGE` and `PARTNER_IMAGE`, the runtime's preserved unlock secret/config,
and the configuration above. For local operator-owned storage enable `--profile local-db`,
set a random URL-safe `EDUCATION_DB_PASSWORD` and use
`postgres://education:<password>@database:5432/education`. Alternatively provide a dedicated
managed database URL. Compose interpolation requires the DB password variable even when the
local-db profile is disabled. It does not publish a database port.

```sh
docker compose -p vc336 -f infra/education-sign-in/compose.yml run --rm partner bootstrap
# Do not bootstrap again once identity exists.
docker compose -p vc336 -f infra/education-sign-in/compose.yml --profile local-db up -d database
# Wait for database health before starting the application.
docker compose -p vc336 -f infra/education-sign-in/compose.yml up -d partner application
```

App and runtime share a network namespace so management remains loopback 3081. Only runtime
public 3080 and browser 3082 are mapped to host loopback. Route independently configured HTTPS
origins to those ports using your ingress; no host mapping exposes management. The browser
app must bind the container interface for the published port to work. Do not route arbitrary
management paths through ingress. Container replacement preserves identity and account DB
volumes, but logs browser sessions out. App software and bundled migrations are independent
of the ecosystem registry database.

Fonts are unmodified existing UI assets with separately bundled official OFL notices and
binary provenance in [fonts.md](src/public/fonts.md). Project code reuse/publication remains
the Education #338 human gate and later Release B #348 gate.

## HTTP checks and physical handoff

The opt-in suite uses actual registry registration, synthetic Gov→enrolment→Education,
the persistent runtime, shared-core headless holder and application HTTP. A narrow proxy
changes actual protected responses only in adversarial tests; it performs no credential
verification. No UI-driving framework or production network bypass is added.

```sh
EDUCATION_APP_SETUP_DATABASE_URL=postgres://vc379:vc379@127.0.0.1:55447/vc336_setup \
EDUCATION_APP_DATABASE_URL=postgres://vc379:vc379@127.0.0.1:55447/vc336_app \
EDUCATION_APP_HTTP_PORT=33600 \
pnpm --filter @unsw-vc/education-sign-in test
```

The first fixture DB has ecosystem migrations through 0022. The separate app DB starts empty
and receives only app-local migrations. Ports 33600–33609 are setup/runtime/app/proxy; 33610–11
are the optional actual Compose check. All derive from the configured base. Turbo serializes
this package after partner-runtime/issuer/trust tests so Next generated state cannot overlap.
PR CI creates separate ephemeral fixture/app databases and enables these HTTP tests. Local
coordinator gates additionally enable the pinned app/runtime container check. Missing opt-in
variables cause skips, which are not completion evidence.

Physical Android steps and exact artifact/source combination are in the revision-specific
handoff under `docs/partner/education-sign-in.md`. Host page inspection at desktop and narrow
width is visual evidence only. Public reachability, actual Android activation/hardware prompt,
installation/upgrade and physical accessibility remain NOT RUN under #338.
