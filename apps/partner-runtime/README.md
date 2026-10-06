# Partner identity and Education verifier

This bootstrap supports one independently operated identity per process on Linux/macOS.
It uses the shared Rust core's ES256 signing handle, not the deterministic demo keys.
It publishes a DID document, signs short-lived endpoint-ownership proofs and runs
Education verification sessions. Credential issuance and public image distribution are later slices. Local container packaging is documented below.

## Initial setup

From the monorepo root, install Node/pnpm and Rust as described in the root README:

```sh
pnpm install --frozen-lockfile
pnpm --filter @unsw-vc/identity-core-node build:native
```

Configure these variables in your supervisor or secret manager. Do not commit secrets.
`PARTNER_UNLOCK_KEY` is exactly 32 random bytes, unpadded base64url, **not a password**.
Generate it once, retain it separately from the encrypted state and deliver it at each
startup. Use a distinct random management token of at least 32 bytes.

```sh
export PARTNER_ORIGIN=https://partner.example
export PARTNER_STATE_DIR="$PWD/.artifacts/partner-identity"
export PARTNER_UNLOCK_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
export PARTNER_MANAGEMENT_TOKEN="$(openssl rand -hex 32)"
export PARTNER_PUBLIC_PORT=3080
export PARTNER_MANAGEMENT_PORT=3081
mkdir -p .artifacts
pnpm --filter @unsw-vc/partner-runtime bootstrap
pnpm --filter @unsw-vc/partner-runtime start
```

Save the generated secrets in protected operator storage before restarting. Bootstrap is
a CLI operation, creates a new 0700 state directory, and refuses any existing directory,
including incomplete state. Normal startup only loads existing state. Never run bootstrap
as an automatic startup fallback. An invalid origin, changed origin, absent/changed public
manifest, missing/corrupt key, incorrect unlock key or unsafe permissions fails startup
with `partner_identity_unavailable`; it does not replace the identity. Partial bootstrap
requires operator recovery from a consistent backup, or an explicit new deployment identity.

The state contains `identity.json` (version, origin and expected public JWK) and
`signing-key.sealed` (0600, AES-256-GCM encrypted P-256 scalar, random nonce and key-ID
binding). Rust decrypts and signs internally. Node receives only the opaque key ID and
public JWK. The unlock secret is available to the Node process, so process isolation and
secret delivery remain operator responsibilities. This is POC encrypted local custody;
it does not claim HSM protection or production assurance.

## HTTPS and endpoint separation

Set `PARTNER_ORIGIN` to the externally reachable HTTPS origin, with no path, query or
userinfo. The DID uses its hostname and optional encoded port. Terminate TLS at your
existing HTTPS proxy. Forward the DID and OID4VP request/response routes to the public listener;
for example, a Caddy site:

```caddyfile
partner.example {
    @did {
        method GET
        path /.well-known/did.json /oid4vp/request/*
    }
    handle @did {
        reverse_proxy 127.0.0.1:3080
    }
    @response {
        method POST
        path /oid4vp/response/*
    }
    handle @response {
        reverse_proxy 127.0.0.1:3080
    }
    handle {
        respond 404
    }
}
```

The public listener binds 0.0.0.0; protect it with your proxy/network policy. The separate
management listener binds 127.0.0.1 and requires its own bearer credential. Never forward
it through the public proxy. Container operators must place management callers in the same
network namespace or use a private authenticated gateway; publishing that port alone will
not make its loopback listener reachable. The registry project credential is a different
credential and does not authorize this runtime. Neither listener exposes keys, state paths,
credentials or request bodies in diagnostics. Startup prints only listener addresses;
bootstrap prints only the DID and public JWK.

Authenticated signing is limited to ownership challenges:

```sh
curl --fail-with-body http://127.0.0.1:3081/management/sign \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"nonce":"challenge-from-registry","audience":"https://registry.example/partner-challenges"}'
```

The response is `{ "jwt": "..." }`. The fixed header is
`{alg:"ES256",typ:"partner-identity-proof+jwt",kid:"<did>#key-1"}` and payload is
`{iss:"<did>",aud:"<audience>",nonce:"<nonce>",iat:<now>,exp:<now+60>}`.
Nonce length is 8–256 characters; audience must be HTTPS and at most 2048 characters.
Additional fields are rejected. Bodies are limited to 4096 bytes and request timeouts to
five seconds. This is an application proof extension, not an OID4VP request object.
Consumers must independently check the expected nonce/audience/expiry and prevent challenge
replay. HTTP failures are `401 unauthorized`, `400 invalid_request` and `404 not_found`.
Proof signing does not register or accredit the deployment.

## Restart, replacement and recovery

Stop the runtime and preserve the **whole state directory**, its permissions, HTTPS origin
and unlock secret before process/container replacement. Start the replacement using `start`,
not `bootstrap`. Retain a protected copy of both state files and restore them together while
stopped; restore the unlock secret separately. Do not copy an identity into a second active
deployment: each deployment must bootstrap distinct state. A missing mount or incompatible
state fails startup. The initial state format is version 1; upgrades must preserve it or
provide an explicit migration. Origin changes and key rotation are not implemented here;
changing configuration does not silently change the identity.

Run the acceptance check from the monorepo root:

```sh
cargo test -p identity-core --test local_signer
pnpm --filter @unsw-vc/partner-runtime test
```

The HTTP check uses real subprocesses, Rust signing and Rust verification: sign, process
replacement with preserved state, verify again against the same public DID; it also checks
unique deployment keys and missing/corrupt/locked/unprotected state. It uses isolated local
HTTP ports behind a configured HTTPS origin. That host identity check does not establish
container behavior; the separate container checks below cover local packaging and replacement.
Public HTTPS reachability, public image distribution and physical Android acceptance are NOT RUN.

## Education sessions

Set `PARTNER_VERIFIER_CONFIG` to a JSON file of at most 16 KiB. It contains only
public configuration; retain the management token and signing secrets separately:

```json
{
  "issuerDid": "did:web:education.example",
  "issuerJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<public-x>",
    "y": "<public-y>"
  },
  "registryOrigin": "https://registry.example",
  "trustAnchorJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<public-x>",
    "y": "<public-y>"
  },
  "statusSources": [
    {
      "url": "https://status.example/education.jwt",
      "publicJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "<public-x>",
        "y": "<public-y>"
      },
      "purpose": "revocation"
    }
  ],
  "maxCacheAgeSeconds": 300
}
```

Supply real pinned P-256 public keys and the accredited Education issuer. Configuration
is copied at startup. An identity-only deployment may omit this file; session routes then
remain unavailable. Initial evidence failure prevents verifier startup. Sessions and caches
are ephemeral: restart retains the Rust signing identity but discards pending sessions and
results. The application must start a new ceremony after restart, never transfer a session
across a configuration or signing-identity change.

The only accepted credential type is `UniversityEducationCredential`, mapped after
issuer/type verification to `urn:credworks:education` version `1`. Credential bytes are
unchanged. `education_eligibility` requests exactly `credentialSubject.enrolled` and
`credentialSubject.institution_id`; `education_sign_in` additionally requests
`credentialSubject.student_id`. Callers cannot add issuers, definitions or claim paths.
Both profiles require current scoped authorization for this runtime's exact DID, origin
and public key. No legacy permission array grants authority.

Use the loopback management listener with the runtime bearer credential:

```sh
curl --fail-with-body http://127.0.0.1:3081/management/sessions \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"profile":"education_sign_in","interaction_id":"application-interaction-123","purpose":"Student sign-in"}'
```

The `201` response supplies `session_id`, `interaction_id`, `request_uri`,
`activation_uri`, `expires_at` and `correlation_capability`. The application binds the
capability to its already protected initiating browser interaction. Keep it server-side;
do not put it in a QR, public URL or wallet request. Display the activation URI as a link
or QR through your application's existing interface. The public URI serves the persisted
ES256 request JWT (`application/oauth-authz-req+jwt`), with exact DCQL, recipient DID,
purpose, nonce, state, audience and an expiry fixed at creation plus 120 seconds.
Retrieval never extends expiry. The response URI is unique to the public ceremony.

Wallets submit `application/x-www-form-urlencoded` to the signed `response_uri`, with
`state` and `vp_token`. The latter is JSON `{ "education_sign_in": ["<SD-JWT+KB>"] }`
(or the eligibility query ID). Exactly one matching presentation and the exact state are
required. Public response acknowledgement is `{ "status": "accepted" }`; it carries no
claims or verification decision. Once admitted, completion is claimed before verification
and cannot be retried, including failed verification.

`GET /management/sessions/<session_id>` returns status without claims.
`POST /management/sessions/<session_id>/result` with JSON `{}` returns the result once.
Both require the bearer token and `X-Session-Capability: <correlation_capability>`.
Public state/request capabilities cannot authorize either endpoint. Concurrent consumption
returns one result and one `409 RESULT_CONSUMED`. Results expire at session creation plus
240 seconds; expired records are removed on the next session operation. A completed
ceremony is not a pending request: delivery after the 120-second request deadline
is permitted while its captured verification authority remains fresh.

A verified result captures an immutable `evidence.expires_at` NumericDate when
verification succeeds. It is the minimum authenticated cache deadline and signed
credential `exp`, when present. This additionally bounds claim delivery by credential
validity. Fractional NumericDates retain the existing core semantics. Retention at
creation plus 240 seconds is a separate storage bound. Before returning verified
claims, consumption checks the original deadline, current exact permission against
the original runtime identity and current authenticated credential status. Refresh
cannot extend an older result's deadline. A stale or withdrawn result becomes a
claim-free protected refusal and is consumed once. This is verification freshness;
it neither grants eligibility nor creates an application login session.

A verified result contains `status: "verified"`, the original `interaction_id`, typed
`claims` and `evidence`: authenticated issuer/type/definition/profile/full paths, verifier
DID, issuer/verifier/holder public-key thumbprints and verification time. A refused result
contains only `status: "refused"`, `interaction_id` and `error.code`. Signatures, holder
binding, audience, nonce, credential and key-binding freshness, exact disclosed paths,
scoped authority, issuer accreditation and active status must all pass. `enrolled=false`
is a verified value. The application explicitly checks eligibility and owns account
mapping/cookies; this runtime implements neither.

## Authenticated evidence cache and bounds

Only configured HTTPS destinations are fetched: `<registryOrigin>/trust-list.jwt`,
`<registryOrigin>/scoped-verifier-permissions.jwt?verifier_did=<URL-encoded-runtime-DID>`
and 1–4 explicitly pinned status URLs/purposes. Credential-provided URLs never initiate
network access. TLS uses normal certificate/hostname validation, redirects are refused,
each fetch has a five-second deadline and a 256 KiB response limit; permission documents
are additionally limited to 16 KiB and two grants. Every document is verified in Rust.
Trust and permission issuer/document identity, configured issuer accreditation/key,
status issuer/document/purpose and signed validity are checked before replacing the cache.

Freshness is the minimum of the signed expiries and the configured maximum age (1–300
seconds). Registry permission publication expires after five minutes. Authenticated
`POST /management/evidence/refresh` with `{}` refreshes all evidence atomically. Failed
refresh retains the prior snapshot only within its original bound. Fresh cached evidence
works offline; absent/stale evidence refuses creation and completion. Refresh is explicit;
operators schedule authenticated refresh before expiry. Scope is rechecked at completion,
so a successful refresh removing a grant affects already pending sessions.

At most 100 sessions/results are retained. Management bodies are limited to 4 KiB, public
responses to 128 KiB, purpose to 200 characters and interaction IDs to 128. Body reading,
headers and idle connections are bounded to five seconds. Verified string claims are
1–256 characters. No credential or claim data appears in error diagnostics.

New session errors use `{ "error": { "code": "..." } }`:

| HTTP            | Codes                                                                                                 |
| --------------- | ----------------------------------------------------------------------------------------------------- |
| 400             | `SESSION_BAD_REQUEST`, `RESPONSE_BAD_REQUEST`, `RESPONSE_STATE_MISMATCH`                              |
| 401             | `SESSION_ACCESS_DENIED` (management bearer refusal retains `unauthorized`)                            |
| 403             | `SCOPE_NOT_PERMITTED`                                                                                 |
| 404             | `SESSION_NOT_FOUND`                                                                                   |
| 408 / 413 / 429 | `REQUEST_DEADLINE` / `REQUEST_TOO_LARGE` / `SESSION_CAPACITY`                                         |
| 409             | `RESULT_PENDING`, `RESULT_CONSUMED`, `SESSION_ALREADY_COMPLETED`                                      |
| 410             | `SESSION_EXPIRED`                                                                                     |
| 503             | `EVIDENCE_UNAVAILABLE`, `EVIDENCE_STALE`, `EVIDENCE_REFRESH_FAILED`, `PERMISSION_VERSION_UNSUPPORTED` |

Protected refused-result codes additionally include `PRESENTATION_VERIFICATION_FAILED`,
`ISSUER_NOT_ACCEPTED`, `TYPE_NOT_ACCEPTED`, `CLAIM_PATHS_NOT_PERMITTED`,
`CLAIM_VALUE_INVALID` and `STATUS_DESTINATION_UNAUTHORIZED`. Rust verification failures retain only validated stable enum codes, including
`INVALID_SIGNATURE`, `BINDING_CHECK_FAILED`, `FRESHNESS_CHECK_FAILED`,
`MISSING_DISCLOSURE` and `STATUS_CHECK_FAILED`. Unknown exceptions use
`PRESENTATION_VERIFICATION_FAILED`. Neither case exposes native error text. Unknown public/management routes retain the original `not_found` response.

The session tests exercise real runtime HTTP and core-backed issuer/holder/signature/status
fixtures with a narrow configured evidence-fetch seam. They establish protocol and access
behavior, not public HTTPS deployment. Container/OpenAPI/full registered synthetic setup
belongs to #363. Physical Android acceptance is **NOT RUN** and remains #338.

## Container and application contract (#363)

The static [OpenAPI document](openapi.json) describes every implemented public and
management route, its authentication, media type, input, result and refusal behavior.
The supported protocol remains W3C SD-JWT+KB, ES256, exact scalar Education DCQL,
`decentralized_identifier` and `direct_post` with one `vp_token` presentation.
Other formats, response modes, arbitrary paths and browser login are unsupported.

Build from a clean committed checkout. The image label records the full source commit;
the image tag and local image ID identify the corresponding build. This command creates
only a local image. It does not publish it:

```sh
export SOURCE_REVISION="$(git rev-parse HEAD)"
export PARTNER_IMAGE="credworks-partner-verifier:git-$SOURCE_REVISION"
docker build --progress plain --build-arg SOURCE_REVISION="$SOURCE_REVISION" \
  -f apps/partner-runtime/Dockerfile -t "$PARTNER_IMAGE" .
docker image inspect "$PARTNER_IMAGE" --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
```

The native build uses the explicit `bindings-node/partner-runtime` feature. It excludes
both deterministic test-key installers, their helper and private scalar constants. The
build checks missing native fixture exports and known private scalar byte sequences.
The key-aware scanner is removed in the build stage before the final runtime COPY;
no runtime image layer contains it. Host container checks independently assert the
fixture exports and scanner are absent from the distributed image.
Default monorepo addons retain existing demos/conformance. Runtime packaging includes
only application/core sources, the Linux addon and production dependencies. It excludes
fixture vectors, tests, private signing material and development build tools. `tsx` is a
runtime dependency because both CLI and public core wrapper are TypeScript.

Use [Compose](../../infra/partner/compose.yml) and the
[public verifier configuration example](examples/verifier.json). Replace public-key
placeholders with independently authenticated pins. Do not take a trust anchor from an
unverified credential. Keep secrets out of the public configuration directory.

```sh
export PARTNER_ORIGIN=https://partner.example
export PARTNER_CONFIG_DIR="$PWD/apps/partner-runtime/examples"
export PARTNER_UNLOCK_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
export PARTNER_MANAGEMENT_TOKEN="$(openssl rand -hex 32)"
export PARTNER_VERIFIER_CONFIG=
docker compose -f infra/partner/compose.yml run --rm partner bootstrap
docker compose -f infra/partner/compose.yml up -d partner
```

Save the unlock secret and runtime token before replacing a process. Explicit bootstrap
creates `/state/identity` once inside the named volume; subsequent starts only load it.
The container runs UID/GID 10001, read-only apart from protected state and bounded `/tmp`,
with dropped capabilities, CPU/memory/PID limits and rotated logs. Only the public listener
is mapped, to host loopback3080 for the existing HTTPS proxy. Management3081 remains
container loopback. Use the public proxy routes above; never proxy management.

Create a registry project through `POST <registry>/api/projects`, then post
`{origin,did,key_id,public_jwk}` using its project credential to
`/api/projects/<project>/verifiers/challenges`. Read the runtime DID through your HTTPS
proxy. Sign the returned nonce/audience from the runtime's network namespace:

```sh
# Set CHALLENGE_NONCE and CHALLENGE_AUDIENCE from the registry response.
# The command returns only a short-lived public proof, never a private key.
docker compose -f infra/partner/compose.yml exec -T \
  -e CHALLENGE_NONCE -e CHALLENGE_AUDIENCE partner sh -c '
  curl --fail-with-body http://127.0.0.1:3081/management/sign \
    -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
    -H "Content-Type: application/json" \
    --data "{\"nonce\":\"$CHALLENGE_NONCE\",\"audience\":\"$CHALLENGE_AUDIENCE\"}"'
```

Post the returned `{jwt}` with the project credential to
`/api/projects/<project>/verifiers/challenges/<challenge_id>/complete`. Technical control
must resolve through the registry's normal public DNS and TLS policy. The headless test's
mapped TLS fixture does not establish publicly reachable registration.

After registration and authenticated public-pin configuration, set
`PARTNER_VERIFIER_CONFIG=/config/verifier.json` and recreate the service:

```sh
export PARTNER_VERIFIER_CONFIG=/config/verifier.json
docker compose -f infra/partner/compose.yml up -d --force-recreate partner
docker compose -f infra/partner/compose.yml exec -T partner sh -c '
  curl --fail-with-body http://127.0.0.1:3081/management/sessions \
    -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
    -H "Content-Type: application/json" \
    --data '\''{"profile":"education_sign_in","interaction_id":"application-123","purpose":"Student sign-in"}'\'''
```

Keep the returned session ID and correlation capability in the initiating application
interaction. For the protected one-time result:

```sh
# Set SESSION_ID and SESSION_CAPABILITY from creation, never from public state.
docker compose -f infra/partner/compose.yml exec -T \
  -e SESSION_ID -e SESSION_CAPABILITY partner sh -c '
  curl --fail-with-body "http://127.0.0.1:3081/management/sessions/$SESSION_ID/result" \
    -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
    -H "X-Session-Capability: $SESSION_CAPABILITY" \
    -H "Content-Type: application/json" --data "{}"'
```

The application checks values itself, for example `enrolled === true` and the configured
institution before granting eligibility. A cryptographically verified `false` is not access.
The runtime creates no cookie, account or browser login.

Stop before backup or restore. Preserve the complete named volume, UID/GID10001,
0700 identity directory, 0600 files, origin and unlock secret separately. Do not use
`docker compose down -v` on an established identity. Container replacement with the
same volume and secrets preserves DID/key; missing state, changed origin or incorrect
unlock refuses startup. It never bootstraps automatically. Pending sessions/results and
cached evidence are ephemeral and are intentionally discarded during replacement.

## Complete setup and acceptance evidence

The complete check creates a project through real Next HTTP, registers this runtime's
persistent identity using real HTTP production handlers and an independent TLS DID
endpoint, reads the actual signed per-verifier publication through Next, then obtains
Government Identity and holder-bound Education through the existing real enrolment flow.
It creates a signed runtime request, presents that issued Education using the shared
core holder, verifies protected correlated claims once, stops issuer/registry processes,
verifies offline from fresh authenticated caches and refuses stale evidence/failed refresh.

Run against a separate migrated PostgreSQL database and free isolated service ports.
The setup uses offsets0–9 and13–15 from `PARTNER_SETUP_HTTP_PORT` (default33200), leaving offsets10–12 free for the existing container checks. Container checking
uses host loopback33210; the actual Compose check uses33211. Compose exposes its public
listener on `PARTNER_HOST_PORT` (default3080). Existing negative-session tests use their existing33170–33172
fixture ports (override the session pair with `PARTNER_SESSION_HTTP_PORT` and TLS transport port with `PARTNER_EVIDENCE_HTTP_PORT`). Turbo serializes shared Next applications after issuer/trust HTTP suites.

```sh
export PARTNER_SETUP_DATABASE_URL=postgres://vc363:vc363@127.0.0.1:55445/vc363
DATABASE_URL="$PARTNER_SETUP_DATABASE_URL" pnpm --filter @unsw-vc/db db:migrate
export PARTNER_SETUP_HTTP_PORT=33200
export PARTNER_CONTAINER_IMAGE="$PARTNER_IMAGE"
export PARTNER_CONTAINER_SOURCE_REVISION="$SOURCE_REVISION"
pnpm --filter @unsw-vc/partner-runtime test
pnpm --filter @unsw-vc/partner-runtime lint
```

Setup/container checks skip explicitly if their environment is absent. Acceptance requires
both enabled. Each evidence bound additionally has an observable runtime HTTP check:
configured max age, signed trust `exp`, permission `exp` and status `validUntil` each
independently expires first. Using only the injected per-runtime clock, they verify fresh
offline success one second before expiry and `EVIDENCE_STALE` at the exact bound for
creation/completion. No global clock, original fixture or unrelated source is changed.
The original #362 corpus remains runnable for issuer/key/holder/type/path/nonce/audience,
credential/key-binding expiry, replay/concurrency, correlation theft and scope revocation.

| #333 criterion                                       | Evidence                                                                                                         |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Authenticated bounded session and activation         | #362 creation/scope/capacity HTTP checks; complete registered setup                                              |
| Signed bindings, freshness and exact disclosure      | #362 negative corpus; complete actual-issued Education presentation                                              |
| Protected interaction and one-time completion/result | #362 race/theft checks; complete correlated result                                                               |
| Typed claims, evidence and stable codes              | #362 verified/ineligible/refusal checks; OpenAPI; no business/cookie behavior                                    |
| Authenticated caching and expiry                     | Complete process-disconnected fresh/stale exchange; independent HTTP checks for each signed/configured bound     |
| Listener/resource/log separation                     | #362 HTTP bounds; Compose; actual container public-route/management isolation                                    |
| Container, configuration, OpenAPI and complete setup | Packaged addon exclusion and bootstrap/replacement/missing-state container checks; this documented runnable flow |

Source/image revision and image ID are recorded by the build command and PR acceptance
report. Host HTTP/TLS tests establish the mapped fixture's behavior, not Internet deployment.
Container tests establish local Linux image packaging, identity preservation and refusal.
Public source/image distribution, public HTTPS reachability and physical Android acceptance
are **NOT RUN** here and remain later release/physical gates. Both repositories stay private.

## Identity update, withdrawal and result freshness (#337)

Keep the old runtime's state volume, configured origin and unlock secret intact. Provision
replacement identity in a new private state directory with explicit bootstrap and a new
unlock secret. Never overwrite the old sealed key or reinterpret its pending capabilities.
For same-DID key rotation, use a separate runtime process: each process retains its original
DID/key snapshot. Provisioning alone conveys no registry authority.

Read the owner-authenticated registration to obtain its current revision. Request
`POST /api/projects/{project}/verifiers/{registration}/challenges` with the replacement
`origin`, `did`, `key_id`, `public_jwk` and `expected_revision`. Have the replacement
runtime sign the returned nonce/audience through its separate authenticated management
listener, then complete the returned challenge path with that JWT and the project bearer.
The registry preserves the registration ID and existing grant scope. Switch the public DID
endpoint to the intended replacement while proving it. See the [registry lifecycle contract](../../docs/partner/verifier-registration.md) for exact owner failures and
permanent identity reservations. A changed origin requires separately provisioned state;
starting established state with a different origin fails without modifying its files.

The old process can use only its already authenticated cache before that cache's original
expiry (at most 300 seconds). Refresh authenticates the current registry document and
cannot grant the old key the replacement's permission. Old protected results also retain
their original evidence deadline; refreshed authority cannot extend them. Consumption
rechecks current exact permission and status and returns a one-time, claim-free refusal if
either no longer authorizes delivery. The completed ceremony's 120-second request deadline
is distinct from its maximum 240-second storage retention. A caller should consume promptly
and apply its own eligibility/login policy to the typed values.

Withdraw with owner-authenticated `DELETE /api/projects/{project}/verifiers/{registration}`
and `{expected_revision}`. Withdrawal needs no reachable old endpoint. Refresh each running
runtime; a withdrawn snapshot refuses new requests and delivery of unconsumed verified
claims. An unreachable registry does not prolong old authority: existing evidence is usable
only until every original signed/configured bound expires, then fails closed. Restart discards
all sessions, results and caches; preserving identity does not preserve ceremony capabilities.

| #337 acceptance                                                        | Evidence across the two children                                                                                                                                                                      |
| ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Owner update/withdrawal, stable registration and immutable grant scope | #379 verifier lifecycle HTTP suite and registry contract                                                                                                                                              |
| Fresh exact endpoint/key proof, revisions, replay and reservations     | #379 exact-target/revision/concurrency/withdrawn-owner HTTP negatives and migration0022                                                                                                               |
| Actual new-key requests and old-key refusals                           | #380 registered setup: actual Government receipt → enrolment → Education, separate same-DID signer processes, authenticated key and origin updates, old pending/completed refusals and new ceremonies |
| Completed results, current permission/status and original deadline     | #380 session HTTP cases: withdrawal, refreshed revocation, immutable deadline, signed fractional credential expiry and one-time races                                                                 |
| Request lifetime versus completed retention                            | #380 HTTP request expiry at120 seconds, verified completed consumption after120 seconds and retirement at240 seconds                                                                                  |
| Offline bounds and preserved identity                                  | Registered setup fresh disconnected ceremony; independent evidence-bound HTTP corpus; existing startup/restart/missing/corrupt/unlock/origin-refusal tests                                            |

These are host HTTP/core and local persistence checks. Physical Android, public deployment
and release remain **NOT RUN**; #337 integration acceptance requires both child gates.
