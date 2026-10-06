# CredWorks integration kit

Project code is licensed under [Apache-2.0](LICENSE); third-party notices remain in force.
Read the [distribution status and limits](DISTRIBUTION.md) before selecting an artifact.

The [canonical partner integration guide](docs/partner/overview.md) covers generic setup, definitions, HTTP APIs and lifecycle operations on the revision-pinned #408 source. Start there for the configurable issuer/verifier kit. Both repositories remain private; physical and public release checks remain NOT RUN.

The existing Education instructions below retain their original frozen source scope. The [canonical Education integration guide](docs/education/overview.md) covers setup, profiles, API, operations and preparation limits.

This private kit exports completed Education source from
`TDS-Digital-ID/university-vc-monorepo` at
`14096ed41ee259e81414fcfa0c3b2ad622a5b426`. It supports Education sign-in and
identifier-free eligibility. It does not distribute an issuer service, a wallet APK,
private ecosystem services, or Git history. Generic issuance is outside this source pin.

Use Node 22.22.0, pnpm 10.34.4 and Rust 1.92.0. The files in `provenance/` record the
allowlist, original hashes and packaging transforms. Frozen builds require only public
package registries; no monorepo mount, private credentials or private service source is
required.

```sh
pnpm install --frozen-lockfile
CARGO_BUILD_JOBS=2 pnpm build
pnpm lint
pnpm exec tsc -p tool/tsconfig.json
pnpm test:boundary
CARGO_BUILD_JOBS=2 PARTNER_SESSION_HTTP_PORT=38710 PARTNER_EVIDENCE_HTTP_PORT=38712 pnpm test:fixtures
```

The default addon is fixture-free. Conformance builds write `native-test` and execute
unchanged assertions in a disposable workspace; they never replace production `native`.
The conformance test output is test material, not a distribution artifact.

## Provision and register the verifier

An operator supplies public HTTPS routing to the runtime's public listener, an
independent trust-registry origin/DID/public anchor, the accepted Education issuer/key,
and signed revocation/suspension sources. Hostname/CA checks and signed authority remain
mandatory. Registration cannot use a private-network production resolver bypass.

Set protected environment variables in the shell without writing them to logs:
`PARTNER_ORIGIN`, `PARTNER_STATE_DIR`, `PARTNER_UNLOCK_KEY` (32 random bytes encoded
base64url), and `PARTNER_MANAGEMENT_TOKEN` (at least 32 bytes). Preserve the unlock secret
and state together. Management binds only to loopback. Bootstrap exactly once:

```sh
mkdir -p .logs
pnpm --filter @unsw-vc/partner-runtime bootstrap
pnpm --filter @unsw-vc/partner-runtime start 2>&1 | tee .logs/partner-runtime.log
```

Initially leave `PARTNER_VERIFIER_CONFIG` unset. The runtime still serves its DID and
protected ownership-proof interface. In another shell, create a mode-0600 registration
configuration containing `registryOrigin`, `registryDid`, `trustAnchorJwk`,
`educationIssuerDid`, `runtimeOrigin`, `managementOrigin` (the exact loopback origin),
and `managementToken`. Run:

```sh
pnpm register /absolute/private/register.json /absolute/private/registration-result.json
```

This creates a project, fetches a challenge, signs it through protected runtime HTTP,
completes ownership, and verifies both signed Education permissions. It writes project
management credentials only to a newly created mode-0600 output, never stdout.

Populate `apps/partner-runtime/examples/verifier.json` into an operator-owned public
configuration file with the pinned issuer/key, independent registry origin/anchor and
actual status URLs/keys. Stop the initial runtime, set `PARTNER_VERIFIER_CONFIG` to that
file and run the same `start` command. Never bootstrap during replacement or delete
established state. Missing/corrupt established identity refuses startup.

## Run the application and HTTP acceptance

The reference app has its own PostgreSQL database and built-in migration ledger. Do not
point it at an ecosystem/registry database. Supply `EDUCATION_APP_DATABASE_URL`,
`EDUCATION_APP_ORIGIN` (public HTTPS), `EDUCATION_RUNTIME_MANAGEMENT` (loopback),
`PARTNER_MANAGEMENT_TOKEN`, `EDUCATION_TRUSTED_ISSUER`, `EDUCATION_VERIFIER_DID` and
`EDUCATION_INSTITUTION`. Run:

```sh
pnpm --filter @unsw-vc/education-sign-in start 2>&1 | tee .logs/education-sign-in.log
```

The browser app uses Secure/HttpOnly/SameSite cookies, CSRF and protected one-time
runtime results. A public `status: accepted` is delivery acknowledgement, not verification.
See the app's packaged OpenAPI and the runtime's `openapi.json`.

The driver requires this registered runtime/application and public synthetic sandbox
services. Its protected JSON configuration contains `registryOrigin`, `registryDid`,
`trustAnchorJwk`, `portalOrigin`, `providerOrigin`, `applicationOrigin`, `runtimeOrigin`,
`governmentIssuerDid`, `educationIssuerDid` and a disposable `stateDir`. Run:

```sh
pnpm acceptance /absolute/private/education-http.json
```

It generates a fresh Rust-held holder key, obtains provider-signed WIA using explicitly
self-asserted **mock platform attestation**, receives synthetic Government credentials,
consents to the exact authenticated enrolment profile, then receives Education. It checks
independent signed permission/request authority before sign-in and eligibility ceremonies,
browser correlation refusal, account continuity and one-time completion. It never imports
private ecosystem source or prints credentials/capabilities. Mock WIA is sandbox evidence,
not hardware attestation or physical wallet acceptance.

This driver alone is not a claim of clean self-service setup: bootstrap, HTTPS routing,
registration, configuration/restart and application/database provisioning are required
operational steps. The complete candidate/setup sibling will execute the full sequence.

## Revision-labelled containers

Build from a checksum-verified source archive or clean committed checkout. Set `SOURCE_REVISION` to the full source revision recorded in its release manifest; a Git checkout may use its clean HEAD. This labels a new build, not the preserved historical image:

```sh
REVISION=${SOURCE_REVISION:?set the full source revision from the release manifest}
docker build --build-arg SOURCE_REVISION="$REVISION" -f apps/partner-runtime/Dockerfile -t "credworks-partner:git-$REVISION" .
docker build --build-arg SOURCE_REVISION="$REVISION" -f apps/education-sign-in/Dockerfile -t "credworks-education:git-$REVISION" .
```

`infra/partner/compose.yml` preserves identity state; `infra/education-sign-in/compose.yml`
adds the browser app and optional dedicated PostgreSQL. Pin both images and public
configuration explicitly. The public listener may be forwarded through the operator's
HTTPS gateway; management remains inaccessible from the host network in Compose.
Container operational commands run inside that network namespace, not through a
published management port. The build scans the production addon and removes the
fixture-aware scanner before final COPY. Final artifact evidence records observed
image IDs and layer checks separately from source provenance.

The producer repositories remain private. Project-owned code is Apache-2.0; third-party
font notices retain their own terms. Public preview availability and remaining acceptance
are recorded separately under #338. This child
prepares source/build delivery, not a complete release candidate. Public deployment and
physical Android acceptance are **NOT RUN**.
