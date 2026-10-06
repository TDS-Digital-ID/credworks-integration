# Partner setup and lifecycle

Start from the checksum-verified source archive supplied with the selected preview, or an authorized checkout of its recorded revision. This is an operator setup path, not an automatic hosted sandbox or a phone acceptance claim. See [revision pins and release gates](overview.md#revision-and-profile-matrix). The kit contains the runtime, migration chain, Rust core and host tools; registry/provider hosting and wallet artifacts are separate inputs.

## Prerequisites and build

Extract the source archive into a new directory and run the commands below from the directory containing `package.json`, `Cargo.lock` and `pnpm-lock.yaml`. Keep its distribution manifest and embedded `provenance/` files. No private Git checkout is needed for an exported archive. With an authorized checkout, select the full source revision recorded in the handoff instead of assuming the default branch is the candidate.

Install Node 22.22.0, pnpm 10.34.4, Rust 1.92.0, PostgreSQL tooling, curl and a working container runtime if using Compose. Supply two distinct HTTPS origins with valid certificates, independently authenticated registry origin/DID/P-256 anchor, provider DID/key, registry project ownership and a dedicated issuer PostgreSQL database. Do not use an ecosystem database or deterministic demo keys. A phone needs reachable HTTPS; local loopback and private CA fixtures do not establish that.

```sh
pnpm install --frozen-lockfile
CARGO_BUILD_JOBS=2 pnpm build
pnpm docs:check
pnpm exec tsc -p tool/tsconfig.json
```

A fresh source build needs public package registries, not private-monorepo access. For local images build from a clean committed revision and keep the resulting image IDs separate from the prepared #408 image pins:

```sh
REVISION=$(git rev-parse HEAD)
docker build --build-arg SOURCE_REVISION="$REVISION" -f apps/partner-runtime/Dockerfile -t "credworks-partner:git-$REVISION" .
docker image inspect "credworks-partner:git-$REVISION" --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
```

## Bootstrap distinct identities

Do this separately for issuer and verifier with distinct state, unlock secret, management token and origin. Inject protected secrets from operator storage. `PARTNER_UNLOCK_KEY` is exactly 32 random bytes in unpadded base64url; the management token is at least 32 bytes. Preserve both for replacement. Set the issuer/verifier public and management ports to different values if sharing a host.

```sh
umask 077
export PARTNER_ORIGIN=https://issuer.example
export PARTNER_STATE_DIR=/absolute/private/issuer-identity
export PARTNER_PUBLIC_PORT=3080
export PARTNER_MANAGEMENT_PORT=3081
# Inject PARTNER_UNLOCK_KEY and PARTNER_MANAGEMENT_TOKEN from protected storage.
# Initially omit issuer/verifier config while proving endpoint ownership.
pnpm --filter @unsw-vc/partner-runtime bootstrap
mkdir -p .logs
pnpm --filter @unsw-vc/partner-runtime start 2>&1 | tee .logs/partner-issuer.log
```

The verifier can use public port 3090 and management port 3091 with its own identity and origin. Bootstrap refuses an existing state directory. Replacement uses `start`, never bootstrap. Public routing forwards DID and enabled OID4VCI/OID4VP/renewal routes only; the management listener binds 127.0.0.1. Keep `/management/*` inaccessible through HTTPS ingress.

For issuance expose GET `/.well-known/did.json`, `/.well-known/openid-credential-issuer`, `/.well-known/oauth-authorization-server`, `/oid4vci/offers/*`, `/oid4vci/status/revocation.jwt` and `/partner-renewals/*`; expose POST `/oid4vci/token`, `/oid4vci/nonce`, `/oid4vci/credential` and the documented exact renewal action routes. Verifier public ingress needs GET `/oid4vp/request/*` and POST `/oid4vp/response/*`. Default-deny all other routes. Configure TLS through the operator's gateway, preserve hostname/CA checks, and never enable a private-network resolver bypass for production registration.

## Registration and authority

Use the shipped `openGeneric` host tool for `register('issuer')` and `register('verifier')`, or use curl through this exact HTTP sequence. Keep every returned body in protected local files. A runtime management bearer and a registry project bearer are different credentials.

1. Create an owner with `POST $REGISTRY/api/projects` and JSON `{}`. Save `project.project_id` and the once-issued `management_credential`.
2. POST `{"origin":...,"did":...,"key_id":...,"public_jwk":...}` to `/api/projects/{project_id}/issuers/challenges` or `/verifiers/challenges` with that project's bearer. Use actual public values from the runtime DID.
3. POST the returned exact `nonce` and `audience` to the runtime's loopback `/management/sign` with its runtime bearer. POST the resulting `{"jwt":...}` to the registry's original `/challenges/{challenge_id}/complete` with the project bearer. Challenges live 120 seconds; ownership proofs live at most 60 seconds. Never put bearers in query strings.
4. Register each [definition](definitions.md) under the issuer's proven root HTTPS namespace or its assigned `urn:project:{project UUID}:` namespace. Adopt the immutable definition for this actual issuer, then grant the separately registered verifier its exact profile and paths.

Save a JSON body with a `definition` wrapper as a protected `definition-request.json`. The issuer registration ID is distinct from the adoption/authorization ID and the verifier grant/permission ID.

```sh
curl --silent --show-error --fail-with-body -X POST \
  "$REGISTRY/api/projects/$PROJECT_ID/issuers/$ISSUER_ID/definitions" \
  -H "Authorization: Bearer $PROJECT_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @definition-request.json -o definition-created.json
# Retain returned definition_record_id as DEFINITION_RECORD_ID.
curl --silent --show-error --fail-with-body -X POST \
  "$REGISTRY/api/projects/$PROJECT_ID/issuers/$ISSUER_ID/adoptions" \
  -H "Authorization: Bearer $PROJECT_TOKEN" -H 'Content-Type: application/json' \
  --data "{\"definition_record_id\":\"$DEFINITION_RECORD_ID\"}" -o adoption.json
# Retain adoption_id as ADOPTION_ID. VERIFIER_ID is the proven verifier registration.
curl --silent --show-error --fail-with-body -X POST \
  "$REGISTRY/api/projects/$PROJECT_ID/issuers/$ISSUER_ID/adoptions/$ADOPTION_ID/verifier-grants" \
  -H "Authorization: Bearer $PROJECT_TOKEN" -H 'Content-Type: application/json' \
  --data "{\"verifier_registration_id\":\"$VERIFIER_ID\",\"profile_name\":\"enabled_only\",\"claim_paths\":[[\"credentialSubject\",\"enabled\"]]}" -o grant.json
```

Read the returned `metadata_url`, `authorization_url` and `permission_url`; independently verify signed authority with the configured registry anchor. Project credential possession cannot self-authorize Education or another issuer. Changed immutable versions refuse; create a new version instead.

## Configure issuer and verifier

Populate the shipped [issuer input](../../apps/partner-runtime/examples/issuer.json) or [structured issuer input](../../apps/partner-runtime/examples/structured-issuer.json) with the actual dedicated DB URL, registry/provider pins, adoption UUIDs, configuration selectors and definition IDs. Populate [scalar verifier](../../apps/partner-runtime/examples/scalar-verifier.json) or [structured verifier](../../apps/partner-runtime/examples/structured-verifier.json) with the issuer key, registry anchor, exact status URL/key/purpose and permission UUIDs. Those files are examples with placeholders, not working production configuration.

Stop both processes before changing configuration. For the issuer set `PARTNER_ISSUER_CONFIG` to its protected file, inject `PARTNER_ISSUER_DATABASE_URL` with the same dedicated database URL, migrate, and initialize issuer state once against the already established signing identity:

```sh
pnpm --filter @unsw-vc/partner-runtime db:migrate
pnpm --filter @unsw-vc/partner-runtime exec node --import tsx src/cli.ts bootstrap-issuer
pnpm --filter @unsw-vc/partner-runtime start 2>&1 | tee .logs/partner-issuer.log
```

For the verifier set `PARTNER_VERIFIER_CONFIG` to its actual public configuration file and restart using `start`. Initial signed evidence failure refuses startup. A verifier-only deployment needs no issuer DB. A runtime may enable both roles explicitly, but a separately operated verifier has its own identity and state.

## Compose alternative

The shipped [issuer Compose](../../infra/partner-issuer/compose.yml) extends the [base runtime Compose](../../infra/partner/compose.yml). Inject `PARTNER_IMAGE`, `PARTNER_ORIGIN`, `PARTNER_CONFIG_DIR`, preserved unlock/token and `PARTNER_ISSUER_POSTGRES_PASSWORD`. The password interpolation is required even if using an external database. With optional `local-db`, the issuer URL is `postgres://credworks:<URL-safe-password>@issuer-db:5432/partner_issuer`. Place issuer config at `/config/issuer.json`; do not commit its database secret.

```sh
docker compose -p partner-issuer -f infra/partner-issuer/compose.yml --profile local-db up -d issuer-db
# One-time identity bootstrap with issuer config disabled; preserve its named volume.
docker compose -p partner-issuer -f infra/partner-issuer/compose.yml run --rm -e PARTNER_ISSUER_CONFIG= partner bootstrap
# Migration CLI is not the image entrypoint, so override it explicitly.
docker compose -p partner-issuer -f infra/partner-issuer/compose.yml run --rm \
  -e PARTNER_ISSUER_DATABASE_URL --entrypoint node partner --import tsx src/issuer-migrate.ts
# After registration and configured adoption IDs, initialize the dedicated ledger once.
docker compose -p partner-issuer -f infra/partner-issuer/compose.yml run --rm partner bootstrap-issuer
docker compose -p partner-issuer -f infra/partner-issuer/compose.yml up -d partner
```

Register after the identity-only public service is reachable, before initializing configured issuer authority. Issuer Compose hardcodes `/config/issuer.json`; changing a host environment variable does not disable it. For that initial ownership step use base Compose with the same project and volume, then stop it before switching to issuer Compose:

```sh
PARTNER_ISSUER_CONFIG= PARTNER_VERIFIER_CONFIG= docker compose -p partner-issuer -f infra/partner/compose.yml up -d partner
# Complete ownership and save the real adoption/configuration IDs, then:
docker compose -p partner-issuer -f infra/partner/compose.yml stop partner
# Use issuer Compose migration/bootstrap-issuer/up commands above with that same project.
```

Run registry signing calls from within the partner's network namespace, for example `docker compose ... exec partner curl ...` against 127.0.0.1:3081. Host loopback cannot reach container management. Use a distinct Compose project and `/config/verifier.json` for the verifier; set `PARTNER_VERIFIER_CONFIG=/config/verifier.json` and use only base Compose. Never share the issuer volume, secrets or DB. The published host port is loopback for the HTTPS gateway; override `PARTNER_HOST_PORT` when both run on one host. Compose logs use bounded container logging; capture diagnostics into `.logs/` if needed.

## Host software-holder lifecycle

Create a mode-0600 JSON config for [GenericConfig](../../tool/generic-http.ts) outside source. It requires `registryOrigin`, `registryDid`, `trustAnchorJwk`, `providerOrigin`, `providerDid`, `providerJwk`, `issuerOrigin`, `issuerManagementOrigin`, `issuerManagementToken`, `verifierOrigin`, `verifierManagementOrigin`, `verifierManagementToken`, `stateDir`, `configurationId`, `definitionId`, `definitionVersion`, `credentialType`, `profileName`, `claimPaths`, `authorizationPath`, `permissionPath`, `statusKeyId` and `statusPublicJwk`. Optional `verifierConfigurationId` permits a different local verifier selector. Rotation/withdrawal additionally require `projectId`, `ownerCredential` and `issuerRegistrationId`. Public origins must be exact HTTPS origins; management must be exact HTTP 127.0.0.1 origins. Use a new empty 0700 holder state directory and keep protected 0600 output and holder key together.

For the neutral entitlement and `enabled_only` profile, a protected input contains:

```json
{"claims":{"enabled":false,"credits":0},"expectedClaims":{"enabled":false}}
```

```sh
pnpm acceptance:generic /absolute/private/generic.json /absolute/private/entitlement-input.json
```

The driver refreshes verifier evidence, creates a recipient-thumbprint-bound offer, receives and verifies the credential with provider-signed mock WIA, durably saves the host receipt, presents exact paths and consumes a correlated typed result once. It generates timestamps at execution, preserves false/zero and refuses any incomplete phase. No mandatory application-language SDK is needed; the service contract is HTTP. This shipped driver is a software holder, not the Android wallet and not genuine hardware attestation. An optional third transport-module argument is an operator/test adapter; default public use keeps the shipped bounded HTTP client and real TLS verification.

For structured examples use `pair-v1` issuer configuration, `left_only` or `whole` verifier profile and its matching protected expected claims. Repeat using `snapshot-v1` and `whole` with its separately authorized definition. For pair left_only, expectedClaims is `{"left":{"name":"North"}}` for the shipped subject. For pair whole, expectedClaims contains the complete shipped details and entries values. For snapshot whole use its separate details/entries values. Results preserve nested subject hierarchy and full paths in evidence. #410 supplies the full tested candidate input inventory.

The lower-level CLI takes a protected file with `{"args":[...]}` and writes its result only to `stateDir/output.json`:

```sh
node --import tsx tool/generic-http.ts /absolute/private/generic.json createSession /absolute/private/session-args.json
node --import tsx tool/generic-http.ts /absolute/private/generic.json renewalStatus /absolute/private/renewal-status-args.json
```

`session-args.json` can contain `{"args":["application-operation-1","Present selected credential"]}`. Renewal status takes `{"args":["saved-renewal-operation-name"]}`. Supported operations are `register`, `createOffer`, `receive`, `createSession`, `present`, `result`, `continue`, `createRenewal`, `renew`, `renewalStatus`, `cancel`, `confirm`, `rotate`, `withdraw`, `revoke`, `status` and `verifyRestored`. Use saved exact receipt/session objects for operations that need them, not invented IDs. `continue(session,input,name)` applies only when the destination issuer role is enabled on that verifier runtime and binds its offer to the successfully verified holder. [API](api.md) and [operations](operations.md#receipt-confirmed-renewal) describe retry and confirmation limits.

Run `pnpm check` and the [negative checks](operations.md#checks-and-troubleshooting) with disposable test state and opt-in databases. #410 owns complete candidate execution, exact Android inventory and operator handoff. Physical checks remain NOT RUN; #338/#348 and Release B after Release A remain release gates.
