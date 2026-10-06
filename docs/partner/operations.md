# Partner operations and limits

Keep operator secrets, raw credentials, claims, offer/request URLs, capabilities, browser cookies and private holder state outside source, image contexts and issue reports. Runtime management credentials, registry project credentials, issuer access tokens and session correlation capabilities have different scopes. The [API](api.md#endpoint-roles-and-credentials) defines their roles. Public diagnostics contain revision, image ID/platform, UTC time, route/method, status and fixed refusal code only.

## Status, cache bounds and issuer offline limits

The issuer supports permanent revocation of one exact committed issuance. `GET /management/issuer/issuances/{issuance_id}/status` is credential-free; POST with exactly `{"state":"revoked"}` sets only that issuance's bit. Retry preserves its original revocation time. Unissued IDs refuse. Suspension, reinstatement and clearing a revoked bit are unsupported. Signed status lists retain the bootstrap identity/key even after credential-key rotation.

Verifier cache age is configured from 1–300 seconds and capped by authenticated signed trust/permission/status expiry. Registry publications and issuer status publication have five-minute validity. Signed credential expiry additionally bounds a positive result. Revocation and permission/project/key withdrawal take effect on successful refresh or no later than the previously authenticated deadline, at most 300 seconds. There is no live CredWorks authorization call required for each presentation. Schedule protected `POST /management/evidence/refresh` before expiry; failure retains only still-fresh evidence and never adds grace or extends an older result deadline.

Fresh cached evidence permits verification during issuer/registry outage only inside those original bounds. Issuance, new registry ownership changes, renewal authorization and receipt confirmation still need their relevant live services and current evidence. Restart loses positive caches; a verifier cannot cold-start offline by inventing fresh trust. The host generic driver fetches live evidence for its operations and is not a substitute for runtime offline-cache checks.

Requests expire 120 seconds after creation; fetching them never extends expiry. Results persist at most 240 seconds after creation. A completed request may yield its result after the request deadline only before the original evidence deadline and with current exact permission/status. Consumption is correlated and one-time. Failed or uncertain completion starts a new ceremony when the original disposition cannot be recovered. A new ceremony cannot restore already consumed source issuance authorization.

The verifier retains original authenticated negative observations with exact issuer key/pin, credential ID/status tuple, status authority and observation time. Withdrawal or an outage cannot make a known revoked instance active. Preserve its entire signed proof store and incident lock. An old active status list does not undo an already authenticated negative; never delete proofs or marker files to make verification pass.

## Retained-key rotation

Credential-key rotation preserves the deployment's DID, bootstrap signer, status authority and historical credential bytes. A retained credential key is permitted for historical verification/recovery, not new minting. It does not rotate the bootstrap verifier/status signer or repair that signer's compromise.

1. Fence competing management writes and save `GET /management/issuer/keys` plus the issuer owner's registry GET revision. Stage one key with the exact `expected_revision`, `project_id`, `issuer_registration_id`, `expected_registry_revision` and new `key_fragment`. Fragments are 1–128 ASCII letters/digits/dot/underscore/hyphen; revisions are integers 0–2147483647. All 64 IDs, including bootstrap and abandoned attempts, are never reused.
2. Keep the preparing/staged request and material durable. Staging pauses new minting with `ISSUER_KEY_STAGING`. Retrieve the exact registry owner key challenge for `operation:rotate`, expected registry revision, new key ID and public JWK. Submit it unchanged to `/management/issuer/keys/proof` at the staged local revision. Complete the original registry challenge with its fresh proof before the original expiry.
3. Activate using `/management/issuer/keys/activate` with staged `expected_revision` and exact `key_id`. Activation authenticates current signed authority for every configured definition and unchanged status authority. Registry owner GET is coordination evidence, not activation authority. An expired or missing grant refuses.
4. Read local/owner state after lost replies. Retry the same stage/proof/activation operation; never choose a new fragment to guess its outcome. A preparing request may recover existing material or be explicitly abandoned at its current local revision. Abandon does not undo registry rotation or restore an old issuance grant. Missing established staged/retained/current material requires a consistent backup.

The shipped `rotate(fragment,operationName)` host operation preserves these requests and replies, authenticates completed authority and recovers lost boundaries. It needs protected project owner fields in GenericConfig. `withdraw(keyId)` uses the bootstrap ownership proof and registry owner challenge to withdraw positive credential authority. It does not delete retained keys or undo known negative status.

Generic verifier configuration still pins its original `scalar.issuerKeyId`/`issuerJwk` and separate bootstrap status key. Authenticated grants marked current or retained supply additional exact public key members resolved from the issuer DID; arbitrary DID members do not grant authority. Sessions freeze that membership. Rotation cannot silently admit a later key into an old request. Refresh evidence and create a new ceremony for newly accepted keys. Credentials signed by retained members remain verifiable only while definition, scoped permission, status and freshness checks pass. Withdrawn positive authority refuses while original negative history survives.

Offers and renewals pin their destination key at creation. After activation, unissued operations pinned to another key refuse rather than rebind or extend deadlines. Committed byte recovery uses the original key's verification authority. Cancel a stale unissued renewal or let its original lease expire, then explicitly authorize a new operation. Ordinary renewal can replace a retained-key predecessor with the current key, but its exact predecessor, holder and successor remain fixed.

## Receipt-confirmed renewal

Version 1 is a CredWorks application extension, not standard OID4VCI notification or an exactly-once transport guarantee. A signed credential or HTTP 200 does not prove durable wallet storage. Confirmation is the authenticated holder's assertion; the issuer cannot inspect the device write.

Create `/management/issuer/renewals` with the exact predecessor issuance ID, configured definition, complete new claims, validity and offer expiry, plus a private `Idempotency-Key`. Save the key and exact body once. The predecessor must be the exact held credential from this ledger and unrevoked. An expired predecessor may authorize renewal only through the core's dedicated signed-iat predecessor validation; it stays expired for presentation. The server derives the existing holder.

The holder reads the confidential proposal, authenticates issuer/definition/status, matches the exact predecessor, reviews replacement values and consents. It signs a fresh nonce proof with audience equal to the full `authorize_uri`, receives the same successor offer, then completes token/nonce/proof/WIA issuance. The response `x_credworks_renewal` identifies the operation, exact predecessor/successor, receipt and canonical same-origin confirm/status/cancel URIs.

Verify the successor and durably save it and pending receipt before sending `event:credential_accepted` with fresh same-holder proof bound to the entire confirm URI. The host `renew(name)` stores the verified successor and exact receipt; `confirm(name)` performs the separate confirmation. The Android wallet keeps normal holder authorization and its own encrypted persistence. Host state does not prove phone acceptance. Failed verification/storage leaves the predecessor retained and sends no confirmation.

| Original phase / interruption | Safe reconciliation |
| --- | --- |
| awaiting_holder, lost creation reply | Retry the same saved body/key; original lease is not extended |
| Lost authorize reply | Before original expiry use a fresh nonce/same-holder proof to recover the same offer |
| Lost token reply | Host tool reports TOKEN_DELIVERY_UNCERTAIN; never restore a spent pre-authorized code |
| Lost credential reply | Retry exact original token/proof/holder within original bounds; recover committed bytes, not a second allocation |
| awaiting_receipt | Issued successor does not prove storage; the live lease persists until confirmation or explicit cancellation |
| Lost confirmation / retiring | Fresh same-holder status/confirmation reconciles original receipt and exact successor; startup resumes persisted retirement |
| Cancellation wins | Invalidate unissued offer or revoke only unconfirmed successor, retaining predecessor |
| Confirmation wins / completed | Cancellation conflicts; repeated confirmation has one predecessor retirement effect |
| Urgent revocation races | Revocation remains permanent; renewal cannot revive either credential or clear its bit |

`renewalStatus(name)` is read/reconciliation, never first storage confirmation. Status/cancel/confirm proofs each use a new nonce and exact action URI audience; public POST query fields are refused. Expired unissued leases require a new authorized attempt. Expiry alone does not free an issued unconfirmed successor. The application must not invent a parallel operation while the original outcome is uncertain.

## Consistent backup, restore and upgrade

Stop and fence all issuer/verifier writers, management clients, replicas and migration jobs before capture. Preserve one generation, not selected rows or only the currently selected signing key.

| State | Capture together |
| --- | --- |
| Issuer PostgreSQL | Whole database and migration ledger, identity/key-selection row, all offers/tokens/nonces, allocation/revocation history and renewal operations |
| Issuer identity | Complete 0700 directory, 0600 identity.json/signing-key.sealed and entire credential-keys directory, retained/abandoned/staged files and original ciphertext hashes |
| Verifier identity | Distinct identity, revocation-proofs directory, inventory, pending proofs and revocation-proofs.lock incident marker |
| Operator configuration | Fixed origins, registry/provider/status pins, definitions/permissions, protected DB and management credentials, separately stored unlock secrets, TLS/routing and application state |
| Evidence | Source/image/platform, migration revision, public key inventory, backup cutoff and checksums; no secret values in public reports |

Use operator PostgreSQL tooling `pg_dump -Fc` and `pg_restore --single-transaction --exit-on-error`, and native `tar` preserving ownership/modes for whole volumes. With native host directories an example stopped-writer capture is:

```sh
umask 077
mkdir /absolute/private/new-backup
pg_dump -Fc "$PARTNER_ISSUER_DATABASE_URL" -f /absolute/private/new-backup/issuer.dump
tar -cpf /absolute/private/new-backup/issuer-identity.tar -C /absolute/private issuer-identity
tar -cpf /absolute/private/new-backup/verifier-identity.tar -C /absolute/private verifier-identity
```

A DB snapshot alone cannot make a concurrently copied identity consistent. Keep all writers stopped through capture, retain protected configs/unlock material separately and record checksums. For Compose copy complete named volumes read-only using native `tar` in the pinned image; preserve UID/GID 10001. Do not pass a source-directory path to archive an unrelated container volume.

Restore into new empty DB/volume resources, preserve original archives and fence the original deployment. Refuse an existing destination rather than erasing it. Restore ownership/modes, the entire DB, config and matching unlock secrets. Private DB address may change; public origin/DID/pins cannot. Start the same immutable image first with `start`. Never run `bootstrap` or `bootstrap-issuer` on restored established state.

For compatible upgrades take another stopped-writer backup, apply only bundled forward migrations through `db:migrate` or the container migration command in [setup](quickstart.md#compose-alternative), then launch the exact new image. Migration history is `partner_runtime_migrations.issuer_migrations`. #408 checked the specific prior kit image source 95a9da7a73d9fe2c2f1e414607ec76e8c586b316 to f632ec5caf8d917304501ad038b2aceef1e46bae, including whole-state/retained-key restoration. This is evidence for that pair, not arbitrary upgrades or downgrades.

Compare public DID and protected key inventory against the captured generation. Fetch fresh signed evidence, start new sessions and check retained/current credentials, exact revoked instances, consumed authorization and pending/completed renewals before switching traffic. Positive caches/sessions/results are ephemeral. A healthy port is insufficient. Keep staged minting paused until normal signed activation authority permits it.

A consistent old backup cannot detect or reconstruct later spent authorization, revocations, confirmations, negative observations or application writes. Once the replacement accepts writes, returning to the old snapshot loses those events. Preserve the newer stores for recovery; do not claim rollback safety, clear revoked bits or delete incident locks. Losing a sealed key/unlock secret cannot be repaired from its public DID. Changing the public hostname changes did:web identity and requires explicit new registration, not editing PARTNER_ORIGIN. Credential rotation cannot repair bootstrap compromise.

## Checks and troubleshooting

```sh
pnpm docs:check
pnpm exec tsc -p tool/tsconfig.json
pnpm test:boundary
CARGO_BUILD_JOBS=2 PARTNER_SESSION_HTTP_PORT=38710 PARTNER_EVIDENCE_HTTP_PORT=38712 pnpm test:fixtures
cargo +1.92.0 test --locked --package identity-core
pnpm acceptance:generic /absolute/private/generic.json /absolute/private/input.json
```

Use disposable test databases/isolated ports and the opt-in variables required by the existing suites. Missing opt-in container/database variables cause explicit skips, not acceptance. `pnpm check` is the full kit docs/type/boundary/fixture gate; acceptance against independently configured services is a separate command with no skip path. #410 owns the final two-definition lifecycle, status, receipt, key-history, negative/recovery and Android candidate inventory. A host software-holder check does not establish physical/public setup.

| Stable refusal | Action |
| --- | --- |
| partner_identity_unavailable | Check preserved origin, regular config files, state/modes, unlock, key files and listener/DB availability; never auto-bootstrap |
| PROJECT_AUTH_DENIED, REGISTRATION_PROOF_REFUSED | Use the correct active project bearer and original fresh endpoint/key challenge |
| DEFINITION_INVALID, GRANT_SCOPE_INVALID, DEFINITION_IMMUTABLE | Use the supported definition/path vocabulary; publish a new version for changed semantics |
| unauthorized, SESSION_ACCESS_DENIED | Correct runtime bearer and initiating correlation capability; issuer/project token cannot substitute |
| SESSION_BAD_REQUEST, RESPONSE_STATE_MISMATCH | Check exact input, supported selector/profile and original state |
| RESULT_PENDING, RESULT_CONSUMED, SESSION_ALREADY_COMPLETED, SESSION_EXPIRED | Respect one-time disposition and original deadlines; begin a new ceremony when required |
| EVIDENCE_STALE, EVIDENCE_UNAVAILABLE, EVIDENCE_REFRESH_FAILED | Check independently pinned signed sources and freshness; fail closed, do not extend caches |
| ISSUER_VALUES_INVALID, ISSUER_VALIDITY_INVALID, ISSUER_BINDING_MISMATCH | Match complete declared claims, integer validity and intended holder; do not coerce values |
| ISSUER_STATUS_UNSUPPORTED, ISSUER_ISSUANCE_NOT_FOUND, ISSUER_ISSUANCE_NOT_ISSUED | Target one committed issuance and revoked only; do not guess another record |
| ISSUER_KEY_REVISION_CONFLICT, ISSUER_KEY_CONFLICT, ISSUER_KEY_STAGING | Inspect original local/registry transition and frozen destination; retry saved exact input |
| ISSUER_KEY_STATE_UNAVAILABLE, ISSUER_STATE_UNAVAILABLE | Restore a complete consistent generation, preserve pending material and incident locks |
| ISSUER_RENEWAL_INVALID_PROOF, ISSUER_RENEWAL_BINDING_MISMATCH, ISSUER_RENEWAL_NOT_CONFIRMABLE | Reconcile original receipt/operation, use fresh exact same-holder proof; never bypass expiry/revocation/storage |
| TOKEN_DELIVERY_UNCERTAIN, PRIVATE_STATE_REFUSED | Retain protected host operation state; reconcile/cancel safely, never recreate established holder keys |
| INVALID_SIGNATURE, BINDING_CHECK_FAILED, STATUS_CHECK_FAILED, REQUEST_SCOPE_NOT_PERMITTED | Refuse disclosure/access; inspect authenticated pins, exact scope and signed evidence |

Read `.logs/partner-issuer.log` and `.logs/partner-verifier.log` or bounded container logs locally. Report only source/image pins and sanitized fixed codes. No framework, new cryptographic implementation or UI-driving suite is needed for these HTTP checks. Physical install/update, hardware authorization, consent and public release remain NOT RUN under #338/#348, and Release B publication follows Release A.
