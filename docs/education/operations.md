# Operations and limits

## Endpoint roles and secrets

| Role | Destination | Material / purpose |
| --- | --- | --- |
| Runtime public | Own registered HTTPS origin | DID, signed request, wallet direct_post; public ceremony capabilities |
| Runtime management | Exact http://127.0.0.1:3081 | Runtime bearer; ownership proof, sessions, one-time results, evidence refresh |
| Registry | Independently provisioned HTTPS origin/DID/key | Project-scoped bearer for writes; signed trust and scoped permissions |
| Education issuer / portal | Metadata-named issuer and authorization-server origins | Synthetic offers, Government enrolment, Education receipt |
| Wallet provider | Provisioned HTTPS origin | Provider-signed mock WIA for sandbox issuance |
| Status | 1–4 configured HTTPS URLs/keys/purposes | Authenticated revocation/suspension data; no credential-directed URL fetch |
| Browser application | Separate configured HTTPS origin | Secure cookie and CSRF; application authorization |
| Application DB | Dedicated PostgreSQL | Persistent account mapping; never ecosystem tables |

Never put runtime bearer, project credential, unlock secret, browser cookie/CSRF or result correlation capability in a QR, public URL, source, logs or issue report. Request/activation URIs are ceremony data but should not be logged either. Retain protected output locally and delete disposable test state when no longer needed.

## Freshness and diagnostics

Requests expire at creation plus 120 seconds; retrieval cannot extend them. Results persist at most creation plus 240 seconds. A completed request may be consumed after 120 seconds only while its original evidence deadline and current scope/status remain valid. Evidence expires at the minimum signed trust/permission/status expiry and configured cache age of 1–300 seconds, additionally bounded by signed credential expiry for results. Registry permission publication lasts five minutes. Fresh offline evidence works; stale or missing evidence fails closed.

Refresh explicitly through protected `POST /management/evidence/refresh` before expiry. Successful refresh withdrawing permission affects pending sessions and completed results. Failed refresh retains only still-fresh prior evidence. Revocation/withdrawal detection therefore follows the authenticated cache bound, at most 300 seconds, and can occur earlier on refresh. No old result deadline is extended.

| Symptom / HTTP | Stable code and action |
| --- | --- |
| Identity startup refusal | partner_identity_unavailable; inspect protected mount/origin/permissions/unlock secret, do not bootstrap |
| 400 | SESSION_BAD_REQUEST, RESPONSE_BAD_REQUEST, RESPONSE_STATE_MISMATCH; check exact fields/state |
| 401 / 403 | SESSION_ACCESS_DENIED / SCOPE_NOT_PERMITTED; check runtime bearer, correlation capability and exact signed grant |
| 409 | RESULT_PENDING, RESULT_CONSUMED, SESSION_ALREADY_COMPLETED; wait only while pending, otherwise start a new ceremony |
| 410 | SESSION_EXPIRED; create a fresh request, never reuse the capability |
| 503 | EVIDENCE_UNAVAILABLE, EVIDENCE_STALE, EVIDENCE_REFRESH_FAILED, PERMISSION_VERSION_UNSUPPORTED; check independent pins and signed freshness |
| Verification refusal | INVALID_SIGNATURE, BINDING_CHECK_FAILED, FRESHNESS_CHECK_FAILED, MISSING_DISCLOSURE, STATUS_CHECK_FAILED; never grant access |
| App refusal | CSRF_REFUSED, INTERACTION_NOT_FOUND/CONSUMED/EXPIRED, EVIDENCE_STALE, ENROLMENT_REQUIRED, INSTITUTION_NOT_ALLOWED, STUDENT_ID_INVALID |
| Availability | RUNTIME_UNAVAILABLE, APPLICATION_UNAVAILABLE; use sanitized readiness logs, start a new interaction after uncertain completion |

Read `.logs/partner-runtime.log`, `.logs/education-sign-in.log`, `.logs/education-caddy.log` and `.logs/education-tunnel.log`. Report source revision, image ID/label, UTC time, route/method, HTTP status and fixed code only. Omit claim values, tokens, keys, raw upstream bodies and personal/device identifiers.

## Runnable negative checks

Run the existing kit checks at the published HTTP boundaries after the production build:

```sh
# Dedicated app-test database and isolated ports; never production storage:
EDUCATION_APP_DATABASE_URL="$TEST_APP_DATABASE_URL" EDUCATION_APP_TEST_PORT=38821 pnpm test:boundary
PARTNER_SESSION_HTTP_PORT=38810 PARTNER_EVIDENCE_HTTP_PORT=38812 pnpm test:fixtures
```

Missing opt-in database/container variables skip their checks and are not acceptance evidence. The real runtime/session suites cover wrong signature/holder/audience/nonce/state, expiry, exact scope, replay/concurrent result consumption, stale/withdrawn authority and revoked evidence. The standalone browser HTTP suite checks secure cookies, missing browser authentication, CSRF and unsupported profiles. The acceptance driver separately checks another-browser completion and account continuity. Incorrect policy values and the complete operational negative matrix require the existing ecosystem/runtime/application acceptance suites in #389; this kit command alone does not establish those observations. To verify local ingress separation without credentials:

```sh
curl --fail https://partner.example.org/.well-known/did.json
curl -s -o /dev/null -w '%{http_code}\n' https://partner.example.org/management/sessions
# Expect 404 from default-deny ingress; never 200 or a management result.
```

The [acceptance driver](quickstart.md#synthetic-onboarding-and-acceptance) exercises actual public HTTP synthetic issuance and presentation. These checks do not establish physical phone authorization or public tunnel availability. #389 records the full clean run and exact artifact combination separately.

## Install, update and recovery

Build revision-labelled images only from a clean committed checkout:

```sh
REVISION=$(git rev-parse HEAD)
docker build --build-arg SOURCE_REVISION="$REVISION" -f apps/partner-runtime/Dockerfile -t "credworks-partner:git-$REVISION" .
docker build --build-arg SOURCE_REVISION="$REVISION" -f apps/education-sign-in/Dockerfile -t "credworks-education:git-$REVISION" .
docker image inspect "credworks-partner:git-$REVISION" --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
```

Use the supplied `infra/partner/compose.yml` or `infra/education-sign-in/compose.yml`, pin images/config, preserve `partner_identity` and `education_accounts`, and inject secrets. The app/runtime share a network namespace for loopback management. Container registration callers must run in that namespace; the host registration tool above applies to native host operation. Never publish a management port. Optional Compose `local-db` needs a URL-safe `EDUCATION_DB_PASSWORD` and database URL `postgres://education:<password>@database:5432/education`; the password interpolation is required even with a managed database.

Before replacement stop the runtime, back up the entire 0700 identity directory with both `identity.json` and 0600 `signing-key.sealed`, preserve their permissions/origin, and separately retain its unlock secret. Back up the dedicated account DB consistently using PostgreSQL tooling. Test restore in an isolated stopped deployment, never two active copies of one signing identity. Start the replacement with `start`, never `bootstrap`. Missing/corrupt established state refuses. State version 1, endpoint changes and signing-key rotation have no automatic migration/rotation here; a new origin/key needs an explicit new identity and re-registration. Losing the key/unlock secret is not recoverable from the public DID. An old DB backup cannot reconstruct accounts created afterward.

Signing identity and application account mappings persist. Runtime sessions/results/evidence cache, browser sessions and interactions are ephemeral; restart logs browsers out and requires fresh ceremonies/evidence. No high availability or production custody assurance is claimed. The production addon excludes deterministic fixture installers; fixture-native output is separate test material.

#389 supplies the exact Android candidate revision/checksum/package/certificate. Verify those before installation, use the documented buildprod artifact, and retain existing holder state. A debug certificate is not a protected release signature and cannot establish upgrade compatibility with a differently signed installed app. Do not uninstall to disguise an upgrade failure. Protected release signing, actual installation/update, genuine holder prompt, accessibility and public reachability remain NOT RUN under #338. Public iOS and broad external-wallet interoperability are unsupported.
