# Generic kit acceptance evidence

The exported production source is pinned to monorepo
`5f00a507a892200cf1fd3b857dc875d556f16c17`. The original source hashes and explicit
kit transformations are checked by `tests/export-boundary.test.mjs`.

`pnpm acceptance:generic CONFIG INPUT [TRANSPORT_MODULE]` exercises an independently
configured issuer, verifier, registry and wallet provider through their real HTTP
interfaces. CONFIG is the protected `GenericConfig` input to `openGeneric`. INPUT
contains `claims` and `expectedClaims`; the latter is the exact permitted disclosure.
An optional transport module exports `client` with the shipped HTTP client contract,
including bounded bodies and deadlines. Keep configuration, holder state, owner
credentials, capabilities, responses and transport mappings outside version control.
The command fails if any required phase or exact result check fails; it has no skip
path. Its protected state records the offer, original proof/delivery, correlated
session, typed result and report. The ordinary `check` command covers runtime/binding behavior, packaging and portable
tool regressions. The separate required core/conformance command is
`cargo +1.92.0 test --locked --package identity-core`; its recorded run passed all 99
tests with zero ignored (`.logs/408-core-rust192.log`). Independently configured
HTTP acceptance is a separate required delivery check, not an implied result of it.

Production containers built from exact kit source
`95a9da7a73d9fe2c2f1e414607ec76e8c586b316` supplied the following local checks.
All producer/registry/provider fixtures remained outside the delivered kit. Signing,
credential and grant authentication, selective disclosure and status verification
used the exported Rust core.

| Contract | Recorded local evidence in `.logs/` |
| --- | --- |
| Scalar false value, exact claims and correlated typed result | `408-scalar-green.log` |
| Nested sibling withheld; whole object/array preserves false and zero | `408-structured-left.log`, `408-structured-whole.log` |
| Permission withdrawn after native signing: no presentation write | `408-permission-red.log`, `408-permission-v2-green.log` |
| A presentation at independent B permits idempotent B issuance | `408-continuation-present.log`, `408-continuation-receive.log` |
| Restored negative status pins bind to authenticated grant | `408-status-binding-red.log`, `408-status-binding-green.log` |
| Revocation during renewal proof: no authorize write | `408-renewal-withdraw-red.log`, `408-renewal-withdraw-green.log` |
| Renewal successor retry, restart confirmation and status | `408-renewal-success-issue.log`, `408-renewal-success-confirm.log` |
| Signed-iat renewal helper: receipt-time-valid negative refuses before authorize; positive and interrupted delivery/restart remain valid | `408-historical-renewal-red.log`, `408-historical-renewal-green.log`, `408-renewal-signed-iat-success.log`, `408-renewal-signed-iat-confirm.log`, `408-renewal-signed-iat-loss.log`, `408-renewal-signed-iat-recover.log` |
| Lost successor reply, exact response recovery after restart, cancellation | `408-renewal-loss.log`, `408-renewal-recover-cancel.log` |
| Rotation stage, registry completion and activation lost replies recover | `408-rotation-stage-loss.log`, `408-rotation-registry-loss.log`, `408-rotation-activation-loss.log`, `408-rotation-boundaries-recovered.log` |
| Retained key presents; frozen set refuses new key; cross-issuer refuses; withdrawn positive fails; original negative survives outage | `408-key-history.log` |
| Core-signed unsupported DCQL controls refused without disclosure | `408-dcql-negative-green.log`, plus `tests/generic-query.test.mjs` |

The #429 binding refresh was rebuilt locally from the exact new source above,
with its separate test addon. All five imported public Node renewal-predecessor
checks passed (`408-renewal-binding-public-tests.log`). Actual HTTP producer
containers remain honestly pinned to the older kit image listed above; the
new local consumer calls the unchanged core algorithm through the new adapter.
The private signed-iat negative fixture authenticates a fresh B credential, adds
`nbf` at its original issuance time, shifts signed `iat` 61 seconds earlier and
keeps `validFrom` consistent with that shifted `iat`. It preserves expiry,
disclosures, ID, allocation and holder. Ordinary receipt-time validation succeeds;
renewal-only validation exceeds the existing 60-second skew and refuses. Baseline
caller sent one authorize POST; the corrected caller sends none. No time tolerance,
core algorithm or production producer was changed.

The malicious DCQL request was signed in a separate private helper using the
established verifier's sealed Rust signing identity. It added an unsupported `values`
control to an otherwise actual Request Object. No new signing endpoint or private
key export was used. Its baseline log `408-dcql-negative-red.log` was obstructed by
a strict status-list time check; it is not evidence of baseline presentation acceptance.
The exact-shape regression and actual signed refusal establish the corrected behavior.

The first standalone gate passed every runtime test except a Docker fixture scratch
mount, corrected by using the kit's ignored artifact directory. Gate 2 passed the
packaged container replacement/restore check and all but one unchanged proof-store
contention assertion: expected `EVIDENCE_STALE`, observed `EVIDENCE_UNAVAILABLE`.
Three focused repeats passed unchanged. The timing failure remains unresolved;
these repeats do not prove its cause. Final standalone gate, distinct-source image
upgrade, final source/image inspection and exact-head PR CI must be recorded against
the reviewed final commit before integration.

Physical phone and hardware key custody are **NOT RUN**. These local software-holder
checks do not replace the #338/#348 operator gates or #410's full candidate matrix.
