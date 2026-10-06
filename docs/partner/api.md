# Partner HTTP API

The [complete runtime OpenAPI](../../apps/partner-runtime/openapi.json) is the exact contract for all 30 operations below. The [Education API](../education/api.md) retains its eight runtime examples and the unchanged [reference application contract](../../apps/education-sign-in/src/public/openapi.json). Runtime version 0.1.0 is not enough to identify compatible artifacts; use the [revision matrix](overview.md#revision-and-profile-matrix).

## Endpoint roles and credentials

| Destination | Authentication / purpose |
| --- | --- |
| Issuer/verifier public HTTPS | DID, metadata, signed requests, holder protocol and signed status; opaque ceremony/offer capabilities are sensitive |
| Runtime management, HTTP 127.0.0.1 | RuntimeBearer is the runtime's management token; keep it private and separate for each deployment |
| Protected session status/result/continuation | RuntimeBearer plus SessionCapability from the initiating session; never put this capability into a QR or public URL |
| Issuer credential endpoint | IssuerToken is the access_token returned by /oid4vci/token; a runtime management token cannot substitute |
| Registry management | Project-scoped bearer, distinct from runtime tokens; endpoint/key proof and issuer-owned definitions/grants |
| Registry/provider/status publications | Independently pinned origin, DID and public key; signature, scope and freshness checks still required |

Management routes are never public ingress. A public `status:accepted` means delivery admission, not verification or application eligibility. Consume the protected correlated result exactly once. A verified result carries typed claims and evidence; a refused result carries a stable code without claims. The application owns account mapping, value policy and cookies.

## Supported protocol and extensions

The issuer supports OID4VCI pre-authorized-code only, `jwt` holder proofs, configured wallet-instance attestation and `vc+sd-jwt`. It requires intended-recipient thumbprint authorization before creating an offer. Possession of the offer or proof key does not replace recipient authorization. Deferred/batch issuance, additional formats and arbitrary OAuth flows are not offered.

The verifier creates one DCQL credential query with registered exact paths, `decentralized_identifier` client ID, signed Request Object, `direct_post`, `state` and JSON `vp_token` mapping the profile/query ID to one SD-JWT+KB. `credworks_scalar` authenticates issuer/definition/profile and canonical authorization/permission publication paths. It carries either one credential key ID or a frozen exact key membership with thumbprints. It is an application extension, not standard OID4VP vocabulary. No arbitrary paths, anchors, URLs, value filters, alternate DCQL controls or overlapping disclosure units can be supplied by the session caller.

`x_credworks_renewal` version 1 and the `/partner-renewals/` messages are a receipt-confirmation application extension, not standard OID4VCI notification. See [renewal behavior](operations.md#receipt-confirmed-renewal). `Idempotency-Key` is required for linked issuance and renewal creation. Keep the same key and exact body for retry. The portable templates below show contract shape; obtain fresh actual values and retain the original private `IDEMPOTENCY_KEY` for those operations.

## Request templates

Set `ISSUER` to the issuer HTTPS origin, `PUBLIC` to the verifier HTTPS origin, `MANAGEMENT` to the appropriate private runtime listener, `MANAGEMENT_TOKEN` to its bearer, `ACCESS_TOKEN` to the issuer token and `CAPABILITY` to the protected session correlation capability. Shared Education templates use `MGMT` and `PARTNER_MANAGEMENT_TOKEN` for that verifier management listener/bearer and `STATE` for its signed session state. Replace `{...}` path slots with the exact returned IDs. JSON strings containing `$HOLDER_PROOF` or `$PROVIDER_ATTESTATION` are literal shape placeholders, not shell expansions. Prepare actual JSON in a protected file and use `--data-binary @request.json`; never paste credential proofs into a support log. Choose current NumericDate validity values within the registered definition and original offer lease. Fixed timestamps in these schema examples are not a runnable live lease. Set `RENEWAL_CAPABILITY` from the returned confidential renewal URI. GET renewal request requires exactly that single `capability` query field.

All 22 generic templates are checked against the `tool/examples/partner-runtime-http.json` in the same checked kit revision. Every table row, request media type, security scheme and request body is checked against current OpenAPI. Shared operations remain independently checked in Education as well.

| Method | Path | Request media | Security |
| --- | --- | --- | --- |
| GET | /.well-known/did.json | - | - |
| GET | /oid4vp/request/{capability} | - | - |
| POST | /oid4vp/response/{capability} | application/x-www-form-urlencoded | - |
| POST | /management/sign | application/json | RuntimeBearer |
| POST | /management/sessions | application/json | RuntimeBearer |
| GET | /management/sessions/{session_id} | - | RuntimeBearer,SessionCapability |
| POST | /management/sessions/{session_id}/result | application/json | RuntimeBearer,SessionCapability |
| POST | /management/evidence/refresh | application/json | RuntimeBearer |
| GET | /.well-known/oauth-authorization-server | - | - |
| GET | /.well-known/openid-credential-issuer | - | - |
| POST | /management/sessions/{session_id}/issuance-offer | application/json | RuntimeBearer,SessionCapability |
| POST | /management/issuer/offers | application/json | RuntimeBearer |
| GET | /oid4vci/offers/{id} | - | - |
| POST | /oid4vci/token | application/x-www-form-urlencoded | - |
| POST | /oid4vci/nonce | - | - |
| POST | /oid4vci/credential | application/json | IssuerToken |
| GET | /oid4vci/status/revocation.jwt | - | - |
| GET | /management/issuer/issuances/{issuance_id}/status | - | RuntimeBearer |
| POST | /management/issuer/issuances/{issuance_id}/status | application/json | RuntimeBearer |
| POST | /management/issuer/renewals | application/json | RuntimeBearer |
| GET | /partner-renewals/{renewal_id} | - | - |
| POST | /partner-renewals/{renewal_id}/authorize | application/json | - |
| POST | /partner-renewals/{renewal_id}/status | application/json | - |
| POST | /partner-renewals/{renewal_id}/cancel | application/json | - |
| POST | /partner-renewals/{renewal_id}/receipts/{receipt_id}/successors/{successor_issuance_id}/confirm | application/json | - |
| GET | /management/issuer/keys | - | RuntimeBearer |
| POST | /management/issuer/keys/stage | application/json | RuntimeBearer |
| POST | /management/issuer/keys/proof | application/json | RuntimeBearer |
| POST | /management/issuer/keys/activate | application/json | RuntimeBearer |
| POST | /management/issuer/keys/abandon | application/json | RuntimeBearer |

## GET /.well-known/did.json

Publishes the persistent DID and public verification methods. Private signing material never leaves the Rust signer.

```sh
# contract runtime GET /.well-known/did.json
curl --fail-with-body -X GET "$PUBLIC/.well-known/did.json"
```

Responses: 200 Persistent partner DID verification methods.

## GET /oid4vp/request/{capability}

Fetches the original signed request, without extending its 120-second lifetime.

```sh
# contract runtime GET /oid4vp/request/{capability}
curl --fail-with-body -X GET "$PUBLIC/oid4vp/request/{capability}"
```

Responses: 200 Signed authorization request; 404 Stable refusal; no diagnostics or claims; 410 Stable refusal; no diagnostics or claims.

## POST /oid4vp/response/{capability}

Admits one correlated wallet response. Public acknowledgement contains no verified claims.

```sh
# contract runtime POST /oid4vp/response/{capability}
curl --fail-with-body -X POST "$PUBLIC/oid4vp/response/{capability}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "state=$STATE" \
  --data-urlencode 'vp_token={"education_sign_in":["<SD-JWT+KB>"]}'
```

Responses: 200 Completion admitted; retrieve protected result; 400 Stable refusal; no diagnostics or claims; 404 Stable refusal; no diagnostics or claims; 408 Stable refusal; no diagnostics or claims; 409 Stable refusal; no diagnostics or claims; 410 Stable refusal; no diagnostics or claims; 413 Stable refusal; no diagnostics or claims.

## POST /management/sign

Signs bounded ownership challenges only, not arbitrary credentials or Request Objects.

```sh
# contract runtime POST /management/sign
curl --fail-with-body -X POST "$MGMT/management/sign" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"nonce":"challenge-from-registry","audience":"https://registry.example.org/partner-challenges"}'
```

Responses: 200 Response; 400 Legacy invalid_request; 401 Runtime bearer refusal or protected correlation refusal; 404 Legacy not_found.

## POST /management/sessions

Creates a 120-second ceremony using configuration_id and profile selectors. The runtime supplies issuer, definition and exact paths from authenticated configuration.

```sh
# contract runtime POST /management/sessions
curl --fail-with-body -X POST "$MGMT/management/sessions" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"profile":"education_sign_in","interaction_id":"application-interaction-123","purpose":"Student sign-in"}'
```

Responses: 201 Response; 400 Stable refusal; no diagnostics or claims; 403 Stable refusal; no diagnostics or claims; 408 Stable refusal; no diagnostics or claims; 413 Stable refusal; no diagnostics or claims; 429 Stable refusal; no diagnostics or claims; 503 Stable refusal; no diagnostics or claims; 401 Runtime bearer refusal or protected correlation refusal.

For a generic ceremony use the configured neutral selector and registered profile instead of the shared Education profile:

```sh
curl --silent --show-error --fail-with-body -X POST "$MANAGEMENT/management/sessions" \
  -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H 'Content-Type: application/json' \
  --data '{"configuration_id":"entitlement","profile":"enabled_only","interaction_id":"application-operation-1","purpose":"Check the enabled value"}' -o session.json
```

The generic response maps `vp_token` to `{"enabled_only":["<SD-JWT+KB>"]}` with the original signed state. Keep `correlation_capability` server-side and consume the returned session's result once. Use a definition/profile actually configured and registered at this verifier.

## GET /management/sessions/{session_id}

Reads claim-free status with the protected correlation capability.

```sh
# contract runtime GET /management/sessions/{session_id}
curl --fail-with-body -X GET "$MGMT/management/sessions/{session_id}" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H "X-Session-Capability: $CORRELATION_CAPABILITY"
```

Responses: 200 Response; 401 Runtime bearer refusal or protected correlation refusal.

## POST /management/sessions/{session_id}/result

Consumes the correlated result once; original evidence expiry and current permission/status still bound delivery.

```sh
# contract runtime POST /management/sessions/{session_id}/result
curl --fail-with-body -X POST "$MGMT/management/sessions/{session_id}/result" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H "X-Session-Capability: $CORRELATION_CAPABILITY" \
  -H 'Content-Type: application/json' \
  --data '{}'
```

Responses: 200 Response; 400 Stable refusal; no diagnostics or claims; 401 Runtime bearer refusal or protected correlation refusal; 408 Stable refusal; no diagnostics or claims; 409 Stable refusal; no diagnostics or claims; 410 Stable refusal; no diagnostics or claims; 413 Stable refusal; no diagnostics or claims.

## POST /management/evidence/refresh

Refreshes authenticated trust, permissions and status. A refresh cannot extend an existing result deadline.

```sh
# contract runtime POST /management/evidence/refresh
curl --fail-with-body -X POST "$MGMT/management/evidence/refresh" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{}'
```

Responses: 200 Evidence replaced; 400 Stable refusal; no diagnostics or claims; 408 Stable refusal; no diagnostics or claims; 413 Stable refusal; no diagnostics or claims; 503 Stable refusal; no diagnostics or claims; 401 Runtime bearer refusal or protected correlation refusal.

## GET /.well-known/oauth-authorization-server

Publishes supported pre-authorized-code token metadata.

```sh
# contract runtime GET /.well-known/oauth-authorization-server
curl --fail-with-body -X GET "$ISSUER/.well-known/oauth-authorization-server"
```

Responses: 200 OAuth authorization server metadata.

## GET /.well-known/openid-credential-issuer

Publishes the actual configured definitions and signed issuer authorization reference.

```sh
# contract runtime GET /.well-known/openid-credential-issuer
curl --fail-with-body -X GET "$ISSUER/.well-known/openid-credential-issuer"
```

Responses: 200 Credential issuer metadata; 503 Current signed issuer authority unavailable.

## POST /management/sessions/{session_id}/issuance-offer

Creates or recovers destination issuance bound to the source verified holder. Requires Idempotency-Key, exact interaction_id and enabled destination issuer configuration; current source/destination authority and status are rechecked. This consumes the source disposition; ordinary result consumption is an alternative.

```sh
# contract runtime POST /management/sessions/{session_id}/issuance-offer
curl --fail-with-body -X POST "$MANAGEMENT/management/sessions/{session_id}/issuance-offer" -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H "X-Session-Capability: $CAPABILITY" -H "Idempotency-Key: $IDEMPOTENCY_KEY" -H 'Content-Type: application/json' --data '{"configuration_id":"entitlement","claims":{"enabled":false,"credits":0},"valid_from":1790899200,"valid_until":1790902800,"offer_expires_at":1790899320,"interaction_id":"application-operation-1"}'
```

Responses: 201 Original confidential offer, created or recovered for identical authenticated input; 400 ISSUER_OFFER_BAD_REQUEST, ISSUER_CONFIGURATION_UNKNOWN, ISSUER_VALUES_INVALID or ISSUER_VALIDITY_INVALID; 401 Runtime authentication refused; 413 Body too large; 415 JSON required; 503 EVIDENCE_STALE, ISSUER_AUTHORITY_UNAVAILABLE, ISSUER_BINDING_UNAVAILABLE or ISSUER_STATE_UNAVAILABLE; 403 ISSUER_BINDING_MISMATCH, VERIFICATION_NOT_PERMITTED, current source permission/authority or status refusal; 409 RESULT_PENDING, RESULT_CONSUMED, ISSUER_BINDING_MISMATCH or ISSUER_OFFER_CONSUMED.

## POST /management/issuer/offers

Creates an authenticated, recipient-thumbprint-bound offer after validating complete claims and validity.

```sh
# contract runtime POST /management/issuer/offers
curl --fail-with-body -X POST "$MANAGEMENT/management/issuer/offers" -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H 'Content-Type: application/json' --data '{"configuration_id":"entitlement","claims":{"enabled":false,"credits":0},"valid_from":1790899200,"valid_until":1790902800,"offer_expires_at":1790899320,"recipient_jwk_thumbprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
```

Responses: 201 Authorized confidential offer; 400 ISSUER_OFFER_BAD_REQUEST, ISSUER_CONFIGURATION_UNKNOWN, ISSUER_VALUES_INVALID or ISSUER_VALIDITY_INVALID; 401 Runtime authentication refused; 413 Body too large; 415 JSON required; 503 ISSUER_AUTHORITY_UNAVAILABLE or ISSUER_STATE_UNAVAILABLE.

## GET /oid4vci/offers/{id}

Reads the confidential pre-authorized offer before its original expiry.

```sh
# contract runtime GET /oid4vci/offers/{id}
curl --fail-with-body -X GET "$ISSUER/oid4vci/offers/{id}"
```

Responses: 200 Standard credential offer; 400 Invalid, expired, consumed or mismatched capability.

## POST /oid4vci/token

Exchanges the one-use pre-authorized code. A lost token response is uncertain, not permission to restore consumed authorization.

```sh
# contract runtime POST /oid4vci/token
curl --fail-with-body -X POST "$ISSUER/oid4vci/token" -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code' --data-urlencode "pre-authorized_code=$PRE_AUTHORIZED_CODE"
```

Responses: 200 Recipient-bound token; 400 invalid_grant or invalid_request; 413 request_too_large; 408 request_deadline.

## POST /oid4vci/nonce

Allocates a nonce for a real signed holder proof.

```sh
# contract runtime POST /oid4vci/nonce
curl --fail-with-body -X POST "$ISSUER/oid4vci/nonce"
```

Responses: 200 Nonce for actual signed holder proof; 500 Sanitized allocation failure.

## POST /oid4vci/credential

Validates token, nonce, holder proof, WIA and exact recipient before committing one credential. Recovery uses the original token/proof/holder within original deadlines.

```sh
# contract runtime POST /oid4vci/credential
curl --fail-with-body -X POST "$ISSUER/oid4vci/credential" -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' --data '{"credential_configuration_id":"entitlement","proofs":{"jwt":["$HOLDER_PROOF"]},"wallet_instance_attestation":"$PROVIDER_ATTESTATION"}'
```

Responses: 200 Exact committed credential; 400 Invalid input/proof/WIA or expired transaction bounds; 401 invalid_token; 413 request_too_large; 503 issuer_authority_unavailable or temporarily_unavailable; 500 server_error, never credentials or diagnostics.

## GET /oid4vci/status/revocation.jwt

Publishes the identity-bound signed revocation list. Credential rotation does not rotate this bootstrap status authority.

```sh
# contract runtime GET /oid4vci/status/revocation.jwt
curl --fail-with-body -X GET "$ISSUER/oid4vci/status/revocation.jwt"
```

Responses: 200 Signed ES256 status list; 404 status_not_found; 503 temporarily_unavailable.

## GET /management/issuer/issuances/{issuance_id}/status

Reads or permanently revokes one exact committed issuance. Credential bytes are not returned. Retried revocation preserves its original time. Suspension and reinstatement are unsupported.

```sh
# contract runtime GET /management/issuer/issuances/{issuance_id}/status
curl --fail-with-body -X GET "$MANAGEMENT/management/issuer/issuances/{issuance_id}/status" -H "Authorization: Bearer $MANAGEMENT_TOKEN"
```

Responses: 200 Exact committed issuance state; references derived from the identity-bound ledger. Retried revocation keeps its original time; legacy signed revocations have unknown time; 401 Runtime management bearer required; holder proof, issuer token and registry project credentials are refused; 404 ISSUER_ISSUANCE_NOT_FOUND in this runtime ledger; 409 ISSUER_ISSUANCE_NOT_ISSUED: offered, redeemed or failed protocol state is not an issued credential; 503 ISSUER_STATE_UNAVAILABLE: unavailable or inconsistent identity, allocation, signed publication or revocation history. Retry the same exact issuance to reconcile an interrupted outcome; never reset the ledger.

## POST /management/issuer/issuances/{issuance_id}/status

Reads or permanently revokes one exact committed issuance. Credential bytes are not returned. Retried revocation preserves its original time. Suspension and reinstatement are unsupported.

```sh
# contract runtime POST /management/issuer/issuances/{issuance_id}/status
curl --fail-with-body -X POST "$MANAGEMENT/management/issuer/issuances/{issuance_id}/status" -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H 'Content-Type: application/json' --data '{"state":"revoked"}'
```

Responses: 200 Exact committed issuance state; references derived from the identity-bound ledger. Retried revocation keeps its original time; legacy signed revocations have unknown time; 401 Runtime management bearer required; holder proof, issuer token and registry project credentials are refused; 404 ISSUER_ISSUANCE_NOT_FOUND in this runtime ledger; 409 ISSUER_ISSUANCE_NOT_ISSUED: offered, redeemed or failed protocol state is not an issued credential; 503 ISSUER_STATE_UNAVAILABLE: unavailable or inconsistent identity, allocation, signed publication or revocation history. Retry the same exact issuance to reconcile an interrupted outcome; never reset the ledger; 400 ISSUER_STATUS_BAD_REQUEST for malformed JSON, unknown fields or missing state; ISSUER_STATUS_UNSUPPORTED for any state other than revoked; 413 REQUEST_TOO_LARGE: JSON body exceeds 1024 bytes; 415 ISSUER_STATUS_BAD_REQUEST: application/json required; 408 REQUEST_DEADLINE: request body exceeded the 5-second bound.

## POST /management/issuer/renewals

Creates one exact predecessor replacement lease with Idempotency-Key. The server derives the existing holder; no arbitrary recipient override is accepted.

```sh
# contract runtime POST /management/issuer/renewals
curl --fail-with-body -X POST "$MANAGEMENT/management/issuer/renewals" -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H "Idempotency-Key: $IDEMPOTENCY_KEY" -H 'Content-Type: application/json' --data '{"version":1,"predecessor_issuance_id":"AAAAAAAAAAAAAAAAAAAAAA","configuration_id":"entitlement","claims":{"enabled":false,"credits":0},"valid_from":1790899200,"valid_until":1790902800,"offer_expires_at":1790899320}'
```

Responses: 201 Original operation, including on identical retry; 400 ISSUER_RENEWAL_BAD_REQUEST, ISSUER_CONFIGURATION_UNKNOWN, ISSUER_VALUES_INVALID or ISSUER_VALIDITY_INVALID; 401 Runtime management bearer required; 404 ISSUER_RENEWAL_NOT_FOUND: exact predecessor is absent from this issuer ledger; 409 ISSUER_RENEWAL_CONFLICT, ISSUER_RENEWAL_BINDING_MISMATCH or ISSUER_RENEWAL_NOT_CONFIRMABLE; 410 ISSUER_RENEWAL_EXPIRED: original lease expired before commit; 408 REQUEST_DEADLINE: body exceeded the 5-second bound; 413 REQUEST_TOO_LARGE: JSON body exceeds 262144 bytes; 415 ISSUER_RENEWAL_BAD_REQUEST: application/json required; 503 ISSUER_AUTHORITY_UNAVAILABLE or ISSUER_STATE_UNAVAILABLE; preserve the operation and retry/reconcile, never reset durable state.

## GET /partner-renewals/{renewal_id}

Returns the proposed exact replacement using one confidential capability query; capability alone cannot authorize issuance.

```sh
# contract runtime GET /partner-renewals/{renewal_id}
curl --fail-with-body -X GET "$ISSUER/partner-renewals/{renewal_id}?capability=$RENEWAL_CAPABILITY"
```

Responses: 200 Current exact operation state; no-store and no-referrer; 400 ISSUER_RENEWAL_BAD_REQUEST: require exactly one well-formed capability query field; 404 ISSUER_RENEWAL_NOT_FOUND: operation or capability does not match; 409 ISSUER_RENEWAL_CONFLICT, ISSUER_RENEWAL_BINDING_MISMATCH or ISSUER_RENEWAL_NOT_CONFIRMABLE; 503 ISSUER_AUTHORITY_UNAVAILABLE or ISSUER_STATE_UNAVAILABLE; preserve the operation and retry/reconcile, never reset durable state; 410 ISSUER_RENEWAL_EXPIRED: expiry equality refuses the request.

## POST /partner-renewals/{renewal_id}/authorize

Requires fresh nonce and same-holder proof with audience equal to the full authorize URI. Retry recovers the same successor offer.

```sh
# contract runtime POST /partner-renewals/{renewal_id}/authorize
curl --fail-with-body -X POST "$ISSUER/partner-renewals/{renewal_id}/authorize" -H 'Content-Type: application/json' --data '{"version":1,"capability":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","proof":{"proof_type":"jwt","jwt":"$HOLDER_PROOF"}}'
```

Responses: 200 Current exact operation state; no-store and no-referrer; 400 ISSUER_RENEWAL_BAD_REQUEST or ISSUER_RENEWAL_INVALID_PROOF. Exact JSON fields and application/json are required; public POST queries are refused; 404 ISSUER_RENEWAL_NOT_FOUND: operation or capability does not match; 409 ISSUER_RENEWAL_CONFLICT, ISSUER_RENEWAL_BINDING_MISMATCH or ISSUER_RENEWAL_NOT_CONFIRMABLE; 503 ISSUER_AUTHORITY_UNAVAILABLE or ISSUER_STATE_UNAVAILABLE; preserve the operation and retry/reconcile, never reset durable state; 408 REQUEST_DEADLINE: body exceeded the 5-second bound; 413 REQUEST_TOO_LARGE: public JSON proof body exceeds 16384 bytes; 410 ISSUER_RENEWAL_EXPIRED: original lease expiry equality refuses authorization.

## POST /partner-renewals/{renewal_id}/status

Reconciles current operation state using fresh same-holder proof. Reading status never confirms storage.

```sh
# contract runtime POST /partner-renewals/{renewal_id}/status
curl --fail-with-body -X POST "$ISSUER/partner-renewals/{renewal_id}/status" -H 'Content-Type: application/json' --data '{"version":1,"proof":{"proof_type":"jwt","jwt":"$HOLDER_PROOF"}}'
```

Responses: 200 Current exact operation state; no-store and no-referrer; 400 ISSUER_RENEWAL_BAD_REQUEST or ISSUER_RENEWAL_INVALID_PROOF. Exact JSON fields and application/json are required; public POST queries are refused; 404 ISSUER_RENEWAL_NOT_FOUND: operation or capability does not match; 409 ISSUER_RENEWAL_CONFLICT, ISSUER_RENEWAL_BINDING_MISMATCH or ISSUER_RENEWAL_NOT_CONFIRMABLE; 503 ISSUER_AUTHORITY_UNAVAILABLE or ISSUER_STATE_UNAVAILABLE; preserve the operation and retry/reconcile, never reset durable state; 408 REQUEST_DEADLINE: body exceeded the 5-second bound; 413 REQUEST_TOO_LARGE: public JSON proof body exceeds 16384 bytes.

## POST /partner-renewals/{renewal_id}/cancel

Cancels an unconfirmed operation. It invalidates an unissued offer or revokes only the issued unconfirmed successor; it does not retire the predecessor.

```sh
# contract runtime POST /partner-renewals/{renewal_id}/cancel
curl --fail-with-body -X POST "$ISSUER/partner-renewals/{renewal_id}/cancel" -H 'Content-Type: application/json' --data '{"version":1,"proof":{"proof_type":"jwt","jwt":"$HOLDER_PROOF"}}'
```

Responses: 200 Current exact operation state; no-store and no-referrer; 400 ISSUER_RENEWAL_BAD_REQUEST or ISSUER_RENEWAL_INVALID_PROOF. Exact JSON fields and application/json are required; public POST queries are refused; 404 ISSUER_RENEWAL_NOT_FOUND: operation or capability does not match; 409 ISSUER_RENEWAL_CONFLICT, ISSUER_RENEWAL_BINDING_MISMATCH or ISSUER_RENEWAL_NOT_CONFIRMABLE; 503 ISSUER_AUTHORITY_UNAVAILABLE or ISSUER_STATE_UNAVAILABLE; preserve the operation and retry/reconcile, never reset durable state; 408 REQUEST_DEADLINE: body exceeded the 5-second bound; 413 REQUEST_TOO_LARGE: public JSON proof body exceeds 16384 bytes.

## POST /partner-renewals/{renewal_id}/receipts/{receipt_id}/successors/{successor_issuance_id}/confirm

Accepts credential_accepted only after client verification and durable storage. The receipt, operation, exact successor and same holder must match. Confirmation retires only the exact predecessor.

```sh
# contract runtime POST /partner-renewals/{renewal_id}/receipts/{receipt_id}/successors/{successor_issuance_id}/confirm
curl --fail-with-body -X POST "$ISSUER/partner-renewals/{renewal_id}/receipts/{receipt_id}/successors/{successor_issuance_id}/confirm" -H 'Content-Type: application/json' --data '{"version":1,"event":"credential_accepted","proof":{"proof_type":"jwt","jwt":"$HOLDER_PROOF"}}'
```

Responses: 200 Current exact operation state; no-store and no-referrer; 400 ISSUER_RENEWAL_BAD_REQUEST or ISSUER_RENEWAL_INVALID_PROOF. Exact JSON fields and application/json are required; public POST queries are refused; 404 ISSUER_RENEWAL_NOT_FOUND: operation or capability does not match; 409 ISSUER_RENEWAL_CONFLICT, ISSUER_RENEWAL_BINDING_MISMATCH or ISSUER_RENEWAL_NOT_CONFIRMABLE; 503 ISSUER_AUTHORITY_UNAVAILABLE or ISSUER_STATE_UNAVAILABLE; preserve the operation and retry/reconcile, never reset durable state; 408 REQUEST_DEADLINE: body exceeded the 5-second bound; 413 REQUEST_TOO_LARGE: public JSON proof body exceeds 16384 bytes.

## GET /management/issuer/keys

Reads local credential-key revision, selected key, retained members and pending rotation.

```sh
# contract runtime GET /management/issuer/keys
curl --fail-with-body -X GET "$MANAGEMENT/management/issuer/keys" -H "Authorization: Bearer $MANAGEMENT_TOKEN"
```

Responses: 200 Local credential-key state; 400 ISSUER_KEY_BAD_REQUEST; 401 unauthorized; 403 ISSUER_KEY_PROOF_REFUSED; 409 ISSUER_KEY_REVISION_CONFLICT, ISSUER_KEY_CONFLICT or ISSUER_KEY_LIMIT; 503 ISSUER_KEY_STATE_UNAVAILABLE or ISSUER_AUTHORITY_UNAVAILABLE; restore complete consistent backup for established missing material.

## POST /management/issuer/keys/stage

Persists one staged credential key and its expected local/registry revisions. Keep pending material for retry and recovery.

```sh
# contract runtime POST /management/issuer/keys/stage
curl --fail-with-body -X POST "$MANAGEMENT/management/issuer/keys/stage" -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H 'Content-Type: application/json' --data '{"expected_revision":0,"project_id":"00000000-0000-4000-8000-000000000001","issuer_registration_id":"00000000-0000-4000-8000-000000000001","expected_registry_revision":0,"key_fragment":"credential-2"}'
```

Responses: 201 Local credential-key state; 400 ISSUER_KEY_BAD_REQUEST; 401 unauthorized; 403 ISSUER_KEY_PROOF_REFUSED; 409 ISSUER_KEY_REVISION_CONFLICT, ISSUER_KEY_CONFLICT or ISSUER_KEY_LIMIT; 503 ISSUER_KEY_STATE_UNAVAILABLE or ISSUER_AUTHORITY_UNAVAILABLE; restore complete consistent backup for established missing material; 408 REQUEST_DEADLINE; request body did not complete within five seconds; 413 REQUEST_TOO_LARGE; request body exceeds 4096 UTF-8 bytes.

## POST /management/issuer/keys/proof

Signs only the exact registry rotation challenge for that staged key/revision.

```sh
# contract runtime POST /management/issuer/keys/proof
curl --fail-with-body -X POST "$MANAGEMENT/management/issuer/keys/proof" -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H 'Content-Type: application/json' --data '{"expected_revision":1,"challenge":{"operation":"rotate","issuer_registration_id":"00000000-0000-4000-8000-000000000001","expected_revision":0,"key_id":"did:web:issuer.example#credential-2","proof_key_id":"did:web:issuer.example#credential-2","challenge_id":"00000000-0000-4000-8000-000000000001","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","audience":"https://registry.example/issuer-key-proof","expires_at":"2026-10-02T12:00:00Z"}}'
```

Responses: 200 Fresh proof; 400 ISSUER_KEY_BAD_REQUEST; 401 unauthorized; 403 ISSUER_KEY_PROOF_REFUSED; 409 ISSUER_KEY_REVISION_CONFLICT, ISSUER_KEY_CONFLICT or ISSUER_KEY_LIMIT; 503 ISSUER_KEY_STATE_UNAVAILABLE or ISSUER_AUTHORITY_UNAVAILABLE; restore complete consistent backup for established missing material; 408 REQUEST_DEADLINE; request body did not complete within five seconds; 413 REQUEST_TOO_LARGE; request body exceeds 4096 UTF-8 bytes.

## POST /management/issuer/keys/activate

Authenticates every configured signed issuer grant before selecting the staged key for new issuance. Retains historical keys.

```sh
# contract runtime POST /management/issuer/keys/activate
curl --fail-with-body -X POST "$MANAGEMENT/management/issuer/keys/activate" -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H 'Content-Type: application/json' --data '{"expected_revision":1,"key_id":"did:web:issuer.example#credential-2"}'
```

Responses: 200 Local credential-key state; 400 ISSUER_KEY_BAD_REQUEST; 401 unauthorized; 403 ISSUER_KEY_PROOF_REFUSED; 409 ISSUER_KEY_REVISION_CONFLICT, ISSUER_KEY_CONFLICT or ISSUER_KEY_LIMIT; 503 ISSUER_KEY_STATE_UNAVAILABLE or ISSUER_AUTHORITY_UNAVAILABLE; restore complete consistent backup for established missing material; 408 REQUEST_DEADLINE; request body did not complete within five seconds; 413 REQUEST_TOO_LARGE; request body exceeds 4096 UTF-8 bytes.

## POST /management/issuer/keys/abandon

Abandons a conflicting pending key without recycling its identity or deleting established retained material.

```sh
# contract runtime POST /management/issuer/keys/abandon
curl --fail-with-body -X POST "$MANAGEMENT/management/issuer/keys/abandon" -H "Authorization: Bearer $MANAGEMENT_TOKEN" -H 'Content-Type: application/json' --data '{"expected_revision":1,"key_id":"did:web:issuer.example#credential-2"}'
```

Responses: 200 Local credential-key state; 400 ISSUER_KEY_BAD_REQUEST; 401 unauthorized; 403 ISSUER_KEY_PROOF_REFUSED; 409 ISSUER_KEY_REVISION_CONFLICT, ISSUER_KEY_CONFLICT or ISSUER_KEY_LIMIT; 503 ISSUER_KEY_STATE_UNAVAILABLE or ISSUER_AUTHORITY_UNAVAILABLE; restore complete consistent backup for established missing material; 408 REQUEST_DEADLINE; request body did not complete within five seconds; 413 REQUEST_TOO_LARGE; request body exceeds 4096 UTF-8 bytes.

For setup and actual protected driver inputs use [quickstart](quickstart.md). For status/cache bounds, retained keys, uncertain outcomes and recovery use [operations](operations.md).
