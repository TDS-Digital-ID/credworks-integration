# Partner HTTP API

The [complete runtime OpenAPI](../../apps/partner-runtime/openapi.json) is the exact contract for all 30 operations below. The [Education API](../education/api.md) retains its eight runtime examples and the unchanged [reference application contract](../../apps/education-sign-in/src/public/openapi.json). Runtime version 0.1.0 is not enough to identify compatible artifacts; use the [revision matrix](overview.md#revision-and-profile-matrix).

## Responses and errors

HTTP success and credential acceptance are separate. A successful result read returns **HTTP 200** with either `status: "verified"` or `status: "refused"`. Always inspect the body. Apply your own enrolment, institution and account policy only after validating a verified result's evidence.

Most session and application errors use a JSON object:

```json
{"error":{"code":"RESULT_PENDING"}}
```

A delivered verification refusal has a different shape and returns no claims:

```json
{"status":"refused","interaction_id":"example-eligibility-1","error":{"code":"STATUS_CHECK_FAILED"}}
```

The runtime listener's bearer-authentication failure uses `{"error":"unauthorized"}`. Its legacy signing/unknown-route errors also use string errors. OID4VCI issuer endpoints use protocol errors such as `{"error":"invalid_grant"}`. Parse the schema for the endpoint and HTTP status; do not assume every `error` is an object. No diagnostic text or credential claims accompany a refusal.

| HTTP status | Meaning in the session flow | Next step |
| --- | --- | --- |
| 201 | Request created. | Save the session and its capability on your backend. Use the returned `expires_at`. |
| 200 | Status read, wallet-delivery acknowledgement, or retrieved result. | Check the endpoint's body. `accepted` acknowledges delivery. `complete` means a result is available. Neither means verification passed. |
| 400 | Invalid input or mismatched response state. | Correct the request. Do not retry the same invalid body. |
| 401 | Management bearer or protected session capability refused. | Check backend credentials and the original session. Removed sessions also refuse access. |
| 403 | Requested scope is not permitted. | Check configured profile and current signed permission. |
| 404 | Public capability or route not found. | Check the exact returned URL; do not guess capabilities. |
| 408 | HTTP request-body deadline exceeded. | This is separate from credential or session expiry. Retry a lost ordinary result read with the same session credentials. Other operations have their own recovery rules. |
| 409 | Operation conflicts with session state. | `RESULT_PENDING` permits waiting. `RESULT_CONSUMED`, `RESULT_LINKED` and `SESSION_ALREADY_COMPLETED` require different recovery; never retry solely because the HTTP status is 409. |
| 410 | Request expired before completion. | Start a fresh verification request. |
| 413 | Request body too large. | Respect the endpoint's body limit. |
| 429 | Retained-session capacity reached. | Back off and wait for retained sessions to expire. Do not create requests in a tight loop. |
| 503 | Required evidence is unavailable, stale or could not be refreshed. | Restore the configured signed evidence. Never extend its expiry locally. |

The endpoint reference lists which statuses each operation actually returns. A `status: "refused"` result can carry an evidence or scope error inside an HTTP 200 response.

## Session deadlines and polling

1. Create a request on your backend and retain the returned `session_id`, `interaction_id`, `correlation_capability` and `expires_at`. Send only the public activation information to the holder.
2. Poll `GET /management/sessions/{session_id}` with the runtime bearer and `X-Session-Capability`. This GET is repeatable and contains no claims. **Poll sequentially about once per second**, with only one request in flight. This is recommended client behaviour, not a promised server rate limit.
3. Continue while status is `pending` or `verifying`. On `complete`, stop polling and read the result. On `expired`, stop. On `consumed`, retry the protected result read only if its delivery was uncertain. `linking` belongs to the original linked issuance operation and must not trigger ordinary result consumption.
4. Keep network timeouts and any retry of a failed status GET within the original deadline. Back off on transient status-read failures. Stop starting new attempts when `expires_at` is reached. Do not use the result POST as the polling endpoint.
5. Read both the HTTP status and result body. Grant access only after the verified result's evidence and your application policy pass.

| Clock or limit | Contract |
| --- | --- |
| Request completion | Normally 120 seconds from creation. Signed authority can shorten a generic request. Use the returned `expires_at`, expressed as Unix **seconds**, not JavaScript milliseconds. |
| Status polling | Does not renew the request or evidence. A one-second interval is guidance for the client. |
| Result retention | 120 seconds after the request deadline, at most 240 seconds from creation. Retention is not permission to use expired evidence. |
| Result validity | The original evidence and credential deadlines still apply. Current permission and status are checked again on every delivery, including retries. Refresh cannot extend an existing result's deadline. |
| Reference application | The supplied `educationClient` permits retrieval until `expires_at + 120`, subject to the result's evidence deadline and browser validity. Its individual runtime HTTP calls time out after 5 seconds. |
| HTTP request deadline | The runtime allows 5 seconds to read a request body and configures 5-second header, request and socket timeouts. This is separate from the 120-second verification window. A body-read timeout returns `408 REQUEST_DEADLINE`; a connection timeout can close the connection without a JSON response. |
| Request sizes | Session management JSON is limited to 4 KiB; wallet presentation bodies to 128 KiB. |

## Result retries and recovery

**A lost result response can be retried with the same session ID, runtime bearer and `X-Session-Capability`.** Repeat `POST /management/sessions/{session_id}/result` with `{}`. Keep these credentials on your backend. Do not ask the holder to repeat verification just because this response was lost.

Results remain in memory until 120 seconds after the original request deadline, at most 240 seconds from creation. This is a retrieval limit, not a guarantee of validity: evidence or credential validity can end sooner. Every verified read, including a retry, checks the original evidence deadline and current signed permission, issuer authority and credential status. A retry may therefore return a refusal even if an earlier read was verified. Once refused, that session never returns verified claims again. Refresh cannot extend its original validity.

An observed `409 RESULT_PENDING` means completion has not finished. Resume status polling before the request deadline. After an ordinary result read, status is `consumed` for compatibility; it means delivery was attempted, not that your application received or applied the result. The protected result POST remains readable within the limits above. Concurrent reads can receive the same result. Apply your business action only once, keyed to the original interaction.

The supplied `educationClient` permits another `consume(originalRequest, apply)` after `RUNTIME_UNAVAILABLE`, including a lost or unreadable runtime response and a runtime 5xx response. Wait about one second between attempts and keep one call in flight. It checks browser ownership and deadlines again. Once validation or the application callback starts, the interaction is terminal: the client never repeats the callback, even if that callback throws. This does not make arbitrary application writes or a lost browser sign-in response replayable.

A runtime restart loses its in-memory sessions; a backend restart also loses the client's private correlation. Start a fresh verification after either restart, a terminal refusal or retention expiry. Removed sessions return `401 SESSION_ACCESS_DENIED`. `409 RESULT_LINKED` and `409 RESULT_CONSUMED` still protect sessions claimed by linked issuance; continue that original linked operation instead of reading an ordinary result. Never repeat the wallet presentation or use result reads to create another linked offer.

Use the runtime and client supplied together in your team starter. [Getting started](../education/getting-started.md) installs the matching images and checks eligibility.

## Refusal codes

These codes name failed checks. They do not always identify a single cause. In particular, do not turn every freshness failure into “credential expired” or every status failure into “credential revoked”.

| Code | Meaning | Suggested display and recovery |
| --- | --- | --- |
| `FRESHNESS_CHECK_FAILED` | A credential or proof failed time-validity checks. Causes include expiry, not-yet-valid credentials, invalid time fields and a presentation proof that is too old or future-dated. | “Validity or freshness check failed.” A new presentation may resolve an old proof; an expired credential needs renewal or reissuance. The code alone does not distinguish these causes. |
| `STATUS_CHECK_FAILED` | A credential status check failed. Causes include revocation, suspension and an invalid or inconsistent status reference. | “Credential status check failed.” Do not grant access or label the credential permanently revoked from this code alone. |
| `STATUS_LIST_STALE` | The signed status list is outside its permitted validity window. | “Status information is out of date.” Restore fresh authenticated status information. |
| `EVIDENCE_STALE` / `EVIDENCE_UNAVAILABLE` | The verifier's required signed evidence expired or is unavailable. | Restore the configured evidence and start a fresh request when needed. This does not establish credential revocation. |
| `INVALID_SIGNATURE` | A required signature could not be verified. | Refuse verification. Check the expected issuer, signing keys and input integrity. |
| `BINDING_CHECK_FAILED` | Holder or presentation binding failed, such as the key, audience or nonce not matching. | Refuse verification. Use the original request with the intended holder and verifier. |
| `MISSING_DISCLOSURE` | A required disclosure is absent. | Check the requested profile and the holder's credential. |
| `SCOPE_NOT_PERMITTED` / `ISSUER_NOT_AUTHORIZED` | Current signed permission or issuer authority does not cover this operation. | Check the registered issuer, definition and exact disclosure profile. |

Only show a more specific label such as “Expired”, “Suspended” or “Revoked” when separately authenticated evidence establishes that cause. Do not parse private diagnostic strings as an application API.


## Endpoint roles and credentials

| Destination | Authentication / purpose |
| --- | --- |
| Issuer/verifier public HTTPS | DID, metadata, signed requests, holder protocol and signed status; opaque ceremony/offer capabilities are sensitive |
| Runtime management, HTTP 127.0.0.1 | RuntimeBearer is the runtime's management token; keep it private and separate for each deployment |
| Protected session status/result/continuation | RuntimeBearer plus SessionCapability from the initiating session; never put this capability into a QR or public URL |
| Issuer credential endpoint | IssuerToken is the access_token returned by /oid4vci/token; a runtime management token cannot substitute |
| Registry management | Project-scoped bearer, distinct from runtime tokens; endpoint/key proof and issuer-owned definitions/grants |
| Registry/provider/status publications | Independently pinned origin, DID and public key; signature, scope and freshness checks still required |

Management routes are never public ingress. A public `status:accepted` means delivery admission, not verification or application eligibility. Read the protected correlated result; retry lost reads within its original limits and apply application effects once. A verified result carries typed claims and evidence; a refused result carries a stable code without claims. The application owns account mapping, value policy and cookies.

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

The generic response maps `vp_token` to `{"enabled_only":["<SD-JWT+KB>"]}` with the original signed state. Keep `correlation_capability` server-side and read the returned session's result. Use a definition/profile actually configured and registered at this verifier.

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

Reads or retries the correlated result; original evidence expiry and current permission/status still bound every delivery.

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
