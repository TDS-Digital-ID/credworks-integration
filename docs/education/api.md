# HTTP API

The actual OpenAPI documents are [runtime OpenAPI](../../apps/partner-runtime/openapi.json) and [application OpenAPI](../../apps/education-sign-in/src/public/openapi.json). They are imported verbatim at the same kit revision as these pages. The tables and curl examples below are checked against those contracts, not a replacement API.

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

Older pinned container previews retain the single-use behaviour. Use the runtime and client from the [result-retry update](../setup/operations.md#upgrade-the-runtime-and-client) together; updating this documentation alone does not change an installed service.

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


## Education verifier runtime subset routes

PUBLIC is the registered HTTPS origin. MGMT is exact loopback http://127.0.0.1:3081. Examples use placeholders; inject real capability/state/interaction values locally. Curl responses may contain protected capabilities: use mode-0600 files, not shared logs. A registry project bearer does not authorize runtime management.

| Method | Path | Request media | Security | HTTP responses |
| --- | --- | --- | --- | --- |
| GET | /.well-known/did.json | - | - | 200 |
| GET | /oid4vp/request/{capability} | - | - | 200, 404, 410 |
| POST | /oid4vp/response/{capability} | application/x-www-form-urlencoded | - | 200, 400, 404, 408, 409, 410, 413 |
| POST | /management/sign | application/json | RuntimeBearer | 200, 400, 401, 404 |
| POST | /management/sessions | application/json | RuntimeBearer | 201, 400, 401, 403, 408, 413, 429, 503 |
| GET | /management/sessions/{session_id} | - | RuntimeBearer,SessionCapability | 200, 401 |
| POST | /management/sessions/{session_id}/result | application/json | RuntimeBearer,SessionCapability | 200, 400, 401, 408, 409, 410, 413 |
| POST | /management/evidence/refresh | application/json | RuntimeBearer | 200, 400, 401, 408, 413, 503 |

```sh
# contract runtime GET /.well-known/did.json
curl --fail-with-body -X GET "$PUBLIC/.well-known/did.json"
```

```sh
# contract runtime GET /oid4vp/request/{capability}
curl --fail-with-body -X GET "$PUBLIC/oid4vp/request/{capability}"
```

```sh
# contract runtime POST /oid4vp/response/{capability}
curl --fail-with-body -X POST "$PUBLIC/oid4vp/response/{capability}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "state=$STATE" \
  --data-urlencode 'vp_token={"education_sign_in":["<SD-JWT+KB>"]}'
```

```sh
# contract runtime POST /management/sign
curl --fail-with-body -X POST "$MGMT/management/sign" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"nonce":"challenge-from-registry","audience":"https://registry.example.org/partner-challenges"}'
```

```sh
# contract runtime POST /management/sessions
curl --fail-with-body -X POST "$MGMT/management/sessions" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"profile":"education_sign_in","interaction_id":"application-interaction-123","purpose":"Student sign-in"}'
```

```sh
# contract runtime GET /management/sessions/{session_id}
curl --fail-with-body -X GET "$MGMT/management/sessions/{session_id}" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H "X-Session-Capability: $CORRELATION_CAPABILITY"
```

```sh
# contract runtime POST /management/sessions/{session_id}/result
curl --fail-with-body -X POST "$MGMT/management/sessions/{session_id}/result" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H "X-Session-Capability: $CORRELATION_CAPABILITY" \
  -H 'Content-Type: application/json' \
  --data '{}'
```

```sh
# contract runtime POST /management/evidence/refresh
curl --fail-with-body -X POST "$MGMT/management/evidence/refresh" \
  -H "Authorization: Bearer $PARTNER_MANAGEMENT_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{}'
```


## Application routes

APP is the exact configured browser HTTPS origin. First GET /api/session into protected cookie/session files, read csrf locally into CSRF, create an interaction, open its activation_uri in the wallet, then complete from that same browser. Refresh csrf after sign-in rotates the cookie. Keep management token and correlation capability entirely on the server. Browser POSTs need Origin, X-CSRF-Token and __Host-education cookie.

| Method | Path | Request media | Security | HTTP responses |
| --- | --- | --- | --- | --- |
| GET | /api/session | - | - | 200 |
| POST | /api/interactions | application/json | browserCookie | 201, 400, 401, 403, 404, 409, 410, 413, 429, 503 |
| POST | /api/interactions/{id}/complete | application/json | browserCookie | 200, 400, 401, 403, 404, 409, 410, 413, 429, 503 |

```sh
# contract application GET /api/session
curl --fail-with-body -X GET "$APP/api/session" \
  -b browser.cookies -c browser.cookies
```

```sh
# contract application POST /api/interactions
curl --fail-with-body -X POST "$APP/api/interactions" \
  -b browser.cookies -c browser.cookies \
  -H "Origin: $APP" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  --data '{"profile":"education_sign_in"}'
```

```sh
# contract application POST /api/interactions/{id}/complete
curl --fail-with-body -X POST "$APP/api/interactions/{id}/complete" \
  -b browser.cookies -c browser.cookies \
  -H "Origin: $APP" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  --data '{}'
```

## Supported options and bounds

Requests are ES256 oauth-authz-req+jwt with decentralized_identifier client ID, nonce/state, vp_token and direct_post. Only one exact Education DCQL query and one SD-JWT+KB presentation are accepted. Public request and response capabilities are 43-character base64url values. Replace `{capability}` and `{session_id}` with returned values, and application `{id}` with its opaque interaction ID before running examples.

The public acknowledgement is exactly `{"status":"accepted"}`. Protected creation returns session_id, interaction_id, request_uri, activation_uri, expires_at and correlation_capability. Result consumption POST uses `{}` and returns `verified` claims/evidence or `refused` with fixed error.code; ordinary result reads are retryable within the original retention and validity limits. Status GET has no claims. Ownership proof signing is the limited partner-identity-proof+jwt extension, not a general signing service. Browser correlation, cookie/CSRF and application account mapping are application extensions, not wallet protocol options.

Runtime management bodies are 4 KiB, wallet responses 128 KiB, retained sessions/results at most 100, purpose 200 characters and interaction ID 128. Runtime fetches have five-second deadlines, 256 KiB evidence caps and 16 KiB/two-grant permission cap. Browser bodies are 4 KiB, protected responses 16 KiB, browser records at most 100 and interactions five per browser. The app bounds headers/body at ten seconds, runtime I/O at five seconds and DB connection/statement/query waits at 3/3/4 seconds. See [freshness and diagnostic codes](operations.md#freshness-and-diagnostics).
