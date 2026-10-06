# HTTP API

The actual OpenAPI documents are [runtime OpenAPI](../../apps/partner-runtime/openapi.json) and [application OpenAPI](../../apps/education-sign-in/src/public/openapi.json). They are imported verbatim at the same kit revision as these pages. The tables and curl examples below are checked against those contracts, not a replacement API.

## Runtime routes

PUBLIC is the registered HTTPS origin. MGMT is exact loopback http://127.0.0.1:3081. Examples use placeholders; inject real capability/state/interaction values locally. Curl responses may contain protected capabilities: use mode-0600 files, not shared logs. A registry project bearer does not authorize runtime management.

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

| Method | Path | Request media | Security |
| --- | --- | --- | --- |
| GET | /api/session | - | - |
| POST | /api/interactions | application/json | browserCookie |
| POST | /api/interactions/{id}/complete | application/json | browserCookie |

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

The public acknowledgement is exactly `{"status":"accepted"}`. Protected creation returns session_id, interaction_id, request_uri, activation_uri, expires_at and correlation_capability. Result consumption POST uses `{}` and returns `verified` claims/evidence or `refused` with fixed error.code once. Status GET has no claims. Ownership proof signing is the limited partner-identity-proof+jwt extension, not a general signing service. Browser correlation, cookie/CSRF and application account mapping are application extensions, not wallet protocol options.

Runtime management bodies are 4 KiB, wallet responses 128 KiB, retained sessions/results at most 100, purpose 200 characters and interaction ID 128. Runtime fetches have five-second deadlines, 256 KiB evidence caps and 16 KiB/two-grant permission cap. Browser bodies are 4 KiB, protected responses 16 KiB, browser records at most 100 and interactions five per browser. The app bounds headers/body at ten seconds, runtime I/O at five seconds and DB connection/statement/query waits at 3/3/4 seconds. See [freshness and diagnostic codes](operations.md#freshness-and-diagnostics).
