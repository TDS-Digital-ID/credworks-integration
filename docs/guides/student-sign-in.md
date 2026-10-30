# Sign in a student

Use sign-in when your app needs to recognise a returning student. It requests enrolment, institution and student ID. Your backend checks the verified result, then finds an application account using the authenticated issuer and student ID together.

[Getting started](../education/getting-started.md) checks eligibility without creating an account or sharing student ID. Complete that lesson first, using the same protected state directory and synthetic credential. Use the same versioned onboarding preview as that lesson.

## 1. Run the sign-in example

From the integration kit root:

```sh
./setup sign-in --state "$HOME/.local/share/credworks-team"
```

The existing software holder signs in twice with the same Education credential and checks that both results identify the same application account. Expect:

```json
{
  "status": "signed_in",
  "account_id": "<your app's opaque account ID>",
  "account_continuity": "verified",
  "shared": ["enrolled", "institution_id", "student_id"]
}
```

The output also labels mock platform attestation. This is a software development check, not evidence of human consent or Android hardware authorization. It uses synthetic values only. The command preserves the holder and saved credential from Getting started; it does not issue a new identity for each login.

The account ID belongs to your app. It is not a student ID, credential ID or holder key. Keep it out of shared diagnostic reports. Two services receiving the same stable student ID can correlate visits, so use eligibility whenever an account is unnecessary.

## 2. Check continuity after restart

Keep your state directory and database, then run:

```sh
./setup stop --state "$HOME/.local/share/credworks-team"
./setup start --state "$HOME/.local/share/credworks-team"
./setup sign-in --state "$HOME/.local/share/credworks-team"
```

Expect `SETUP_STOPPED`, then `SETUP_READY`, then `signed_in` with the same account ID. The database keeps the exact issuer/student mapping. Back up that database with your service state; losing it loses account continuity.

Browser sessions and pending interactions are temporary. An app restart logs browsers out and invalidates their pending requests. Open the app again and start a new request. A fresh verified sign-in finds the existing account. The software command also starts a fresh browser session on each run.

## 3. Understand the browser exchange

Your frontend talks to your app over its configured HTTPS origin. It needs no credential SDK or particular frontend framework.

1. `GET /api/session` returns a CSRF token and sets the protected browser cookie.
2. `POST /api/interactions` with `{"profile":"education_sign_in"}` creates a request. Include the cookie, exact `Origin` and `X-CSRF-Token` on each POST. Open the returned `activation_uri` in the wallet and let the user review all three details.
3. `POST /api/interactions/<id>/complete` with `{}` asks your backend to finish. Only the initiating browser can complete it. `RESULT_PENDING` means delivery has not finished; check again before expiry.
4. A successful completion returns `signed_in` and the app account ID. The server rotates its cookie. Fetch `/api/session` again for the new CSRF token.

A wallet's delivery message does not sign anyone in. The app must consume the protected verifier result and apply its policy. Neither the runtime management bearer nor the result capability belongs in browser code, URLs or logs.

## If sign-in stops

| Outcome | Next action |
| --- | --- |
| User cancels sharing | Keep them signed out. Let them start a fresh request when ready. |
| `RESULT_PENDING` | Check completion again from the same browser before the deadline. |
| `INTERACTION_EXPIRED`, `EVIDENCE_STALE` or `RESULT_UNAVAILABLE` | Start a new request. Never extend a deadline or reuse an old result. |
| `CSRF_REFUSED` or `BROWSER_REQUIRED` | Reload the app for a fresh session, then start again. Do not disable the checks. |
| `INTERACTION_NOT_FOUND` or `INTERACTION_CONSUMED` | Use the initiating browser. If it restarted or already completed, start a fresh request. |
| `ENROLMENT_REQUIRED` or `INSTITUTION_NOT_ALLOWED` | The verified credential does not meet your app's policy. Refuse sign-in; do not rewrite its values. |

For setup or interrupted synthetic receipt, use [Getting started recovery](../education/getting-started.md#if-setup-stops). Continue with [Connect your backend](connect-your-backend.md) to adapt the working app, or use the [HTTP reference](../education/api.md) for request schemas and limits.
