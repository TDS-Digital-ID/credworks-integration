# Connect your backend

The supplied Node.js app uses `educationClient` from
`@unsw-vc/education-sign-in/client`. Reuse that module when adapting the app.
It creates requests, keeps result capabilities private, retries failed result reads, applies each callback once, and
checks issuer, verifier, disclosure, enrolment, institution and deadlines.
Your backend owns browser sessions, CSRF protection and accounts.

## Keep management private

Keep the starter's `network_mode: service:partner` and management address
`http://127.0.0.1:3081`. That loopback belongs to the shared container namespace.
Never publish port 3081. Preserve the supplied token, issuer/verifier pins and
institution policy. An adapted backend needs its own reviewed image and deployment
configuration; guided setup continues to pin the supplied example images.

## Create and consume a request

This is the credential-specific part of the supplied server. `browser` is the
server-held initiating session, `config` is protected application configuration,
and `accounts` is your account store. Call these handlers only after checking the
browser cookie, exact Origin and CSRF token.

```ts
import { educationClient } from '@unsw-vc/education-sign-in/client';

const education = educationClient(config);

// Request handler: retain the original object in this browser's server-side state.
const request = await education.create('education_sign_in', () => {
  assertBrowserCurrent(browser);
});
browser.interactions.set(request.id, request);
returnJson(request); // Only public activation/request information is returned.

// Completion handler: look up the request from this initiating browser only.
const original = browser.interactions.get(requestId);
if (!original) throw interactionNotFound();
const accountId = await education.consume(original, claims =>
  accounts.account(config.issuer, claims.student_id as string),
);
rotateBrowserSession(browser, accountId);
returnJson({ status: 'signed_in', account_id: accountId });
```

The client checks `assertBrowserCurrent` after network and account I/O. It also
rechecks interaction and evidence expiry after the account callback. The callback
may find or create an account; grant access or rotate cookies only after `consume`
returns successfully. The account key remains the authenticated issuer/student pair.
The example server handles concurrent browser rotation and retires pending requests.

For eligibility, create `education_eligibility` and consume it with a callback that
returns `eligible` without creating an account. No student ID is requested.

Keep the original request object on the server. Its private capability is held by
the client and cannot be reconstructed from browser JSON. A restart requires a new
request. A pending result throws `Refusal` with code `RESULT_PENDING` and permits
another completion attempt. `RUNTIME_UNAVAILABLE` also permits retrying the same
request after a short delay, with one call in flight. Once validation or the application
callback starts, it is terminal, including if the callback throws. A fresh verification
must not duplicate an uncertain application write. Retrieval is limited to the original
`expires_at + 120`, evidence validity and the current browser. See [sign-in recovery](student-sign-in.md#if-sign-in-stops).

## Check your adaptation

Preserve secure cookies, Origin/CSRF checks, browser binding, concurrency limits,
account uniqueness and cookie rotation from the starter. Test wrong-browser
completion, pending/replayed results, expiry during database work, policy refusal,
and account continuity after restart. Never return claims or log capabilities.

The [client source](../../apps/education-sign-in/src/client.ts) and reference server
are in the [public integration repository](https://github.com/TDS-Digital-ID/credworks-integration).
Get that developer source when adapting your backend; the private starter contains
the files needed to run the supplied containers. Other backend languages use the
same [HTTP contract](../education/api.md) and must preserve these checks. A software
holder result does not qualify a new backend's refusal paths or physical consent.

See [session deadlines and polling](../education/api.md#session-deadlines-and-polling), [result retry recovery](../education/api.md#result-retries-and-recovery) and the [refusal codes](../education/api.md#refusal-codes) before adapting completion handling.
