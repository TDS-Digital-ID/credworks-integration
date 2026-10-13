# Connect your backend

Keep the working [student sign-in example](student-sign-in.md) as your comparison while you connect your app. The supplied TypeScript/Node.js backend is in `apps/education-sign-in/src/server.ts`. It uses ordinary HTTP and a dedicated Postgres account store. Your frontend can use any framework, or none. Other backend languages use the same [HTTP contract](../education/api.md).

Your backend owns browser sessions, application policy and accounts. The verifier runtime handles credential proofs through the shared Rust core. Do not decode a wallet credential in frontend code and turn its claims into a login.

## 1. Keep management local

The working `infra/education-sign-in/compose.yml` puts the application inside the verifier's network namespace:

```yaml
application:
  network_mode: service:partner
  environment:
    EDUCATION_RUNTIME_MANAGEMENT: http://127.0.0.1:3081
```

Keep this arrangement for your backend container. Loopback here means the shared container namespace, not your laptop. Runtime management listens only there; Compose does not publish port 3081. The app's port 3082 and verifier's public port 3080 reach HTTPS through the existing finite tunnel routes. A separate container on the default bridge cannot reach management through its own loopback address.

The complete Compose service also supplies the runtime token, pinned issuer/verifier, institution policy and dedicated app database. Preserve its non-root user, read-only filesystem and other restrictions when adapting it. The registry project credential is a different secret and cannot authorize runtime management.

First work from the supplied source and passing example. An edited backend needs its own reviewed image and deployment configuration; the guided setup deliberately pins the supplied images and refuses a silent replacement. Do not edit generated state or publish a management port to make a different image fit. Record your source revision, image digest and relevant HTTP checks before deploying your adaptation.

## 2. Create a request on the server

The browser first obtains its session and CSRF token, then asks your app to create an interaction. Keep the starter's exact Origin/CSRF checks and protected cookie. Generate an unpredictable interaction ID and bind it to that initiating browser before returning anything.

The following TypeScript shows the protected HTTP exchange inside `server.ts`. `runtime` is the starter's bounded, server-only HTTP helper. It adds the runtime bearer, refuses redirects, limits responses and applies a five-second timeout. `interactionId` and the selected profile belong to the server's browser record.

```ts
const created = await runtime('/management/sessions', {
  profile: 'education_sign_in',
  interaction_id: interactionId,
  purpose: 'Sign in to this application with Education',
});
```

Require HTTP 201, the exact interaction ID, a future deadline and valid request/session fields. Save `session_id`, `correlation_capability`, profile and deadline with the browser's interaction. Return only the opaque app interaction ID, `activation_uri`, `request_uri`, profile and presentation deadline to the browser.

The user opens the activation link, reviews the recipient and three requested fields, then authorizes disclosure. Public delivery acknowledgement is only `{"status":"accepted"}`. It contains no authenticated application decision.

## 3. Consume the result and apply policy

When the initiating browser asks to complete, check its Origin, CSRF token and saved interaction. Claim that interaction before network I/O so concurrent requests cannot consume it twice. Use only the saved server-side session and capability:

```ts
const outcome = await runtime(
  '/management/sessions/' + encodeURIComponent(interaction.sessionId) + '/result',
  {},
  interaction.capability,
);
```

This is a POST with `Authorization: Bearer <runtime token>`, `X-Session-Capability: <saved capability>` and `Content-Type: application/json`. Both secrets stay on your backend. A 409 `RESULT_PENDING` allows another check. Other uncertain or failed consumption needs a fresh interaction; do not replay a possibly consumed result.

For HTTP 200, retain the starter's `validate` checks before creating a login:

- `status` is `verified` and `interaction_id` matches the original request.
- Evidence names your pinned issuer and verifier, Education type, `urn:credworks:education` version `1`, and the exact requested profile and paths.
- The only claims are `enrolled`, `institution_id` and `student_id`. Enrolment is exactly `true`, institution matches your configured policy, and student ID is a bounded, nonblank string.
- Browser, interaction and immutable evidence deadlines have not expired. Recheck after network and database waits.

The existing account store then finds or creates an account using the exact authenticated issuer/student pair:

```ts
const verified = validate(outcome.body, interaction);
const accountId = await store.account(
  config.issuer,
  verified.claims.student_id as string,
);
```

These are excerpts, not a replacement server. Keep the surrounding status, concurrency and deadline checks in `server.ts`. The database unique constraint in `src/accounts.ts` makes concurrent sign-ins converge on one account. Never use a browser-supplied student ID, a credential instance ID or a holder key as the account key.

Finally rotate the browser cookie and CSRF secret, retire its old pending interactions, and return `{"status":"signed_in","account_id":"<app ID>"}`. Return no credential contents. For eligibility, request only enrolment and institution and return `eligible` without calling the account store.

## 4. Check your adaptation

Run the working sign-in command before and after your change. Keep a dedicated application database. Confirm the same issuer/student account survives repeat login and app restart, while old browser sessions and pending requests do not. Exercise wrong-browser completion, CSRF refusal, expiry, duplicate completion and policy refusal through your app's HTTP endpoints.

The supplied example's producer tests cover these outcomes against real verifier results. They are the behavior to preserve when changing languages or frameworks. Your new backend still needs its own checks; a successful software-holder run alone does not prove every refusal path.

Use the [sign-in recovery table](student-sign-in.md#if-sign-in-stops) for expected failures and [HTTP API](../education/api.md) for complete schemas, status codes and bounds. Keep raw responses, cookies, management tokens and result capabilities out of shared logs.
