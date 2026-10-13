# Getting started

Build an app that checks whether a student is enrolled at an accepted institution.
The student shares only enrolment and institution. This check does not create an
app account or disclose a student ID.

You will run the supplied app and verifier, receive a synthetic Education credential,
and get `eligible` from your app's backend. A credential is an issuer-signed record.
The verifier checks its signature, holder, allowed disclosure and current status;
your app then applies its institution and enrolment policy.

## Before you start

Use the [student onboarding preview](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/student-onboarding-preview-20261013). Earlier previews do not include these setup commands or container archives. If the release is unavailable, it has not been published yet; wait for it rather than substituting an older bundle.

Install [Git](https://git-scm.com/downloads) if needed, then get the matching source:

```sh
git clone --branch student-onboarding-preview-20261013 --single-branch https://github.com/TDS-Digital-ID/credworks-integration.git
cd credworks-integration
```

You need Docker with Compose, `cloudflared`, and a domain in your team's Cloudflare
account. Your team runs the app, verifier and database and keeps their keys and
backups. CredWorks runs the sandbox issuers and trust registry. Domain registration
may cost money; Cloudflare's tunnel service does not provide a free domain.

Start in the kit's root directory. Keep your private setup state outside Git.
You do not need Node.js or Rust installed for this path. Public Education software
checks passed on macOS ARM64 and an Ubuntu ARM64 virtual machine. Platform and Android limits are listed in
[the setup evidence](../setup/guide.md#platform-evidence).

## 1. Run your team services

Follow [Set up your team services](../setup/guide.md). It walks through account
authorization, loading the checked images, choosing two fixed HTTPS names and
registering your verifier.

Stop at `SETUP_READY`. Open your app's HTTPS address and check that the Education
page loads without a certificate warning. Keep the same state directory for every
command below. Do not replace keys or delete volumes to fix a failed setup.

## 2. Check eligibility with a software holder

From the kit root, use the state directory you chose during setup:

```sh
./setup eligibility --state "$HOME/.local/share/credworks-team"
```

The command runs the supplied software holder inside the checked container. It
receives synthetic Government ID, presents it for enrolment, and receives a
synthetic Education credential. It then requests and shares only `enrolled` and
`institution_id` with your verifier.

This is development evidence. The software holder uses labelled mock platform
attestation. It does not test a phone, human consent or hardware authorization.
Never supply real identity information to this sandbox exercise.

Expect a result containing:

```json
{
  "status": "eligible",
  "account": "none",
  "shared": ["enrolled", "institution_id"]
}
```

The result also labels its software-holder attestation. `eligible` means the app
backend consumed its authenticated verifier result and accepted its policy. A wallet
message such as “Details delivered” or the verifier's public `accepted` response
only confirms delivery. Neither grants app access.

The command keeps its test holder and credential in the protected state directory.
A repeat uses them for a new eligibility request. It does not replace your service
identity or create a sign-in account. Do not publish the state directory or raw logs.

## 3. Recover from an interrupted request

If a wallet user cancels sharing, nothing has been sent. Return to the same app page
and start a fresh eligibility request when ready. Cancellation is a normal outcome;
do not treat a pending delivery as approval.

An expired request also needs a fresh request. For this software exercise, rerun the
same command. Once synthetic receipt has finished, the command reuses the saved
credential and creates a fresh request with a new deadline.

If synthetic receipt itself stopped before its outcome could be saved, the command
reports `EDUCATION_ONBOARDING_INTERRUPTED`. Preserve the state and ask the operator
to reconcile that attempt. Do not delete the holder or repeat issuance blindly.
For connectivity or permission failures, run:

```sh
./setup doctor --state "$HOME/.local/share/credworks-team"
```

Use [setup diagnostics](../setup/guide.md#find-the-first-failing-step) to fix the
first failing step. Keep TLS validation and the supplied trust configuration intact.

## Next steps

Continue with [Try the Android wallet](../guides/android-wallet.md) for the separate phone follow-up.
Android must exercise real consent, cancellation and hardware authorization; this
software check does not replace it. iPhone: Coming soon.

Continue with [Sign in a student](../guides/student-sign-in.md) when your app needs an account. Use [profiles and application policy](profiles.md) to choose between eligibility
and student sign-in. Sign-in shares a student ID and creates an account association.
[Issue a custom credential](../guides/issue-a-credential.md) walks through your own synthetic credential type. [Partner integration](../partner/overview.md) explains the underlying concepts.
Keep [HTTP API](api.md) and [operations](operations.md) nearby as references.
