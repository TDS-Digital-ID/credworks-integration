# Verify selected fields

Check whether a holder is a club member without asking which club they joined.
Your verifier requests only `member` from the synthetic credential you issued.
For the default example, the selected `member` value is `true` and `club` is absent.
For a supplied definition, setup uses its single profile and checks exactly those
fields against the saved synthetic claims.

## Before you start

Complete [Issue a custom credential](issue-a-credential.md) and receive its example.
Keep that issuer running. Choose another unused hostname for your verifier,
such as `check.your-domain.example`. It needs a separate identity and state
folder. It does not need another database.

The default example expires **one hour after the offer is prepared**. A supplied definition uses its `max_validity_seconds`. Repeating `issue` reuses
that receipt and checks its current validity; it does not extend or replace it.
If it has expired, keep the receipt and keys. Ask your issuer operator to arrange
an explicit new synthetic issuance through the [advanced issuance procedure](../partner/quickstart.md#host-software-holder-lifecycle).
Do not delete state or turn off expiry checks.

This tutorial uses the same software holder. Android consent and hardware
authorization remain a separate check.

## 1. Prepare the verifier

Run from the kit directory, replacing the hostname with one you own:

```sh
./setup prepare --role verifier \
  --state "$HOME/.credworks/club-verifier" \
  --runtime-origin https://check.your-domain.example \
  --issuer-state "$HOME/.credworks/club-issuer"
```

Expect `SETUP_PREPARED`. The issuer and verifier must use different origins and
state folders. Setup preserves the issuer's keys and existing software holder.
The local verifier port defaults to `3084`; set `--runtime-port` during preparation
if it is occupied.

## 2. Register and grant the exact permission

```sh
./setup resume --state "$HOME/.credworks/club-verifier"
```

Expect `SETUP_CUSTOM_VERIFIER_READY`. Setup proves the verifier owns its hostname,
then uses your issuer's protected project credential to grant the selected profile.
For the default example this is `membership`, permitting only `member`.

The verifier registration identifies the recipient. The issuer adoption identifies
which issuer may issue this definition. The permission identifies which fields
that recipient may request under that adoption. They are separate identifiers;
setup records and connects them for you. Registration alone does not grant access
to arbitrary credential fields.

Management stays on loopback. Do not expose port `3081` or copy the project
credential into browser code.

## 3. Verify the member flag

```sh
./setup verify --state "$HOME/.credworks/club-verifier"
```

Expect `SOFTWARE_HOLDER_CUSTOM_VERIFIED`. The command checks the authenticated
result against the selected profile and saved synthetic claims, rejecting extra
fields. It prints no claim values.
A public "accepted" response only acknowledges delivery; it is not the result.

You can stop and start this verifier, then repeat the check. Its identity and
permission remain the same, and it uses the preserved holder key and receipt.
Each check requests a fresh, short-lived presentation.

## 4. Check refusal after revocation

Do this after your successful check. This permanently revokes **only the saved
synthetic example credential**. It keeps its receipt and holder key for diagnosis.

```sh
./setup revoke-example --state "$HOME/.credworks/club-issuer"
./setup verify --state "$HOME/.credworks/club-verifier"
```

The first command reports `SYNTHETIC_EXAMPLE_REVOKED`. The second must refuse with
`STATUS_CHECK_FAILED`. It must not report a verified member result. This proves
that a previously valid credential cannot bypass current revocation checks.
Revocation cannot be undone by rerunning `issue`.

## Recover without replacing identity

| Message | Next action |
| --- | --- |
| `SETUP_PERMISSION_UNAVAILABLE` | Restore registry connectivity and resume with the same state. An identical grant request is safe to retry. |
| `SETUP_ISSUER_REQUIRED` or `SETUP_ISSUER_NOT_READY` | Use the original issuer state folder and finish its setup first. |
| `SETUP_PERMISSION_REFUSED` | Preserve both state folders. Check the registered recipient and exact profile with the issuer operator. |
| `STATUS_CHECK_FAILED` | The credential may be revoked or suspended, or its status reference may be invalid. Do not infer revocation from this code alone. |
| `FRESHNESS_CHECK_FAILED` | A time-validity check failed. The credential may be expired or not yet valid, or the proof may be too old or future-dated. Preserve state and identify the cause before reissuing. |

State folders contain keys, management credentials and credential contents. Share
only the command, refusal code and candidate revision when asking for help.
See [definitions and disclosure](../partner/definitions.md) for custom profiles
and [operations](../partner/operations.md) for backups and lifecycle procedures.

See the [refusal-code reference](../education/api.md#refusal-codes) for the broader meanings and recovery guidance.
