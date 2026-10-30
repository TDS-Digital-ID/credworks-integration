# Issue a custom credential

Build a synthetic club membership credential with two fields: `member` and `club`.
You will run your own issuer, then receive its credential with the software holder.
This is a development check. It does not test Android hardware authorization.

## Before you start

Use the reviewed kit and Docker with Compose. Choose two unused hostnames for an
issuer and verifier. Install `cloudflared` and authorize your domain with
`cloudflared tunnel login`. You do not need the Education app or its database.
This walkthrough runs two identities, two public hostnames and one issuer database.
Setup downloads and verifies any missing pinned images.

Run commands from the integration kit directory. No host Node.js or Rust build
is needed.

## Use your own definition

The default below issues club membership. To use your own scalar credential, create
one JSON file containing `definition` and synthetic `claims`. For example:

```json
{
  "definition": {
    "id": "https://issuer.your-domain.example/definitions/workshop-access",
    "version": "1",
    "credential_type": "SyntheticWorkshopAccess",
    "label": "Synthetic workshop access",
    "max_validity_seconds": 3600,
    "claims": [
      { "name": "qualified", "label": "Qualified", "value_type": "boolean", "required": true },
      { "name": "workshop", "label": "Workshop", "value_type": "string", "required": true }
    ],
    "profiles": [{ "name": "access", "claim_paths": [["credentialSubject", "qualified"]] }]
  },
  "claims": { "qualified": true, "workshop": "Synthetic training workshop" }
}
```

Set the definition's origin to your issuer's origin. Add
`--definition /absolute/path/credential.json` to the preparation command below.
Setup validates the definition and claims through the Rust core, stores them in
protected state, and creates the definition, adoption and verifier grant. You copy
no registration IDs. The original file is unnecessary for `resume` or `start`.

Guided setup accepts one scalar disclosure profile. Nested/object/array definitions
use the [advanced workflow](../partner/quickstart.md). Definitions and prepared input
are immutable. Repeat preparation with the same file; use the advanced versioning
workflow for changes to an established definition. Never reset identity to change it.

## 1. Prepare your issuer

Replace the hostname below with one you own. Keep the state directory outside
Git. It will contain management credentials and keys.

```sh
./setup prepare --role issuer \
  --state "$HOME/.credworks/club-issuer" \
  --runtime-origin https://issuer.your-domain.example
```

Expect `SETUP_PREPARED`. Check the hostname before continuing. Once registered,
that hostname identifies your issuer; changing it is a migration, not a rerun.
The local issuer port is `3083`. Use `--runtime-port` during preparation if that
port is occupied.

## 2. Register and start it

```sh
./setup resume --state "$HOME/.credworks/club-issuer"
```

Expect `SETUP_ISSUER_READY`. Setup creates a named tunnel and DNS route, proves
ownership of your issuer, and starts its dedicated database. Public management
routes remain unavailable.

Without `--definition`, setup registers and adopts the original example:

```json
{
  "member": true,
  "club": "Example Robotics Club"
}
```

A **project** owns the registry management credential. An **issuer** is the service
that signs credentials. A **definition** describes a credential's fields and
allowed disclosure profiles. An **adoption** authorizes this issuer to use that
definition. Registration proves technical control; it does not make your team a
university or an identity authority.

The default definition is version `1`, named `SyntheticClubMembership`, under
`https://YOUR-ISSUER/definitions/club-membership`. Your project controls that
namespace. Its `membership` profile requests only `member`, leaving `club`
withheld. Use only synthetic values in this sandbox.

## 3. Receive the example

```sh
./setup issue --state "$HOME/.credworks/club-issuer"
```

Expect `SOFTWARE_HOLDER_RECEIPT_VERIFIED`. For either definition, the Rust-backed client binds
the offer to its preserved holder key, checks issuer authorization and live
revocation status, then verifies and stores the receipt. The sandbox wallet
provider still supplies the required attestation. Software test attestation is
not hardware-backed proof.

The default example expires one hour after its offer is prepared. A supplied definition uses its `max_validity_seconds`. Repeating `issue`
reuses it and checks its current validity; it does not extend the lifetime. After
expiry, preserve the receipt and keys and ask the issuer operator to arrange an
explicit new synthetic issuance through the [advanced issuance procedure](../partner/quickstart.md#host-software-holder-lifecycle).
Do not erase state or bypass expiry checks.

The receipt and holder key stay in the protected `software-holder` directory.
Do not paste those files, tokens or credential contents into a support report.
Normal issuance has no separate issuer-side receipt-confirmation endpoint. Here,
receipt means the holder verified and stored the credential; renewal confirmation
is a separate advanced operation.

## Retry or stop

Rerun the same command with the same state directory. Completed registration,
definition and adoption are reused. Repeating `issue` checks the same receipt;
it does not create another credential.

```sh
./setup doctor --state "$HOME/.credworks/club-issuer"
./setup stop --state "$HOME/.credworks/club-issuer"
./setup start --state "$HOME/.credworks/club-issuer"
```

Stop retains the keys, project credential, holder state and database. Back up
these together using [the operations guide](../partner/operations.md). Do not
remove Docker volumes or edit generated configuration to fix an error.

| Message | Next action |
| --- | --- |
| `SETUP_DNS_REFUSED` | Check that the hostname is unused and Cloudflare is authorized. Do not overwrite a conflicting record. |
| `SETUP_DEFINITION_UNAVAILABLE` | Restore registry connectivity, then resume with the same state. Exact definition and adoption requests can be retried. |
| `SETUP_OFFER_OUTCOME_UNKNOWN` | Preserve the holder state. Ask the issuer operator to reconcile the original offer; do not create a replacement to hide the failure. |
| `TOKEN_DELIVERY_UNCERTAIN` | Preserve the offer and holder state. A token response may have been lost; ask the operator to reconcile it. |
| `FRESHNESS_CHECK_FAILED` | A time-validity check failed, including expired offers or evidence. Preserve state for diagnosis; this code is not specific to credential expiry. |
| `SETUP_ISSUER_BOOTSTRAP_INTERRUPTED` | Preserve the database and identity. Resume checks the existing runtime; an unconfirmed database bootstrap needs operator help. |

Share only the stable error code, command name and candidate revision when asking
for help. See [credential definitions](../partner/definitions.md) for the full
contract and [the API reference](../partner/api.md) for advanced issuance.

Next, [verify selected fields](verify-a-credential.md) with a separate verifier.

See the [refusal-code reference](../education/api.md#refusal-codes).
