# Setup recovery and platform evidence

Use the same protected state directory and original volumes on every retry.
Return to [team setup](guide.md) for a new installation.

## Upgrade the runtime and client

Use the [result-retry update](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/result-retry-update-20261030) to install the corrected runtime and Education client together. Download its source archive, verify it against `SHA256SUMS`, and extract it into a new folder. Keep your existing private state directory and Docker volumes.

From the new kit folder, with Docker running:

```sh
./setup upgrade --state "$HOME/.local/share/credworks-team"
./setup doctor --state "$HOME/.local/share/credworks-team"
```

Use your actual state path if it differs. The command downloads and checks the pinned images for your architecture, verifies their source labels, updates the saved image references and restarts the same services. Keys, origins, registration, database volumes and existing accounts are preserved. In-flight verification requests and browser logins must start again after the restart. No wallet update or credential reissuance is required for this fix.

If interrupted, rerun the same upgrade command from the same new kit. It resumes only that exact transition. `SETUP_UPGRADE_PENDING` means normal setup is waiting for this recovery. `SETUP_UPGRADE_REFUSED` or `SETUP_IMAGE_REFUSED` means the supplied images or saved files do not match; preserve the files and resolve the mismatch. A protected `runtime-upgrade-backup.<previous-revision>.json` remains in the state directory. It contains private configuration and must not be shared.

The new helper can still start or stop an installation using the previous pinned images. Those older images retain single-use results until you run the upgrade. Use the new kit folder for later setup commands. A custom backend using `educationClient` must also take the updated client source; HTTP integrations use the [result retry contract](../education/api.md#result-retries-and-recovery).

## Interrupted course import

If the first course `prepare` stops, repeat that exact command with the same bundle,
origins, image selection and state path. Setup retains the selected local secrets
and finishes complete matching writes. Start, resume and doctor wait until the import
finishes. Do not replace the bundle or create a new state directory.

For `SETUP_TUNNEL_IMPORT_AMBIGUOUS`, stop and preserve the whole directory. After
confirming the earlier process has ended, the operator takes a protected copy and
checks `tunnel-import.json` against the original allocation and bundle. If that
committed journal is complete and an adjacent `.pending` file is truncated, move
only that failed pending file to protected evidence, then repeat the same `prepare`
command. Keep the journal, local secrets and all committed files unchanged.
If the journal itself is incomplete, a committed file conflicts, or an older kit
left only a credential without a journal, keep the attempt stopped for operator
reconciliation or restore a known complete backup. Do not guess missing secrets,
edit saved hashes or delete state to continue.

## Stop, resume and diagnose

```sh
./setup stop --state "$HOME/.local/share/credworks-team"
./setup start --state "$HOME/.local/share/credworks-team"
./setup doctor --state "$HOME/.local/share/credworks-team"
```

Stop retains the identity, database and project credential. Start resumes the saved
installation. Doctor checks the running app, public boundary and signed permission
and status evidence. Browser sessions expire after restart; saved account mappings
remain in the database.

Back up the protected directory and both named volumes together. Never use
`down --volumes`, delete keys, regenerate an unlock secret or create a new project to
repair a failed attempt. The broader [container guide](containers.md) explains the
service layout.

## Replace a supplied tunnel or recover its credential

Losing the original delivery bundle does not affect an imported installation. Setup
keeps its own protected credential copy. If that copy is lost, restore its exact
bytes from a protected backup, or ask the operator for a replacement. If a credential
may have escaped, use the operator's [replacement procedure](operator.md#course-tunnel-replacement-and-retirement).
Copying a file locally does not revoke a credential at Cloudflare.

The operator supplies a new tunnel UUID and bundle for your existing group, teaching
account and exact origins. They also confirm the old UUID from the inventory. Keep
the existing state directory, keys, database and registry project. Run:

```sh
./setup replace-tunnel \
  --state "$HOME/.local/share/credworks-team" \
  --group banana --from-tunnel OLD_TUNNEL_UUID \
  --tunnel-bundle "$HOME/.local/share/course-handoff/banana-replacement.json" \
  --runtime-origin https://banana-verify.your-course-domain \
  --app-origin https://banana-app.your-course-domain
```

Use your confirmed values, with `cherry` for the other group. The bundle must be a
private, owner-held regular file with mode `0600`. The replacement must have a new
tunnel UUID. Setup refuses changed group, account, origins, trust inputs, or a
previously replaced tunnel. It preserves the DID, signing key, project credential,
database and software holder, then starts the installation through the usual HTTPS
and registration checks. Finish with `./setup eligibility --state ...` and confirm
the backend reports `eligible`. Existing sign-in accounts must still work.

An interrupted replacement records its intended old/new UUIDs and credential digest
in protected local state. Repeat the exact command with the same bundle and old
UUID. A different replacement is refused while that journal exists. After
`SETUP_TUNNEL_REPLACED`, a later start failure can also use `./setup start --state ...`.
Repeating the accepted replacement restores its missing credential file if needed.
Do not copy an old credential over the new one or edit the saved hashes.

If setup reports `SETUP_TUNNEL_REPLACEMENT_AMBIGUOUS`, keep the state and all `.pending`
files. Confirm the earlier process has ended, then give the operator the refusal
code and public old/new UUIDs through the support channel. The operator first makes
a protected copy of the state and confirms the committed state and replacement
journal against the inventory and the original bundle. A complete matching pending
write recovers automatically. For an incomplete pending write, the operator may move
only that failed `.pending` file to protected evidence, keeping the committed state
and journal in place, then repeat the exact command. If the committed state or
intended replacement cannot be established, stop and restore the known complete
backup. Never guess a UUID, edit a state file, or delete application data to continue.

## Hand over the active host

Each group nominates one active host. Two hosts on one tunnel can serve different
keys or database records. Stop the old host with `./setup stop --state ...` before
taking a consistent protected backup of the state directory and both named volumes.
Transfer that backup privately. Restore the same Compose project, volume names,
absolute state/kit paths, architecture and exact image identities on the new host.
Do not run fresh preparation or bootstrap against empty volumes.

Start on the new host, run `doctor`, check the unchanged public DID and verify
eligibility and an existing sign-in account. Record the new active host in the
operator inventory. Keep the old host stopped. If its credential may still be used
without consent, the operator retires the old tunnel and supplies a replacement
before handover. Local stop cannot enforce that against a compromised host. Missing
keys or database backups require operator investigation; tunnel replacement cannot
reconstruct them.

## Find the first failing step

For the course starter, rerun `./setup` after fixing a missing prerequisite. Use
`./setup doctor` to diagnose or `./setup stop` to stop while keeping the saved state.
The default location is `$HOME/.local/share/credworks-team`. If your earlier setup
used another directory, pass that same `--state` path to every command.

`SETUP_TEAM_BUNDLE_REQUIRED` means the first-run starter is missing `team.json`.
Obtain the private starter from your operator. `SETUP_CONFIRMATION_REQUIRED` or
`SETUP_CONFIRMATION_REFUSED` means registration has not been started by this run;
confirm only after comparing the team and addresses with the separate handoff.
A changed bundle is refused against an existing identity. Use the operator's
replacement procedure, never delete state to import a different team.


| Result | What to do |
| --- | --- |
| `SETUP_DOCKER_UNAVAILABLE` | Start Docker or resolve its OS permission prompt. |
| `SETUP_IMAGE_UNAVAILABLE` or `SETUP_IMAGE_REFUSED` | Load the matching checked archive. Do not retag a different image. |
| `SETUP_CLOUDFLARE_AUTHORIZATION_REQUIRED` | Own-domain mode only: finish `cloudflared tunnel login` for the intended domain, then resume. Course groups should check they prepared with their supplied bundle. |
| `SETUP_DNS_REFUSED` | Own-domain mode only: inspect the conflicting hostname in Cloudflare. Setup will not replace it. Course DNS belongs to the operator. |
| `SETUP_CONNECTIVITY_UNAVAILABLE` after creating DNS | Your network may still cache the earlier missing DNS record. Keep the saved state, allow DNS to propagate, then rerun `./setup resume` with the same state directory. Do not replace the tunnel or origins, or disable TLS checks. |
| `SETUP_TUNNEL_OUTCOME_UNKNOWN` | Preserve the saved name and credentials. Resume reads the authenticated tunnel list. If still unresolved, ask the account operator to reconcile that exact tunnel. |
| `SETUP_TUNNEL_IMPORT_PENDING` | Repeat the original course `prepare` command with its bundle. Startup waits for the recorded import to finish. |
| `SETUP_TUNNEL_IMPORT_AMBIGUOUS` | Preserve all files and follow [interrupted course import recovery](#interrupted-course-import). |
| `SETUP_TUNNEL_BUNDLE_REFUSED` | Check the independently confirmed group/origins and request the correct bounded JSON bundle from the operator. Do not edit account or tunnel identifiers to make a different credential fit. |
| `SETUP_TUNNEL_IDENTITY_REFUSED` | Preserve state. Existing credential bytes differ from the saved binding. Restore the exact protected backup or ask the operator to reconcile the unexpected file. Do not edit the saved hashes. |
| `SETUP_TUNNEL_CREDENTIAL_REQUIRED` | Restore the saved credential file from the protected backup, or use the operator-issued [explicit replacement](#replace-a-supplied-tunnel-or-recover-its-credential). Keep all other state. |
| `SETUP_TUNNEL_REPLACEMENT_REFUSED` | Confirm the expected old UUID, new bundle, group, account and exact origins with the operator. An earlier bundle or a different pending replacement cannot be substituted. |
| `SETUP_TUNNEL_REPLACEMENT_PENDING` | Repeat the exact `replace-tunnel` command and bundle. Normal startup waits until that recorded replacement is complete. |
| `SETUP_TUNNEL_REPLACEMENT_AMBIGUOUS` | Preserve all files and follow the [operator-assisted pending-write recovery](#replace-a-supplied-tunnel-or-recover-its-credential). |
| `SETUP_START_FAILED` | Check Docker and whether host ports 3080 or 3082 are occupied. Keep the dedicated database and its password. |
| `HTTP_TRANSPORT_UNAVAILABLE` or a public HTTPS error | Check DNS, the tunnel and internet connectivity. Do not disable TLS validation. |
| `REGISTRATION_*` or a permission error | Keep `registration-result.json`. Fix the reported connectivity or permission prerequisite, then rerun `./setup resume` with the same state directory. Use the [registration recovery reference](../education/operations.md#registration-recovery) for code meanings; its native `pnpm register` command is not needed for guided setup. |
| `SETUP_STATE_REFUSED` or `SETUP_STORAGE_REFUSED` | Restore the original inputs and permissions. Preserve any `.pending` file for operator-assisted recovery. |
| `SETUP_BUSY` | Confirm the earlier setup process has stopped before removing only the `.lock` directory. |

Diagnostics print stage names and refusal codes. Do not publish `team.env`,
`state.json`, registration journals, tunnel credentials, `docker compose config`
or raw service logs. Report the command, refusal code and image/source revision.

Advanced deployments can supply unused local ports at preparation with
`--runtime-port` and `--app-port`. An independently authenticated alternate ecosystem
requires both `--ecosystem /absolute/config.json` and `--ecosystem-sha256 HASH`.
These choices are saved and cannot silently change on a later run.

Docker's image ID can differ between the build engine and a clean archive import.
The candidate lists the exact builder, imported-manifest and classic-store identities
for the same checked bytes. Setup selects an installed identity and retains that
exact binding. If a saved identity becomes unavailable after changing Docker stores,
restore the original image; setup will not silently migrate existing state.

## Platform evidence

The rows below record the earlier published own-domain path. The supplied-tunnel
candidate passed its CLI-to-backend eligibility journey on macOS ARM64 through local
mapped HTTPS. Live Cloudflare authorization, routing and retirement, and actual
cross-group browser behavior remain NOT RUN. The historical rows do not qualify the
course allocation for handoff.

| Environment | Observed checks | Limit |
| --- | --- | --- |
| macOS ARM64 | Public HTTPS setup, registration, software eligibility and sign-in; full stop/start preserved identity, credentials and account | Software holder with labelled mock platform attestation |
| Ubuntu 26.04 ARM64 virtual machine | Supplied public-only source and images; Education setup, eligibility, sign-in and restart; custom receipt, member-only verification, restart and exact revocation refusal | Existing prepared VM; recovered after operator DNS cache actions and same-state retries; public release download not tested |
| AMD64 containers | Image build and container checks under emulation | Native Linux AMD64 host not verified |
| Windows/WSL2 | NOT RUN; no Windows machine available | Instructions are provided without a verified support claim |
| Pixel 7, Android 17, arm64-v8a | New Government receipt, Education enrolment and receipt, Android cancellation, then successful disclosure and app-confirmed eligibility | One phone with the exact wallet candidate already installed; installation and other devices not tested; iPhone is coming soon |

On 13 October 2026, the macOS ARM64 custom flow also passed over public HTTPS: issuance, selected-field verification of only the boolean `member`, full stop/start with the same identity and receipt, then exact revocation and refusal of the revoked credential. The first verifier resume failed with a transport error; one retry with the same saved state passed. The cause of that transient failure was not isolated.

The Ubuntu run preserved its initial DNS and issuer identity-check failures. It completed after two operator DNS cache refreshes and documented same-state recovery, without changing keys, origins or trust settings. Its revocation check refused the saved credential before presentation; forced delivery of a revoked credential was not tested.

The Android run first encountered stale signed evidence and expired requests. Those attempts did not pass. Refreshing with `doctor` before each fresh request allowed the cancellation and successful eligibility checks to complete, with the same held credential and unchanged deadlines. These are sandbox observations, not production assurance.

For API integration, see [HTTP responses and error formats](../education/api.md#responses-and-errors), [polling and deadlines](../education/api.md#session-deadlines-and-polling), [lost result responses](../education/api.md#result-retries-and-recovery) and [refusal-code meanings](../education/api.md#refusal-codes).
