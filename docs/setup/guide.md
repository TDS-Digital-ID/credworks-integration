# Set up your team services

Run your own Education example app, verifier and database. Setup prepares the files,
starts containers, connects a Cloudflare named tunnel and registers your verifier.
Your team keeps the keys and operates these services.

Use the [student onboarding preview](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/student-onboarding-preview-20261013) and its exact container archives below. Do not substitute a moving image tag. If the release is unavailable, publication has not happened yet.

## Before you start

You need:

- A domain your team controls, added to your own Cloudflare account. Domain registration
  may cost money. Cloudflare's free tunnel service does not include a free domain.
- Two unused hostnames, such as `verify.your-domain` and `app.your-domain`.
- Docker with Compose, and the `cloudflared` command. On Windows, use a WSL2 Linux
  terminal with Docker integration and keep files in the Linux filesystem.
- The checksum-verified container archive for your architecture. The
  [candidate manifest](../../config/setup-candidate.json) records both image IDs,
  source revision and archive checksums. Follow the loading steps below.

See [platform evidence](#platform-evidence) for the checks completed on each host.

Keep the kit at a stable path. Choose a private state directory outside Git and keep
its files together. Do not use a temporary directory for a real team installation.

Install [Git](https://git-scm.com/downloads) for the source checkout, [Docker for your platform](https://docs.docker.com/get-started/get-docker/), including [Docker Compose](https://docs.docker.com/compose/install/), and [cloudflared from Cloudflare](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/). Docker Desktop includes Compose; Linux Engine users need the Compose plugin. Start Docker and finish any first-run prompts, then check:

```sh
git --version
docker version
docker compose version
cloudflared --version
```

Expect a Git version, Docker client **and server** versions, a Compose version, and a cloudflared version. If a command is missing or Docker cannot reach its server, finish that installation before proceeding. On WSL2, run these checks inside the same Linux terminal you will use for setup.

## Load the candidate images

The versioned preview supplies both archives below. Select one for your Docker engine. A missing release or download is a stop condition; do not use an older release or rebuild an image to fill this prerequisite.

Check your Docker engine architecture with `docker info --format '{{.Architecture}}'`. Choose the matching pair below before downloading. For ARM64 (`aarch64` or `arm64`):

```sh
ARCHIVE=education-containers-61c2b16b6f43dc72c0e31a8d4ee6837f04a6eccb-arm64.tar
EXPECTED=5c3580ce25a70713cff1b877be8f0d52cee547aff3503a52f1403daeaffa5d1e
```

For AMD64 (`x86_64` or `amd64`):

```sh
ARCHIVE=education-containers-61c2b16b6f43dc72c0e31a8d4ee6837f04a6eccb-amd64.tar
EXPECTED=8a9436793b76dcdf80dba17d0951e157387c87e2225b44d5856b0aba9afea157
```

Download the selected archive from the same release, then load it only if its checksum passes. Run in a new download directory to preserve earlier artifacts:

```sh
mkdir onboarding-images
cd onboarding-images
curl --fail --location --output "$ARCHIVE" \
  "https://github.com/TDS-Digital-ID/credworks-integration/releases/download/student-onboarding-preview-20261013/$ARCHIVE"
```

Continue only after the download succeeds:

```sh
if command -v sha256sum >/dev/null; then
  printf '%s  %s\n' "$EXPECTED" "$ARCHIVE" | sha256sum --check && docker load --input "$ARCHIVE"
else
  printf '%s  %s\n' "$EXPECTED" "$ARCHIVE" | shasum -a 256 --check && docker load --input "$ARCHIVE"
fi
```

Return to the kit directory. Setup will also inspect the loaded images against the pinned identities before using them.

## 1. Authorize your account

Run this yourself and finish the browser prompt for your domain:

```sh
cloudflared tunnel login
```

Setup does not create an account, buy a domain or answer OS prompts. Complete any
Docker permission or first-run dialogs before continuing. Never run setup with `sudo`
or share your Cloudflare certificate, tunnel credentials or state files.

## 2. Prepare your configuration

From the kit root, replace the directory and both hostnames:

```sh
./setup prepare --state "$HOME/.local/share/credworks-team" \
  --runtime-origin https://verify.your-domain \
  --app-origin https://app.your-domain
```

Expect `SETUP_PREPARED`. This writes protected local configuration without creating
Cloudflare resources. It selects immutable images for the container engine's
architecture and uses the independently authenticated ecosystem configuration shipped
with this candidate. It never learns the trust anchor from a live registry response.

Review your two origins before the next command. They become your verifier's persistent
identity. Temporary `trycloudflare.com` names are refused.

## 3. Start and register

```sh
./setup resume --state "$HOME/.local/share/credworks-team"
```

Setup creates one named tunnel and two DNS routes without overwriting existing DNS.
It starts a dedicated database and the supplied app, checks normal public HTTPS,
proves control of the verifier key and verifies both Education permission grants.
Management remains local. Only the app's intended pages and credential protocol
routes enter the tunnel; all other public paths are refused.

Expect `SETUP_READY`. Open your app origin. You now have a running app and a registered
verifier. This does not yet prove credential acceptance: the next lesson runs the
[Getting started software-holder check](../education/getting-started.md#2-check-eligibility-with-a-software-holder), followed by a separate Android interaction.

If a command fails, keep the files and rerun the same command after fixing the named
prerequisite. Setup reuses its keys and registration. Saved configuration takes precedence over
ambient `PARTNER_*` and `EDUCATION_*` shell variables. It refuses changed origins,
trust configuration or incompatible state instead of silently replacing them.

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

## Find the first failing step

| Result | What to do |
| --- | --- |
| `SETUP_DOCKER_UNAVAILABLE` | Start Docker or resolve its OS permission prompt. |
| `SETUP_IMAGE_UNAVAILABLE` or `SETUP_IMAGE_REFUSED` | Load the matching checked archive. Do not retag a different image. |
| `SETUP_CLOUDFLARE_AUTHORIZATION_REQUIRED` | Finish `cloudflared tunnel login` for the intended domain, then resume. |
| `SETUP_DNS_REFUSED` | Inspect the conflicting hostname in Cloudflare. Setup will not replace it. |
| `SETUP_CONNECTIVITY_UNAVAILABLE` after creating DNS | Your network may still cache the earlier missing DNS record. Keep the saved state, allow DNS to propagate, then rerun `./setup resume` with the same state directory. Do not replace the tunnel or origins, or disable TLS checks. |
| `SETUP_TUNNEL_OUTCOME_UNKNOWN` | Preserve the saved name and credentials. Resume reads the authenticated tunnel list. If still unresolved, ask the account operator to reconcile that exact tunnel. |
| `SETUP_TUNNEL_CREDENTIAL_REQUIRED` | Recover the original credential file for the saved tunnel into `tunnel-credentials.json`, owned by you with mode `0600`. Do not create a replacement tunnel. |
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

## Next: issue your own synthetic credential

When the Education example works, follow [Issue a custom credential](../guides/issue-a-credential.md).
It uses a separate issuer hostname, identity and database while preserving this setup.

## Platform evidence

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
