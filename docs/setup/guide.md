# Set up your team services

Run the Education app, verifier and database on your computer. Keep one active host
per team. Setup preserves your keys and registration across retries.

## Before you start

Use the reviewed kit supplied by your operator. These instructions require the
updated setup helper; earlier public previews keep their original instructions.
Install [Docker with Compose](https://docs.docker.com/get-started/get-docker/) and
finish its first-run prompts. On Windows, use a Docker-enabled WSL2 Linux terminal.
Keep the kit at a stable path and private state outside Git.

## Course teams

Use [Getting started](../education/getting-started.md). The private starter includes
its team assignment. Run `./setup`; it prepares, starts and checks eligibility in one
run. Confirmation happens before registration. Repeating the command preserves the
same identity and accounts. No Cloudflare account or hostnames need to be entered.

## Own-domain setup

This is the advanced alternative for teams without an operator-supplied starter.
Install [cloudflared](https://developers.cloudflare.com/tunnel/downloads/), authorize
your domain with `cloudflared tunnel login`, and choose two unused hostnames.

For custom credentials, use [Issue a custom credential](../guides/issue-a-credential.md)
instead. That path needs only an issuer and verifier.

## Prepare your configuration

Run from the kit directory, substituting your own addresses:

```sh
./setup prepare --state "$HOME/.local/share/credworks-team" \
  --runtime-origin https://verify.your-domain \
  --app-origin https://app.your-domain
```

Expect `SETUP_PREPARED`. Preparation downloads missing pinned images and verifies
their size, checksum and identity before use. Review the origins before registration;
they permanently identify this installation. Keep the state directory and volumes.

## Start and check

```sh
./setup resume
./setup eligibility
```

Expect `SETUP_READY`, then an `eligible` result. Open your app's HTTPS address without
a certificate warning. Own-domain setup creates a named tunnel and unused DNS routes.
Management stays private. This software-holder check uses synthetic data and mock
attestation; it does not prove phone consent.

## Upgrade an existing installation

Use the [runtime and client upgrade](operations.md#upgrade-the-runtime-and-client). It preserves the existing identity and accounts.

## Stop, resume and diagnose

```sh
./setup stop --state "$HOME/.local/share/credworks-team"
./setup start --state "$HOME/.local/share/credworks-team"
./setup doctor --state "$HOME/.local/share/credworks-team"
```

Stop retains keys and accounts. Start uses the saved installation. Back up its private
state and both named volumes together. Never delete volumes or replace keys to repair
an error. Share diagnostic codes only, never state, credentials or raw logs.

## Interrupted course import

See [import recovery](operations.md#interrupted-course-import).

## Replace a supplied tunnel or recover its credential

See [credential replacement](operations.md#replace-a-supplied-tunnel-or-recover-its-credential).

## Hand over the active host

See [host handover](operations.md#hand-over-the-active-host).

## Find the first failing step

See [diagnostics](operations.md#find-the-first-failing-step).

## Course operator allocation

See [operator allocation](operator.md#course-operator-allocation).

## Course tunnel replacement and retirement

See [operator retirement](operator.md#course-tunnel-replacement-and-retirement).

## Platform evidence

See [tested platforms and limits](operations.md#platform-evidence).

## Load the candidate images

Preparation downloads and verifies missing images automatically. See [preparation](#prepare-your-configuration).

## Next: issue your own synthetic credential

Continue with [custom issuance](../guides/issue-a-credential.md).
