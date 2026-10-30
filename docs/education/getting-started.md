# Getting started

Set up the example app on **one team computer**. It checks student eligibility using
synthetic credentials. Your operator supplies the private starter package and the
team's addresses.

## 1. Start Docker

Install [Docker with Compose](https://docs.docker.com/get-started/get-docker/) once,
finish its first-run prompts, and leave it running. On Windows, use a Docker-enabled
WSL2 Linux terminal.

## 2. Get your team starter

Download and extract the private package supplied by your operator. It contains
`setup`, `team.json` and `START-HERE.txt`, plus a `.credworks` support folder.
Keep the whole folder at a stable location and keep the package private.
The team file contains a tunnel credential.

## 3. Run setup

Open a terminal in that folder and run:

```sh
./setup
```

Check the displayed team and addresses against your separate course handoff, then
type your team name to confirm. Setup verifies the images, prepares your private
keys, starts the services, registers your verifier and checks eligibility.
You do not need to enter hostnames, choose storage paths or run registration commands.

## 4. Open your app

Wait for `TEAM_READY: Eligibility checked`. Setup opens the app and prints its HTTPS
address. If no browser opens, use that address yourself.

The automated check confirms that the backend accepted a synthetic credential while
receiving only enrolment and institution. It uses a software holder with mock
attestation. Phone consent is a separate [Android walkthrough](../guides/android-wallet.md).
The browser app needs a wallet for a new interactive request.

**Setup is complete.** [Connect your backend](../guides/connect-your-backend.md) when
ready to adapt the example, or [try student sign-in](../guides/student-sign-in.md).

## If setup stops

Fix the reported prerequisite and rerun `./setup` in the same folder. It keeps your
identity and checks the saved installation. State lives outside the kit at
`$HOME/.local/share/credworks-team`; keep it and the Docker volumes.

For `EDUCATION_ONBOARDING_INTERRUPTED`, preserve everything and ask the operator to
reconcile the attempt. Never erase keys or repeat an uncertain issuance manually.
See [troubleshooting](../setup/operations.md#find-the-first-failing-step).

Existing installations at another location use `./setup up --state /your/existing/path`.
Without a course starter, follow [own-domain setup](../setup/guide.md).
