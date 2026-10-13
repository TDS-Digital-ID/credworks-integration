# Run the Education containers

The supplied Education app, partner runtime and database run in containers. You do not
need Rust, PostgreSQL or Node installed on the host. The runtime image contains the
shared Rust core. Building images from source is an advanced maintainer task.

Start with [guided setup](guide.md) to prepare configuration and register your verifier.
This page describes the container layout and advanced manual operation.

## Prepare the host

Use Docker Engine with the Compose v2 plugin on Linux, or Docker Desktop on macOS.
On Windows, enable WSL2 and Docker Desktop's WSL integration, then run all commands in
your Linux distribution's terminal. Keep configuration in that distribution's Linux
filesystem rather than a Windows-mounted directory, so Unix file permissions work.
The container engine must report `linux` and either `aarch64`/`arm64` or `x86_64`/`amd64`.
Other architectures and Windows containers are unsupported.

```sh
docker version
docker compose version
docker info --format '{{.OSType}} {{.Architecture}}'
```

If Docker is missing, install the platform's Docker package. If the client cannot reach
the engine, start Docker Desktop or ask the machine administrator to grant access to
the Docker service. Complete installation and permission prompts yourself. Do not run
setup with `sudo` to bypass a missing Docker permission.

Choose the candidate matching the engine architecture. Verify the provided archive's
SHA256 against the candidate manifest before `docker load --input <archive>`. Use each
image's recorded immutable `sha256:...` ID as `PARTNER_IMAGE` and `EDUCATION_APP_IMAGE`.
Do not select a moving `latest` tag. Use the [versioned download and checksum steps](guide.md#load-the-candidate-images); a missing release is not permission to substitute another image.

## Configure a protected directory

Guided setup supplies these values. For manual configuration, create a private directory
with permissions `0700` and an environment file with permissions `0600`. Keep it outside
Git. Never paste the environment file or `docker compose config` output into an issue.

Set the variables in [the Compose configuration](../../infra/education-sign-in/compose.yml)
and [the app configuration table](../../apps/education-sign-in/README.md#prerequisites-and-configuration).
Use fixed, independently served HTTPS origins for the runtime and app. Preserve the
runtime unlock key and management token across every restart. The management token is
only for the local backend; it is not a project registration credential.

For the dedicated local database set `EDUCATION_DB_PASSWORD` to a random URL-safe secret
and `EDUCATION_APP_DATABASE_URL` to
`postgres://education:<that-password>@database:5432/education`. No database port is
published. Do not point this app at a registry database or another app's migration ledger.
Set `PARTNER_CONFIG_DIR` to a separate public-only child directory containing verifier
configuration. Mount that child directly with directory mode `0755` and file mode `0644`
so container user `10001` can read it on Linux. Keep operator secrets in the private parent
with mode `0700` and files `0600`; never mount that whole parent as public configuration.

Set `PARTNER_VERIFIER_CONFIG` to its container path, for example `/config/verifier.json`,
when the registered verifier configuration is ready. An empty value starts the identity
and public DID listener, but cannot verify Education. Obtain trust pins independently;
a DID document fetched from a service does not authenticate its own registry root.

## Start and restart

Run from the repository root. Replace `/absolute/path/team.env` with your protected file.
Keep the same project name, environment file and volumes on every invocation.

```sh
docker compose --env-file /absolute/path/team.env -p credworks-team \
  -f infra/education-sign-in/compose.yml --profile local-db run --rm partner bootstrap
```

Run bootstrap only for a new identity. It refuses existing identity state. Do not remove
that state to make it succeed. Resume an existing installation with the next commands.

```sh
docker compose --env-file /absolute/path/team.env -p credworks-team \
  -f infra/education-sign-in/compose.yml --profile local-db up -d --wait database

docker compose --env-file /absolute/path/team.env -p credworks-team \
  -f infra/education-sign-in/compose.yml --profile local-db up -d partner application

curl --fail http://127.0.0.1:3080/.well-known/did.json
curl --fail http://127.0.0.1:3082/api/session
```

The app returns `status: anonymous` before sign-in. This proves startup, not verifier
registration or credential acceptance. Its log reports `education_application_ready`.
A missing variable produces `education_application_configuration_missing` with variable
names only. Other startup errors point to configuration, database connectivity and port
availability without printing secret values.

App and runtime share a network namespace. The app reaches management at loopback
`127.0.0.1:3081`; that port is never published. Only public runtime `3080` and app `3082`
are bound to host loopback. Route your two HTTPS origins to these public listeners.
Never tunnel management or put its token or result capabilities into browser code.

```sh
docker compose --env-file /absolute/path/team.env -p credworks-team \
  -f infra/education-sign-in/compose.yml --profile local-db stop
# Restart with the two up commands above. Do not bootstrap again.
```

Stop, restart and container replacement retain the named identity and database volumes.
Browser sessions expire on app restart, while stored account mappings remain. Back up
the volumes and protected secrets together. Do not use `down --volumes`, delete volumes,
change the project name or replace unlock keys as a repair step.

## If startup fails

- Docker reports a port already in use: stop the competing service you own, or select
  unused `PARTNER_HOST_PORT` and `EDUCATION_APP_HOST_PORT` values in the protected file.
  Update local tunnel destinations to match. Public origins and keys do not change.
- The image does not match the architecture: load the matching candidate and verify its
  image ID and architecture. Emulation is not a substitute for a supported host check.
- Compose names a missing variable: add that variable to the protected file and retry.
  Keep existing secrets. Do not print the file while troubleshooting.
- The app cannot reach its database: start the dedicated database with `--wait`, confirm
  the configured host is `database`, and preserve its original password and volume.
- The runtime refuses bootstrap or startup: check the original state volume, origin,
  unlock key and config file permissions. Do not generate another identity to recover.
- HTTPS or registration is not ready: keep the existing containers and identity. Finish
  fixed-origin routing and verified configuration in guided setup before requesting a
  credential. A working local page alone does not prove phone reachability.

## Platform evidence

A Linux image build, including one under emulation, does not prove Windows/WSL2 works.
Record the host OS, container engine, architecture, exact image ID, source revision and
commands for each observed run. macOS ARM64, native Linux AMD64 and Windows/WSL2 checks
are separate observations. Unavailable environments remain NOT RUN until tested.
