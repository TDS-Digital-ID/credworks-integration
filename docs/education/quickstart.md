# Setup and registration

New here? Start with [Getting started](getting-started.md) and the container-based
[team setup](../setup/guide.md). This page retains the advanced native setup and
registration contract for existing integrations.

These commands are a runbook, not evidence that a particular deployment has passed acceptance. Use a fresh kit checkout, the toolchain in the [compatibility table](overview.md#compatibility-and-availability), PostgreSQL for a dedicated application database, OpenSSL, Caddy, and cloudflared for the optional named tunnel. Install CLI packages through your platform package manager. Container use also requires an initialized Docker runtime. OS trust, elevation or account prompts require the operator.

## Published CredWorks sandbox configuration

Use the [versioned sandbox configuration](../../config/credworks-sandbox-20261011.json) for the public CredWorks preview. It supplies public origins, issuer/provider keys, the independent registry root, signed status sources and the Education institution policy. It contains no project credentials or partner keys. Your own HTTPS origins, database, runtime secrets and persistent identities remain operator prerequisites.

Acquire this file from a full commit of the public `TDS-Digital-ID/credworks-integration` repository authenticated through your trusted GitHub account or release handoff. Record the commit and verify the file's SHA-256 against the value below. Do not acquire your root key from the runtime registry and then use that key to authenticate the same registry. The checksum detects changes; trust in the publisher supplies the initial authority.

```sh
# Set the full public commit supplied by the authenticated handoff.
REVISION=${PUBLIC_SOURCE_REVISION:?set the authenticated full public commit}
curl --fail --silent --show-error --proto '=https' \
  "https://raw.githubusercontent.com/TDS-Digital-ID/credworks-integration/$REVISION/config/credworks-sandbox-20261011.json" \
  -o credworks-sandbox-20261011.json
shasum -a 256 credworks-sandbox-20261011.json
```

Expected SHA-256: `554b1a092b30b888b243c47ee22f526fa573f51322ac9972549774288314c096`.

The configuration records the operator's independent host inspection and wallet-build checksums. The pinned registry public-key coordinates and service origins match those wallet builds. The wallet derives registry identity from its configured origin; the published configuration uses the live registry key ID. Issuer/provider keys were checked against the authenticated host and signed accreditation.

The configuration records a specific authenticated observation. It is not a permanent trust-update service. Before use, check that the selected release still names these origins and key coordinates. Follow signed evidence freshness checks normally. On changed keys, withdrawn authority, stale evidence or unavailable services, stop and obtain a reviewed replacement configuration from the authenticated publisher. Do not automatically adopt keys from a live DID response, replace an identity, or extend an evidence deadline. New origins or wallet pins require a new candidate and affected checks.

Map the published values into the protected files below:

| Consumer | Published values |
|---|---|
| `register.json` | `registryOrigin`, `registryDid`, `trustAnchorJwk`; use `education.issuerDid` as `educationIssuerDid` |
| Verifier JSON | `education.issuerDid` as `issuerDid`, `education.issuerJwk` as `issuerJwk`, `registryOrigin`, `trustAnchorJwk`, all `education.statusSources`; keep `maxCacheAgeSeconds` at 300 |
| App environment | `education.issuerDid` as `EDUCATION_TRUSTED_ISSUER`, `education.institution` as `EDUCATION_INSTITUTION`; derive `EDUCATION_VERIFIER_DID` from your own runtime's published DID |
| `education-http.json` | `registryOrigin`, `registryDid`, `trustAnchorJwk`, `portalOrigin`, `providerOrigin`; map `government.issuerDid` and `education.issuerDid` to the corresponding issuer DID fields |

Keep your own runtime/app origins, loopback management address, management token and disposable holder state in protected operator files. The public configuration does not grant partner authority. Registration and signed permissions below are still required.

## Build and protect state

```sh
pnpm install --frozen-lockfile
CARGO_BUILD_JOBS=2 pnpm build
pnpm docs:check
umask 077
mkdir -p "$HOME/.credworks-education" .logs
export PARTNER_STATE_DIR="$HOME/.credworks-education/identity"
export PARTNER_UNLOCK_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
export PARTNER_MANAGEMENT_TOKEN="$(openssl rand -hex 32)"
export PARTNER_PUBLIC_PORT=3080
export PARTNER_MANAGEMENT_PORT=3081
```

Store both generated secrets in protected operator storage before stopping the shell. The unlock key is 32 random bytes, base64url, not a password. State is encrypted local custody, not an HSM. Do not log secrets or commit configuration containing tokens. Bootstrap refuses any existing state directory, including incomplete state.

## HTTPS and development tunnel

Use two stable HTTPS names in a domain you control, for example partner.example.org and app.example.org. A changing quick-tunnel hostname changes the verifier DID and invalidates its persistent origin. Use a named tunnel and fixed DNS names. Before bootstrap, set `PARTNER_ORIGIN` and `EDUCATION_APP_ORIGIN` to those exact HTTPS origins. The registry, issuer and status services must also be independently reachable over normally validated HTTPS.

An operator with a Cloudflare zone and tunnel permissions performs:

```sh
cloudflared tunnel login
cloudflared tunnel create credworks-education
cloudflared tunnel route dns credworks-education partner.example.org
cloudflared tunnel route dns credworks-education app.example.org
```

Record the returned tunnel UUID. In protected operator storage create `tunnel.yml`, replacing UUID and credentials path with the actual values:

```yaml
tunnel: REPLACE_WITH_TUNNEL_UUID
credentials-file: /absolute/protected/REPLACE_WITH_TUNNEL_UUID.json
ingress:
  - hostname: partner.example.org
    service: http://127.0.0.1:8080
  - hostname: app.example.org
    service: http://127.0.0.1:8080
  - service: http_status:404
```

Create a Caddyfile with a finite route list. Cloudflare terminates external TLS; Caddy listens on loopback behind that tunnel:

```caddyfile
{
    admin off
    auto_https off
    persist_config off
    storage file_system {
        root /absolute/protected/education-caddy-storage
    }
}
http://partner.example.org:8080 {
    bind 127.0.0.1
    @read {
        method GET
        path /.well-known/did.json /oid4vp/request/*
    }
    handle @read {
        reverse_proxy 127.0.0.1:3080
    }
    @write {
        method POST
        path /oid4vp/response/*
    }
    handle @write {
        reverse_proxy 127.0.0.1:3080
    }
    handle {
        respond 404
    }
}
http://app.example.org:8080 {
    bind 127.0.0.1
    @read {
        method GET
        path / /openapi.json /api/session /app.js /app.css /spectral.ttf /mono.ttf /fonts /spectral-OFL.txt /mono-OFL.txt
    }
    handle @read {
        reverse_proxy 127.0.0.1:3082
    }
    @write {
        method POST
        path /api/interactions /api/interactions/*/complete
    }
    handle @write {
        reverse_proxy 127.0.0.1:3082
    }
    handle {
        respond 404
    }
}
```

Replace the storage path with a dedicated operator-owned directory outside any existing Caddy storage. These HTTP-only loopback sites sit behind Cloudflare TLS. Disable Caddy's admin listener and config persistence so a candidate does not share port 2019, overwrite another process's saved config or clean its certificate cache. The finite asset paths above are the files served by the delivered reference app.

```sh
caddy validate --config /absolute/protected/Caddyfile --adapter caddyfile
caddy run --config /absolute/protected/Caddyfile --adapter caddyfile 2>&1 | tee .logs/education-caddy.log
# In another shell:
cloudflared tunnel --config /absolute/protected/tunnel.yml ingress validate
cloudflared tunnel --config /absolute/protected/tunnel.yml run credworks-education 2>&1 | tee .logs/education-tunnel.log
```

The public runtime listener binds 0.0.0.0; firewall direct access so only the local proxy reaches it. Management binds 127.0.0.1:3081 and must never be forwarded. Do not disable CA/hostname checks or use private-network resolver overrides in production. Tunnel account login is an operator prerequisite, not a test bypass.

## Disposable quick-tunnel candidate

For the isolated host candidate, cloudflared Quick Tunnels need no account/domain credentials. They are temporary testing origins, not an identity migration or a supported deployment. Start two quick tunnels before bootstrap, retain their processes, and record each actual HTTPS hostname from local output:

```sh
umask 077
printf '{}\n' > "$HOME/.credworks-education/quick-tunnel.yml"
cloudflared tunnel --config "$HOME/.credworks-education/quick-tunnel.yml" --url http://127.0.0.1:8080 --http-host-header partner-candidate.local 2>&1 | tee .logs/education-quick-runtime.log
# In another shell:
cloudflared tunnel --config "$HOME/.credworks-education/quick-tunnel.yml" --url http://127.0.0.1:8081 --http-host-header app-candidate.local 2>&1 | tee .logs/education-quick-app.log
```

The explicit empty config prevents an existing `~/.cloudflared/config.yml` from supplying unrelated named-tunnel ingress or credentials. Leave existing tunnel configuration untouched. Keep raw tunnel logs protected; publish only sanitized settings and reachability evidence. Verify both allowed gateway paths through the actual public HTTPS origins before bootstrap with temporary transport probes that contain no identity or signing key. A generated hostname or connected tunnel log alone does not prove forwarding. Remove the probes before starting the runtime/app, then verify the real public DID matches bootstrap output and management routes return 404.

Use the Caddy route lists above with runtime site address `http://partner-candidate.local:8080` and app site address `http://app-candidate.local:8081`. Retain `bind 127.0.0.1` and all finite matchers. The host-header flags select those internal proxy sites only; signed public origins remain the actual HTTPS tunnel hostnames. Set PARTNER_ORIGIN and EDUCATION_APP_ORIGIN to those observed origins before bootstrap, and use the same origins in registration, app config and driver config. Do not invent a hostname or replace a signed ecosystem URL with it.

Use a fresh disposable protected state directory and database. Keep the same tunnel processes/origins alive through registration and identity-only → verifier restart. If a tunnel origin changes or a step fails, preserve state and logs for diagnosis; never restart that identity under a replacement hostname. A new tunnel identity needs distinct explicit bootstrap/registration. Record observed tunnel routing and management refusal separately; these commands alone are not execution evidence. Public runtime reachability, mapped fixture ecosystem transport, mock WIA and physical authorization require separate evidence labels.

## Bootstrap, register, configure and restart

```sh
export PARTNER_ORIGIN=https://partner.example.org
export EDUCATION_APP_ORIGIN=https://app.example.org
unset PARTNER_VERIFIER_CONFIG
pnpm --filter @unsw-vc/partner-runtime bootstrap
pnpm --filter @unsw-vc/partner-runtime start 2>&1 | tee .logs/partner-runtime.log
```

In another protected shell, create `/absolute/protected/register.json` with these exact keys, replacing public pins and the management token. Use mode 0600:

```json
{
  "registryOrigin": "https://registry.example.org",
  "registryDid": "did:web:registry.example.org",
  "trustAnchorJwk": {"kty":"EC","crv":"P-256","x":"PINNED_PUBLIC_X","y":"PINNED_PUBLIC_Y"},
  "educationIssuerDid": "did:web:education.example.org",
  "runtimeOrigin": "https://partner.example.org",
  "managementOrigin": "http://127.0.0.1:3081",
  "managementToken": "REPLACE_WITH_PROTECTED_RUNTIME_TOKEN"
}
```

```sh
chmod 600 /absolute/protected/register.json
pnpm register /absolute/protected/register.json /absolute/protected/registration-result.json
```

Keep both files private (mode 0600) and the output directory mode 0700. The output is a progress file: it stores the project credential as soon as received. After a connectivity or permission failure, rerun the **same command with the same files**. The tool reuses the saved project and completed registration, checks authenticated registry state, and renews an expired known challenge. It never bootstraps a new runtime identity.

Expected result: `VERIFIER_REGISTERED_PROTECTED_OUTPUT_WRITTEN`. This means both signed Education permissions were verified. A partial progress file alone does not mean registration succeeded. If the command reports an unknown outcome or a lock, follow [registration recovery](operations.md#registration-recovery); do not delete the file and start again.

The tool creates a project, fetches the public DID, obtains a registry challenge, signs it through protected runtime HTTP, completes endpoint/key ownership and verifies both signed Education grants with the independent registry DID/anchor. The progress file is mode 0600 and contains the separate project management credential; protect it like a password. Registration establishes endpoint/key control, never credential issuer authority or permission to add Education claims.

Create a public verifier JSON using the following shape and independently provisioned keys/status URLs. It must not contain secrets:

```json
{
  "issuerDid": "did:web:education.example.org",
  "issuerJwk": {"kty":"EC","crv":"P-256","x":"PINNED_ISSUER_X","y":"PINNED_ISSUER_Y"},
  "registryOrigin": "https://registry.example.org",
  "trustAnchorJwk": {"kty":"EC","crv":"P-256","x":"PINNED_REGISTRY_X","y":"PINNED_REGISTRY_Y"},
  "statusSources": [{"url":"https://status.example.org/education.jwt","publicJwk":{"kty":"EC","crv":"P-256","x":"PINNED_STATUS_X","y":"PINNED_STATUS_Y"},"purpose":"revocation"}],
  "maxCacheAgeSeconds": 300
}
```

The runtime derives the expected registry DID from registryOrigin and checks exact signed trust/permission/status document IDs. A random tunnel URL cannot substitute for a signed ecosystem origin. The registration CLI has no mapped TLS/DNS injection option; any isolated test mapping belongs to the external environment with normal certificate/hostname verification.

Supply all credential status purposes in use, with 1–4 explicit sources. Stop the identity-only runtime with its supervisor or Ctrl-C. Preserve state and secrets, set `PARTNER_VERIFIER_CONFIG=/absolute/operator/verifier.json`, and repeat the same start command. Startup fetches signed evidence and fails closed if absent. Never bootstrap a replacement.

## Dedicated application database

Use an empty operator-owned database, separate from registry/issuer databases. For local PostgreSQL, create the dedicated login/database once:

```sh
createuser --pwprompt education_app
createdb --owner education_app education_app
```

The password prompt belongs to the operator. Inject its connection string as `EDUCATION_APP_DATABASE_URL` through protected secret storage. The app applies bundled Drizzle migrations at startup; start one app instance at a time.

```sh
export EDUCATION_RUNTIME_MANAGEMENT=http://127.0.0.1:3081
export EDUCATION_TRUSTED_ISSUER=did:web:education.example.org
export EDUCATION_VERIFIER_DID=did:web:partner.example.org
export EDUCATION_INSTITUTION=REPLACE_WITH_ALLOWED_INSTITUTION
export EDUCATION_APP_PORT=3082
pnpm --filter @unsw-vc/education-sign-in start 2>&1 | tee .logs/education-sign-in.log
```

The app also requires the previously protected `PARTNER_MANAGEMENT_TOKEN`, `EDUCATION_APP_ORIGIN` and database URL. Forward only the documented browser routes.

## Synthetic onboarding and acceptance

Configure `/absolute/protected/education-http.json` with `registryOrigin`, `registryDid`, `trustAnchorJwk`, `portalOrigin`, `providerOrigin`, `applicationOrigin`, `runtimeOrigin`, `governmentIssuerDid`, `educationIssuerDid`, and a disposable protected `stateDir`. Origins must match the actual metadata roles. The issuer DID origin is not automatically the portal/authorization-server origin.

```sh
pnpm acceptance /absolute/protected/education-http.json
```

The driver does not read registration-result.json. It creates a second independent project for synthetic onboarding; registration above owns verifier endpoint/key control.

The kit-only driver creates a project, allocates a synthetic person using a UUID `allocation_id`, and requests a setup with UUID `request_id` and scenario `valid`. It receives Government Identity through the public pre-authorized-code flow and provider-signed mock WIA, verifies the signed enrolment request and independent trust, presents exactly given name/family name/date of birth with consented scope, then retries the same setup request to obtain holder-bound Education. Partners integrate Education; Government is the internal enrolment prerequisite. No real personal data is used.

The driver exercises browser correlation refusal, both profiles, repeat sign-in account continuity and consumed-result replay. It uses a Rust-held headless key and self-asserted mock platform attestation, not genuine Android authorization. A physical wallet must still review recipient, purpose, chosen instance and exact values and complete normal holder authorization. See [negative checks and recovery](operations.md).
