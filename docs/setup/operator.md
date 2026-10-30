# Course operator procedures

These procedures are for the course operator. Students follow [team setup](guide.md).

## Course operator allocation

This is an operator prerequisite, not a student task. No teaching account or domain
is allocated by this document. Use a dedicated teaching Cloudflare account and a
separate registrable teaching domain. Record their exact account ID, zone ID and
domain in a protected inventory before any write. Record the renewal owner/date,
course end date and private delivery channel. Keep production resources out of this
inventory and administration context.

| Group | Named tunnel | Exact origins beneath the teaching domain |
| --- | --- | --- |
| banana | `comp3900-banana` | `https://banana-verify.<teaching-domain>`, `https://banana-app.<teaching-domain>` |
| cherry | `comp3900-cherry` | `https://cherry-verify.<teaching-domain>`, `https://cherry-app.<teaching-domain>` |

Record each tunnel UUID, its two DNS record IDs/targets, allocation status and nominated
active host. The groups need separate tunnels and secrets. Do not create wildcard DNS,
private-network routes, shared application databases or student account memberships.

1. Use an operator workstation/profile dedicated to teaching administration. In the
   Cloudflare dashboard, confirm the teaching account ID and domain against the
   inventory. Authorize `cloudflared tunnel login` for that account/domain and keep
   its `cert.pem` in a private directory. Do not reuse an inherited production login.
   If the account or domain differs, stop before creating anything.
2. Set `TEACHING_CERT` to that certificate, `TEACHING_ADMIN` to a protected directory,
   and `GROUP` to `banana` or `cherry`. Use `umask 077`, mode `0700` for directories
   and `0600` for credentials/inventory. Set `TUNNEL_NAME` to the exact table entry.
   Inspect only that allocation:

   ```sh
   cloudflared tunnel --origincert "$TEACHING_CERT" list --output json --name "$TUNNEL_NAME"
   ```

   An existing name must match the recorded UUID and teaching account. If creation
   was interrupted, reconcile the exact name/UUID and original credential file
   before continuing. Do not blindly create another tunnel, delete a resource or
   overwrite a credential. An unresolved outcome needs operator investigation.
3. Only when both the provider name and local credential path are unused, create the
   one allocation. Keep the result private:

   ```sh
   env -u TUNNEL_CREATE_SECRET cloudflared tunnel --origincert "$TEACHING_CERT" \
     create --credentials-file "$TEACHING_ADMIN/$GROUP-credential.json" \
     --output json "$TUNNEL_NAME" > "$TEACHING_ADMIN/$GROUP-create.json"
   ```

   Record the new UUID after comparing the dashboard with the saved result. Before
   any DNS change or handoff, construct the bundle below using the expected account
   ID and UUID from the inventory. A mismatch stops the operation. Do not delete
   resources in an unexpected account to conceal a mistake.
4. Inspect the teaching zone for both exact names. Create a route only if absent;
   reuse it only if its UUID target and allocation already match. A conflicting
   record stops provisioning. For each recorded hostname, run:

   ```sh
   env -u TUNNEL_FORCE_PROVISIONING_DNS cloudflared tunnel --origincert "$TEACHING_CERT" \
     route dns --overwrite-dns=false "$TUNNEL_ID" "$HOSTNAME"
   ```

   Confirm both proxied CNAMEs point to `<tunnel-uuid>.cfargotunnel.com`, record their
   IDs, and check that the other group's records are unchanged. Do not add routes
   to production hosts or private networks.
5. Deliver only that group's bundle through the agreed private channel. Separately
   confirm the group, exact origins, kit revision and nominated active host. Students
   generate their own signing keys, project credential and database password during
   setup. Do not deliver those secrets, `cert.pem`, API tokens or another group's bundle.

To construct the data-only bundle, set `TEACHING_ACCOUNT_ID`, `TEACHING_DOMAIN`,
`TUNNEL_ID`, `GROUP` and `TEACHING_ADMIN` from the verified inventory, then run this
on the operator machine with Node.js. None of these variables contains a secret.
Export those five variables for this command. It reads the credential from disk and
writes a new file without printing its content. The provider's optional `Endpoint`
must be absent or empty; the bundle contains only the three tunnel credential fields.

```js
// Save as an operator-only .cjs script, then run with node. Keep its output file private.
try {
  const assert = require('node:assert/strict');
  const fs = require('node:fs');
  const path = require('node:path');
  const { TEACHING_ACCOUNT_ID: accountId, TEACHING_DOMAIN: domain,
    TUNNEL_ID: tunnelId, GROUP: group, TEACHING_ADMIN: directory } = process.env;
  assert(['banana', 'cherry'].includes(group));
  assert(/^[a-f0-9]{32}$/.test(accountId));
  assert(/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(tunnelId));
  assert(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain));
  const raw = JSON.parse(fs.readFileSync(path.join(directory, `${group}-credential.json`)));
  assert.equal(raw.AccountTag, accountId);
  assert.equal(raw.TunnelID, tunnelId);
  assert(!raw.Endpoint);
  assert(/^[A-Za-z0-9+/]{43}=$/.test(raw.TunnelSecret));
  assert.equal(Buffer.from(raw.TunnelSecret, 'base64').toString('base64'), raw.TunnelSecret);
  const credentials = { AccountTag: raw.AccountTag, TunnelID: raw.TunnelID, TunnelSecret: raw.TunnelSecret };
  const bundle = { version: 1, group, runtimeOrigin: `https://${group}-verify.${domain}`,
    appOrigin: `https://${group}-app.${domain}`, accountId, tunnelId, credentials };
  fs.writeFileSync(path.join(directory, `${group}.json`), JSON.stringify(bundle) + '\n',
    { flag: 'wx', mode: 0o600 });
} catch {
  console.error('COURSE_BUNDLE_REFUSED');
  process.exitCode = 1;
}
```

The bundle limit is 4 KiB. Unknown fields and changed group/account/origin bindings
are refused. These checks prevent mistakes on the supported setup path. A student
can alter local code or ingress, so isolation depends on Cloudflare's tunnel/DNS
authorization, no private-network access, and the existing project API's server-side
authorization. Cloudflare documents the different authority of
[tunnel credentials and account certificates](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/tunnel-permissions/).
Keep that distinction when reviewing or replacing any credential.

Before real handoff, qualify wrong-tunnel credentials and peer-host ingress in the
teaching account with harmless canary responses, ordinary TLS enabled and the other
group still working. Local mapped HTTPS tests cannot prove provider authorization.
Renew the teaching domain while allocations remain active. Keep the course end date
and later retirement evidence in the inventory; never recycle one group's hostname
to a different group. Tunnel shutdown and registry-project withdrawal are separate actions.

## Deliver a private team starter

Package the reviewed, committed kit with only that team's validated bundle. On the
operator workstation, from a clean kit checkout with Node.js:

```sh
node tool/package-team.mjs /absolute/private/banana.json /absolute/private/banana-starter.tar.gz
```

The output is private and refuses overwriting. It contains a `setup` launcher,
`team.json`, `START-HERE.txt` and a `.credworks` folder with the required committed
runtime helpers and licence. Developer source, tests, build files, other bundles
and account certificates are excluded. Deliver it through the agreed private channel and confirm
the team and exact app/verifier addresses separately. The team extracts it, starts
Docker and runs `./setup`. They confirm the assignment before registration.

The helper chooses `$HOME/.local/share/credworks-team`, protects the imported
credential, starts the saved services and checks eligibility. A failed check never
reports `TEAM_READY`. Keep one active host; use the existing host-handover procedure
for a move. Existing custom state paths require `./setup up --state /existing/path`.

## Course tunnel replacement and retirement

These operations require the operator's teaching authority. Students receive only
their tunnel-specific credential, never the account certificate or a DNS token.
Use the recorded account ID, zone ID, tunnel UUID and two exact DNS record IDs.
Recheck the account and zone in the dashboard before each change. Compare the peer's
record IDs, targets and live eligibility result before and after the operation.
Production inventory checks are read-only. Destructive qualification must use
explicitly designated disposable teaching resources.

For compromise or end-of-course retirement:

1. Mark that allocation `retirement pending` in the protected inventory. Record the
   old UUID, exact hostnames, DNS record IDs/targets and active connector IDs. Do not
   depend on the student stopping a process. Inspect the recorded tunnel:

   ```sh
   cloudflared tunnel --origincert "$TEACHING_CERT" info "$OLD_TUNNEL_ID"
   ```

2. Disconnect the recorded connectors, then force deletion so active connections
   cannot prevent tunnel deletion:

   ```sh
   cloudflared tunnel --origincert "$TEACHING_CERT" cleanup "$OLD_TUNNEL_ID"
   cloudflared tunnel --origincert "$TEACHING_CERT" delete -f "$OLD_TUNNEL_ID"
   ```

   Cloudflare documents [connector cleanup and forced deletion](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/tunnel-useful-commands/).
   Verify the deleted UUID in the authenticated dashboard or deleted-tunnel listing.
   A disconnected connector alone can reconnect while its tunnel remains valid.
   If interrupted, reconcile that UUID and its deletion status. An already deleted
   UUID completes this step; an authorization error or a missing active-list entry
   does not. Never replace a failed command with an account-wide cleanup.
3. Observe that an already connected disposable canary stops serving. Attempt a
   fresh connector using the old credential from a protected file with no account
   certificate or API token. Keep ordinary TLS validation on. Confirm it cannot
   reconnect or serve either old hostname, while the peer still reaches backend
   `eligible`. Retain only refusal codes, timestamps and public resource IDs. If
   old ingress survives, investigate the exact connector/provider state and leave
   retirement pending. DNS deletion is not evidence of credential invalidation.
4. For final retirement, open the teaching zone's DNS records in the dashboard.
   Locate each saved record ID and confirm its exact name and old UUID target, then
   delete only those two records. If already absent, record that result. A changed
   ID, name or target stops cleanup for investigation. Do not delete by a broad
   hostname search. Confirm both origins no longer reach the service and the peer
   remains eligible. Mark `ingress retired` with sanitized evidence and keep the
   hostname allocation reserved permanently for that group.

For replacement, retain those two hostnames for the same group. After the old tunnel
has been deleted and old-credential refusal observed, allocate a new named tunnel in
the same teaching account. Record a distinct generation name such as
`comp3900-banana-r2`, its new UUID, and `replacement pending` before delivery. Follow
the [allocation checks and bundle recipe](#course-operator-allocation) in a new
protected generation directory so prior evidence is not overwritten. If creation
is interrupted, reconcile that recorded generation name and UUID before retrying.

In the teaching DNS dashboard, edit only the two recorded records whose names and
targets still match the old allocation. Change their targets to the new UUID, retain
proxying, and record the resulting IDs/targets. If an earlier step already removed
them, create only the absent recorded names with `--overwrite-dns=false`. Reconcile
each record independently on retry. Refuse an unexpected target; do not force an
overwrite. Confirm the peer is unchanged, then privately deliver the new bundle and
old UUID for the student's explicit replacement command. Qualify the unchanged DID,
project and account continuity, backend eligibility, old-credential refusal and peer
eligibility before marking the generation active. Some downtime is expected.

At course end, retire each group separately with the same peer control while that
peer is still active. Record the final course-wide shutdown after both retirements.
Keep the non-secret allocation/retirement record and the domain renewal owner/date.
Remove unneeded protected delivery copies under the course retention policy after
evidence is complete. Keep renewing the domain while any allocation or reference
still depends on it; do not let it expire as a substitute for retirement.

Ingress retirement ends the course-provided route. It does not withdraw the registry
project, revoke signed permissions, or bar an ordinary Internet client from public
APIs. The normal project withdrawal API requires the owning project credential and
separate authorization. The owner sends `DELETE /api/projects/{project_id}` to the
configured registry with its current project bearer and confirms `{"withdrawn":true}`.
This permanently disables project management access; there is no restore operation.
Existing signed Education permissions can remain usable until their five-minute
expiry, as described in [evidence freshness](../education/operations.md#freshness-and-diagnostics).
This runbook grants no operator override.
Provider authorization, connector termination, reconnect refusal and live routing
remain unqualified until the live acceptance records those observations. Local
replacement tests and a locally stopped service cannot establish them.
