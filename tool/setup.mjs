import { pathToFileURL, fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { httpClient } from './http-client.mjs';
import { readCredential } from './setup-credential.mjs';
const fail = (code) => { throw Error(code); };
const digest = value => createHash('sha256').update(value).digest('hex');
const random = () => randomBytes(32).toString('base64url');
const json = path => JSON.parse(readFileSync(path, 'utf8'));
function origin(value) {
  let url;
  try { url = new URL(value); } catch { fail('SETUP_ORIGIN_REFUSED'); }
  if (url.protocol !== 'https:' || url.origin !== value || url.username || url.password || url.port || !url.hostname.includes('.') || url.hostname.endsWith('.trycloudflare.com') || url.hostname.endsWith('.localhost')) fail('SETUP_ORIGIN_REFUSED');
  return value;
}
function protectedPath(path, directory = false) {
  const info = lstatSync(path);
  if (!(directory ? info.isDirectory() : info.isFile()) || info.uid !== process.getuid() || (info.mode & (directory ? 0o077 : 0o177))) fail('SETUP_STORAGE_REFUSED');
}
function suppliedBundle(path, group, runtimeOrigin, appOrigin) {
  protectedPath(path);
  if (lstatSync(path).size > 4096) fail('SETUP_TUNNEL_BUNDLE_REFUSED');
  let bundle;
  try { bundle = json(path); } catch { fail('SETUP_TUNNEL_BUNDLE_REFUSED'); }
  const fields = ['version', 'group', 'runtimeOrigin', 'appOrigin', 'accountId', 'tunnelId', 'credentials'];
  if (!bundle || typeof bundle !== 'object' || Object.keys(bundle).length !== fields.length || !fields.every(field => Object.hasOwn(bundle, field))) fail('SETUP_TUNNEL_BUNDLE_REFUSED');
  const domain = new URL(runtimeOrigin).hostname.slice(`${group}-verify.`.length);
  if (bundle.version !== 1 || !['banana', 'cherry'].includes(group) || bundle.group !== group || bundle.runtimeOrigin !== runtimeOrigin || bundle.appOrigin !== appOrigin || runtimeOrigin !== `https://${group}-verify.${domain}` || appOrigin !== `https://${group}-app.${domain}` || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) fail('SETUP_TUNNEL_BUNDLE_REFUSED');
  const credentials = bundle.credentials;
  if (!/^[a-f0-9]{32}$/.test(bundle.accountId) || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(bundle.tunnelId) || !credentials || Object.keys(credentials).length !== 3 || credentials.TunnelID !== bundle.tunnelId || credentials.AccountTag !== bundle.accountId || typeof credentials.TunnelSecret !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(credentials.TunnelSecret) || Buffer.from(credentials.TunnelSecret, 'base64').toString('base64') !== credentials.TunnelSecret) fail('SETUP_TUNNEL_BUNDLE_REFUSED');
  return bundle;
}
export function readCourseBundle(path) {
  protectedPath(path);
  if (lstatSync(path).size > 4096) fail('SETUP_TUNNEL_BUNDLE_REFUSED');
  let value;
  try { value = json(path); } catch { fail('SETUP_TUNNEL_BUNDLE_REFUSED'); }
  return suppliedBundle(path, value?.group, origin(value?.runtimeOrigin), origin(value?.appOrigin));
}
function atomic(path, value, mode = 0o600) {
  const pending = path + '.pending';
  const fd = openSync(pending, 'wx', mode);
  try { writeFileSync(fd, value); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(pending, path);
  const directory = openSync(dirname(path), 'r');
  try { fsyncSync(directory); } finally { closeSync(directory); }
}
function recoveryWrite(path, value, refusal = 'SETUP_TUNNEL_REPLACEMENT_AMBIGUOUS') {
  const pending = path + '.pending';
  if (existsSync(pending)) {
    protectedPath(pending);
    if (!readFileSync(pending).equals(Buffer.from(value))) fail(refusal);
    const file = openSync(pending, 'r');
    try { fsyncSync(file); } finally { closeSync(file); }
    renameSync(pending, path);
    const directory = openSync(dirname(path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } else atomic(path, value);
}
const candidate = json(resolve(dirname(fileURLToPath(import.meta.url)), '../config/setup-candidate.json'));
const previousCandidate = json(resolve(dirname(fileURLToPath(import.meta.url)), '../config/setup-candidate-20261013.json'));
function validImage(id, platform, role) {
  return [platform?.[role], platform?.[role + 'Imported'], platform?.[role + 'Config']].filter(Boolean).includes(id);
}
function inspectImages(binding, inspected) {
  if (!Array.isArray(inspected) || inspected.length !== 2) fail('SETUP_IMAGE_REFUSED');
  for (const [index, expected] of [binding.partnerImage, binding.appImage].entries()) {
    const image = inspected[index];
    if (image.Id !== expected || image.Os !== 'linux' || image.Architecture !== binding.architecture || image.Config?.User !== '10001:10001' || image.Config?.Labels?.['org.opencontainers.image.revision'] !== binding.sourceRevision) fail('SETUP_IMAGE_REFUSED');
  }
}
function tunnelCredentialName(state) {
  if (state.tunnelCredentialFile && state.tunnelCredentialFile !== `tunnel-credentials.${state.tunnelId}.json`) fail('SETUP_STATE_REFUSED');
  if (state.tunnelCredentialFile && !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(state.tunnelId)) fail('SETUP_STATE_REFUSED');
  return state.tunnelCredentialFile ?? 'tunnel-credentials.json';
}
function readState(root, replacingTunnel = false, upgrading) {
  protectedPath(root, true);
  if (!upgrading && ['runtime-upgrade.json', 'runtime-upgrade.json.pending'].some(name => existsSync(join(root, name)))) fail('SETUP_UPGRADE_PENDING');
  if (existsSync(join(root, 'tunnel-import.json')) || existsSync(join(root, 'tunnel-import.json.pending'))) fail('SETUP_TUNNEL_IMPORT_PENDING');
  if (!replacingTunnel && (existsSync(join(root, 'tunnel-replacement.json')) || existsSync(join(root, 'tunnel-replacement.json.pending')))) fail('SETUP_TUNNEL_REPLACEMENT_PENDING');
  if (readdirSync(root).some(name => name.endsWith('.pending') && !upgrading?.pending.has(name) && !(replacingTunnel && (['state.json.pending', 'tunnel-replacement.json.pending'].includes(name) || /^tunnel-credentials\.[a-f0-9-]+\.json\.pending$/.test(name))))) fail('SETUP_STORAGE_REFUSED');
  protectedPath(join(root, 'state.json'));
  const state = json(join(root, 'state.json'));
  if (state.version !== 1 || !/^[a-z0-9-]+$/.test(state.project) || !/^[A-Za-z0-9_-]{43}$/.test(state.unlockKey) || !/^[A-Za-z0-9_-]{43}$/.test(state.managementToken) || !/^[A-Za-z0-9_-]{43}$/.test(state.databasePassword)) fail('SETUP_STATE_REFUSED');
  const selected = [candidate, previousCandidate].find(value => value.sourceRevision === state.binding?.sourceRevision);
  const platform = selected?.platforms[state.binding?.architecture];
  if (!selected || !validImage(state.binding?.partnerImage, platform, 'partner') || !validImage(state.binding?.appImage, platform, 'application')) fail('SETUP_IMAGE_REFUSED');
  if (!state.configurationHashes) fail('SETUP_STATE_REFUSED');
  for (const [name, expected] of Object.entries(state.configurationHashes)) {
    if (!['team.env', 'registration-config.json', 'partner-image', 'public/verifier.json', 'issuer.json', 'issuer-compose.json'].includes(name)) fail('SETUP_STATE_REFUSED');
    if (name !== 'public/verifier.json') protectedPath(join(root, name));
    else if (!lstatSync(join(root, name)).isFile()) fail('SETUP_STORAGE_REFUSED');
    const actual = digest(readFileSync(join(root, name)));
    if (actual !== expected && !upgrading?.hashes.get(name)?.has(actual)) fail('SETUP_STATE_REFUSED');
  }
  if (state.binding.suppliedTunnel) {
    const path = join(root, tunnelCredentialName(state));
    if (!existsSync(path)) {
      if (!replacingTunnel) fail('SETUP_TUNNEL_CREDENTIAL_REQUIRED');
    } else {
      protectedPath(path);
      if (digest(readFileSync(path)) !== state.tunnelCredentialHash) fail('SETUP_TUNNEL_IDENTITY_REFUSED');
      const credentials = json(path);
      if (credentials.TunnelID !== state.tunnelId || credentials.AccountTag !== state.binding.suppliedTunnel.accountId) fail('SETUP_TUNNEL_IDENTITY_REFUSED');
    }
  }
  return state;
}
function save(root, state, write = atomic) { write(join(root, 'state.json'), JSON.stringify(state, null, 2) + '\n'); }
function writeConfiguration(root, state, writeFile = atomic) {
  const hashes = {};
  const write = (name, bytes) => { writeFile(join(root, name), bytes); hashes[name] = digest(bytes); };
  const b = state.binding, e = state.ecosystem;
  const values = {
    PARTNER_IMAGE: b.partnerImage, EDUCATION_APP_IMAGE: b.appImage,
    PARTNER_ORIGIN: b.runtimeOrigin, EDUCATION_APP_ORIGIN: b.appOrigin,
    PARTNER_UNLOCK_KEY: state.unlockKey, PARTNER_MANAGEMENT_TOKEN: state.managementToken,
    EDUCATION_DB_PASSWORD: state.databasePassword,
    EDUCATION_APP_DATABASE_URL: `postgres://education:${state.databasePassword}@database:5432/education`,
    EDUCATION_TRUSTED_ISSUER: e.education.issuerDid,
    EDUCATION_VERIFIER_DID: 'did:web:' + new URL(b.runtimeOrigin).host,
    EDUCATION_INSTITUTION: e.education.institution,
    PARTNER_CONFIG_DIR: join(root, 'public'),
    PARTNER_VERIFIER_CONFIG: state.configured ? '/config/verifier.json' : '',
    PARTNER_HOST_PORT: b.runtimePort, EDUCATION_APP_HOST_PORT: b.appPort,
  };
  if (b.role === 'verifier') {
    for (const name of Object.keys(values)) if (name.startsWith('EDUCATION_')) delete values[name];
  }
  if (b.role === 'issuer') {
    for (const name of Object.keys(values)) if (name.startsWith('EDUCATION_')) delete values[name];
    Object.assign(values, { PARTNER_VERIFIER_CONFIG: '', PARTNER_ISSUER_POSTGRES_PASSWORD: state.databasePassword, PARTNER_ISSUER_DATABASE_URL: `postgres://credworks:${state.databasePassword}@issuer-db:5432/partner_issuer`, PARTNER_ISSUER_CONFIG: state.configured ? '/issuer-config/issuer.json' : '' });
  }
  if (Object.values(values).some(value => /[\r\n'"$`\\]/.test(String(value)))) fail('SETUP_CONFIGURATION_REFUSED');
  if (b.role === 'issuer') {
    write('issuer-compose.json', JSON.stringify({ services: { partner: { environment: { PARTNER_ISSUER_CONFIG: state.configured ? '/issuer-config/issuer.json' : '', PARTNER_ISSUER_DATABASE_URL: values.PARTNER_ISSUER_DATABASE_URL }, volumes: ['issuer_config:/issuer-config:ro'] } }, volumes: { issuer_config: {} } }) + '\n');
  }
  write('team.env', Object.entries(values).map(([key, value]) => `${key}='${value}'`).join('\n') + '\n');
  write('partner-image', b.partnerImage + '\n');
  const registration = { registryOrigin: e.registryOrigin, registryDid: e.registryDid, trustAnchorJwk: e.trustAnchorJwk, educationIssuerDid: e.education.issuerDid, runtimeOrigin: b.runtimeOrigin, managementOrigin: 'http://127.0.0.1:3081', managementToken: state.managementToken };
  write('registration-config.json', JSON.stringify(registration) + '\n');
  state.configurationHashes = Object.fromEntries(['team.env', 'partner-image', 'registration-config.json', ...(b.role === 'issuer' ? ['issuer-compose.json', ...(state.configured ? ['issuer.json'] : [])] : state.configured ? ['public/verifier.json'] : [])].map(name => [name, hashes[name] ?? digest(readFileSync(join(root, name)))]));
  save(root, state, writeFile);
}
function upgrade(root, options) {
  if (Object.keys(options).some(key => !['--state', '--partner-image', '--app-image', '--kit-root', '--image-inspection'].includes(key))) fail('SETUP_ARGUMENTS_REFUSED');
  const journalPath = join(root, 'runtime-upgrade.json');
  const existing = [journalPath, journalPath + '.pending'].find(existsSync);
  let journal;
  if (existing) { protectedPath(existing); journal = json(existing); }
  const original = journal?.before ?? readState(root);
  const platform = candidate.platforms[original.binding.architecture];
  const binding = { ...original.binding, sourceRevision: candidate.sourceRevision,
    partnerImage: options['--partner-image'], appImage: options['--app-image'], kitRoot: resolve(options['--kit-root']) };
  if (!validImage(binding.partnerImage, platform, 'partner') || !validImage(binding.appImage, platform, 'application')) fail('SETUP_IMAGE_REFUSED');
  inspectImages(binding, json(options['--image-inspection']));
  if (journal && !isDeepStrictEqual(journal.binding, binding)) fail('SETUP_UPGRADE_REFUSED');
  const next = { ...structuredClone(original), binding }, writes = new Map();
  writeConfiguration(root, next, (path, bytes) => writes.set(path.slice(root.length + 1), bytes));
  if (!existing && isDeepStrictEqual(next, original)) { console.log('SETUP_UPGRADED'); return; }
  const backupName = `runtime-upgrade-backup.${original.binding.sourceRevision}.json`;
  const hashes = new Map([...writes].filter(([name]) => name !== 'state.json').map(([name, bytes]) => [name, new Set([original.configurationHashes[name], digest(bytes)])]));
  const pending = new Set([...writes.keys(), 'runtime-upgrade.json', backupName].map(name => name + '.pending'));
  const current = readState(root, false, { hashes, pending });
  if (!isDeepStrictEqual(current, original) && !isDeepStrictEqual(current, next)) fail('SETUP_UPGRADE_REFUSED');
  journal ??= { before: original, binding, files: Object.fromEntries([...writes.keys()].map(name => [name, readFileSync(join(root, name), 'utf8')])) };
  if (Object.keys(journal.files).sort().join() !== [...writes.keys()].sort().join()) fail('SETUP_UPGRADE_REFUSED');
  for (const [name, bytes] of Object.entries(journal.files)) {
    if (typeof bytes !== 'string' || (name === 'state.json' ? !isDeepStrictEqual(JSON.parse(bytes), original) : digest(bytes) !== original.configurationHashes[name])) fail('SETUP_UPGRADE_REFUSED');
  }
  const journalBytes = JSON.stringify(journal) + '\n';
  const backup = join(root, backupName);
  if (existsSync(backup)) { protectedPath(backup); if (readFileSync(backup, 'utf8') !== journalBytes) fail('SETUP_UPGRADE_REFUSED'); }
  // Check every interrupted write before changing anything. Only this exact
  // transition can resume; keys, origins, registration and volumes are preserved.
  for (const [name, bytes] of [...writes, ['runtime-upgrade.json', journalBytes], [backupName, journalBytes]]) {
    const path = join(root, name + '.pending');
    if (existsSync(path)) { protectedPath(path); if (readFileSync(path, 'utf8') !== bytes) fail('SETUP_UPGRADE_REFUSED'); }
  }
  recoveryWrite(journalPath, journalBytes, 'SETUP_UPGRADE_REFUSED');
  if (!existsSync(backup) || existsSync(backup + '.pending')) recoveryWrite(backup, journalBytes, 'SETUP_UPGRADE_REFUSED');
  for (const [name, bytes] of writes) recoveryWrite(join(root, name), bytes, 'SETUP_UPGRADE_REFUSED');
  unlinkSync(journalPath);
  const directory = openSync(root, 'r');
  try { fsyncSync(directory); } finally { closeSync(directory); }
  console.log('SETUP_UPGRADED');
}
async function available(call, location) {
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      const response = await call(location);
      if (![502, 503].includes(response.status)) return response;
    } catch (error) {
      if (!['HTTP_TRANSPORT_UNAVAILABLE', 'HTTP_DEADLINE_EXCEEDED'].includes(error.message)) throw error;
    }
    if (attempt < 9) await new Promise(resolve => setTimeout(resolve, 1000));
  }
  fail('SETUP_CONNECTIVITY_UNAVAILABLE');
}
async function main(args) {
  const [command, ...flags] = args;
  const options = {};
  for (let i = 0; i < flags.length; i += 2) {
    if (!flags[i].startsWith('--') || !flags[i + 1] || options[flags[i]]) fail('SETUP_ARGUMENTS_REFUSED');
    options[flags[i]] = flags[i + 1];
  }
  const root = resolve(options['--state'] ?? '.credworks');
  if (command === 'upgrade') { upgrade(root, options); return; }
  if (command === 'course-input') {
    const bundle = options['--input'] ? readCourseBundle(options['--input']) : undefined;
    const importing = ['tunnel-import.json', 'tunnel-import.json.pending'].some(name => existsSync(join(root, name)));
    const state = existsSync(join(root, 'state.json')) && !importing ? readState(root) : undefined;
    if (state && ((state.binding.role ?? 'education') !== 'education' || !state.binding.suppliedTunnel)) fail('SETUP_ROLE_REFUSED');
    if (bundle && state && (bundle.group !== state.binding.suppliedTunnel.group || bundle.accountId !== state.binding.suppliedTunnel.accountId ||
        bundle.runtimeOrigin !== state.binding.runtimeOrigin || bundle.appOrigin !== state.binding.appOrigin || bundle.tunnelId !== state.tunnelId ||
        digest(JSON.stringify(bundle.credentials) + '\n') !== state.tunnelCredentialHash)) fail('SETUP_TUNNEL_IDENTITY_REFUSED');
    if (!bundle && !state) fail('SETUP_TEAM_BUNDLE_REQUIRED');
    console.log([bundle?.group ?? state.binding.suppliedTunnel.group, bundle?.runtimeOrigin ?? state.binding.runtimeOrigin, bundle?.appOrigin ?? state.binding.appOrigin].join('\n'));
    return;
  }
  if (command === 'prepare') {
    const role = options['--role'] ?? 'education';
    if (!['education', 'issuer', 'verifier'].includes(role) || (role !== 'education' && options['--app-origin']) || (role !== 'verifier' && options['--issuer-state']) || (role !== 'issuer' && options['--definition'])) fail('SETUP_ROLE_REFUSED');
    const runtimeOrigin = origin(options['--runtime-origin']), appOrigin = role === 'education' ? origin(options['--app-origin']) : undefined;
    if (runtimeOrigin === appOrigin) fail('SETUP_ORIGIN_REFUSED');
    if ((options['--group'] || options['--tunnel-bundle']) && (role !== 'education' || !options['--group'] || !options['--tunnel-bundle'])) fail('SETUP_TUNNEL_BUNDLE_REFUSED');
    const bundle = options['--tunnel-bundle'] ? suppliedBundle(options['--tunnel-bundle'], options['--group'], runtimeOrigin, appOrigin) : undefined;
    const platform = candidate.platforms[options['--architecture']];
    if (!platform) fail('SETUP_PLATFORM_REFUSED');
    const ecosystemPath = options['--ecosystem'] ?? resolve(dirname(fileURLToPath(import.meta.url)), '../config', candidate.ecosystemFile);
    const ecosystemBytes = readFileSync(ecosystemPath);
    const ecosystemSha256 = options['--ecosystem-sha256'] ?? candidate.ecosystemSha256;
    if (digest(ecosystemBytes) !== ecosystemSha256) fail('SETUP_TRUST_INPUT_REFUSED');
    const ecosystem = JSON.parse(ecosystemBytes);
    for (const value of [ecosystem.registryOrigin, ecosystem.portalOrigin, ecosystem.providerOrigin]) origin(value);
    if (ecosystem.version !== 1 || ecosystem.registryDid !== 'did:web:' + new URL(ecosystem.registryOrigin).host || !ecosystem.trustAnchorJwk?.x || !ecosystem.education?.issuerJwk?.x || !ecosystem.education?.statusSources?.length || !ecosystem.education?.institution) fail('SETUP_TRUST_INPUT_REFUSED');
    let issuerState, issuerProject;
    if (role === 'verifier') {
      if (!options['--issuer-state']) fail('SETUP_ISSUER_REQUIRED');
      issuerState = resolve(options['--issuer-state']);
      const issuer = readState(issuerState);
      if (issuer.binding.role !== 'issuer' || issuerState === root) fail('SETUP_ISSUER_REQUIRED');
      if (issuer.binding.runtimeOrigin === runtimeOrigin) fail('SETUP_ORIGIN_REFUSED');
      issuerProject = issuer.project;
      if (issuer.binding.ecosystemSha256 !== ecosystemSha256) fail('SETUP_TRUST_INPUT_REFUSED');
    }
    const credential = options['--definition'] ? await readCredential(options['--definition'], runtimeOrigin) : undefined;
    const binding = { ...(role !== 'education' ? { role } : {}), ...(credential ? { credential } : {}), ...(issuerState ? { issuerState, issuerProject } : {}), ...(bundle ? { suppliedTunnel: { group: bundle.group, accountId: bundle.accountId } } : {}), runtimeOrigin, ...(appOrigin ? { appOrigin } : {}), ecosystemSha256, architecture: options['--architecture'], partnerImage: options['--partner-image'] ?? platform.partner, appImage: options['--app-image'] ?? platform.application, sourceRevision: candidate.sourceRevision, runtimePort: Number(options['--runtime-port'] ?? (role === 'issuer' ? 3083 : role === 'verifier' ? 3084 : 3080)), appPort: Number(options['--app-port'] ?? 3082), kitRoot: resolve(options['--kit-root'] ?? '.') };
    if (!validImage(binding.partnerImage, platform, 'partner') || !validImage(binding.appImage, platform, 'application')) fail('SETUP_IMAGE_REFUSED');
    if (options['--image-inspection']) inspectImages(binding, json(options['--image-inspection']));
    if ([binding.runtimePort, binding.appPort].some(port => !Number.isInteger(port) || port < 1024 || port > 65535) || binding.runtimePort === binding.appPort) fail('SETUP_PORT_REFUSED');
    if (!existsSync(root)) mkdirSync(root, { mode: 0o700 });
    protectedPath(root, true);
    const journal = join(root, 'tunnel-import.json');
    const interrupted = [journal, journal + '.pending'].find(existsSync);
    if (existsSync(join(root, 'state.json')) && !interrupted) {
      const saved = readState(root);
      if (!isDeepStrictEqual(saved.binding, binding)) fail('SETUP_STATE_REFUSED');
      if (bundle && (saved.tunnelId !== bundle.tunnelId || !isDeepStrictEqual(json(join(root, tunnelCredentialName(saved))), bundle.credentials))) fail('SETUP_TUNNEL_IDENTITY_REFUSED');
      console.log('SETUP_PREPARED_EXISTING_STATE'); return;
    }
    if (!interrupted && readdirSync(root).filter(name => name !== '.lock').length) fail('SETUP_STORAGE_REFUSED');
    const suffix = randomBytes(8).toString('hex');
    let state = { version: 1, binding, ecosystem, project: 'credworks-' + suffix, tunnelName: 'credworks-' + suffix, phase: 'prepared', unlockKey: random(), managementToken: random(), databasePassword: random(), configured: false };
    if (interrupted) {
      if (!bundle) fail('SETUP_TUNNEL_IMPORT_PENDING');
      protectedPath(interrupted);
      try { state = json(interrupted); } catch { fail('SETUP_TUNNEL_IMPORT_AMBIGUOUS'); }
      const expected = { version: 1, binding, ecosystem, project: state?.project, tunnelName: state?.project, phase: 'prepared', unlockKey: state?.unlockKey, managementToken: state?.managementToken, databasePassword: state?.databasePassword, configured: false, tunnelId: bundle.tunnelId, tunnelCredentialHash: digest(JSON.stringify(bundle.credentials) + '\n') };
      if (!/^credworks-[a-f0-9]{16}$/.test(state?.project) || ['unlockKey', 'managementToken', 'databasePassword'].some(key => !/^[A-Za-z0-9_-]{43}$/.test(state?.[key])) || !isDeepStrictEqual(state, expected)) fail('SETUP_STATE_REFUSED');
    }
    if (bundle) {
      const credentialBytes = JSON.stringify(bundle.credentials) + '\n';
      state.tunnelId = bundle.tunnelId; state.tunnelCredentialHash = digest(credentialBytes);
      const writes = [[journal, JSON.stringify(state, null, 2) + '\n'], [join(root, 'tunnel-credentials.json'), credentialBytes]];
      writeConfiguration(root, { ...state }, (path, bytes) => writes.push([path, bytes]));
      const allowed = new Set(['.lock', 'public', ...writes.flatMap(([path]) => [path.slice(root.length + 1), path.slice(root.length + 1) + '.pending'])]);
      if (readdirSync(root).some(name => !allowed.has(name))) fail('SETUP_STORAGE_REFUSED');
      const publicPath = join(root, 'public');
      if (existsSync(publicPath)) {
        const info = lstatSync(publicPath);
        if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o022) || readdirSync(publicPath).length) fail('SETUP_STORAGE_REFUSED');
      }
      for (const [path, bytes] of writes) {
        for (const existing of [path, path + '.pending'].filter(existsSync)) {
          protectedPath(existing);
          if (!readFileSync(existing).equals(Buffer.from(bytes))) fail('SETUP_TUNNEL_IMPORT_AMBIGUOUS');
        }
      }
      // Record the selected identity before writing any of its credential or configuration files.
      for (const [path, bytes] of writes) {
        if (!existsSync(path) || existsSync(path + '.pending')) recoveryWrite(path, bytes, 'SETUP_TUNNEL_IMPORT_AMBIGUOUS');
      }
      if (!existsSync(publicPath)) mkdirSync(publicPath, { mode: 0o755 });
      unlinkSync(journal);
      const directory = openSync(root, 'r');
      try { fsyncSync(directory); } finally { closeSync(directory); }
      console.log('SETUP_PREPARED'); return;
    }
    save(root, state);
    mkdirSync(join(root, 'public'), { mode: 0o755 });
    writeConfiguration(root, state);
    console.log('SETUP_PREPARED'); return;
  }
  const state = readState(root, command === 'replace-tunnel');
  if (command === 'replace-tunnel') {
    if (Object.keys(options).some(key => !['--state', '--group', '--tunnel-bundle', '--runtime-origin', '--app-origin', '--from-tunnel'].includes(key))) fail('SETUP_ARGUMENTS_REFUSED');
    if (!state.binding.suppliedTunnel || options['--group'] !== state.binding.suppliedTunnel.group || options['--runtime-origin'] !== state.binding.runtimeOrigin || options['--app-origin'] !== state.binding.appOrigin) fail('SETUP_TUNNEL_REPLACEMENT_REFUSED');
    const bundle = suppliedBundle(options['--tunnel-bundle'], options['--group'], origin(options['--runtime-origin']), origin(options['--app-origin']));
    const credentialBytes = JSON.stringify(bundle.credentials) + '\n';
    const replacement = { fromTunnel: options['--from-tunnel'], tunnelId: bundle.tunnelId, credentialHash: digest(credentialBytes) };
    if (bundle.accountId !== state.binding.suppliedTunnel.accountId) fail('SETUP_TUNNEL_REPLACEMENT_REFUSED');
    const repeated = isDeepStrictEqual(state.tunnelReplacement, replacement);
    if (!repeated && (replacement.fromTunnel !== state.tunnelId || bundle.tunnelId === state.tunnelId || state.tunnelReplacedIds?.includes(bundle.tunnelId))) fail('SETUP_TUNNEL_REPLACEMENT_REFUSED');
    const filename = `tunnel-credentials.${bundle.tunnelId}.json`;
    if (readdirSync(root).some(name => name.endsWith('.pending') && !['state.json.pending', 'tunnel-replacement.json.pending', filename + '.pending'].includes(name))) fail('SETUP_STORAGE_REFUSED');
    const journal = join(root, 'tunnel-replacement.json'), journalBytes = JSON.stringify(replacement) + '\n';
    if (!repeated) {
      state.tunnelReplacedIds = [...(state.tunnelReplacedIds ?? []), state.tunnelId];
      state.tunnelId = bundle.tunnelId; state.tunnelCredentialHash = replacement.credentialHash;
      state.tunnelCredentialFile = filename; state.tunnelReplacement = replacement;
    }
    const statePath = join(root, 'state.json'), stateBytes = JSON.stringify(state, null, 2) + '\n';
    for (const [path, bytes] of [[journal, journalBytes], [join(root, filename), credentialBytes], [statePath, stateBytes]]) {
      if (path !== statePath && existsSync(path)) {
        protectedPath(path);
        if (!readFileSync(path).equals(Buffer.from(bytes))) fail('SETUP_TUNNEL_REPLACEMENT_REFUSED');
      }
      if (existsSync(path + '.pending')) {
        protectedPath(path + '.pending');
        if (!readFileSync(path + '.pending').equals(Buffer.from(bytes))) fail('SETUP_TUNNEL_REPLACEMENT_AMBIGUOUS');
      }
    }
    recoveryWrite(journal, journalBytes);
    if (!existsSync(join(root, filename)) || existsSync(join(root, filename + '.pending'))) recoveryWrite(join(root, filename), credentialBytes);
    recoveryWrite(statePath, stateBytes);
    unlinkSync(journal);
    console.log('SETUP_TUNNEL_REPLACED'); return;
  }
  const customIssuer = () => {
    if (state.binding.role !== 'verifier') fail('SETUP_ISSUER_REQUIRED');
    const issuer = readState(state.binding.issuerState);
    if (issuer.project !== state.binding.issuerProject || issuer.binding.role !== 'issuer' || issuer.binding.runtimeOrigin === state.binding.runtimeOrigin || issuer.binding.ecosystemSha256 !== state.binding.ecosystemSha256) fail('SETUP_ISSUER_REQUIRED');
    if (issuer.phase !== 'ready') fail('SETUP_ISSUER_NOT_READY');
    return issuer;
  };
  if (['eligibility', 'sign-in', 'android-offer', 'android-activation'].includes(command)) {
    if ((state.binding.role ?? 'education') !== 'education') fail('SETUP_ROLE_REFUSED');
    if (state.phase !== 'ready' || !state.configured) fail('SETUP_REGISTRATION_INCOMPLETE');
    protectedPath(join(root, 'registration-result.json'));
    const registration = json(join(root, 'registration-result.json'));
    if (registration.phase !== 'complete') fail('SETUP_REGISTRATION_INCOMPLETE');
    if (command.startsWith('android-')) {
      const { androidOffer, androidActivation } = await import('./setup-android.mjs');
      console.log(command === 'android-offer' ? await androidOffer(root, state, registration, options['--attempt']) : androidActivation(root, state, registration, options['--stage']));
      return;
    }
    const e = state.ecosystem;
    if (!e.government?.issuerDid) fail('SETUP_TRUST_INPUT_REFUSED');
    const { runEducation, registeredCeremonies } = await import('./education-http.ts');
    const config = { registryOrigin: e.registryOrigin, registryDid: e.registryDid, trustAnchorJwk: e.trustAnchorJwk, portalOrigin: e.portalOrigin, providerOrigin: e.providerOrigin, applicationOrigin: state.binding.appOrigin, runtimeOrigin: state.binding.runtimeOrigin, governmentIssuerDid: e.government.issuerDid, educationIssuerDid: e.education.issuerDid, stateDir: join(root, 'software-holder') };
    const flow = await runEducation(config, undefined, registration);
    const profiles = command === 'sign-in' ? ['education_sign_in', 'education_sign_in'] : ['education_eligibility'];
    const result = await registeredCeremonies(config, flow, profiles);
    console.log(JSON.stringify(result)); return;
  }
  if (command === 'get') {
    const fields = { project: state.project, partnerImage: state.binding.partnerImage, appImage: state.binding.appImage, phase: state.phase, issuerBootstrap: state.issuerBootstrap ?? '', tunnelName: state.tunnelName, tunnelId: state.tunnelId ?? '', tunnelMode: state.binding.suppliedTunnel ? 'supplied' : 'owned', runtimeHost: new URL(state.binding.runtimeOrigin).hostname, appHost: state.binding.appOrigin ? new URL(state.binding.appOrigin).hostname : '', role: state.binding.role ?? 'education', issuerState: state.binding.issuerState ?? '' };
    if (!(options['--field'] in fields)) fail('SETUP_FIELD_REFUSED');
    console.log(fields[options['--field']]); return;
  }
  if (command === 'inspect-images') {
    inspectImages(state.binding, json(options['--input']));
    console.log('SETUP_IMAGES_VERIFIED'); return;
  }
  if (command === 'check-local' || command === 'check-public' || command === 'ready' || command === 'register') {
    const local = await available(httpClient({}, 'http://127.0.0.1:3080'), 'http://127.0.0.1:3080/.well-known/did.json');
    if (local.status !== 200) fail('SETUP_LOCAL_IDENTITY_UNAVAILABLE');
    const document = local.json();
    if (document.id !== 'did:web:' + new URL(state.binding.runtimeOrigin).host || document.verificationMethod?.length !== 1 || (state.didDocument && !isDeepStrictEqual(document, state.didDocument))) fail('SETUP_IDENTITY_REFUSED');
    if (!state.didDocument) { state.didDocument = document; state.phase = 'bootstrapped'; save(root, state); }
    if (command === 'check-local') { console.log('SETUP_LOCAL_IDENTITY_VERIFIED'); return; }
    const call = httpClient();
    const publicDid = await available(call, state.binding.runtimeOrigin + '/.well-known/did.json');
    if (publicDid.status !== 200 || !isDeepStrictEqual(publicDid.json(), document)) fail('SETUP_PUBLIC_IDENTITY_REFUSED');
    if (state.binding.appOrigin) {
      const session = await available(call, state.binding.appOrigin + '/api/session');
      if (session.status !== 200 || session.json().status !== 'anonymous') fail('SETUP_PUBLIC_APP_UNAVAILABLE');
    }
    for (const base of [state.binding.runtimeOrigin, state.binding.appOrigin].filter(Boolean)) {
      for (const path of ['/management/sign', '/management/evidence/refresh', '/unlisted-route', '/%2e%2e/management/sign']) {
        if ((await call(base + path)).status !== 404) fail('SETUP_PUBLIC_BOUNDARY_REFUSED');
      }
    }
    if ((await call(state.binding.runtimeOrigin + '/.well-known/did.json', { method: 'POST' })).status !== 404) fail('SETUP_PUBLIC_BOUNDARY_REFUSED');
    if (command === 'check-public') { console.log('SETUP_PUBLIC_HTTPS_VERIFIED'); return; }
    if (command === 'ready' && (!state.configured || !existsSync(join(root, 'registration-result.json')))) fail('SETUP_REGISTRATION_INCOMPLETE');
    const { registerVerifier, registerIssuer, registerCustomVerifier } = await import('./register-verifier.ts');
    await (state.binding.role === 'issuer' ? registerIssuer : state.binding.role === 'verifier' ? registerCustomVerifier : registerVerifier)(json(join(root, 'registration-config.json')), join(root, 'registration-result.json'));
    if (command === 'register') { state.phase = 'registered'; save(root, state); console.log('SETUP_REGISTERED'); return; }
    if (!state.configured) fail('SETUP_CONFIGURATION_REQUIRED');
    if (state.binding.role === 'issuer') {
      const { issuerReady } = await import('./setup-issuer.ts');
      await issuerReady(root, state);
      state.phase = 'ready'; state.issuerBootstrap = 'complete'; save(root, state);
      console.log('SETUP_ISSUER_READY: Registered issuer and dedicated database are running. Run ./setup issue for a synthetic software-holder receipt. Android is separate.'); return;
    }
    const refreshed = await httpClient({}, 'http://127.0.0.1:3081')('http://127.0.0.1:3081/management/evidence/refresh', { method: 'POST', headers: { authorization: 'Bearer ' + state.managementToken, 'content-type': 'application/json' }, body: '{}' });
    if (refreshed.status !== 200 || refreshed.json().status !== 'refreshed') fail('SETUP_SIGNED_EVIDENCE_UNAVAILABLE');
    if (state.binding.role === 'verifier') { customIssuer(); state.phase = 'ready'; save(root, state); console.log('SETUP_CUSTOM_VERIFIER_READY: Exact membership permission and signed evidence verified. Run ./setup verify for the software-holder check.'); return; }
    state.phase = 'ready'; save(root, state); console.log('SETUP_READY: Registered Education verifier and app are running. Next run the software-holder development check; Android authorization is separate.'); return;
  }
  if (command === 'configure') {
    protectedPath(join(root, 'registration-result.json'));
    if (json(join(root, 'registration-result.json')).phase !== 'complete') fail('SETUP_REGISTRATION_INCOMPLETE');
    if (state.binding.role === 'issuer') {
      const { configureIssuer } = await import('./setup-issuer.ts');
      await configureIssuer(root, state, atomic);
      state.configured = true; save(root, state); writeConfiguration(root, state);
      console.log('SETUP_ISSUER_CONFIGURED'); return;
    }
    if (state.binding.role === 'verifier') {
      const { configureCustomVerifier } = await import('./setup-verifier.ts');
      await configureCustomVerifier(root, state, customIssuer(), atomic);
      state.configured = true; save(root, state); writeConfiguration(root, state);
      console.log('SETUP_CUSTOM_VERIFIER_CONFIGURED'); return;
    }
    const e = state.ecosystem;
    atomic(join(root, 'public/verifier.json'), JSON.stringify({ issuerDid: e.education.issuerDid, issuerJwk: e.education.issuerJwk, registryOrigin: e.registryOrigin, trustAnchorJwk: e.trustAnchorJwk, statusSources: e.education.statusSources, maxCacheAgeSeconds: 300 }, null, 2) + '\n', 0o644);
    state.configured = true; save(root, state); writeConfiguration(root, state);
    console.log('SETUP_VERIFIER_CONFIGURED'); return;
  }
  if (command === 'verify') {
    if (state.binding.role !== 'verifier' || state.phase !== 'ready') fail('SETUP_CUSTOM_VERIFIER_NOT_READY');
    const { verifyExample } = await import('./setup-verifier.ts');
    await verifyExample(root, state, customIssuer()); return;
  }
  if (command === 'issue' || command === 'revoke-example') {
    if (state.binding.role !== 'issuer' || state.phase !== 'ready') fail('SETUP_ISSUER_NOT_READY');
    const { issueExample, revokeExample } = await import('./setup-issuer.ts');
    await (command === 'issue' ? issueExample : revokeExample)(root, state); return;
  }
  if (command === 'tunnel-reconcile') {
    let id = state.tunnelId;
    if (!state.binding.suppliedTunnel) {
      const listing = json(options['--list']) ?? [];
      if (!Array.isArray(listing)) fail('SETUP_TUNNEL_LIST_REFUSED');
      const matches = listing.filter(item => item.name === state.tunnelName && (!item.deleted_at || item.deleted_at === '0001-01-01T00:00:00Z'));
      if (matches.length > 1) fail('SETUP_TUNNEL_OUTCOME_UNKNOWN');
      if (!matches.length) {
        if (state.tunnelPhase || state.tunnelId) fail('SETUP_TUNNEL_OUTCOME_UNKNOWN');
        state.tunnelPhase = 'creating'; save(root, state); console.log('CREATE'); return;
      }
      id = matches[0].id;
      if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(id) || (state.tunnelId && state.tunnelId !== id)) fail('SETUP_TUNNEL_IDENTITY_REFUSED');
    }
    const credentialsPath = join(root, tunnelCredentialName(state));
    if (!existsSync(credentialsPath)) fail('SETUP_TUNNEL_CREDENTIAL_REQUIRED');
    protectedPath(credentialsPath);
    const credentials = json(credentialsPath);
    if (credentials.TunnelID !== id || !/^[a-f0-9]{32}$/.test(credentials.AccountTag) || typeof credentials.TunnelSecret !== 'string' || Buffer.from(credentials.TunnelSecret, 'base64').length !== 32) fail('SETUP_TUNNEL_IDENTITY_REFUSED');
    state.tunnelId = id; state.tunnelPhase = 'created'; save(root, state);
    const runtimeHost = new URL(state.binding.runtimeOrigin).hostname, appHost = state.binding.appOrigin ? new URL(state.binding.appOrigin).hostname : undefined;
    const ingress = [
      { hostname: runtimeHost, path: state.binding.role === 'issuer' ? '^/(\\.well-known/(did\\.json|openid-credential-issuer|oauth-authorization-server)|oid4vci/offers/[A-Za-z0-9_-]+|oid4vci/(token|nonce|credential|status/revocation\\.jwt))$' : '^/(\\.well-known/did\\.json|oid4vp/(request|response)/[A-Za-z0-9_-]+)$', service: 'http://127.0.0.1:3080' },
      { hostname: runtimeHost, service: 'http_status:404' },
      ...(appHost ? [{ hostname: appHost, path: '^/($|openapi\\.json$|api/session$|app\\.(js|css)$|spectral\\.ttf$|mono\\.ttf$|fonts$|spectral-OFL\\.txt$|mono-OFL\\.txt$|api/interactions$|api/interactions/[A-Za-z0-9_-]+/complete$)', service: 'http://127.0.0.1:3082' },
      { hostname: appHost, service: 'http_status:404' }] : []), { service: 'http_status:404' },
    ];
    atomic(join(root, 'tunnel.yml'), JSON.stringify({ tunnel: id, 'credentials-file': '/tunnel/tunnel-credentials.json', metrics: '127.0.0.1:20241', ingress }, null, 2) + '\n');
    const tunnel = { image: 'cloudflare/cloudflared:2026.9.3@sha256:072c067d25ccbe61d46e18f0d0723255f2bb5304f7317caa95b27031520ff92c', user: `${process.getuid()}:${process.getgid()}`, network_mode: 'service:partner', depends_on: ['partner'], read_only: true, restart: 'unless-stopped', cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], command: ['tunnel', '--no-autoupdate', '--config', '/tunnel/tunnel.yml', 'run'], volumes: [`${root}/tunnel.yml:/tunnel/tunnel.yml:ro`, `${credentialsPath}:/tunnel/tunnel-credentials.json:ro`], logging: { driver: 'json-file', options: { 'max-size': '10m', 'max-file': '3' } } };
    atomic(join(root, 'tunnel-compose.json'), JSON.stringify({ services: { tunnel } }, null, 2) + '\n');
    console.log(id); return;
  }
  if (command === 'mark') {
    if (options['--phase'] === 'issuer-bootstrap-started') { state.issuerBootstrap = 'started'; save(root, state); return; }
    if (!['bootstrap-started', 'bootstrapped'].includes(options['--phase'])) fail('SETUP_PHASE_REFUSED');
    state.phase = options['--phase']; save(root, state); return;
  }
  fail('SETUP_COMMAND_REFUSED');
}
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(error => {
    console.error(/^[A-Z][A-Z0-9_]+$/.test(error.message) ? error.message : 'SETUP_FAILED');
    process.exitCode = 1;
  });
}
