import { randomUUID } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, openSync, closeSync, fsyncSync, writeFileSync, readFileSync, renameSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { httpClient } from './http-client.mjs';
const fail = code => { throw Error(code); };
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
function protect(path, directory = false) {
  const st = lstatSync(path);
  if (!(directory ? st.isDirectory() : st.isFile()) || st.uid !== process.getuid() || st.mode & (directory ? 0o077 : 0o177)) fail('ANDROID_STORAGE_REFUSED');
}
function write(path, value) {
  if (existsSync(path)) protect(path);
  const fd = openSync(path + '.pending', 'wx', 0o600);
  try { writeFileSync(fd, value); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(path + '.pending', path);
  const dir = openSync(dirname(path), 'r');
  try { fsyncSync(dir); } finally { closeSync(dir); }
}
function load(root, state, registration, create = false) {
  const directory = join(root, 'android');
  if (!existsSync(directory) && create) mkdirSync(directory, { mode: 0o700 });
  if (!existsSync(directory)) fail('ANDROID_OFFER_REQUIRED');
  protect(directory, true);
  if (readdirSync(directory).some(name => name.endsWith('.pending'))) fail('ANDROID_STORAGE_REFUSED');
  const path = join(directory, 'journal.json');
  const binding = { project: registration.project.project_id, portal: state.ecosystem.portalOrigin, app: state.binding.appOrigin };
  let journal;
  if (existsSync(path)) {
    protect(path); journal = JSON.parse(readFileSync(path, 'utf8'));
    if (journal.version !== 1 || !isDeepStrictEqual(journal.binding, binding) || !uuid(journal.allocationId) || !Array.isArray(journal.attempts) || journal.attempts.some(a => !uuid(a.requestId))) fail('ANDROID_STATE_REFUSED');
  } else {
    if (!create) fail('ANDROID_OFFER_REQUIRED');
    journal = { version: 1, binding, allocationId: randomUUID(), attempts: [] };
    write(path, JSON.stringify(journal));
  }
  return { directory, journal, save: () => write(path, JSON.stringify(journal)) };
}
function portalUrl(value, portal, pattern) {
  let url; try { url = new URL(value); } catch { fail('ANDROID_ACTIVATION_REFUSED'); }
  if (url.origin !== portal || url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !pattern.test(url.pathname)) fail('ANDROID_ACTIVATION_REFUSED');
  return url.href;
}
function activation(attempt, stage, portal, checkExpiry = true) {
  if (!['government', 'enrolment', 'education'].includes(stage)) fail('ANDROID_STAGE_REFUSED');
  if (!attempt.links?.[stage]) fail('ANDROID_STAGE_NOT_READY');
  const link = attempt.links[stage];
  if (stage === 'enrolment') {
    if (!Number.isFinite(Date.parse(attempt.expiresAt)) || (checkExpiry && Date.now() >= Date.parse(attempt.expiresAt))) fail('ANDROID_ATTEMPT_EXPIRED');
    const uri = new URL(link);
    if (uri.protocol !== 'openid4vp:' || uri.host !== 'authorize' || uri.pathname || uri.username || uri.password || uri.hash || [...uri.searchParams.keys()].sort().join() !== 'client_id,request_uri') fail('ANDROID_ACTIVATION_REFUSED');
    portalUrl(uri.searchParams.get('request_uri'), portal, /^\/oid4vp\/enrolment\/request\/[A-Za-z0-9_-]+$/);
    if (uri.searchParams.get('client_id') !== 'decentralized_identifier:did:web:' + new URL(portal).hostname) fail('ANDROID_ACTIVATION_REFUSED');
    return uri.href;
  }
  return 'openid-credential-offer://?credential_offer_uri=' + encodeURIComponent(portalUrl(link, portal, /^\/c\/[A-Za-z0-9_-]+$/));
}
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export async function androidOffer(root, state, registration, selected, call = httpClient()) {
  const { directory, journal, save } = load(root, state, registration, true);
  const index = selected === undefined ? (journal.selected ?? Math.max(journal.attempts.length, 1)) : Number(selected);
  if (!Number.isSafeInteger(index) || index < 1 || index > journal.attempts.length + 1 || (selected !== undefined && String(index) !== selected)) fail('ANDROID_ATTEMPT_REFUSED');
  const request = async (path, body) => {
    const result = await call(journal.binding.portal + path, { method: 'POST', headers: { authorization: 'Bearer ' + registration.management_credential, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    if (result.status !== 201) fail('ANDROID_SETUP_UNAVAILABLE');
    return result.json();
  };
  const people = '/api/sandbox/projects/' + encodeURIComponent(journal.binding.project) + '/education/people';
  if (!journal.personId) {
    const person = await request(people, { allocation_id: journal.allocationId });
    if (!uuid(person.person_id)) fail('ANDROID_RESPONSE_REFUSED');
    journal.personId = person.person_id; save();
  }
  if (!uuid(journal.personId)) fail('ANDROID_STATE_REFUSED');
  if (index === journal.attempts.length + 1) journal.attempts.push({ requestId: randomUUID() });
  journal.selected = index; save();
  const attempt = journal.attempts[index - 1];
  const result = await request(people + '/' + journal.personId + '/setups', { request_id: attempt.requestId, scenario: 'valid' });
  if (!uuid(result.setup_id) || result.person?.person_id !== journal.personId || result.retired || (attempt.setupId && attempt.setupId !== result.setup_id)) fail('ANDROID_RESPONSE_REFUSED');
  const portal = journal.binding.portal;
  const links = { government: portalUrl(result.government_identity_offer_uri, portal, /^\/c\/[A-Za-z0-9_-]+$/), enrolment: result.enrolment?.activationUri };
  if (result.education_offer_uri) links.education = portalUrl(result.education_offer_uri, portal, /^\/c\/[A-Za-z0-9_-]+$/);
  const updated = { ...attempt, setupId: result.setup_id, expiresAt: result.enrolment?.expiresAt, links };
  // Validate all received activations without treating an expired original request as a fresh one.
  const deadline = Date.parse(updated.expiresAt);
  if (!Number.isFinite(deadline)) fail('ANDROID_RESPONSE_REFUSED');
  for (const stage of Object.keys(links)) activation(updated, stage, portal, false);
  journal.attempts[index - 1] = updated; journal.selected = index; save();
  const labels = { government: 'Receive synthetic Government ID', enrolment: 'Share identity for enrolment', education: 'Receive synthetic Education' };
  const list = Object.keys(links).map(stage => `<li><a href="${escape(activation(updated, stage, portal, false))}">${labels[stage]}</a></li>`).join('');
  const file = join(directory, `attempt-${index}.html`);
  write(file, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'"><title>Private Android onboarding</title><h1>Android attempt ${index}</h1><p>Private activation links. Do not upload this file or use an online QR service. Open a link only on your intended phone. The wallet still requires review and Android authorization.</p><p>Enrolment deadline: ${escape(updated.expiresAt)}. Retrying does not extend it. If expired, explicitly select the next attempt number; keep this original.</p><ol>${list}</ol><p>Use the same newly received Government credential for enrolment. Education becomes available after identity sharing; rerun android-offer to update this file.</p></html>`);
  return file;
}
export function androidActivation(root, state, registration, stage) {
  const { journal } = load(root, state, registration);
  const attempt = journal.attempts[journal.selected - 1];
  if (!attempt) fail('ANDROID_OFFER_REQUIRED');
  return activation(attempt, stage, journal.binding.portal);
}
