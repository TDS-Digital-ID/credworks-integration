import { execFileSync } from 'node:child_process';
import { closeSync, mkdirSync, mkdtempSync, openSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readCourseBundle } from './setup.mjs';

const kit = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const supportFiles = [
  'setup', 'LICENSE',
  'config/setup-candidate.json', 'config/setup-candidate-20261013.json', 'config/credworks-sandbox-20261011.json',
  'infra/education-sign-in/compose.yml', 'infra/partner/compose.yml', 'infra/partner-issuer/compose.yml',
  'tool/setup.mjs', 'tool/setup-credential.mjs', 'tool/http-client.mjs',
  'tool/register-verifier.ts', 'tool/education-http.ts', 'tool/setup-android.mjs', 'tool/android-open',
  'tool/setup-issuer.ts', 'tool/setup-verifier.ts', 'tool/generic-http.ts',
];
let temporary, output, descriptor;
try {
  if (process.argv.length !== 4) throw Error('Usage: node tool/package-team.mjs PRIVATE_BUNDLE PRIVATE_OUTPUT.tar.gz');
  const bundle = resolve(process.argv[2]);
  const destination = resolve(process.argv[3]);
  output = join(realpathSync(dirname(destination)), basename(destination));
  if (!relative(kit, output).startsWith('..' + '/')) throw Error('COURSE_PACKAGE_OUTSIDE_KIT_REQUIRED');
  const team = readCourseBundle(bundle);
  const git = (...args) => execFileSync('git', ['-C', kit, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  git('diff', '--quiet', 'HEAD');
  const revision = git('rev-parse', 'HEAD').trim();
  temporary = mkdtempSync(join(tmpdir(), 'credworks-team-package-'));
  const directory = join(temporary, 'credworks-team');
  mkdirSync(directory, { mode: 0o700 });
  const copyCommitted = (source, destination) => {
    const entry = git('ls-tree', revision, '--', source).trim();
    const match = entry.match(/^(100644|100755) blob [a-f0-9]{40}\t(.+)$/);
    if (!match || match[2] !== source) throw Error('COURSE_PACKAGE_SOURCE_REFUSED');
    const bytes = execFileSync('git', ['-C', kit, 'show', `${revision}:${source}`], { stdio: ['ignore', 'pipe', 'pipe'] });
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, bytes, { flag: 'wx', mode: match[1] === '100755' ? 0o755 : 0o644 });
  };
  // Runtime helpers only. Developer source, tests and build files stay in the public repository.
  for (const source of supportFiles) copyCommitted(source, join(directory, '.credworks', source));
  copyCommitted('tool/team-launcher', join(directory, 'setup'));
  writeFileSync(join(directory, '.credworks/package.json'), '{"type":"module"}\n', { flag: 'wx', mode: 0o644 });
  writeFileSync(join(directory, 'team.json'), JSON.stringify(team) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(directory, 'START-HERE.txt'),
    `CredWorks course starter\nTeam: ${team.group}\nApp: ${team.appOrigin}\nVerifier: ${team.runtimeOrigin}\nKit: ${revision}\n\n` +
    'Keep this package private. Use one active team computer.\nStart Docker, open a terminal in this folder, and run ./setup.\nCompare the team and addresses with your separate course handoff before confirming.\nSetup downloads the checked images, checks eligibility and opens the app.\nKeep this folder intact. Repeat ./setup to resume the same installation.\nHelp: https://credworks.xyz/developers/getting-started\nBackend source: https://github.com/TDS-Digital-ID/credworks-integration\n', { flag: 'wx', mode: 0o600 });
  descriptor = openSync(output, 'wx', 0o600);
  execFileSync('tar', ['-czf', '-', '-C', temporary, 'credworks-team'], { stdio: ['ignore', descriptor, 'pipe'], env: { ...process.env, COPYFILE_DISABLE: '1' } });
  closeSync(descriptor); descriptor = undefined;
  console.log(`COURSE_PACKAGE_READY: ${team.group}, kit ${revision}. Deliver privately with a separate confirmation of the team addresses.`);
} catch (error) {
  if (descriptor !== undefined) { closeSync(descriptor); rmSync(output); }
  console.error(/^[A-Z][A-Z0-9_]+$/.test(error.message) || error.message.startsWith('Usage:') ? error.message : 'COURSE_PACKAGE_REFUSED');
  process.exitCode = 1;
} finally {
  if (temporary) rmSync(temporary, { recursive: true, force: true });
}
