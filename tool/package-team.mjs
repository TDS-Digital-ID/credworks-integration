import { execFileSync } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readCourseBundle } from './setup.mjs';

const kit = resolve(dirname(fileURLToPath(import.meta.url)), '..');
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
  const archive = join(temporary, 'source.tar');
  git('archive', '--format=tar', '--prefix=credworks-team/', '--output', archive, revision);
  execFileSync('tar', ['-xf', archive, '-C', temporary], { stdio: ['ignore', 'pipe', 'pipe'] });
  const directory = join(temporary, 'credworks-team');
  // Only committed code and this team's validated credential enter the private handoff.
  writeFileSync(join(directory, 'team.json'), JSON.stringify(team) + '\n', { flag: 'wx', mode: 0o600 });
  writeFileSync(join(directory, 'START-HERE.txt'),
    `CredWorks course starter\nTeam: ${team.group}\nApp: ${team.appOrigin}\nVerifier: ${team.runtimeOrigin}\nKit: ${revision}\n\n` +
    'Keep this package private. Use one active team computer.\nStart Docker, open a terminal in this folder, and run ./setup.\nCompare the team and addresses with your separate course handoff before confirming.\nSetup checks eligibility and opens the app. Repeat ./setup to resume the same installation.\nPrivate state is kept in $HOME/.local/share/credworks-team.\nSee docs/education/getting-started.md for help.\n', { flag: 'wx', mode: 0o600 });
  descriptor = openSync(output, 'wx', 0o600);
  execFileSync('tar', ['-czf', '-', '-C', temporary, 'credworks-team'], { stdio: ['ignore', descriptor, 'pipe'] });
  closeSync(descriptor); descriptor = undefined;
  console.log(`COURSE_PACKAGE_READY: ${team.group}, kit ${revision}. Deliver privately with a separate confirmation of the team addresses.`);
} catch (error) {
  if (descriptor !== undefined) { closeSync(descriptor); rmSync(output); }
  console.error(/^[A-Z][A-Z0-9_]+$/.test(error.message) || error.message.startsWith('Usage:') ? error.message : 'COURSE_PACKAGE_REFUSED');
  process.exitCode = 1;
} finally {
  if (temporary) rmSync(temporary, { recursive: true, force: true });
}
