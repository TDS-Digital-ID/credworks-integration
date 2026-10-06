# Education source export

Source: private `TDS-Digital-ID/university-vc-monorepo` commit
`14096ed41ee259e81414fcfa0c3b2ad622a5b426`. Files were selected with `git archive`;
no source Git history was imported. `source-files.json` records each original path
and SHA256 before packaging changes.

Packaging changes:

- Root Cargo workspace includes only the unchanged identity-core and Node binding crates.
  Cargo.lock removes only unused packages after workspace closure resolution; all
  retained package versions, sources and checksums remain unchanged.
- Root package scripts/name target the three exported packages. The unused root Turbo
  dependency is removed. The public driver root declares the already pinned workspace
  core package, @types/node 24.10.0 and tsx 4.23.0. Retained versions are unchanged.
- pnpm-lock.yaml removes excluded workspace importers and the unused root Turbo entry, and adds the existing pinned driver dependency
  entries to the root importer. All resolution records,
  dependency versions and integrity checksums remain unchanged.
- Root TypeScript configuration removes unused private UI path aliases.
- Node binding's default native build enables `partner-runtime`, excluding deterministic
  fixture installers. Fixture conformance uses `native-test` and a disposable wrapper
  checkout; it never overwrites production `native` output.

Rust algorithms and binding source, Node wrapper source, verifier runtime source, and
reference application source are unchanged. New standalone tools/tests/docs have no
monorepo source hash. Subsequent transformations must be added here explicitly.

Both repositories remain private. No project reuse license or publication permission is
implied. Third-party font license notices remain in the app distribution. Physical
Android acceptance and public deployment are NOT RUN. This kit supports Education
verification/sign-in and identifier-free eligibility; generic issuer functionality is
outside this source pin.

- Native host and Docker build commands pass `--locked` to Cargo through napi-rs.
  The Dockerfile otherwise retains the original production feature, binary scan,
  and scanner removal before final COPY. A narrow root .dockerignore excludes
  history, generated binaries, fixture output, caches, state and secrets.

- Exported runtime tests invoke the isolated fixture runner. It builds a separate
  native-test addon, installs a disposable workspace with the same frozen lock,
  and executes unchanged core-binding/runtime assertions against that test addon.
  The standalone app omits private ecosystem test helpers; the public driver is
  verified against an external pinned ecosystem fixture.

- Root package is ESM for the standalone TypeScript CLI entry points. New driver
  dependencies reuse already locked versions. New HTTPS tools validate origin/scope
  and sample verification time after network completion; enrolment and presentation
  bodies carry the original authenticated deadline into the TLS write boundary.

- Reference app test entry point invokes the standalone subprocess HTTP checks
  instead of excluded private ecosystem fixtures. CI provisions only its own
  dedicated app database, builds locked production/test outputs independently,
  and enables revision-labelled runtime container checks.

- Runtime container test resource labels and host ports are mechanically changed
  to vc387 and 38730/38731. Existing assertions, protocol and clock checks are
  unchanged. HTTPS test injection accepts only CA, DNS lookup and mapped port;
  TLS verification-disable options are refused.

- The disposable test workspace also copies the two allowlisted Compose files
  under infra, so the unchanged enabled container assertions execute the actual
  runtime Compose contract. This test-only change leaves deployed runtime/application
  source and production build commands unchanged. Docker COPY includes the runner
  in its build context; images remain explicitly pinned to source ed5b8be.

- Generated native index.cjs/index.js/index.d.ts wrappers from the source archive
  are classified as omitted_generated_files, not committed export files. The
  locked napi build regenerates them into ignored production/test output.
