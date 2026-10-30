# Generic source export

Original source is private monorepo `5f00a507a892200cf1fd3b857dc875d556f16c17`.
`generic-source-files.json` enumerates 106 exact original paths and SHA256 hashes.
Each file was read with `git show <revision>:<path>`; no Git history was copied.
The original Education manifest, candidate and image records remain unchanged.

The export refreshes the shared Rust core, Node wrapper and runtime together.
The #429 refresh adds only the exact Node adapter/public API and its renewal-only
predecessor tests; the Rust core algorithm and runtime remain unchanged.
It adds issuer-protocol, all five PostgreSQL migrations with their journal and
snapshots, migration CLI/configuration, neutral scalar/structured configurations,
OpenAPI and the issuer Compose dependency. Generated native wrappers and private
registry/setup/registered-rotation producers are excluded. Test-only synthetic
authorities stay in tests and never enter the deployed runtime package.

Packaging transformations retain the existing two-crate Cargo workspace, locked
native commands, separate native-test output and production fixture scanner.
The pnpm lock uses the exact source runtime/issuer-protocol importers and frozen
resolution records, retaining the existing standalone root and Education entries.
The root build includes issuer-protocol. Docker passes `--locked` and retains its
pinned Rust 1.92.0/Node 22.22.0 toolchains and production feature/exclusion scan.

Portable runtime suites retain their source assertions. Only explicitly bound
host ports and disposable container resource prefixes change to the reserved
292xx/vc408 range. Container protocol port3443 and signed fixture identities are
unchanged. The fixture runner enumerates the complete portable core-binding,
issuer-protocol and runtime suite list in its disposable native-test workspace.
Registered ecosystem handlers remain outside the distribution.

The Education docs checker retains its exact eight verifier operations. The
remaining22 operations have checked machine-readable curl examples. Their union
must equal the complete current OpenAPI contract. Existing Education application
and verifier checks remain mandatory. The shared HTTP client retains its default
131072-byte bound and permits an explicit bounded262144-byte evidence read.

The #435 documentation-only correction replaces the historical runtime README with
links to the five canonical partner pages and shipped OpenAPI, Compose and configuration
examples. Its manifest entry retains the original monorepo revision/hash and records
the new exported SHA256. The docs checker now checks local links in all distributed
Markdown files. Production sources, dependencies, image labels and earlier observations
remain unchanged.

Both repositories remain private. This is preparation, not public availability,
physical acceptance or a full generic candidate. Reuse licensing, release signing,
publication and physical Android acceptance remain human gates #338/#348.

## Preview distribution licensing, 2026-10-06

The operator delegated the project reuse licence and chose to defer remaining phone tests.
Apache-2.0 now applies to project-owned exported source. Cargo workspace and Node package
licence metadata changed; the manifest preserves original producer hashes and the prior
export hashes for these explicit transformations. Runtime code, lockfiles and dependency
versions are unchanged. Existing image archives retain their historical labels and bytes;
they are not rebuilt or attributed to this metadata change.

Root LICENSE, NOTICE and DISTRIBUTION.md are new distribution documents. Current licence
status prose and portable example links are updated separately from historical source pins.
Third-party attribution/licence texts are preserved. Physical results are not upgraded to
PASS, and public distribution remains pending its own concrete artifacts and checks.

## Container onboarding source refresh, 2026-10-13

The Education startup diagnostic and its CLI/Compose checks are copied exactly from
monorepo `61c2b16b6f43dc72c0e31a8d4ee6837f04a6eccb`. New manifest entries carry
that per-file source revision; the original generic and Education exports remain
historical records. The container guide moves to `docs/setup/containers.md`, outside
the finite partner reference index. The app README keeps its existing distribution
licence wording and links to that portable guide path. Root boundary checks now run
the exported CLI check; Compose checks run only with explicit candidate image inputs.

Existing runtime/core bytes, dependency locks and historical release archives are
unchanged. New image candidates retain their own producer source labels and inspection
evidence. Preparing this source export does not publish those images or establish
native Linux or Windows/WSL2 support.

## Versioned onboarding preview documentation

The container guide now links to the versioned image download and checksum steps,
with a stop condition when the release is unavailable. Its manifest entry records
the new exported SHA256 and the preceding guided-setup export hash. The original
producer source revision, path and source hash remain unchanged. This documentation
change does not rebuild or relabel the historical image archives.

## Shared client and one-command course starter, 2026-10-29

The app README describes the kit's shared backend client. Its export hash now records
that documentation change; the previous export hash and original producer revision
and source hash remain recorded. The course setup helper and private starter packaging
reuse the pinned images. No historical archive is rebuilt or relabelled.

## Retryable result delivery, 2026-10-30

Runtime sessions, the Education client and browser diagnostic, their regression tests,
and both OpenAPI documents were refreshed from monorepo
`4be274ebc92a8653f56f83661d035150d1497770`. Each refreshed manifest entry records
its exact source revision, source hash and export hash. The session HTTP fixture uses
the reserved kit port; production code is copied exactly. The packaged issuer test
now expects repeated ordinary reads to return the same result.

The helper accepts the previous and current pinned image sets. Explicit `./setup upgrade`
checks the new images, keeps a protected backup and resumes interrupted configuration
writes without changing keys, origins, registration, project names or database volumes.
The previous candidate is retained for existing installations. The current candidate
records newly built image archives, never relabelled historical ones.

The lockfile export record now includes the schema-validation dependencies already
introduced by the preceding API documentation update. No dependency versions changed
in this runtime fix. Rust core and issuer-protocol source are unchanged.
