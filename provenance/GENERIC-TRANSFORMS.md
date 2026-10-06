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
