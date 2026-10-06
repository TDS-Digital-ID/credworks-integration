# Education export verification

Exported source: `14096ed41ee259e81414fcfa0c3b2ad622a5b426` in the private
monorepo. Kit review base: `b215a588bd53eaabfe7995071c7615a897664350`.
The original source-file SHA256 manifest is `source-files.json`; transformations
are recorded in `TRANSFORMS.md`. No monorepo history was imported.

## Images

Both Linux arm64 images were built from kit source
`ed5b8bea4322e358f802b3bdff91e0cd474b3aa0` with that revision label:

| Image | Local image ID |
| --- | --- |
| `vc387-partner:git-ed5b8bea4322e358f802b3bdff91e0cd474b3aa0` | `sha256:3954597d71cdb0d49ecb6073981f2f9c0d5896776c47b88b0e0e66deefa2516b` |
| `vc387-education:git-ed5b8bea4322e358f802b3bdff91e0cd474b3aa0` | `sha256:7f5c42da3806a39e32c467b1f99eb32dc299194ec9bef07465cf9872f4da9978` |

The app context was an exact `git archive` of that commit. Later commit
`7be5704087a50e7a036e4f88bec8854c38f5ca15` changes the disposable test runner
and provenance only; deployed runtime/application source and production build
commands remain unchanged. This does not assert equality of Docker contexts.
Neither image is published. `docker save` inspection covered all 12 distinct
layers and 11,801 entries: no build-only scanner path or native-test output;
17 project source/addon files contained neither known fixture scalar. Third-party
binary byte sequences are not treated as fixture-key provenance.

## Commands and local evidence

Commands ran in the standalone kit without a mounted monorepo or private build
credentials. Cargo uses `CARGO_BUILD_JOBS=2` and `--locked`; production native
build enables `partner-runtime`, while fixture output is separately built in
`native-test` and executed in a disposable workspace.

| Command/check | Result | Local log |
| --- | --- | --- |
| `pnpm install --frozen-lockfile` | passed | `.logs/install-frozen.log` |
| production `build:native` and packaged-addon scanner | passed; fixture exports/scalars absent | `.logs/kit-native-production.log`, `.logs/addon-final.log` |
| `cargo test --locked -p identity-core` | 78 passed, zero failed | `.logs/kit-cargo-tests.log` |
| `pnpm test:fixtures`, image opt-in below | core adapter 13/13; runtime 26/26; zero skipped | `.logs/kit-fixtures-enabled.log` |
| `pnpm test:boundary`, dedicated app database | 4/4; zero skipped | `.logs/boundary-enabled.log` |
| `pnpm lint`; `pnpm exec tsc -p tool/tsconfig.json` | passed | `.logs/lint-final.log`, `.logs/tool-typecheck-final.log` |
| runtime/app Docker builds | passed | `.logs/image-partner.log`, `.logs/image-education.log` |
| actual Education Compose startup | host app access, dedicated database, identity and management isolation passed | `.logs/compose-education.log` |
| all-layer inspection | passed | `.logs/image-layers.log` |

Enabled fixture command:

```sh
CARGO_BUILD_JOBS=2 \
PARTNER_CONTAINER_IMAGE=vc387-partner:git-ed5b8bea4322e358f802b3bdff91e0cd474b3aa0 \
PARTNER_CONTAINER_SOURCE_REVISION=ed5b8bea4322e358f802b3bdff91e0cd474b3aa0 \
PARTNER_SESSION_HTTP_PORT=38710 PARTNER_EVIDENCE_HTTP_PORT=38712 \
pnpm test:fixtures
EDUCATION_APP_DATABASE_URL=postgres://vc379:vc379@127.0.0.1:55447/vc387_app \
EDUCATION_APP_TEST_PORT=38721 pnpm test:boundary
```

Container checks preserve the original bootstrap, replacement identity/proof,
expiry and public/management isolation assertions. The Education Compose check
used project `vc387-education-check`, ports 38732/38733, preserved random unlock
and management secrets, and the dedicated `vc387_app` database. All owned test
containers/listeners/Compose volumes were removed; unrelated infrastructure was
preserved. Commands never log capability or presentation values.

## Actual exported-tool HTTP flow

The actual kit driver ran against an external ecosystem fixture pinned to the
same immutable monorepo source, in a separate generated-state checkout
`vc-kit-387-ecosystem`. Its private setup harness is not exported, imported by
kit tools, or required by kit installation/build/CI. Local evidence is
`.logs/kit-http-exercise.log` in that external checkout. The driver passed:
Government issuance, authenticated enrolment and Education issuance; browser
correlation refusal; repeat sign-in account continuity; identifier-free
eligibility; and consumed completion replay refusal.

TLS fixtures used normal CA/hostname checks, with only DNS lookup and port mapping
injected. Exact configured role origins routed registry to 38700, portal to
38701, status to 38702, metadata to 38703, provider to 38711, runtime to its
allocated listener, and app to 38708 through TLS port 38709. Forwarded Host was
preserved; unknown origins refused. WIA came from two actual public provider
HTTP 201 responses using a fresh Rust-held holder and self-asserted
`mock_platform_attestation`. This is sandbox attestation, not hardware evidence.
No production verification bypass was added.

This proves the exported driver's HTTP behavior against a prepared external
fixture. It does not claim the complete clean self-service/tunnel sequence owned
by #389. Standalone CI runs the exported locked closure and enabled container
checks; external ecosystem orchestration remains a separately recorded local
check. Physical Android, public reachability and release are NOT RUN. A complete
private/local candidate belongs to #349; public release remains gated by #338
signing, license/publication approval and physical acceptance.
