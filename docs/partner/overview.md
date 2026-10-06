# Partner integration

This kit packages independently operated issuer and verifier services, neutral examples and HTTP tools on the shared Rust identity-core. Partners own signing identities, issuance records, status and application decisions. Registration proves endpoint and key control. It does not establish institutional authority or authorize Education claims.

Read [setup and lifecycle](quickstart.md), [definitions and disclosure](definitions.md), [HTTP API](api.md) and [operations and limits](operations.md). The existing [Education integration](../education/overview.md), [Education setup](../education/quickstart.md), [Education profiles](../education/profiles.md), [Education API](../education/api.md) and [Education operations](../education/operations.md) retain their Release A scope and frozen candidate references.

## Revision and profile matrix

A source label identifies the commit used to build an image. A later integration or documentation commit does not relabel that image.

| Component | Prepared and checked combination |
| --- | --- |
| Monorepo source export | 5f00a507a892200cf1fd3b857dc875d556f16c17 |
| Generic kit production source / OCI revision | f632ec5caf8d917304501ad038b2aceef1e46bae |
| Kit integration base for these docs | 226a59da91e75807cf3ede9621888abcb13b4577 |
| Local runtime image | vc408-partner:git-f632ec5caf8d917304501ad038b2aceef1e46bae, linux/arm64, ID sha256:be7e6e82bfb3de4659d63832c85e2f8a0f7db2a82d8c7c4ad31a5a9266804f8a |
| Local Education app image | vc408-education:git-f632ec5caf8d917304501ad038b2aceef1e46bae, linux/arm64, ID sha256:2f1f52036a8df7626037ca8e9a133f278b2adce7d8a032680a6f735d18b070f3 |
| Toolchain | Node 22.22.0, pnpm 10.34.4, Rust 1.92.0, frozen pnpm and locked Cargo dependencies |
| Credential / binding | W3C VC Data Model 2.0 SD-JWT, vc+sd-jwt, ES256/P-256, holder binding, did:web |
| Issuance | OID4VCI 1.0 Final pre-authorized-code, jwt holder proof, configured provider-signed WIA; recipient key thumbprint required |
| Presentation | OID4VP 1.0 Final, decentralized_identifier, direct_post, one DCQL credential query with exact registered paths |
| Generic shapes | string, boolean, safe finite number/integer, nested object properties, complete object/array values |
| Application extensions | credworks_scalar request authority, metadata issuer authorization, receipt-confirmed renewal version 1 |
| Status / trust | Signed Bitstring Status List revocation; issuer-scoped signed definitions and verifier permissions; retained credential-key membership |
| Education baseline | Original monorepo export 14096ed41ee259e81414fcfa0c3b2ad622a5b426; preserve its candidate/artifact pins and application contract |
| #408 evidence | 130 runtime checks, 25 Node checks, 8 boundary checks, core/conformance 99 checks; software-holder HTTP checks; no physical observations |
| Final generic candidate / Android | #410 records its exact source, APK checksum, signer and endpoint combination; this page does not claim that candidate run |

The source export manifest and [packaging transforms](../../provenance/GENERIC-TRANSFORMS.md) describe original files and deliberate packaging changes. [Earlier generic acceptance evidence](../../provenance/GENERIC-ACCEPTANCE.md) distinguishes intermediate producer pins from later consumer checks. Final #408 closure records the production source/image pins above and its successful third standalone gate and exact-head CI. These are private local images, not public registry downloads. Other CPU architectures require their own build and inspection.

## Availability and release limits

Both TDS-Digital-ID/universityvc-integration and TDS-Digital-ID/university-vc-monorepo remain private. An authorized checkout can build without private-monorepo access, private build secrets or monorepo history. The source export is not a public release or a complete hosted sandbox. An operator must supply reachable HTTPS, independent registry/provider trust anchors, project ownership, PostgreSQL and persistent state.

Project reuse licensing, publication rights, protected Android release signing and physical public setup remain human prerequisites. Third-party notices do not grant project reuse rights. #338 owns Release A acceptance, #348 owns Release B acceptance, and both remain open. Release B publication follows Release A. Physical install/update, device key authorization, consent and public clean setup are NOT RUN by this documentation task. Host software-holder checks use self-asserted mock platform attestation and do not prove phone or hardware custody.

Unsupported options include dc+sd-jwt, other suites, Presentation Exchange, arbitrary DCQL controls, array-element disclosure, overlapping hidden ancestor/child paths, proximity transports, public iOS distribution and broad unrelated-wallet interoperability. There is one issuer identity per deployment. The kit makes no production key-custody, high-availability or institutional accreditation claim.

## One documentation source

These five indexed pages are canonical. CredWorks imports reviewed committed files and both existing OpenAPI contracts into an offline snapshot with an immutable full kit revision and per-file SHA256 hashes. Site builds read that snapshot without fetching private repositories. Source edits come here first; #410 must correct instruction defects here and re-import the new pin. While access remains private, report sanitized failures in the monorepo GitHub issue tracker with source/image revisions and fixed refusal codes.
