# Partner integration

This kit packages independently operated issuer and verifier services, neutral examples and HTTP tools on the shared Rust identity-core. Partners own signing identities, issuance records, status and application decisions. Registration proves endpoint and key control. It does not establish institutional authority or authorize Education claims.

Read [setup and lifecycle](quickstart.md), [definitions and disclosure](definitions.md), [HTTP API](api.md) and [operations and limits](operations.md). For student eligibility and sign-in, use the [Education integration](../education/overview.md) and [Getting started](../education/getting-started.md).

## Revision and profile matrix

Use the [setup manifest](../../config/setup-candidate.json) for exact container archives, image identities, architectures and checksums. Setup downloads and checks the matching images. A source label identifies the commit used to build an image; documentation has its own source revision.

| Component | Supported configuration |
| --- | --- |
| Runtime and Education app source | 4be274ebc92a8653f56f83661d035150d1497770 |
| Container architectures | linux/arm64 and linux/amd64 |
| Toolchain | Node 22.22.0, pnpm 10.34.4, Rust 1.92.0, locked pnpm and Cargo dependencies |
| Credential / binding | W3C VC Data Model 2.0 SD-JWT, vc+sd-jwt, ES256/P-256, holder binding, did:web |
| Issuance | OID4VCI 1.0 Final pre-authorized-code, jwt holder proof, configured provider-signed WIA; recipient key thumbprint required |
| Presentation | OID4VP 1.0 Final, decentralized_identifier, direct_post, one DCQL credential query with exact registered paths |
| Generic shapes | string, boolean, safe finite number/integer, nested object properties, complete object/array values |
| Application extensions | credworks_scalar request authority, metadata issuer authorization, receipt-confirmed renewal version 1 |
| Status / trust | Signed Bitstring Status List revocation; issuer-scoped signed definitions and verifier permissions; retained credential-key membership |
| Result delivery | Authenticated retries within the original retention and evidence limits; current authorization and status checked on every verified delivery |
| Android | Separate signed [wallet download and consent flow](../guides/android-wallet.md) |

## Availability and release limits

Public source and artifacts are in [TDS-Digital-ID/credworks-integration](https://github.com/TDS-Digital-ID/credworks-integration). Both producer repositories remain private. Source builds require public package registries. Project-owned code is Apache-2.0; third-party terms remain unchanged. Read the artifact manifests, notices and corresponding-source attachments when downloading images or the APK.

Teams operate their own HTTPS services, databases and protected identities. The private starter contains the team's tunnel assignment and independently authenticated sandbox configuration. [Getting started](../education/getting-started.md) explains setup and the first development milestone. See [platform evidence](../setup/operations.md#platform-evidence) for the checked environments and their limits. Software-holder checks use labelled mock platform attestation and do not establish hardware custody.

Unsupported options include dc+sd-jwt, other suites, Presentation Exchange, arbitrary DCQL controls, array-element disclosure, overlapping hidden ancestor/child paths, proximity transports, public iOS distribution and broad unrelated-wallet interoperability. There is one issuer identity per deployment. The kit makes no production key-custody, high-availability or institutional accreditation claim.

## One documentation source

These indexed pages are canonical. CredWorks imports reviewed committed files and both existing OpenAPI contracts into an offline snapshot with an immutable full kit revision and per-file SHA256 hashes. Site builds read that snapshot without fetching repositories. Source edits come here first, then the site imports the reviewed distribution revision. Report sanitized failures through the [public issue tracker](https://github.com/TDS-Digital-ID/credworks-integration/issues), with source/image revisions and fixed refusal codes. Never include credentials, keys or bearer tokens.
