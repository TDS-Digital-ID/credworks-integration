# Education integration

Education integration, experimental preview. This kit supports independently operated Education verification and a reference browser application. It reuses the Rust identity-core and thin Node binding exported from monorepo revision `14096ed41ee259e81414fcfa0c3b2ad622a5b426`. The Education source provides verification and sign-in; its release includes a separately built signed wallet APK and image archive. Generic partner credentials are covered by Release B.

Start with [setup and registration](quickstart.md), then [profiles and application policy](profiles.md), [HTTP API](api.md), and [operations and limits](operations.md).

## Compatibility and availability

| Component or option | Supported preparation |
| --- | --- |
| Kit source | Public [Education preview](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/release-a-preview-20261006); use its pinned source archive |
| Native toolchain | Node 22.22.0, pnpm 10.34.4, Rust 1.92.0, locked dependencies |
| Host | Linux or macOS; P-256 encrypted local Rust signing identity |
| Verifier | Education definition urn:credworks:education version 1 only |
| Credential | W3C VC Data Model 2.0 SD-JWT+KB, vc+sd-jwt, ES256/P-256 |
| Presentation | OID4VP 1.0 Final, exact scalar DCQL, decentralized_identifier, direct_post, vp_token |
| Synthetic receipt | Existing Education service's Government enrolment prerequisite, OID4VCI pre-authorized-code flow, provider-signed mock WIA |
| Wallet | Registered Education Android flow; normal consent and holder authorization retained |
| iOS | Deadline-bearing registered signing refuses when safe preauthorization is unavailable; public iOS distribution unsupported |
| Images | Public linux/arm64 image archive, original source ed5b8bea4322e358f802b3bdff91e0cd474b3aa0; inspect the release manifest |
| Android artifact | Release-signed buildprod APK, source9130db0e727490857bebeef64b74cec19ee9297e; checksum/certificate in the release manifest |
| Public setup / physical Android | Public downloads verified; complete public-only setup remains incomplete, remaining phone checks operator-deferred |
| Other formats/options | dc+sd-jwt, Presentation Exchange, arbitrary paths, custom definitions, proximity transports and unrelated-wallet compatibility unsupported by this kit |

The public distribution is TDS-Digital-ID/credworks-integration. Both original producer repositories remain private. Project-owned code is Apache-2.0; preserve the supplied third-party notices and corresponding-source attachments. Release A and Release B are available as experimental previews, not completed physical acceptance. Startup intermittency remains unresolved; do not clear wallet storage or replace keys to bypass it. No production assurance is claimed.

The documented examples still require independently authenticated ecosystem origins, trust anchors, issuer/status keys and institution policy. A complete public sandbox bootstrap configuration has not yet been published. Do not obtain an initial root of trust from the same registry it is meant to authenticate or substitute private operator configuration when claiming a public-only setup.

The CredWorks developer pages render a committed snapshot of these indexed pages and actual OpenAPI files, pinned to one full kit revision with per-file SHA256 provenance. Normal site builds do not fetch repositories. Changes originate here, then use the explicit site import command. Report sanitized integration failures through the [public issue tracker](https://github.com/TDS-Digital-ID/credworks-integration/issues), including source/image revisions and fixed error codes. Never attach credentials, keys or bearer tokens.
