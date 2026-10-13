# Education integration

Use an Education credential to check eligibility or sign a student into your app.
[Getting started](getting-started.md) checks enrolment and institution without
creating an account. Add sign-in only when your app needs to recognise a returning
student.

Your team runs the verifier and app. CredWorks supplies the sandbox Education issuer
and publishes which details each verifier may request. Registration proves control
of your endpoint and key; it does not establish institutional authority.

## Compatibility and availability

| Component or option | Supported preparation |
| --- | --- |
| Kit source | Public [Education preview](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/release-a-preview-20261006); use its pinned source archive |
| Native toolchain | Node 22.22.0, pnpm 10.34.4, Rust 1.92.0, locked dependencies |
| Host | New container setup has local macOS ARM64 evidence; native Linux AMD64 and Windows/WSL2 remain unverified |
| Verifier | Education definition urn:credworks:education version 1 only |
| Credential | W3C VC Data Model 2.0 SD-JWT+KB, vc+sd-jwt, ES256/P-256 |
| Presentation | OID4VP 1.0 Final, exact scalar DCQL, decentralized_identifier, direct_post, vp_token |
| Synthetic receipt | Existing Education service's Government enrolment prerequisite, OID4VCI pre-authorized-code flow, provider-signed mock WIA |
| Wallet | Registered Education Android flow; normal consent and holder authorization retained |
| iPhone | Coming soon |
| Images | Public linux/arm64 image archive, original source ed5b8bea4322e358f802b3bdff91e0cd474b3aa0; inspect the release manifest |
| Android artifact | Release-signed buildprod APK, source9130db0e727490857bebeef64b74cec19ee9297e; checksum/certificate in the release manifest |
| Public setup / physical Android | Earlier published candidates have retained-scope Pixel evidence; the new guided setup requires its own public and Android qualification |
| Other formats/options | dc+sd-jwt, Presentation Exchange, arbitrary paths, custom definitions, proximity transports and unrelated-wallet compatibility unsupported by this kit |

The [public distribution](https://github.com/TDS-Digital-ID/credworks-integration/releases)
contains experimental previews. The later generic physical preview records one
Pixel's results and the separate published Education eligibility/sign-in checks.
Those observations do not qualify every device or the new onboarding candidate.
Software-holder checks use mock platform attestation; no production assurance is claimed.

The new guided setup ships [independently authenticated sandbox configuration](../../config/credworks-sandbox-20261011.json).
Keep its reviewed checksum and trust anchor. Do not learn your initial trust anchor
from the registry it authenticates. New commands and architecture-specific container
candidates remain unpublished until qualification and release approval.

Both producer repositories remain private. Project-owned code is Apache-2.0;
preserve third-party notices and corresponding-source attachments.

The CredWorks developer pages render a committed snapshot of these indexed pages and actual OpenAPI files, pinned to one full kit revision with per-file SHA256 provenance. Normal site builds do not fetch repositories. Changes originate here, then use the explicit site import command. Report sanitized integration failures through the [public issue tracker](https://github.com/TDS-Digital-ID/credworks-integration/issues), including source/image revisions and fixed error codes. Never attach credentials, keys or bearer tokens.
