# Education integration

Use an Education credential to check eligibility or sign a student into your app.
[Getting started](getting-started.md) checks enrolment and institution without
creating an account. Add sign-in only when your app needs to recognise a returning
student.

Your team runs the verifier and app. CredWorks supplies the sandbox Education issuer
and publishes which details each verifier may request. Registration proves control
of your endpoint and key; it does not establish institutional authority.

## Compatibility and availability

| Component or option | Supported configuration |
| --- | --- |
| Kit | Use your team's private starter and follow [Getting started](getting-started.md). Public source is available in [the integration repository](https://github.com/TDS-Digital-ID/credworks-integration). |
| Containers | ARM64 and AMD64 runtime/app archives are selected and verified by setup using the [setup manifest](../../config/setup-candidate.json). |
| Native toolchain | Node 22.22.0, pnpm 10.34.4, Rust 1.92.0, locked dependencies |
| Verifier | Education definition urn:credworks:education version 1 only |
| Credential | W3C VC Data Model 2.0 SD-JWT+KB, vc+sd-jwt, ES256/P-256 |
| Presentation | OID4VP 1.0 Final, exact scalar DCQL, decentralized_identifier, direct_post, vp_token |
| Synthetic receipt | Government enrolment prerequisite, OID4VCI pre-authorized-code flow, provider-signed mock WIA |
| Android | Separate signed [wallet download and consent flow](../guides/android-wallet.md) |
| iPhone | Coming soon |
| Checks and host limits | See [platform evidence](../setup/operations.md#platform-evidence). |
| Other formats/options | dc+sd-jwt, Presentation Exchange, arbitrary paths, proximity transports and unrelated-wallet compatibility are unsupported. Use the [partner integration](../partner/overview.md) for custom definitions. |

Setup includes [independently authenticated sandbox configuration](../../config/credworks-sandbox-20261011.json).
Keep its reviewed checksum and trust anchor. Do not learn your initial trust anchor
from the registry it authenticates. Software-holder checks use mock platform
attestation; no production assurance is claimed.

Both producer repositories remain private. Project-owned code is Apache-2.0;
preserve third-party notices and corresponding-source attachments.

The CredWorks developer pages render a committed snapshot of these indexed pages and actual OpenAPI files, pinned to one full kit revision with per-file SHA256 provenance. Normal site builds do not fetch repositories. Changes originate here, then use the explicit site import command. Report sanitized integration failures through the [public issue tracker](https://github.com/TDS-Digital-ID/credworks-integration/issues), including source/image revisions and fixed error codes. Never attach credentials, keys or bearer tokens.
