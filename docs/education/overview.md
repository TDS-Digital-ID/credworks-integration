# Education integration

Private preparation, Education only. This kit supports independently operated Education verification and a reference browser application. It reuses the Rust identity-core and thin Node binding exported from monorepo revision `14096ed41ee259e81414fcfa0c3b2ad622a5b426`. It ships neither a credential issuer nor a wallet APK. Generic partner credentials belong to the later Release B scope.

Start with [setup and registration](quickstart.md), then [profiles and application policy](profiles.md), [HTTP API](api.md), and [operations and limits](operations.md).

## Compatibility and availability

| Component or option | Supported preparation |
| --- | --- |
| Kit source | Private TDS-Digital-ID/universityvc-integration, branch build/poc |
| Native toolchain | Node 22.22.0, pnpm 10.34.4, Rust 1.92.0, locked dependencies |
| Host | Linux or macOS; P-256 encrypted local Rust signing identity |
| Verifier | Education definition urn:credworks:education version 1 only |
| Credential | W3C VC Data Model 2.0 SD-JWT+KB, vc+sd-jwt, ES256/P-256 |
| Presentation | OID4VP 1.0 Final, exact scalar DCQL, decentralized_identifier, direct_post, vp_token |
| Synthetic receipt | Existing Education service's Government enrolment prerequisite, OID4VCI pre-authorized-code flow, provider-signed mock WIA |
| Wallet | Registered Education Android flow; normal consent and holder authorization retained |
| iOS | Deadline-bearing registered signing refuses when safe preauthorization is unavailable; public iOS distribution unsupported |
| Images | Local revision-labelled production images; not publicly published |
| Android artifact | Final #389 candidate pending; protected release signing under #338 |
| Public setup / physical Android | NOT RUN for this documentation slice; #389 owns clean host setup, #338 owns physical/public acceptance |
| Other formats/options | dc+sd-jwt, Presentation Exchange, arbitrary paths, custom definitions, proximity transports and unrelated-wallet compatibility unsupported by this kit |

The kit and site source repository, TDS-Digital-ID/university-vc-monorepo, are both private. Existing authenticated source access permits this preparation; it is not public availability. Project code is licensed under Apache-2.0 (root `LICENSE`), with third-party notices preserved. See root `DISTRIBUTION.md` for the selected preview scope and deferred physical checks. Public availability and released clean setup remain #338 prerequisites. #348 retains later Release B acceptance. No production deployment is authorized or claimed here.

The CredWorks developer pages render a committed snapshot of these indexed pages and actual OpenAPI files, pinned to one full kit revision with per-file SHA256 provenance. Normal site builds never fetch private repositories. Changes originate here, then use the explicit site import command. Report sanitized integration failures in the monorepo GitHub issue tracker while access remains private; no public support channel is claimed.
