# Partner issuer and verifier runtime

This standalone runtime uses the shared Rust identity-core. Configure an issuer, a verifier, or both; partners retain signing identities, issuance records, status and application decisions.

The five [canonical partner pages](../../docs/partner/overview.md) are the maintained instructions:

- [Overview and release limits](../../docs/partner/overview.md)
- [Standalone setup and lifecycle](../../docs/partner/quickstart.md)
- [Definitions and disclosure](../../docs/partner/definitions.md)
- [HTTP API and curl examples](../../docs/partner/api.md)
- [Operations, rotation, full-state recovery and troubleshooting](../../docs/partner/operations.md)

Use the actual [OpenAPI contract](openapi.json), [verifier Compose](../../infra/partner/compose.yml), [issuer Compose](../../infra/partner-issuer/compose.yml), and [verifier configuration](examples/verifier.json) and [issuer configuration](examples/issuer.json). The [standalone kit README](../../README.md) retains the frozen Education setup and build checks. Follow the canonical quickstart for current public routing and issuer/verifier setup; protect the management listener from public ingress.

Both repositories remain private. Source and local image preparation do not establish public availability or physical Android acceptance. Release B publication follows Release A; the canonical overview records the original source and image observations and remaining human gates.
