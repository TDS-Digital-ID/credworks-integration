# Definitions and disclosure

A partner registers a namespaced definition ID, immutable version, credential type, labels, maximum validity and disclosure profiles with the registry. The issuer's signed authorization authenticates that whole definition and the actual issuer/key. The issuer project owner grants a registered verifier a profile for the exact issuer, definition/version/type, verifier DID/origin/key and allowed paths. Another project's credential, a shared type name or a reused profile name grants no authority. CredWorks controls Education permissions.

## Scalar example

This neutral definition imposes no partner business model. Adopt it under an ID in your registered namespace and substitute that same ID everywhere in issuer and verifier configuration.

```json
{
  "id": "https://issuer.example/definitions/entitlement",
  "version": "1",
  "credential_type": "PartnerEntitlement",
  "label": "Neutral entitlement",
  "max_validity_seconds": 3600,
  "claims": [
    {"name":"enabled","label":"Enabled","value_type":"boolean","required":true},
    {"name":"credits","label":"Credits","value_type":"integer","required":true}
  ],
  "profiles": [
    {"name":"enabled_only","claim_paths":[["credentialSubject","enabled"]]},
    {"name":"complete","claim_paths":[["credentialSubject","enabled"],["credentialSubject","credits"]]}
  ]
}
```

Offer claims are `{"enabled":false,"credits":0}`. Both values are valid and must survive receipt and presentation without coercion. An `enabled_only` result discloses only `enabled`. A successful cryptographic result with `enabled:false` does not grant application access. The application checks its own values after `status:verified` and the expected definition/version.

## Structured example

The [pair and snapshot definitions](../../apps/partner-runtime/examples/structured-definitions.json), [subjects](../../apps/partner-runtime/examples/structured-subjects.json), [issuer configuration](../../apps/partner-runtime/examples/structured-issuer.json) and [verifier configuration](../../apps/partner-runtime/examples/structured-verifier.json) are neutral prepared inputs. Replace placeholder keys, publication UUIDs and origins with authenticated values. A second supported definition requires registration and configuration, not wallet code or a manual CredWorks host edit.

```json
{
  "left":{"name":"Left value"},
  "right":{"name":"Right value"},
  "details":{"active":false,"count":0},
  "entries":[{"label":"First","active":false},0]
}
```

`["credentialSubject","left","name"]` and `["credentialSubject","right","name"]` are distinct paths even though their leaf names match. `left_only` discloses the first without the second. `whole` discloses the entire declared `details` object and `entries` array. This reveals every value inside those units. Array indices, wildcards, arbitrary JSONPath and overlapping hidden ancestor/child units are unsupported. Object/array selective disclosure means the complete declared value, not selected array elements.

Generic results retain full path identity in `evidence.claim_paths`; structured consumers use the full-path claim representation from [the actual result schema](../../apps/partner-runtime/openapi.json). Do not flatten nested siblings into one `name` or treat labels as identifiers. Unknown claims, undeclared shapes, null, missing required values and type coercion refuse.

## Supported bounds and configuration

| Option | Bound / behavior |
| --- | --- |
| Definition claims / profile paths | 1–64; paths start at credentialSubject, 2–16 string components |
| Scalar values | Strings at most 1024 UTF-8 bytes; boolean; finite safe number/integer within ±9007199254740991 |
| Structured values | Whole subject at most 65536 compact UTF-8 bytes, total depth 16, total nodes 1024, at most 64 immediate object/array entries; no null or array-element selection |
| Deployment definitions / profiles | At most 16 configured definitions; at most 16 profiles per definition |
| Configuration / profile selector | 1–64 ASCII letters, digits, underscore or hyphen |
| Definition version | 1–64 letters, digits, dot, underscore or hyphen |
| Definition ID / credential type | At most 256 / 128 characters |
| Runtime public configuration | At most 16 KiB; exact known fields, no extra fields; canonical lowercase UUID publication references |
| Generic Request Object | At most 262144 bytes; unsupported DCQL controls refuse before disclosure |

Issuer configuration contains `databaseUrl`, `registryOrigin`, `registryDid`, `trustAnchorJwk`, `walletProviderDid`, `walletProviderJwk` and `definitions`. Each definition selects `configurationId`, `authorizationId`, `definitionId`, `definitionVersion` and `credentialType`. The database URL is a secret; protect this file.

Verifier configuration retains `issuerDid`, `issuerJwk`, `registryOrigin`, `trustAnchorJwk`, `statusSources` and `maxCacheAgeSeconds`. Its generic `scalar` object selects `registryDid`, `issuerKeyId` and `definitions`. Each definition selects `configurationId`, `authorizationId`, `definitionId`, `definitionVersion`, `credentialType` and `profiles`; profiles select `name` and `permissionId`. See [scalar verifier input](../../apps/partner-runtime/examples/scalar-verifier.json). Authenticated registry publications supply labels and exact paths, never the session caller.

After credential-key rotation, follow [retained-key configuration](operations.md#retained-key-rotation). A session captures its accepted membership; fetching a newer grant cannot silently add a key to that request. Apply partner policy only to protected, correlated one-time results. Preserve issuer, definition/version and full paths alongside typed claims.

Continue with [setup](quickstart.md#registration-and-authority), [API contracts](api.md) or the separate [Education profiles](../education/profiles.md).
