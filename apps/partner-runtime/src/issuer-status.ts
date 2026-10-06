import * as core from "@unsw-vc/identity-core-node";
import type { RuntimeIdentity } from "./runtime.js";
export function signIssuerStatus(
  origin: string,
  identity: RuntimeIdentity,
  now: number,
  encodedList = core.encodeBitstringStatusList(131072, []),
) {
  return core.signBitstringStatusListCredential({
    payload: {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/status/v1",
      ],
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      issuer: identity.did,
      validFrom: new Date(now * 1000).toISOString().replace(".000Z", "Z"),
      validUntil: new Date((now + 300) * 1000)
        .toISOString()
        .replace(".000Z", "Z"),
      credentialSubject: {
        id: `${origin}/oid4vci/status/revocation.jwt#list`,
        type: "BitstringStatusList",
        statusPurpose: "revocation",
        encodedList,
      },
    },
    header: { alg: "ES256", typ: "status-list+jwt", kid: identity.keyId },
    keyId: identity.keyId,
  });
}
