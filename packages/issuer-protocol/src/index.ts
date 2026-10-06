import type * as Core from "@unsw-vc/identity-core-node";
export class IssuerProtocolError extends Error {}
type CoreVerifier = Pick<typeof Core, "verifyCompactJwsJson">;
function requireField(condition: boolean, message: string): void {
  if (!condition) throw new IssuerProtocolError(message);
}
export function verifyHolderProof(input: {
  core: CoreVerifier;
  proofJwt: string;
  holderPublicJwk: Core.PublicJwk;
  expectedAudience: string;
  nowUnixSeconds: number;
  maxAgeSeconds: number;
  maxFutureSkewSeconds: number;
}): string {
  const verified = input.core.verifyCompactJwsJson({
    compactJws: input.proofJwt,
    publicJwk: input.holderPublicJwk,
  });
  const payload = verified.payload as {
    aud?: unknown;
    nonce?: unknown;
    iat?: unknown;
  };
  requireField(
    verified.header.typ === "openid4vci-proof+jwt",
    "proof typ is invalid",
  );
  requireField(
    payload.aud === input.expectedAudience,
    "proof audience is invalid",
  );
  requireField(
    typeof payload.nonce === "string" && payload.nonce.length > 0,
    "proof nonce is required",
  );
  requireField(
    typeof payload.iat === "number" && Number.isInteger(payload.iat),
    "proof iat is required",
  );
  const issued = payload.iat as number;
  requireField(
    issued >= input.nowUnixSeconds - input.maxAgeSeconds &&
      issued <= input.nowUnixSeconds + input.maxFutureSkewSeconds,
    "proof issued-at is outside the accepted freshness window",
  );
  return payload.nonce as string;
}
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  return JSON.stringify(value);
}
export function verifyWalletInstanceAttestation(input: {
  core: CoreVerifier;
  compactJws: string;
  providerPublicJwk: Core.PublicJwk;
  providerDid: string;
  expectedAudience: string;
  holderPublicJwk: Core.PublicJwk;
  nowUnixSeconds: number;
}): "mock_platform_attestation" | "dev_bypass" {
  const verified = input.core.verifyCompactJwsJson({
    compactJws: input.compactJws,
    publicJwk: input.providerPublicJwk,
  });
  const payload = verified.payload as {
    iss?: unknown;
    aud?: unknown;
    iat?: unknown;
    exp?: unknown;
    cnf?: { jwk?: unknown };
    attestation_method?: unknown;
  };
  requireField(
    verified.header.typ === "wallet-instance-attestation+jwt",
    "WIA typ is invalid",
  );
  requireField(payload.iss === input.providerDid, "WIA issuer is invalid");
  requireField(
    payload.aud === input.expectedAudience,
    "WIA audience is invalid",
  );
  requireField(
    typeof payload.iat === "number" &&
      typeof payload.exp === "number" &&
      payload.iat <= input.nowUnixSeconds &&
      payload.exp > input.nowUnixSeconds,
    "WIA freshness is invalid",
  );
  requireField(
    canonicalJson(payload.cnf?.jwk) === canonicalJson(input.holderPublicJwk),
    "WIA holder binding is invalid",
  );
  requireField(
    payload.attestation_method === "mock_platform_attestation" ||
      payload.attestation_method === "dev_bypass",
    "WIA attestation method is invalid",
  );
  return payload.attestation_method as
    "mock_platform_attestation" | "dev_bypass";
}
