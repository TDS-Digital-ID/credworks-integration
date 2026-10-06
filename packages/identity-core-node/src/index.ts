import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const native = require("../native/index.cjs") as NativeBinding;

export type CoreErrorCode =
  | "INVALID_INPUT"
  | "UNSUPPORTED_ALGORITHM"
  | "INVALID_KEY"
  | "INVALID_SIGNATURE"
  | "MALFORMED_JWS"
  | "JSON_SERIALIZATION"
  | "KEY_NOT_FOUND"
  | "SIGNING_FAILED"
  | "VERIFICATION_FAILED"
  | "CLOCK_UNAVAILABLE"
  | "RESOLVER_UNAVAILABLE"
  | "SALT_UNAVAILABLE"
  | "TRUST_CHECK_FAILED"
  | "STATUS_CHECK_FAILED"
  | "STATUS_LIST_STALE"
  | "BINDING_CHECK_FAILED"
  | "FRESHNESS_CHECK_FAILED"
  | "ATTACHMENT_CHECK_FAILED"
  | "DISCLOSURE_DIGEST_MISMATCH"
  | "MISSING_DISCLOSURE";

export type PublicJwk = {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  kid?: string;
};

export type JwePublicJwk = PublicJwk & {
  alg: "ECDH-ES";
  use: "enc";
};

export type Oid4vciEncryptionJwk = JwePublicJwk & {
  kid: string;
};

export type Oid4vciCredentialResponseEncryption = {
  jwk: JwePublicJwk;
  enc: "A256GCM";
  zip?: "DEF";
};

export type Oid4vciEncryptionParameters = {
  jwk: Oid4vciEncryptionJwk;
  enc: "A256GCM";
  zip?: "DEF";
};

export type JwsHeader = {
  alg: "ES256";
  typ?: string;
  cty?: string;
  kid?: string;
  jwk?: PublicJwk;
  x5c?: string[];
};

export type DeterministicTestX509Identity = {
  public_jwk: PublicJwk;
  x5c: string[];
  trust_anchor_pem: string;
};

export type DisclosureSpec = {
  object_path: string[];
  claim_name: string;
};

export type IssuedDisclosure = {
  object_path: string[];
  claim_name: string;
  salt: string;
  encoded: string;
  digest: string;
};

export type IssuedSdJwt = {
  issuer_jwt: string;
  compact: string;
  payload: unknown;
  disclosures: IssuedDisclosure[];
};

export type DisclosureProfile = {
  name: string;
  claim_paths: string[][];
};

export type SdJwtPresentation = {
  presentation: string;
  disclosed_sd_jwt: string;
  selected_disclosures: string[];
  kb_jwt: string;
  sd_hash: string;
};

export type SdJwtVerificationOptions = {
  audience: string;
  nonce: string;
  now_unix_seconds: number;
  max_kb_age_seconds: number;
  required_claims: string[][];
  expected_typ?: string;
};

export type CredentialFormat = "w3c_vc_data_model" | "ietf_sd_jwt_vc";

export type SdJwtCredentialVerificationOptions = {
  now_unix_seconds: number;
  required_claims: string[][];
  format: CredentialFormat;
};

export type VerifiedSdJwtPresentation = {
  issuer_header: JwsHeader;
  kb_header: JwsHeader;
  processed_payload: unknown;
};

export type VerifiedSdJwtCredential = {
  issuer_header: JwsHeader;
  processed_payload: unknown;
};

export type DidDocument = {
  "@context": string[];
  id: string;
  verificationMethod: Array<{
    id: string;
    type: "JsonWebKey";
    controller: string;
    publicKeyJwk: PublicJwk;
  }>;
  assertionMethod: string[];
  authentication: string[];
};

export type PlannedIssuerDid = {
  key: string;
  label: string;
  host: string;
  did: string;
  credential_types: string[];
};

export type CredentialStatus = {
  id: string;
  type: "BitstringStatusListEntry";
  statusPurpose: "revocation" | "suspension";
  statusListIndex: string;
  statusListCredential: string;
};

export type BitstringStatusListCredentialPayload = {
  "@context": string[];
  type: string[];
  issuer: string;
  credentialSubject: {
    id: string;
    type: "BitstringStatusList";
    statusPurpose: "revocation" | "suspension";
    encodedList: string;
  };
  validFrom?: string;
  validUntil?: string;
};

export type CredentialStatusResolution = {
  status_list_credential: string;
  status_list_index: number;
  status_purpose: string;
  revoked: boolean;
};

export type StatusListSizeReport = {
  bit_len: number;
  uncompressed_bytes: number;
  encoded_list_bytes: number;
};

export type TrustListStatus = "active" | "inactive";

export type TrustListEntry = {
  issuer_did: string;
  credential_types: string[];
  status: TrustListStatus;
  public_jwk?: PublicJwk;
  public_jwk_sha256_thumbprint?: string;
};

export type VerifierTrustListEntry = {
  verifier_did: string;
  credential_type: string;
  profile_name: string;
  claim_paths: string[][];
  status: TrustListStatus;
};

export type ScalarCredentialDefinition = {
  id: string;
  version: string;
  credential_type: string;
  label: string;
  max_validity_seconds: number;
  claims: {
    name: string;
    /** Exact object-property path; omitted means ["credentialSubject", name]. */
    path?: string[];
    label: string;
    value_type: "string" | "boolean" | "integer" | "number" | "object" | "array";
    required: boolean;
  }[];
  profiles: { name: string; claim_paths: string[][] }[];
};
export type SubjectValidationMode = "complete" | "disclosed";
export type CredentialKeyState = "current" | "retained" | "withdrawn";
export type IssuerAuthorityPurpose = "issuance" | "verification";
export type IssuerStatusAuthority = {
  key_id: string;
  public_jwk_sha256_thumbprint: string;
};
export type IssuerAuthorization = {
  credential_issuer_did: string;
  credential_issuer_key_id: string;
  credential_issuer_public_jwk_sha256_thumbprint: string;
  definition: ScalarCredentialDefinition;
  status: "active" | "inactive";
  /** Both fields are absent for authenticated legacy entries, or present together. */
  key_state?: CredentialKeyState;
  status_authority?: IssuerStatusAuthority;
};
export type IssuerAuthorizations = {
  version: 1;
  id: string;
  issuer: string;
  iat: number;
  exp: number;
  authorizations: IssuerAuthorization[];
};
export type IssuerAuthorizationRequest = {
  registry_did: string;
  credential_issuer_did: string;
  credential_issuer_key_id: string;
  credential_issuer_public_jwk: PublicJwk;
  definition_id: string;
  definition_version: string;
  credential_type: string;
  /** Omission is issuance-safe; retained keys require explicit verification. */
  purpose?: IssuerAuthorityPurpose;
};

export type ScopedVerifierPermission = {
  credential_issuer_did: string;
  definition_id: string;
  definition_version: string;
  credential_type: string;
  verifier_did: string;
  verifier_origin: string;
  verifier_public_jwk_sha256_thumbprint: string;
  profile_name: string;
  claim_paths: string[][];
  status: TrustListStatus;
};
export type ScopedVerifierPermissions = {
  version: 1;
  id: string;
  issuer: string;
  iat: number;
  exp: number;
  permissions: ScopedVerifierPermission[];
};
export type ScopedVerifierPermissionRequest = Omit<ScopedVerifierPermission, "status" | "verifier_public_jwk_sha256_thumbprint"> & {
  verifier_public_jwk: PublicJwk;
};
export type ScopedVerifierPermissionResult = {
  permission: ScopedVerifierPermission;
  claim_paths: string[][];
  active: boolean;
};

export type TrustListPayload = {
  id: string;
  issuer: string;
  iat: number;
  exp: number;
  entries: TrustListEntry[];
  verifiers?: VerifierTrustListEntry[];
};

export type TrustAccreditationResult = {
  issuer_did: string;
  credential_type: string;
  active: boolean;
  public_jwk_sha256_thumbprint: string;
};

export type VerifierTrustAccreditationResult = {
  verifier_did: string;
  credential_type: string;
  profile_name: string;
  claim_paths: string[][];
  active: boolean;
};

export type VerifiedOid4vpRequest = {
  header: JwsHeader;
  payload: Record<string, unknown>;
  verifier_did: string;
};

export type KeyProofInput = {
  audience: string;
  nonce: string;
  iat: number;
  keyId: string;
  publicJwk?: PublicJwk;
};

export type VerifiedJwsJson = {
  header: JwsHeader;
  payload: unknown;
};

export type DpopVerificationOptions = {
  expected_htu: string;
  expected_htm: string;
  now_unix_seconds: number;
  max_age_seconds: number;
  access_token?: string;
  expected_nonce?: string;
};

export type VerifiedDpopProof = {
  public_jwk: PublicJwk;
  public_jwk_sha256_thumbprint: string;
  htu: string;
  htm: string;
  iat: number;
  jti: string;
};

export type ClientAttestationVerificationOptions = {
  trusted_attester_jwk: PublicJwk;
  expected_attester_issuer: string;
  expected_client_id?: string;
  expected_audience: string;
  now_unix_seconds: number;
  max_age_seconds: number;
  expected_challenge?: string;
};

export type VerifiedClientAttestation = {
  client_id: string;
  client_instance_jwk: PublicJwk;
  client_instance_jwk_sha256_thumbprint: string;
  attestation_issued_at: number;
  proof_issued_at: number;
  proof_jti: string;
};

type NativeBinding = {
  crateName(): string;
  persistentSigningKeyRaw(
    path: string,
    unlockKey: string,
    keyId: string,
    create: boolean,
  ): string;
  installDeterministicTestKeyRaw(keyId: string, slot: string): string;
  installDeterministicTestX509KeyRaw(keyId: string, slot: string): string;
  sha256B64UrlRaw(inputBase64url: string): string;
  publicJwkRaw(keyId: string): string;
  randomUrlsafeRaw(byteLength: number): string;
  generateOidfEncryptionKeyRaw(keyId: string): string;
  encryptOid4vciJweRaw(plaintextJson: string, parametersJson: string): string;
  decryptOid4vciJweRaw(compactJwe: string, keyId: string): string;
  signCompactJwsJsonRaw(
    headerJson: string,
    payloadJson: string,
    keyId: string,
  ): string;
  verifyCompactJwsJsonRaw(compactJws: string, publicJwkJson: string): string;
  verifyDpopProofRaw(compactJws: string, optionsJson: string): string;
  verifyClientAttestationRaw(
    clientAttestationJwt: string,
    clientAttestationPopJwt: string,
    optionsJson: string,
  ): string;
  oid4vciEncryptionPublicJwkRaw(keyId: string): string;
  encryptOid4vciCredentialResponseRaw(
    plaintextJson: string,
    parametersJson: string,
  ): string;
  validateOid4vciCredentialResponseEncryptionRaw(
    parametersJson: string,
  ): string;
  decryptOid4vciJweRaw(compactJwe: string, keyId: string): string;
  issueSdJwtRaw(
    payloadJson: string,
    disclosureSpecsJson: string,
    decoyDigests: number,
    headerJson: string,
    keyId: string,
    saltsJson: string,
  ): string;
  issueSdJwtWithFormatRaw(
    payloadJson: string,
    disclosureSpecsJson: string,
    decoyDigests: number,
    headerJson: string,
    keyId: string,
    saltsJson: string,
    formatJson: string,
  ): string;
  presentSdJwtRaw(
    compactSdJwt: string,
    profileJson: string,
    holderKeyId: string,
    audience: string,
    nonce: string,
    iat: number,
  ): string;
  verifySdJwtPresentationRaw(
    presentation: string,
    issuerJwkJson: string,
    optionsJson: string,
  ): string;
  verifySdJwtCredentialRaw(
    compactSdJwt: string,
    issuerJwkJson: string,
    optionsJson: string,
  ): string;
  verifySdJwtPresentationWithDidWebRaw(
    presentation: string,
    resolverResponsesJson: string,
    optionsJson: string,
  ): string;
  verifyCompactJwsWithDidWebIssuerRaw(
    compactJws: string,
    resolverResponsesJson: string,
  ): string;
  verifyOid4vpRequestObjectRaw(
    compactJws: string,
    resolverResponsesJson: string,
    nowUnixSeconds: number,
  ): string;
  didWebFromHostRaw(host: string): string;
  didWebToHttpsUrlRaw(did: string): string;
  plannedIssuerDidWebIdentitiesRaw(baseDomain: string): string;
  buildDidWebDocumentRaw(did: string, publicJwksJson: string): string;
  resolveDidWebDocumentRaw(did: string, resolverResponsesJson: string): string;
  resolveDidWebKeyRaw(
    issuerDid: string,
    kid: string,
    resolverResponsesJson: string,
  ): string;
  encodeBitstringStatusListRaw(bitLen: number, setIndicesJson: string): string;
  statusListSizeReportRaw(bitLen: number, encodedList: string): string;
  publicJwkSha256ThumbprintRaw(publicJwkJson: string): string;
  verifyPartnerIdentityProofRaw(
    jwt: string,
    publicJwkJson: string,
    optionsJson: string,
  ): void;
  validateScalarDefinitionRaw(definitionJson: string): void;
  validateScalarSubjectRaw(
    definitionJson: string,
    subjectJson: string,
    modeJson: string,
  ): void;
  signIssuerAuthorizationsRaw(
    payloadJson: string,
    headerJson: string,
    keyId: string,
  ): string;
  verifyIssuerAuthorizationRaw(
    compact: string,
    anchorJson: string,
    requestJson: string,
    now: number,
  ): string;
  verifyScalarCredentialAuthorizationRaw(
    credential: string,
    issuerKeyJson: string,
    authorization: string,
    anchorJson: string,
    registryDid: string,
    now: number,
    modeJson: string,
  ): string;
  verifyScalarRenewalPredecessorRaw(
    credential: string,
    issuerKeyJson: string,
    authorization: string,
    anchorJson: string,
    registryDid: string,
    now: number,
  ): string;
  signScopedVerifierPermissionsRaw(
    payloadJson: string,
    headerJson: string,
    keyId: string,
  ): string;
  verifyScopedVerifierPermissionRaw(
    compactJws: string,
    trustAnchorJwkJson: string,
    requestJson: string,
    nowUnixSeconds: number,
  ): string;
  signTrustListRaw(
    payloadJson: string,
    headerJson: string,
    keyId: string,
  ): string;
  verifyTrustListRaw(compactJws: string, trustAnchorJwkJson: string): string;
  verifyTrustListAccreditationRaw(
    compactJws: string,
    trustAnchorJwkJson: string,
    issuerDid: string,
    credentialType: string,
    issuerJwkJson: string,
    nowUnixSeconds: number,
  ): string;
  verifyVerifierTrustListAccreditationRaw(
    compactJws: string,
    trustAnchorJwkJson: string,
    verifierDid: string,
    credentialType: string,
    profileName: string,
    requestedClaimPathsJson: string,
    nowUnixSeconds: number,
  ): string;
  signBitstringStatusListCredentialRaw(
    payloadJson: string,
    headerJson: string,
    keyId: string,
  ): string;
  verifyBitstringStatusListCredentialRaw(
    compactJws: string,
    statusListJwkJson: string,
  ): string;
  verifyBitstringStatusListCredentialAtRaw(
    compactJws: string,
    statusListJwkJson: string,
    nowUnixSeconds: number,
  ): string;
  resolveCredentialStatusRaw(
    statusJson: string,
    resolverResponsesJson: string,
    statusListJwkJson: string,
  ): string;
  resolveCredentialStatusAtRaw(
    statusJson: string,
    resolverResponsesJson: string,
    statusListJwkJson: string,
    nowUnixSeconds: number,
  ): string;
  verifyCredentialStatusActiveRaw(
    statusJson: string,
    resolverResponsesJson: string,
    statusListJwkJson: string,
  ): string;
  verifyCredentialStatusActiveAtRaw(
    statusJson: string,
    resolverResponsesJson: string,
    statusListJwkJson: string,
    nowUnixSeconds: number,
  ): string;
  verifyAttachmentRaw(
    attachmentBase64url: string,
    expectedSha256B64url: string,
  ): string;
};

export const crateName = native.crateName;

export function installDeterministicTestKey(
  keyId: string,
  slot: "issuer" | "holder" | `issuer:${number}`,
): PublicJwk {
  return parseNativeJson(native.installDeterministicTestKeyRaw(keyId, slot));
}

export function installDeterministicTestX509Key(
  keyId: string,
  slot: `issuer:${number}`,
): DeterministicTestX509Identity {
  return parseNativeJson(native.installDeterministicTestX509KeyRaw(keyId, slot));
}

export function publicJwk(keyId: string): PublicJwk {
  return parseNativeJson(native.publicJwkRaw(keyId));
}

export function sha256B64Url(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
  return unwrapNative(native.sha256B64UrlRaw(bytes.toString("base64url")));
}

/** Explicit creation or loading; only the public JWK crosses this boundary. */
export function persistentSigningKey(input: {path: string; unlockKey: string; keyId: string; create: boolean}): PublicJwk {
  return parseNativeJson(native.persistentSigningKeyRaw(input.path, input.unlockKey, input.keyId, input.create));
}

export function randomUrlSafe(byteLength = 32): string {
  return unwrapNative(native.randomUrlsafeRaw(byteLength));
}

export function generateOidfEncryptionKey(keyId: string): Oid4vciEncryptionJwk {
  return parseNativeJson(native.generateOidfEncryptionKeyRaw(keyId));
}

export function encryptOid4vciJwe(input: {
  plaintext: unknown;
  parameters: Oid4vciEncryptionParameters;
}): string {
  return unwrapNative(
    native.encryptOid4vciJweRaw(
      stringify(input.plaintext),
      stringify(input.parameters),
    ),
  );
}

export function decryptOid4vciJwe(input: {
  compactJwe: string;
  keyId: string;
}): unknown {
  return parseNativeJson(
    native.decryptOid4vciJweRaw(input.compactJwe, input.keyId),
  );
}

export function signCompactJwsJson(input: {
  header: JwsHeader;
  payload: unknown;
  keyId: string;
}): string {
  return unwrapNative(
    native.signCompactJwsJsonRaw(
      stringify(input.header),
      stringify(input.payload),
      input.keyId,
    ),
  );
}

export function createKeyProof(input: KeyProofInput): string {
  return signCompactJwsJson({
    header: {
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      kid: input.keyId,
      ...(input.publicJwk ? { jwk: input.publicJwk } : {}),
    },
    payload: {
      aud: input.audience,
      nonce: input.nonce,
      iat: input.iat,
    },
    keyId: input.keyId,
  });
}

export function verifyCompactJwsJson(input: {
  compactJws: string;
  publicJwk: PublicJwk;
}): VerifiedJwsJson {
  return parseNativeJson(
    native.verifyCompactJwsJsonRaw(
      input.compactJws,
      stringify(input.publicJwk),
    ),
  );
}

export function verifyDpopProof(input: {
  compactJws: string;
  options: DpopVerificationOptions;
}): VerifiedDpopProof {
  return parseNativeJson(
    native.verifyDpopProofRaw(
      input.compactJws,
      stringify(input.options),
    ),
  );
}

export function verifyClientAttestation(input: {
  clientAttestationJwt: string;
  clientAttestationPopJwt: string;
  options: ClientAttestationVerificationOptions;
}): VerifiedClientAttestation {
  return parseNativeJson(
    native.verifyClientAttestationRaw(
      input.clientAttestationJwt,
      input.clientAttestationPopJwt,
      stringify(input.options),
    ),
  );
}

export function oid4vciEncryptionPublicJwk(keyId: string): JwePublicJwk {
  return parseNativeJson(native.oid4vciEncryptionPublicJwkRaw(keyId));
}

export function encryptOid4vciCredentialResponse(input: {
  plaintext: unknown;
  parameters: Oid4vciCredentialResponseEncryption;
}): string {
  return unwrapNative(
    native.encryptOid4vciCredentialResponseRaw(
      stringify(input.plaintext),
      stringify(input.parameters),
    ),
  );
}

export function validateOid4vciCredentialResponseEncryption(
  parameters: Oid4vciCredentialResponseEncryption,
): void {
  unwrapNative(
    native.validateOid4vciCredentialResponseEncryptionRaw(stringify(parameters)),
  );
}

export function issueSdJwt(input: {
  payload: unknown;
  disclosureSpecs: DisclosureSpec[];
  decoyDigests?: number;
  header: JwsHeader;
  keyId: string;
  salts: string[];
}): IssuedSdJwt {
  return parseNativeJson(
    native.issueSdJwtRaw(
      stringify(input.payload),
      stringify(input.disclosureSpecs),
      input.decoyDigests ?? 0,
      stringify(input.header),
      input.keyId,
      stringify(input.salts),
    ),
  );
}

export function issueSdJwtWithFormat(input: {
  payload: unknown;
  disclosureSpecs: DisclosureSpec[];
  decoyDigests?: number;
  header: JwsHeader;
  keyId: string;
  salts: string[];
  format: CredentialFormat;
}): IssuedSdJwt {
  return parseNativeJson(
    native.issueSdJwtWithFormatRaw(
      stringify(input.payload),
      stringify(input.disclosureSpecs),
      input.decoyDigests ?? 0,
      stringify(input.header),
      input.keyId,
      stringify(input.salts),
      stringify(input.format),
    ),
  );
}

export function presentSdJwt(input: {
  compactSdJwt: string;
  profile: DisclosureProfile;
  holderKeyId: string;
  audience: string;
  nonce: string;
  iat: number;
}): SdJwtPresentation {
  return parseNativeJson(
    native.presentSdJwtRaw(
      input.compactSdJwt,
      stringify(input.profile),
      input.holderKeyId,
      input.audience,
      input.nonce,
      input.iat,
    ),
  );
}

export function verifySdJwtPresentation(input: {
  presentation: string;
  issuerJwk: PublicJwk;
  options: SdJwtVerificationOptions;
}): VerifiedSdJwtPresentation {
  return parseNativeJson(
    native.verifySdJwtPresentationRaw(
      input.presentation,
      stringify(input.issuerJwk),
      stringify(input.options),
    ),
  );
}

export function verifySdJwtCredential(input: {
  compactSdJwt: string;
  issuerJwk: PublicJwk;
  options: SdJwtCredentialVerificationOptions;
}): VerifiedSdJwtCredential {
  return parseNativeJson(
    native.verifySdJwtCredentialRaw(
      input.compactSdJwt,
      stringify(input.issuerJwk),
      stringify(input.options),
    ),
  );
}

export function verifySdJwtPresentationWithDidWeb(input: {
  presentation: string;
  resolverResponses: Record<string, string>;
  options: SdJwtVerificationOptions;
}): VerifiedSdJwtPresentation {
  return parseNativeJson(
    native.verifySdJwtPresentationWithDidWebRaw(
      input.presentation,
      stringify(input.resolverResponses),
      stringify(input.options),
    ),
  );
}

export function verifyOid4vpRequestObject(input: {
  compactJws: string;
  resolverResponses: Record<string, string>;
  nowUnixSeconds: number;
}): VerifiedOid4vpRequest {
  return parseNativeJson(
    native.verifyOid4vpRequestObjectRaw(
      input.compactJws,
      stringify(input.resolverResponses),
      input.nowUnixSeconds,
    ),
  );
}

export function didWebFromHost(host: string): string {
  return unwrapNative(native.didWebFromHostRaw(host));
}

export function didWebToHttpsUrl(did: string): string {
  return unwrapNative(native.didWebToHttpsUrlRaw(did));
}

export function plannedIssuerDidWebIdentities(
  baseDomain: string,
): PlannedIssuerDid[] {
  return parseNativeJson(native.plannedIssuerDidWebIdentitiesRaw(baseDomain));
}

export function buildDidWebDocument(
  did: string,
  publicJwks: PublicJwk[],
): DidDocument {
  return parseNativeJson(native.buildDidWebDocumentRaw(did, stringify(publicJwks)));
}

export function resolveDidWebDocument(input: {
  did: string;
  resolverResponses: Record<string, string>;
}): DidDocument {
  return parseNativeJson(
    native.resolveDidWebDocumentRaw(
      input.did,
      stringify(input.resolverResponses),
    ),
  );
}

export function resolveDidWebKey(input: {
  issuerDid: string;
  kid: string;
  resolverResponses: Record<string, string>;
}): PublicJwk {
  return parseNativeJson(
    native.resolveDidWebKeyRaw(
      input.issuerDid,
      input.kid,
      stringify(input.resolverResponses),
    ),
  );
}

export function encodeBitstringStatusList(
  bitLen: number,
  setIndices: number[],
): string {
  return unwrapNative(
    native.encodeBitstringStatusListRaw(bitLen, stringify(setIndices)),
  );
}

export function statusListSizeReport(
  bitLen: number,
  encodedList: string,
): StatusListSizeReport {
  return parseNativeJson(native.statusListSizeReportRaw(bitLen, encodedList));
}

export function publicJwkSha256Thumbprint(publicJwk: PublicJwk): string {
  return unwrapNative(native.publicJwkSha256ThumbprintRaw(stringify(publicJwk)));
}

export function signScopedVerifierPermissions(input: {
  payload: ScopedVerifierPermissions;
  header: JwsHeader;
  keyId: string;
}): string {
  return unwrapNative(
    native.signScopedVerifierPermissionsRaw(
      stringify(input.payload),
      stringify(input.header),
      input.keyId,
    ),
  );
}

export function verifyScopedVerifierPermission(input: {
  compactJws: string;
  trustAnchorJwk: PublicJwk;
  request: ScopedVerifierPermissionRequest;
  nowUnixSeconds: number;
}): ScopedVerifierPermissionResult {
  return parseNativeJson(
    native.verifyScopedVerifierPermissionRaw(
      input.compactJws,
      stringify(input.trustAnchorJwk),
      stringify(input.request),
      input.nowUnixSeconds,
    ),
  );
}

export function signTrustList(input: {
  payload: TrustListPayload;
  header: JwsHeader;
  keyId: string;
}): string {
  return unwrapNative(
    native.signTrustListRaw(
      stringify(input.payload),
      stringify(input.header),
      input.keyId,
    ),
  );
}

export function verifyTrustList(input: {
  compactJws: string;
  trustAnchorJwk: PublicJwk;
}): [JwsHeader, TrustListPayload] {
  return parseNativeJson(
    native.verifyTrustListRaw(
      input.compactJws,
      stringify(input.trustAnchorJwk),
    ),
  );
}

export function verifyTrustListAccreditation(input: {
  compactJws: string;
  trustAnchorJwk: PublicJwk;
  issuerDid: string;
  credentialType: string;
  issuerJwk: PublicJwk;
  nowUnixSeconds: number;
}): TrustAccreditationResult {
  return parseNativeJson(
    native.verifyTrustListAccreditationRaw(
      input.compactJws,
      stringify(input.trustAnchorJwk),
      input.issuerDid,
      input.credentialType,
      stringify(input.issuerJwk),
      input.nowUnixSeconds,
    ),
  );
}

export function verifyVerifierTrustListAccreditation(input: {
  compactJws: string;
  trustAnchorJwk: PublicJwk;
  verifierDid: string;
  credentialType: string;
  profileName: string;
  requestedClaimPaths: string[][];
  nowUnixSeconds: number;
}): VerifierTrustAccreditationResult {
  return parseNativeJson(
    native.verifyVerifierTrustListAccreditationRaw(
      input.compactJws,
      stringify(input.trustAnchorJwk),
      input.verifierDid,
      input.credentialType,
      input.profileName,
      stringify(input.requestedClaimPaths),
      input.nowUnixSeconds,
    ),
  );
}

export function signBitstringStatusListCredential(input: {
  payload: BitstringStatusListCredentialPayload;
  header: JwsHeader;
  keyId: string;
}): string {
  return unwrapNative(
    native.signBitstringStatusListCredentialRaw(
      stringify(input.payload),
      stringify(input.header),
      input.keyId,
    ),
  );
}

export function verifyBitstringStatusListCredential(input: {
  compactJws: string;
  statusListJwk: PublicJwk;
}): [JwsHeader, BitstringStatusListCredentialPayload] {
  return parseNativeJson(
    native.verifyBitstringStatusListCredentialRaw(
      input.compactJws,
      stringify(input.statusListJwk),
    ),
  );
}

export function verifyBitstringStatusListCredentialAt(input: {
  compactJws: string;
  statusListJwk: PublicJwk;
  nowUnixSeconds: number;
}): [JwsHeader, BitstringStatusListCredentialPayload] {
  return parseNativeJson(
    native.verifyBitstringStatusListCredentialAtRaw(
      input.compactJws,
      stringify(input.statusListJwk),
      input.nowUnixSeconds,
    ),
  );
}

export function resolveCredentialStatus(input: {
  status: CredentialStatus;
  resolverResponses: Record<string, string>;
  statusListJwk: PublicJwk;
}): CredentialStatusResolution {
  return parseNativeJson(
    native.resolveCredentialStatusRaw(
      stringify(input.status),
      stringify(input.resolverResponses),
      stringify(input.statusListJwk),
    ),
  );
}

export function resolveCredentialStatusAt(input: {
  status: CredentialStatus;
  resolverResponses: Record<string, string>;
  statusListJwk: PublicJwk;
  nowUnixSeconds: number;
}): CredentialStatusResolution {
  return parseNativeJson(
    native.resolveCredentialStatusAtRaw(
      stringify(input.status),
      stringify(input.resolverResponses),
      stringify(input.statusListJwk),
      input.nowUnixSeconds,
    ),
  );
}

export function verifyCredentialStatusActive(input: {
  status: CredentialStatus;
  resolverResponses: Record<string, string>;
  statusListJwk: PublicJwk;
}): void {
  unwrapNative(
    native.verifyCredentialStatusActiveRaw(
      stringify(input.status),
      stringify(input.resolverResponses),
      stringify(input.statusListJwk),
    ),
  );
}

export function verifyCredentialStatusActiveAt(input: {
  status: CredentialStatus;
  resolverResponses: Record<string, string>;
  statusListJwk: PublicJwk;
  nowUnixSeconds: number;
}): void {
  unwrapNative(
    native.verifyCredentialStatusActiveAtRaw(
      stringify(input.status),
      stringify(input.resolverResponses),
      stringify(input.statusListJwk),
      input.nowUnixSeconds,
    ),
  );
}

export function verifyAttachment(
  attachment: Uint8Array,
  expectedSha256B64url: string,
): void {
  unwrapNative(
    native.verifyAttachmentRaw(toBase64Url(attachment), expectedSha256B64url),
  );
}

export function uc3StudySpaceProfile(): DisclosureProfile {
  return {
    name: "uc3_study_space",
    claim_paths: [
      ["credentialSubject", "enrolled"],
      ["credentialSubject", "institution_id"],
    ],
  };
}

function parseNativeJson<T>(value: unknown): T {
  return JSON.parse(unwrapNative(value)) as T;
}

function unwrapNative(value: unknown): string {
  if (value instanceof Error) {
    throw value;
  }
  if (typeof value !== "string") {
    throw new Error(String(value));
  }
  if (value.startsWith("Error: ")) {
    throw new Error(value);
  }
  return value;
}

function stringify(value: unknown): string {
  return JSON.stringify(value);
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function verifyPartnerIdentityProof(input: {
  jwt: string; publicJwk: PublicJwk; options: {
    issuer: string; key_id: string; audience: string; nonce: string; now_unix_seconds: number;
  };
}): void {
  native.verifyPartnerIdentityProofRaw(input.jwt, stringify(input.publicJwk), stringify(input.options));
}

export function validateScalarDefinition(
  definition: ScalarCredentialDefinition,
): void {
  native.validateScalarDefinitionRaw(stringify(definition));
}
export function validateScalarSubject(input: {
  definition: ScalarCredentialDefinition;
  subject: Record<string, unknown>;
  mode: SubjectValidationMode;
}): void {
  native.validateScalarSubjectRaw(
    stringify(input.definition),
    stringify(input.subject),
    stringify(input.mode),
  );
}
export function signIssuerAuthorizations(input: {
  payload: IssuerAuthorizations;
  header: JwsHeader;
  keyId: string;
}): string {
  return unwrapNative(
    native.signIssuerAuthorizationsRaw(
      stringify(input.payload),
      stringify(input.header),
      input.keyId,
    ),
  );
}
export function verifyIssuerAuthorization(input: {
  compactJws: string;
  trustAnchorJwk: PublicJwk;
  request: IssuerAuthorizationRequest;
  nowUnixSeconds: number;
}): IssuerAuthorization {
  return parseNativeJson(
    native.verifyIssuerAuthorizationRaw(
      input.compactJws,
      stringify(input.trustAnchorJwk),
      stringify(input.request),
      input.nowUnixSeconds,
    ),
  );
}
export function verifyScalarCredentialAuthorization(input: {
  compactSdJwt: string;
  issuerJwk: PublicJwk;
  compactAuthorization: string;
  trustAnchorJwk: PublicJwk;
  registryDid: string;
  nowUnixSeconds: number;
  mode: SubjectValidationMode;
}): VerifiedSdJwtCredential {
  return parseNativeJson(
    native.verifyScalarCredentialAuthorizationRaw(
      input.compactSdJwt,
      stringify(input.issuerJwk),
      input.compactAuthorization,
      stringify(input.trustAnchorJwk),
      input.registryDid,
      input.nowUnixSeconds,
      stringify(input.mode),
    ),
  );
}

/** Authenticates a complete predecessor at signed iat under current exact authority.
 * Does not verify current status or confer presentation validity.
 */
export function verifyScalarRenewalPredecessor(input: {
  compactSdJwt: string;
  issuerJwk: PublicJwk;
  compactAuthorization: string;
  trustAnchorJwk: PublicJwk;
  registryDid: string;
  nowUnixSeconds: number;
}): VerifiedSdJwtCredential {
  return parseNativeJson(
    native.verifyScalarRenewalPredecessorRaw(
      input.compactSdJwt,
      stringify(input.issuerJwk),
      input.compactAuthorization,
      stringify(input.trustAnchorJwk),
      input.registryDid,
      input.nowUnixSeconds,
    ),
  );
}
