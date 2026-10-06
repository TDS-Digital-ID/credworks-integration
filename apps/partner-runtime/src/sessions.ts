import { declaredPath, subjectValue } from "./subject-paths.js";
import * as core from "@unsw-vc/identity-core-node";
import { timingSafeEqual } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { RuntimeIdentity } from "./runtime.js";
import {
  EDUCATION_PROFILES,
  EDUCATION_TYPE,
  EvidenceCache,
  VerificationError,
  type Profile,
  type DisclosureScope,
  type CredentialKey,
} from "./evidence-cache.js";

// Only stable Rust enum codes cross the protected result boundary; diagnostics never do.
const CORE_ERROR_CODES: ReadonlySet<string> = new Set<core.CoreErrorCode>([
  "INVALID_INPUT",
  "UNSUPPORTED_ALGORITHM",
  "INVALID_KEY",
  "INVALID_SIGNATURE",
  "MALFORMED_JWS",
  "JSON_SERIALIZATION",
  "KEY_NOT_FOUND",
  "SIGNING_FAILED",
  "VERIFICATION_FAILED",
  "CLOCK_UNAVAILABLE",
  "RESOLVER_UNAVAILABLE",
  "SALT_UNAVAILABLE",
  "TRUST_CHECK_FAILED",
  "STATUS_CHECK_FAILED",
  "STATUS_LIST_STALE",
  "BINDING_CHECK_FAILED",
  "FRESHNESS_CHECK_FAILED",
  "ATTACHMENT_CHECK_FAILED",
  "DISCLOSURE_DIGEST_MISMATCH",
  "MISSING_DISCLOSURE",
]);
function protectedFailureCode(error: unknown): string {
  if (error instanceof VerificationError) return error.code;
  const prefix =
    error instanceof Error ? /^([A-Z_]+):/.exec(error.message)?.[1] : undefined;
  return prefix && CORE_ERROR_CODES.has(prefix)
    ? prefix
    : "PRESENTATION_VERIFICATION_FAILED";
}

// The core has authenticated and validated this subject. Enforce only the exact
// permitted disclosure units, then preserve their types and object hierarchy.
function scalarResultClaims(
  subject: Record<string, unknown>,
  scope: DisclosureScope,
): Record<string, unknown> {
  if (!scope.definition)
    throw new VerificationError("SCOPE_NOT_PERMITTED", 403);
  const permitted = new Set(
    scope.claimPaths.map((path) => JSON.stringify(path)),
  );
  for (const claim of scope.definition.claims) {
    const path = declaredPath(claim);
    if (
      subjectValue(subject, path) !== undefined &&
      !permitted.has(JSON.stringify(path))
    ) {
      throw new VerificationError("CLAIM_PATHS_NOT_PERMITTED");
    }
  }
  const result: Record<string, unknown> = {};
  // Scope order preserves the existing scalar protected-result serialization.
  for (const path of scope.claimPaths) {
    const value = subjectValue(subject, path);
    if (value === undefined)
      throw new VerificationError("CLAIM_PATHS_NOT_PERMITTED");
    let container = result;
    for (const name of path.slice(1, -1)) {
      if (!Object.hasOwn(container, name)) container[name] = {};
      container = container[name] as Record<string, unknown>;
    }
    container[path.at(-1)!] = value;
  }
  return result;
}

const SESSION_SECONDS = 120;
const RETENTION_SECONDS = 120;
const MAX_SESSIONS = 100;
// Authenticated verification metadata only. No credential, presentation or claims.
export type HolderBinding = {
  interactionId: string;
  configurationId?: string;
  profile: string;
  scope: Pick<
    DisclosureScope,
    "definitionId" | "definitionVersion" | "credentialType" | "claimPaths"
  >;
  issuerDid: string;
  issuerKeyId?: string;
  issuerThumbprint: string;
  verifierDid: string;
  verifierThumbprint: string;
  holderThumbprint: string;
  expiresAt: number;
  credentialStatus: core.CredentialStatus;
};
type Session = {
  id: string;
  publicCapability: string;
  correlationHash: string;
  interactionId: string;
  profile: Profile;
  configurationId?: string;
  issuerKeyId?: string;
  selectedKey?: CredentialKey;
  scope: DisclosureScope;
  nonce: string;
  state: string;
  expiresAt: number;
  retireAt: number;
  request: string;
  phase: "pending" | "verifying" | "complete" | "linking" | "consumed";
  linkedInput?: unknown;
  result?: Record<string, unknown>;
  evidenceExpiresAt?: number;
  credentialStatus?: core.CredentialStatus;
};
export class Sessions {
  private readonly sessions = new Map<string, Session>();
  constructor(
    private readonly origin: string,
    private readonly identity: RuntimeIdentity,
    readonly cache: EvidenceCache,
    private readonly now: () => number,
  ) {}
  private prune() {
    for (const [id, session] of this.sessions)
      if (this.now() >= session.retireAt) this.sessions.delete(id);
  }
  create(value: unknown) {
    const input = value as {
      profile: Profile;
      interaction_id: string;
      purpose: string;
      configuration_id?: string;
    };
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).sort().join() !==
        (this.cache.config.scalar
          ? "configuration_id,interaction_id,profile,purpose"
          : "interaction_id,profile,purpose") ||
      typeof input.profile !== "string" ||
      (this.cache.config.scalar
        ? typeof input.configuration_id !== "string" ||
          !/^[A-Za-z0-9_-]{1,64}$/.test(input.configuration_id)
        : !Object.hasOwn(EDUCATION_PROFILES, input.profile)) ||
      typeof input.interaction_id !== "string" ||
      input.interaction_id.length < 1 ||
      input.interaction_id.length > 128 ||
      typeof input.purpose !== "string" ||
      input.purpose.length < 1 ||
      input.purpose.length > 200
    )
      throw new VerificationError("SESSION_BAD_REQUEST");
    this.prune();
    if (this.sessions.size >= MAX_SESSIONS)
      throw new VerificationError("SESSION_CAPACITY", 429);
    const scope = this.cache.permit(input.profile, input.configuration_id);
    const id = core.randomUrlSafe(32),
      publicCapability = core.randomUrlSafe(32),
      correlation = core.randomUrlSafe(32);
    const nonce = core.randomUrlSafe(32),
      state = core.randomUrlSafe(32),
      iat = this.now(),
      exp = scope.credentialKeys && !(scope.credentialKeys.length === 1 && scope.credentialKeys[0]!.keyId === this.cache.config.scalar?.issuerKeyId)
        ? Math.min(iat + SESSION_SECONDS, this.cache.current().freshUntil) : iat + SESSION_SECONDS;
    const clientId = "decentralized_identifier:" + this.identity.did;
    const request = core.signCompactJwsJson({
      keyId: this.identity.keyId,
      header: {
        alg: "ES256",
        typ: "oauth-authz-req+jwt",
        kid: this.identity.keyId,
      },
      payload: {
        client_id: clientId,
        response_type: "vp_token",
        response_mode: "direct_post",
        response_uri: this.origin + "/oid4vp/response/" + publicCapability,
        nonce,
        state,
        iat,
        exp,
        aud: "https://self-issued.me/v2",
        purpose: input.purpose,
        ...(this.cache.config.scalar
          ? {
              credworks_scalar: {
                credential_issuer_did: this.cache.config.issuerDid,
                ...(scope.credentialKeys!.length === 1 && scope.credentialKeys![0]!.keyId === this.cache.config.scalar.issuerKeyId
                  ? { credential_issuer_key_id: this.cache.config.scalar.issuerKeyId }
                  : { credential_issuer_keys: scope.credentialKeys!.map((key) => ({ key_id: key.keyId, public_jwk_sha256_thumbprint: key.thumbprint })) }),
                definition_id: scope.definitionId,
                definition_version: scope.definitionVersion,
                authorization_path: scope.authorizationPath,
                permission_path: scope.permissionPath,
                profile_name: input.profile,
              },
            }
          : {}),
        dcql_query: {
          credentials: [
            {
              id: input.profile,
              format: "vc+sd-jwt",
              meta: {
                type_values: [
                  [
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                    scope.credentialType,
                  ],
                ],
              },
              claims: scope.claimPaths.map((path) => ({
                path,
              })),
            },
          ],
        },
      },
    });
    this.sessions.set(id, {
      id,
      publicCapability,
      correlationHash: core.sha256B64Url(correlation),
      interactionId: input.interaction_id,
      profile: input.profile,
      configurationId: input.configuration_id,
      issuerKeyId: input.configuration_id
        ? this.cache.config.scalar?.issuerKeyId
        : undefined,
      scope,
      nonce,
      state,
      expiresAt: exp,
      retireAt: exp + RETENTION_SECONDS,
      request,
      phase: "pending",
      ...(this.cache.config.scalar
        ? { evidenceExpiresAt: Math.min(exp, this.cache.current().freshUntil) }
        : {}),
    });
    const requestUri = this.origin + "/oid4vp/request/" + publicCapability;
    return {
      session_id: id,
      interaction_id: input.interaction_id,
      correlation_capability: correlation,
      request_uri: requestUri,
      activation_uri:
        "openid4vp://authorize?" +
        new URLSearchParams({ client_id: clientId, request_uri: requestUri }),
      expires_at: exp,
    };
  }
  private publicSession(capability: string) {
    this.prune();
    const session = [...this.sessions.values()].find(
      (session) => session.publicCapability === capability,
    );
    if (!session) throw new VerificationError("SESSION_NOT_FOUND", 404);
    if (this.now() >= session.expiresAt)
      throw new VerificationError("SESSION_EXPIRED", 410);
    return session;
  }
  request(capability: string) {
    const session = this.publicSession(capability);
    this.authorize(session);
    return session.request;
  }
  private authorize(session: Session) {
    if (
      this.cache.config.scalar &&
      (session.evidenceExpiresAt === undefined ||
        this.now() >= session.evidenceExpiresAt)
    )
      throw new VerificationError("EVIDENCE_STALE", 503);
    const current = this.cache.permit(session.profile, session.configurationId);
    if (
      JSON.stringify(current.claimPaths) !==
      JSON.stringify(session.scope.claimPaths)
    )
      throw new VerificationError("SCOPE_NOT_PERMITTED", 403);
    if (session.selectedKey && !current.credentialKeys?.some((key) =>
      key.keyId === session.selectedKey!.keyId && key.thumbprint === session.selectedKey!.thumbprint))
      throw new VerificationError("ISSUER_NOT_AUTHORIZED", 403);
    return current;
  }
  private protectedSession(id: string, capability: unknown) {
    this.prune();
    const session = this.sessions.get(id);
    const hash = Buffer.from(
      core.sha256B64Url(typeof capability === "string" ? capability : ""),
    );
    if (
      !session ||
      !timingSafeEqual(Buffer.from(session.correlationHash), hash)
    )
      throw new VerificationError("SESSION_ACCESS_DENIED", 401);
    return session;
  }
  status(id: string, capability: unknown) {
    const session = this.protectedSession(id, capability);
    return {
      session_id: id,
      interaction_id: session.interactionId,
      status:
        this.now() >= session.expiresAt && session.phase === "pending"
          ? "expired"
          : session.phase,
      expires_at: session.expiresAt,
    };
  }
  consume(id: string, capability: unknown) {
    const session = this.protectedSession(id, capability);
    if (session.phase === "linking")
      throw new VerificationError("RESULT_LINKED", 409);
    if (session.phase === "consumed")
      throw new VerificationError("RESULT_CONSUMED", 409);
    if (session.phase !== "complete")
      throw new VerificationError(
        this.now() >= session.expiresAt ? "SESSION_EXPIRED" : "RESULT_PENDING",
        this.now() >= session.expiresAt ? 410 : 409,
      );
    let result = session.result;
    if (result?.status === "verified") {
      try {
        if (
          session.evidenceExpiresAt === undefined ||
          this.now() >= session.evidenceExpiresAt
        )
          throw new VerificationError("EVIDENCE_STALE", 503);
        this.authorize(session);
        this.cache.status(session.credentialStatus!, session.selectedKey);
        if (this.now() >= session.evidenceExpiresAt)
          throw new VerificationError("EVIDENCE_STALE", 503);
      } catch (error) {
        result = {
          status: "refused",
          interaction_id: session.interactionId,
          error: { code: protectedFailureCode(error) },
        };
      }
    }
    session.phase = "consumed";
    session.result = undefined;
    session.credentialStatus = undefined;
    return result;
  }
  validateBinding(binding: HolderBinding) {
    if (this.now() >= binding.expiresAt)
      throw new VerificationError("EVIDENCE_STALE", 503);
    const scope = this.cache.permit(binding.profile, binding.configurationId);
    if (
      binding.issuerDid !== this.cache.config.issuerDid ||
      (binding.configurationId
        ? !scope.credentialKeys?.some((key) => key.keyId === binding.issuerKeyId && key.thumbprint === binding.issuerThumbprint)
        : binding.issuerKeyId !== undefined || binding.issuerThumbprint !== core.publicJwkSha256Thumbprint(this.cache.config.issuerJwk)) ||
      binding.verifierDid !== this.identity.did ||
      binding.verifierThumbprint !==
        core.publicJwkSha256Thumbprint(this.identity.publicJwk) ||
      !isDeepStrictEqual(binding.scope, {
        definitionId: scope.definitionId,
        definitionVersion: scope.definitionVersion,
        credentialType: scope.credentialType,
        claimPaths: scope.claimPaths,
      })
    )
      throw new VerificationError("ISSUER_BINDING_MISMATCH", 403);
    try {
      this.cache.status(binding.credentialStatus, binding.issuerKeyId ? { keyId: binding.issuerKeyId, thumbprint: binding.issuerThumbprint } : undefined);
      if (this.now() >= binding.expiresAt)
        throw new VerificationError("EVIDENCE_STALE", 503);
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      throw new VerificationError(protectedFailureCode(error), 403);
    }
  }
  link(
    id: string,
    capability: unknown,
    interaction: string,
    input: unknown,
  ): HolderBinding {
    const session = this.protectedSession(id, capability);
    if (session.interactionId !== interaction)
      throw new VerificationError("ISSUER_BINDING_MISMATCH", 403);
    if (session.phase === "consumed")
      throw new VerificationError("RESULT_CONSUMED", 409);
    if (session.phase !== "complete" && session.phase !== "linking")
      throw new VerificationError("RESULT_PENDING", 409);
    if (
      session.result?.status !== "verified" ||
      !session.credentialStatus ||
      session.evidenceExpiresAt === undefined
    )
      throw new VerificationError("VERIFICATION_NOT_PERMITTED", 403);
    if (
      session.phase === "linking" &&
      !isDeepStrictEqual(session.linkedInput, input)
    )
      throw new VerificationError("ISSUER_BINDING_MISMATCH", 409);
    const evidence = session.result.evidence as Record<string, unknown>;
    const binding: HolderBinding = {
      interactionId: session.interactionId,
      ...(session.configurationId === undefined
        ? {}
        : { configurationId: session.configurationId }),
      ...(session.issuerKeyId === undefined
        ? {}
        : { issuerKeyId: session.issuerKeyId }),
      profile: session.profile,
      scope: {
        definitionId: session.scope.definitionId,
        definitionVersion: session.scope.definitionVersion,
        credentialType: session.scope.credentialType,
        claimPaths: session.scope.claimPaths,
      },
      issuerDid: evidence.issuer_did as string,
      issuerThumbprint: evidence.issuer_public_jwk_sha256_thumbprint as string,
      verifierDid: evidence.verifier_did as string,
      verifierThumbprint:
        evidence.verifier_public_jwk_sha256_thumbprint as string,
      holderThumbprint: evidence.holder_public_jwk_sha256_thumbprint as string,
      expiresAt: Math.min(session.expiresAt, session.evidenceExpiresAt),
      credentialStatus: session.credentialStatus,
    };
    this.validateBinding(binding);
    // Once claimed, only an identical link may retry. A failed/unknown DB commit
    // never restores ordinary result consumption or authorizes different inputs.
    session.phase = "linking";
    session.linkedInput = structuredClone(input);
    return structuredClone(binding);
  }
  linked(id: string, capability: unknown) {
    const session = this.sessions.get(id);
    if (!session || session.phase !== "linking") return;
    this.protectedSession(id, capability);
    session.phase = "consumed";
    session.result = undefined;
    session.credentialStatus = undefined;
    session.linkedInput = undefined;
  }
  async complete(capability: string, form: URLSearchParams) {
    const session = this.publicSession(capability);
    if (session.phase !== "pending")
      throw new VerificationError("SESSION_ALREADY_COMPLETED", 409);
    if (
      [...form.keys()].sort().join() !== "state,vp_token" ||
      form.get("state") !== session.state
    )
      throw new VerificationError("RESPONSE_STATE_MISMATCH");
    let presentation: string;
    try {
      const value = JSON.parse(form.get("vp_token")!);
      if (
        !value ||
        Object.keys(value).length !== 1 ||
        !Array.isArray(value[session.profile]) ||
        value[session.profile].length !== 1 ||
        typeof value[session.profile][0] !== "string"
      )
        throw Error();
      presentation = value[session.profile][0];
    } catch {
      throw new VerificationError("RESPONSE_BAD_REQUEST");
    }
    session.phase = "verifying"; // Claim completion before any asynchronous verification can begin.
    try {
      await Promise.resolve();
      let scope = this.authorize(session);
      let issuerJwk = this.cache.config.issuerJwk;
      const options = {
        audience: "decentralized_identifier:" + this.identity.did,
        nonce: session.nonce,
        now_unix_seconds: this.now(),
        max_kb_age_seconds: SESSION_SECONDS,
        required_claims: scope.claimPaths,
        expected_typ: "vc+sd-jwt",
      };
      let verified: core.VerifiedSdJwtPresentation | undefined;
      if (this.cache.config.scalar) {
        const keys = session.scope.credentialKeys!;
        let kid: unknown;
        if (keys.length === 1 && keys[0]!.keyId === this.cache.config.scalar.issuerKeyId) {
          // Keep legacy signature/refusal behavior, then enforce exact frozen kid.
          verified = core.verifySdJwtPresentation({ presentation, issuerJwk, options });
          kid = verified.issuer_header.kid;
        } else {
          // Untrusted header is a bounded hint; core verification establishes authority.
          const encoded = presentation.split(".", 1)[0]!;
          if (encoded.length > 8192) throw new VerificationError("ISSUER_NOT_AUTHORIZED", 403);
          kid = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")).kid;
        }
        const selected = keys.find((key) => key.keyId === kid);
        if (!selected) throw new VerificationError("ISSUER_NOT_AUTHORIZED", 403);
        session.selectedKey = selected;
        session.issuerKeyId = selected.keyId;
        scope = this.authorize(session);
        issuerJwk = selected.publicJwk;
      }
      verified ??= core.verifySdJwtPresentation({ presentation, issuerJwk, options });
      const payload = verified.processed_payload as Record<string, unknown>;
      if (
        payload.iss !== this.cache.config.issuerDid ||
        payload.issuer !== this.cache.config.issuerDid
      )
        throw new VerificationError("ISSUER_NOT_ACCEPTED");
      if (
        !Array.isArray(payload.type) ||
        payload.type.length !== 2 ||
        !payload.type.includes("VerifiableCredential") ||
        !payload.type.includes(scope.credentialType)
      )
        throw new VerificationError("TYPE_NOT_ACCEPTED");
      if (this.cache.config.scalar) {
        const reference = payload.credentialDefinition as
          | { id?: unknown; version?: unknown }
          | undefined;
        if (
          !reference ||
          reference.id !== scope.definitionId ||
          reference.version !== scope.definitionVersion
        )
          throw new VerificationError("DEFINITION_NOT_ACCEPTED");
        // Holder binding and sd_hash were already verified above by the same core.
        // Its scalar API takes credential framing, without the trailing KB-JWT.
        core.verifyScalarCredentialAuthorization({
          compactSdJwt: presentation.slice(
            0,
            presentation.lastIndexOf("~") + 1,
          ),
          issuerJwk,
          compactAuthorization: scope.compactAuthorization!,
          trustAnchorJwk: this.cache.config.trustAnchorJwk,
          registryDid: this.cache.config.scalar.registryDid,
          nowUnixSeconds: this.now(),
          mode: "disclosed",
        });
      }
      const allowedMetadata = [
        "@context",
        "id",
        "type",
        "iss",
        "issuer",
        "iat",
        "nbf",
        "exp",
        "validFrom",
        "validUntil",
        "cnf",
        "credentialStatus",
        "credentialSubject",
        "_sd",
        "_sd_alg",
        ...(this.cache.config.scalar ? ["credentialDefinition"] : []),
      ];
      if (Object.keys(payload).some((key) => !allowedMetadata.includes(key)))
        throw new VerificationError("CLAIM_PATHS_NOT_PERMITTED");
      const subject = payload.credentialSubject as Record<string, unknown>;
      const fields = scope.claimPaths.map((path) => path[1]!);
      if (
        !subject ||
        typeof subject !== "object" ||
        Array.isArray(subject) ||
        (!this.cache.config.scalar &&
          Object.keys(subject).some(
            (key) => key !== "_sd" && !fields.includes(key),
          ))
      )
        throw new VerificationError("CLAIM_PATHS_NOT_PERMITTED");
      if (
        !this.cache.config.scalar &&
        (typeof subject.enrolled !== "boolean" ||
          typeof subject.institution_id !== "string" ||
          subject.institution_id.length < 1 ||
          subject.institution_id.length > 256 ||
          (session.profile === "education_sign_in" &&
            (typeof subject.student_id !== "string" ||
              subject.student_id.length < 1 ||
              subject.student_id.length > 256)))
      )
        throw new VerificationError("CLAIM_VALUE_INVALID");
      this.cache.status(payload.credentialStatus as core.CredentialStatus, session.selectedKey);
      if (this.now() >= session.expiresAt)
        throw new VerificationError("SESSION_EXPIRED", 410);
      // The core authenticated NumericDate already preserves finite fractional values.
      session.evidenceExpiresAt = Math.min(
        session.evidenceExpiresAt ?? Infinity,
        this.cache.current().freshUntil,
        typeof payload.exp === "number" ? payload.exp : Infinity,
        typeof payload.validUntil === "string"
          ? Date.parse(payload.validUntil) / 1000
          : Infinity,
      );
      if (this.now() >= session.evidenceExpiresAt)
        throw new VerificationError("EVIDENCE_STALE", 503);
      session.credentialStatus =
        payload.credentialStatus as core.CredentialStatus;
      const claims = this.cache.config.scalar
        ? scalarResultClaims(subject, scope)
        : Object.fromEntries(fields.map((field) => [field, subject[field]]));
      session.result = {
        status: "verified",
        interaction_id: session.interactionId,
        claims,
        evidence: {
          issuer_did: this.cache.config.issuerDid,
          credential_type: scope.credentialType,
          definition_id: scope.definitionId,
          definition_version: scope.definitionVersion,
          profile: session.profile,
          claim_paths: scope.claimPaths,
          verifier_did: this.identity.did,
          verifier_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(
            this.identity.publicJwk,
          ),
          issuer_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(
            issuerJwk,
          ),
          holder_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(
            (payload.cnf as { jwk: core.PublicJwk }).jwk,
          ),
          verified_at: this.now(),
          expires_at: session.evidenceExpiresAt,
        },
      };
    } catch (error) {
      session.result = {
        status: "refused",
        interaction_id: session.interactionId,
        error: {
          code: protectedFailureCode(error),
        },
      };
    }
    session.phase = "complete";
    return { status: "accepted" };
  }
}
