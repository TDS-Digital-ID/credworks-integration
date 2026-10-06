import * as core from "@unsw-vc/identity-core-node";
import { timingSafeEqual } from "node:crypto";
import type { RuntimeIdentity } from "./runtime.js";
import {
  EDUCATION_PROFILES,
  EDUCATION_TYPE,
  EvidenceCache,
  VerificationError,
  type Profile,
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

const SESSION_SECONDS = 120;
const RETENTION_SECONDS = 120;
const MAX_SESSIONS = 100;
type Session = {
  id: string;
  publicCapability: string;
  correlationHash: string;
  interactionId: string;
  profile: Profile;
  nonce: string;
  state: string;
  expiresAt: number;
  retireAt: number;
  request: string;
  phase: "pending" | "verifying" | "complete" | "consumed";
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
    };
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).sort().join() !== "interaction_id,profile,purpose" ||
      !Object.hasOwn(EDUCATION_PROFILES, input.profile) ||
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
    this.cache.permit(input.profile);
    const id = core.randomUrlSafe(32),
      publicCapability = core.randomUrlSafe(32),
      correlation = core.randomUrlSafe(32);
    const nonce = core.randomUrlSafe(32),
      state = core.randomUrlSafe(32),
      iat = this.now(),
      exp = iat + SESSION_SECONDS;
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
        dcql_query: {
          credentials: [
            {
              id: input.profile,
              format: "vc+sd-jwt",
              meta: {
                type_values: [
                  [
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                    EDUCATION_TYPE,
                  ],
                ],
              },
              claims: EDUCATION_PROFILES[input.profile].map((path) => ({
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
      nonce,
      state,
      expiresAt: exp,
      retireAt: exp + RETENTION_SECONDS,
      request,
      phase: "pending",
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
    this.cache.permit(session.profile);
    return session.request;
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
        this.cache.permit(session.profile);
        this.cache.status(session.credentialStatus!);
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
      this.cache.permit(session.profile);
      const verified = core.verifySdJwtPresentation({
        presentation,
        issuerJwk: this.cache.config.issuerJwk,
        options: {
          audience: "decentralized_identifier:" + this.identity.did,
          nonce: session.nonce,
          now_unix_seconds: this.now(),
          max_kb_age_seconds: SESSION_SECONDS,
          required_claims: EDUCATION_PROFILES[session.profile],
          expected_typ: "vc+sd-jwt",
        },
      });
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
        !payload.type.includes(EDUCATION_TYPE)
      )
        throw new VerificationError("TYPE_NOT_ACCEPTED");
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
      ];
      if (Object.keys(payload).some((key) => !allowedMetadata.includes(key)))
        throw new VerificationError("CLAIM_PATHS_NOT_PERMITTED");
      const subject = payload.credentialSubject as Record<string, unknown>;
      const fields = EDUCATION_PROFILES[session.profile].map(
        (path) => path[1]!,
      );
      if (
        !subject ||
        typeof subject !== "object" ||
        Array.isArray(subject) ||
        Object.keys(subject).some(
          (key) => key !== "_sd" && !fields.includes(key),
        )
      )
        throw new VerificationError("CLAIM_PATHS_NOT_PERMITTED");
      if (
        typeof subject.enrolled !== "boolean" ||
        typeof subject.institution_id !== "string" ||
        subject.institution_id.length < 1 ||
        subject.institution_id.length > 256 ||
        (session.profile === "education_sign_in" &&
          (typeof subject.student_id !== "string" ||
            subject.student_id.length < 1 ||
            subject.student_id.length > 256))
      )
        throw new VerificationError("CLAIM_VALUE_INVALID");
      this.cache.status(payload.credentialStatus as core.CredentialStatus);
      if (this.now() >= session.expiresAt)
        throw new VerificationError("SESSION_EXPIRED", 410);
      // The core authenticated NumericDate already preserves finite fractional values.
      session.evidenceExpiresAt = Math.min(
        this.cache.current().freshUntil,
        typeof payload.exp === "number" ? payload.exp : Infinity,
      );
      session.credentialStatus =
        payload.credentialStatus as core.CredentialStatus;
      const claims = Object.fromEntries(
        fields.map((field) => [field, subject[field]]),
      );
      session.result = {
        status: "verified",
        interaction_id: session.interactionId,
        claims,
        evidence: {
          issuer_did: this.cache.config.issuerDid,
          credential_type: EDUCATION_TYPE,
          definition_id: "urn:credworks:education",
          definition_version: "1",
          profile: session.profile,
          claim_paths: EDUCATION_PROFILES[session.profile],
          verifier_did: this.identity.did,
          verifier_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(
            this.identity.publicJwk,
          ),
          issuer_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(
            this.cache.config.issuerJwk,
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
