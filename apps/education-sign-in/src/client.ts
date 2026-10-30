import { randomBytes } from "node:crypto";

export type Profile = "education_sign_in" | "education_eligibility";
export type EducationConfig = {
  runtimeManagement: string;
  runtimeToken: string;
  issuer: string;
  verifierDid: string;
  institution: string;
};
export type Verification = Readonly<{
  id: string;
  profile: Profile;
  activation_uri: string;
  request_uri: string;
  expires_at: number;
}>;
export class Refusal extends Error {
  constructor(readonly code: string, readonly status = 400) {
    super(code);
  }
}
const paths = (profile: Profile) =>
  ["enrolled", "institution_id", ...(profile === "education_sign_in" ? ["student_id"] : [])]
    .map(field => ["credentialSubject", field]);
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Refusal("RESULT_INVALID");
  return value as Record<string, unknown>;
}

// Keep this client on the backend. Only the public request may reach the browser.
export function educationClient(config: EducationConfig, now = () => Date.now() / 1000) {
  config = { ...config };
  const management = new URL(config.runtimeManagement);
  if (management.protocol !== "http:" || management.hostname !== "127.0.0.1" ||
      management.origin !== config.runtimeManagement || !config.runtimeToken ||
      !config.issuer || !config.verifierDid || !config.institution) {
    throw Error("application configuration invalid");
  }
  const sessions = new WeakMap<Verification, {
    sessionId: string;
    capability: string;
    phase: "pending" | "consuming" | "consumed";
    assertCurrent: () => void;
  }>();
  async function runtime(path: string, value: unknown, capability?: string) {
    const response = await fetch(config.runtimeManagement + path, {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(5000),
      headers: {
        authorization: "Bearer " + config.runtimeToken,
        "content-type": "application/json",
        ...(capability ? { "x-session-capability": capability } : {}),
      },
      body: JSON.stringify(value),
    });
    let size = 0;
    const chunks: Uint8Array[] = [];
    if (!response.body) throw new Refusal("RUNTIME_UNAVAILABLE", 503);
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value: chunk } = await reader.read();
        if (done) break;
        size += chunk.length;
        if (size > 16384) throw new Refusal("RUNTIME_UNAVAILABLE", 503);
        chunks.push(chunk);
      }
    } finally {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    try {
      return { status: response.status, body: object(JSON.parse(Buffer.concat(chunks).toString("utf8"))) };
    } catch {
      throw new Refusal("RUNTIME_UNAVAILABLE", 503);
    }
  }
  function current(request: Verification) {
    if (now() >= request.expires_at + 120) throw new Refusal("INTERACTION_EXPIRED", 410);
  }
  function validate(result: Record<string, unknown>, request: Verification) {
    if (result.interaction_id !== request.id) throw new Refusal("RESULT_INVALID");
    if (result.status !== "verified") throw new Refusal("VERIFICATION_REFUSED", 403);
    const evidence = object(result.evidence), claims = object(result.claims);
    if (typeof evidence.expires_at !== "number" || !Number.isFinite(evidence.expires_at) || now() >= evidence.expires_at) {
      throw new Refusal("EVIDENCE_STALE", 410);
    }
    if (evidence.issuer_did !== config.issuer || evidence.verifier_did !== config.verifierDid ||
        evidence.credential_type !== "UniversityEducationCredential" || evidence.definition_id !== "urn:credworks:education" ||
        evidence.definition_version !== "1" || evidence.profile !== request.profile ||
        JSON.stringify(evidence.claim_paths) !== JSON.stringify(paths(request.profile)) ||
        Object.keys(claims).sort().join() !== paths(request.profile).map(path => path[1]).sort().join()) {
      throw new Refusal("RESULT_INVALID");
    }
    if (claims.enrolled !== true) throw new Refusal("ENROLMENT_REQUIRED", 403);
    if (claims.institution_id !== config.institution) throw new Refusal("INSTITUTION_NOT_ALLOWED", 403);
    if (request.profile === "education_sign_in" && (typeof claims.student_id !== "string" ||
        claims.student_id.length < 1 || claims.student_id.length > 128 || claims.student_id.trim() !== claims.student_id ||
        /[\x00-\x1f\x7f]/.test(claims.student_id))) throw new Refusal("STUDENT_ID_INVALID", 403);
    return { claims, deadline: evidence.expires_at };
  }
  return {
    async create(profile: Profile, assertCurrent: () => void): Promise<Verification> {
      if (!["education_sign_in", "education_eligibility"].includes(profile)) throw new Refusal("REQUEST_BAD_REQUEST");
      assertCurrent();
      const id = randomBytes(32).toString("base64url");
      let created;
      try {
        created = await runtime("/management/sessions", {
          profile, interaction_id: id,
          purpose: profile === "education_sign_in" ? "Sign in to this application with Education" : "Check eligibility without creating an account",
        });
      } catch { throw new Refusal("RUNTIME_UNAVAILABLE", 503); }
      assertCurrent();
      const value = created.body;
      if (created.status !== 201 || value.interaction_id !== id || typeof value.session_id !== "string" ||
          typeof value.correlation_capability !== "string" || typeof value.expires_at !== "number" ||
          !Number.isFinite(value.expires_at) || value.expires_at <= now() ||
          typeof value.activation_uri !== "string" || typeof value.request_uri !== "string") {
        throw new Refusal("RUNTIME_UNAVAILABLE", 503);
      }
      const request = Object.freeze({ id, profile, activation_uri: value.activation_uri, request_uri: value.request_uri, expires_at: value.expires_at });
      sessions.set(request, { sessionId: value.session_id, capability: value.correlation_capability, phase: "pending", assertCurrent });
      return request;
    },
    async consume<T>(request: Verification, apply: (claims: Readonly<Record<string, unknown>>) => T | Promise<T>): Promise<T> {
      const session = sessions.get(request);
      if (!session) throw new Refusal("INTERACTION_NOT_FOUND", 404);
      if (session.phase !== "pending") throw new Refusal("INTERACTION_CONSUMED", 409);
      try {
        current(request);
        session.assertCurrent();
      } catch (error) {
        session.phase = "consumed";
        throw error;
      }
      session.phase = "consuming";
      let outcome;
      try {
        outcome = await runtime("/management/sessions/" + encodeURIComponent(session.sessionId) + "/result", {}, session.capability);
      } catch {
        // No application effects have started. A lost/truncated reply can be read
        // again using the same runtime session and private capability.
        session.phase = "pending";
        throw new Refusal("RUNTIME_UNAVAILABLE", 503);
      }
      session.phase = "consumed";
      if (outcome.status >= 500) {
        session.phase = "pending";
        throw new Refusal("RUNTIME_UNAVAILABLE", 503);
      }
      if (outcome.status === 409 && object(outcome.body.error).code === "RESULT_PENDING") {
        session.phase = "pending";
        throw new Refusal("RESULT_PENDING", 409);
      }
      if (outcome.status !== 200) throw new Refusal("RESULT_UNAVAILABLE", 410);
      session.assertCurrent();
      current(request);
      const verified = validate(outcome.body, request);
      const result = await apply(Object.freeze(verified.claims));
      session.assertCurrent();
      current(request);
      if (now() >= verified.deadline) throw new Refusal("EVIDENCE_STALE", 410);
      return result;
    },
  };
}
