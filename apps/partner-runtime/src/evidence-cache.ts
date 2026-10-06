import * as core from "@unsw-vc/identity-core-node";
import type { PublicJwk, CredentialStatus } from "@unsw-vc/identity-core-node";
import type { RuntimeIdentity } from "./runtime.js";
export const EDUCATION_TYPE = "UniversityEducationCredential";
export const EDUCATION_PROFILES = {
  education_eligibility: [
    ["credentialSubject", "enrolled"],
    ["credentialSubject", "institution_id"],
  ],
  education_sign_in: [
    ["credentialSubject", "enrolled"],
    ["credentialSubject", "institution_id"],
    ["credentialSubject", "student_id"],
  ],
};
export type Profile = keyof typeof EDUCATION_PROFILES;
export class VerificationError extends Error {
  constructor(
    readonly code: string,
    readonly status = 400,
  ) {
    super(code);
  }
}
export type VerifierConfig = {
  issuerDid: string;
  issuerJwk: PublicJwk;
  registryOrigin: string;
  trustAnchorJwk: PublicJwk;
  statusSources: {
    url: string;
    publicJwk: PublicJwk;
    purpose: "revocation" | "suspension";
  }[];
  maxCacheAgeSeconds: number;
};
function httpsUrl(value: unknown): URL {
  if (typeof value !== "string" || value.length > 2048)
    throw Error("invalid verifier configuration");
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.hash)
    throw Error("invalid verifier configuration");
  return url;
}
function publicKey(value: unknown): value is PublicJwk {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const key = value as PublicJwk;
  return (
    Object.keys(key).every((field) =>
      ["kty", "crv", "x", "y", "kid"].includes(field),
    ) &&
    key.kty === "EC" &&
    key.crv === "P-256" &&
    typeof key.x === "string" &&
    typeof key.y === "string"
  );
}
export function validateVerifierConfig(value: unknown): VerifierConfig {
  const config = value as VerifierConfig;
  if (
    !config ||
    typeof config !== "object" ||
    Object.keys(config).sort().join() !==
      "issuerDid,issuerJwk,maxCacheAgeSeconds,registryOrigin,statusSources,trustAnchorJwk" ||
    typeof config.issuerDid !== "string" ||
    !publicKey(config.issuerJwk) ||
    !publicKey(config.trustAnchorJwk) ||
    !Number.isInteger(config.maxCacheAgeSeconds) ||
    config.maxCacheAgeSeconds < 1 ||
    config.maxCacheAgeSeconds > 300 ||
    !Array.isArray(config.statusSources) ||
    config.statusSources.length < 1 ||
    config.statusSources.length > 4
  )
    throw Error("invalid verifier configuration");
  httpsUrl(core.didWebToHttpsUrl(config.issuerDid));
  if (httpsUrl(config.registryOrigin).origin !== config.registryOrigin)
    throw Error("invalid registry origin");
  const seen = new Set<string>();
  for (const source of config.statusSources) {
    if (
      !source ||
      Object.keys(source).sort().join() !== "publicJwk,purpose,url" ||
      !publicKey(source.publicJwk) ||
      !["revocation", "suspension"].includes(source.purpose) ||
      seen.has(source.url)
    )
      throw Error("invalid status configuration");
    httpsUrl(source.url);
    seen.add(source.url);
  }
  return config;
}
export type EvidenceFetcher = (url: string) => Promise<string>;
export const fetchEvidence: EvidenceFetcher = async (url) => {
  const signal = AbortSignal.timeout(5000);
  const response = await fetch(url, {
    redirect: "error",
    signal,
    headers: { accept: "application/jwt" },
  });
  if (response.status !== 200 || !response.body)
    throw Error("evidence unavailable");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 262144) throw Error("evidence too large");
      chunks.push(value);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.concat(chunks),
    );
  } finally {
    void reader.cancel().catch(() => {});
  }
};
type Snapshot = {
  trust: string;
  permissions: string;
  statuses: Map<string, string>;
  freshUntil: number;
};
export class EvidenceCache {
  private snapshot?: Snapshot;
  private refreshPending?: Promise<void>;
  readonly permissionsUrl: string;
  constructor(
    readonly config: VerifierConfig,
    readonly identity: RuntimeIdentity,
    private readonly now: () => number,
    private readonly fetcher: EvidenceFetcher = fetchEvidence,
  ) {
    validateVerifierConfig(config);
    this.permissionsUrl =
      config.registryOrigin +
      "/scoped-verifier-permissions.jwt?verifier_did=" +
      encodeURIComponent(identity.did);
  }
  refresh(): Promise<void> {
    return (this.refreshPending ??= this.load().finally(() => {
      this.refreshPending = undefined;
    }));
  }
  private async load() {
    try {
      const trustUrl = this.config.registryOrigin + "/trust-list.jwt";
      const urls = [
        trustUrl,
        this.permissionsUrl,
        ...this.config.statusSources.map((source) => source.url),
      ];
      const bytes = await Promise.all(urls.map((url) => this.fetcher(url)));
      if (
        bytes.some(
          (value) =>
            typeof value !== "string" || Buffer.byteLength(value) > 262144,
        ) ||
        Buffer.byteLength(bytes[1]!) > 16384
      )
        throw Error();
      const now = this.now();
      const [_, trust] = core.verifyTrustList({
        compactJws: bytes[0]!,
        trustAnchorJwk: this.config.trustAnchorJwk,
      });
      const trustDid = core.didWebFromHost(
        new URL(this.config.registryOrigin).host,
      );
      if (trust.issuer !== trustDid || trust.id !== trustUrl) throw Error();
      core.verifyTrustListAccreditation({
        compactJws: bytes[0]!,
        trustAnchorJwk: this.config.trustAnchorJwk,
        issuerDid: this.config.issuerDid,
        credentialType: EDUCATION_TYPE,
        issuerJwk: this.config.issuerJwk,
        nowUnixSeconds: now,
      });
      const verified = core.verifyCompactJwsJson({
        compactJws: bytes[1]!,
        publicJwk: this.config.trustAnchorJwk,
      });
      const permissions = verified.payload as {
        version: number;
        issuer: string;
        id: string;
        iat: number;
        exp: number;
        permissions: unknown[];
      };
      if (permissions.version !== 1)
        throw new VerificationError("PERMISSION_VERSION_UNSUPPORTED", 503);
      if (
        verified.header.typ !== "scoped-verifier-permissions+jwt" ||
        permissions.issuer !== trustDid ||
        permissions.id !== this.permissionsUrl ||
        !Array.isArray(permissions.permissions) ||
        permissions.permissions.length > 2 ||
        !Number.isSafeInteger(permissions.iat) ||
        !Number.isSafeInteger(permissions.exp) ||
        permissions.iat > now ||
        permissions.exp <= now ||
        permissions.exp - permissions.iat > 300
      )
        throw Error();
      const expiries = [trust.exp, permissions.exp];
      const statuses = new Map<string, string>();
      for (let i = 0; i < this.config.statusSources.length; i++) {
        const source = this.config.statusSources[i]!;
        const compact = bytes[i + 2]!;
        const [__, status] = core.verifyBitstringStatusListCredentialAt({
          compactJws: compact,
          statusListJwk: source.publicJwk,
          nowUnixSeconds: now,
        });
        if (
          status.issuer !== this.config.issuerDid ||
          status.credentialSubject.id !== source.url + "#list" ||
          status.credentialSubject.statusPurpose !== source.purpose ||
          !status.validUntil
        )
          throw Error();
        const expiry = Date.parse(status.validUntil) / 1000;
        if (!Number.isFinite(expiry)) throw Error();
        expiries.push(expiry);
        statuses.set(source.url, compact);
      }
      this.snapshot = {
        trust: bytes[0]!,
        permissions: bytes[1]!,
        statuses,
        freshUntil: Math.min(now + this.config.maxCacheAgeSeconds, ...expiries),
      };
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      throw new VerificationError("EVIDENCE_REFRESH_FAILED", 503);
    }
  }
  current(): Snapshot {
    if (!this.snapshot)
      throw new VerificationError("EVIDENCE_UNAVAILABLE", 503);
    if (this.now() >= this.snapshot.freshUntil)
      throw new VerificationError("EVIDENCE_STALE", 503);
    return this.snapshot;
  }
  permit(profile: Profile) {
    const snapshot = this.current();
    try {
      core.verifyScopedVerifierPermission({
        compactJws: snapshot.permissions,
        trustAnchorJwk: this.config.trustAnchorJwk,
        request: {
          credential_issuer_did: this.config.issuerDid,
          definition_id: "urn:credworks:education",
          definition_version: "1",
          credential_type: EDUCATION_TYPE,
          verifier_did: this.identity.did,
          verifier_origin: new URL(core.didWebToHttpsUrl(this.identity.did))
            .origin,
          verifier_public_jwk: this.identity.publicJwk,
          profile_name: profile,
          claim_paths: EDUCATION_PROFILES[profile],
        },
        nowUnixSeconds: this.now(),
      });
    } catch {
      throw new VerificationError("SCOPE_NOT_PERMITTED", 403);
    }
  }
  status(status: CredentialStatus) {
    const snapshot = this.current();
    const source = this.config.statusSources.find(
      (source) =>
        source.url === status.statusListCredential &&
        source.purpose === status.statusPurpose,
    );
    if (!source)
      throw new VerificationError("STATUS_DESTINATION_UNAUTHORIZED", 400);
    core.verifyCredentialStatusActiveAt({
      status,
      resolverResponses: { [source.url]: snapshot.statuses.get(source.url)! },
      statusListJwk: source.publicJwk,
      nowUnixSeconds: this.now(),
    });
  }
}
