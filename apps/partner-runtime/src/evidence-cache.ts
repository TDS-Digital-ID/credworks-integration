import * as core from "@unsw-vc/identity-core-node";
import type { PublicJwk, CredentialStatus } from "@unsw-vc/identity-core-node";
import type { RuntimeIdentity } from "./runtime.js";
import { RevocationProofs, statusSourceKeyId } from "./revocation-proofs.js";
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
export type Profile = string;
export type ScalarDefinitionPolicy = {
  configurationId: string;
  authorizationId: string;
  definitionId: string;
  definitionVersion: string;
  credentialType: string;
  profiles: { name: string; permissionId: string }[];
};
export type CredentialKey = {
  keyId: string;
  publicJwk: PublicJwk;
  thumbprint: string;
  definition: core.ScalarCredentialDefinition;
};
export type CredentialPin = Pick<CredentialKey, "keyId" | "thumbprint">;
export type DisclosureScope = {
  definitionId: string;
  definitionVersion: string;
  credentialType: string;
  claimPaths: string[][];
  authorizationPath?: string;
  permissionPath?: string;
  compactAuthorization?: string;
  // Complete definition from the same already-authenticated exact issuer grant.
  definition?: core.ScalarCredentialDefinition;
  credentialKeys?: CredentialKey[];
};
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
  scalar?: {
    registryDid: string;
    issuerKeyId: string;
    definitions: ScalarDefinitionPolicy[];
  };
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
      (config.scalar === undefined
        ? "issuerDid,issuerJwk,maxCacheAgeSeconds,registryOrigin,statusSources,trustAnchorJwk"
        : "issuerDid,issuerJwk,maxCacheAgeSeconds,registryOrigin,scalar,statusSources,trustAnchorJwk") ||
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
  if (config.scalar !== undefined) {
    const scalar = config.scalar;
    if (
      !scalar ||
      typeof scalar !== "object" ||
      Array.isArray(scalar) ||
      Object.keys(scalar).sort().join() !==
        "definitions,issuerKeyId,registryDid" ||
      typeof scalar.registryDid !== "string" ||
      core.didWebFromHost(new URL(config.registryOrigin).host) !==
        scalar.registryDid ||
      typeof scalar.issuerKeyId !== "string" ||
      !scalar.issuerKeyId.startsWith(config.issuerDid + "#") ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(
        scalar.issuerKeyId.slice(config.issuerDid.length + 1),
      ) ||
      !Array.isArray(scalar.definitions) ||
      scalar.definitions.length < 1 ||
      scalar.definitions.length > 16
    )
      throw Error("invalid scalar verifier configuration");
    const configurations = new Set<string>(),
      references = new Set<string>(),
      permissionReferences = new Set<string>();
    for (const definition of scalar.definitions) {
      if (
        !definition ||
        typeof definition !== "object" ||
        Array.isArray(definition) ||
        Object.keys(definition).sort().join() !==
          "authorizationId,configurationId,credentialType,definitionId,definitionVersion,profiles" ||
        typeof definition.configurationId !== "string" ||
        !/^[A-Za-z0-9_-]{1,64}$/.test(definition.configurationId) ||
        typeof definition.authorizationId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
          definition.authorizationId,
        ) ||
        configurations.has(definition.configurationId) ||
        references.has(definition.authorizationId) ||
        typeof definition.definitionId !== "string" ||
        definition.definitionId.length < 1 ||
        definition.definitionId.length > 256 ||
        typeof definition.definitionVersion !== "string" ||
        !/^[A-Za-z0-9._-]{1,64}$/.test(definition.definitionVersion) ||
        typeof definition.credentialType !== "string" ||
        !/^[A-Za-z0-9._:-]{1,128}$/.test(definition.credentialType) ||
        !Array.isArray(definition.profiles) ||
        definition.profiles.length < 1 ||
        definition.profiles.length > 16 ||
        definition.profiles.some(
          (profile) =>
            !profile ||
            typeof profile !== "object" ||
            Array.isArray(profile) ||
            Object.keys(profile).sort().join() !== "name,permissionId" ||
            typeof profile.name !== "string" ||
            !/^[A-Za-z0-9_-]{1,64}$/.test(profile.name) ||
            typeof profile.permissionId !== "string" ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
              profile.permissionId,
            ),
        ) ||
        new Set(definition.profiles.map((profile) => profile.name)).size !==
          definition.profiles.length
      )
        throw Error("invalid scalar verifier configuration");
      for (const profile of definition.profiles) {
        if (permissionReferences.has(profile.permissionId))
          throw Error("duplicate scalar permission reference");
        permissionReferences.add(profile.permissionId);
      }
      const id = new URL(definition.definitionId);
      if (
        !["https:", "urn:"].includes(id.protocol) ||
        id.username ||
        id.password ||
        id.hash ||
        /\s/.test(definition.definitionId)
      )
        throw Error("invalid scalar definition identifier");
      configurations.add(definition.configurationId);
      references.add(definition.authorizationId);
    }
  }
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
  trust?: string;
  authorizations: Map<string, string>;
  credentialKeys: Map<string, CredentialKey[]>;
  permissions: Map<string, string>;
  statuses: Map<string, string>;
  freshUntil: number;
};
export class EvidenceCache {
  private snapshot?: Snapshot;
  private refreshPending?: Promise<void>;
  private readonly revoked: RevocationProofs;
  readonly permissionsUrl: string;
  constructor(
    readonly config: VerifierConfig,
    readonly identity: RuntimeIdentity,
    private readonly now: () => number,
    private readonly fetcher: EvidenceFetcher = fetchEvidence,
    stateDir: string,
  ) {
    validateVerifierConfig(config);
    this.revoked = new RevocationProofs(stateDir, identity, config, now);
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
      const scalar = this.config.scalar;
      const authorityUrls =
        scalar?.definitions.map(
          (definition) =>
            this.config.registryOrigin +
            `/issuer-authorizations/${definition.authorizationId}.jwt`,
        ) ?? [];
      const permissionUrls = scalar
        ? scalar.definitions.flatMap((definition) =>
            definition.profiles.map(
              (profile) =>
                this.config.registryOrigin +
                `/scoped-verifier-permissions/${profile.permissionId}.jwt`,
            ),
          )
        : [this.permissionsUrl];
      const urls = [
        ...permissionUrls,
        ...this.config.statusSources.map((source) => source.url),
        ...(scalar ? authorityUrls : [trustUrl]),
      ];
      const bytes = await Promise.all(urls.map((url) => this.fetcher(url)));
      if (
        bytes.some(
          (value) =>
            typeof value !== "string" || Buffer.byteLength(value) > 262144,
        ) ||
        Buffer.byteLength(bytes[0]!) > (scalar ? 262144 : 16384)
      )
        throw Error();
      const now = this.now();
      const trustDid = core.didWebFromHost(
        new URL(this.config.registryOrigin).host,
      );
      const expiries: number[] = [];
      const authorizations = new Map<string, string>();
      const credentialKeys = new Map<string, CredentialKey[]>();
      let issuerDocument: string | undefined;
      let trust: string | undefined;
      if (!scalar) {
        trust = bytes.at(-1)!;
        const [_, document] = core.verifyTrustList({
          compactJws: trust,
          trustAnchorJwk: this.config.trustAnchorJwk,
        });
        if (document.issuer !== trustDid || document.id !== trustUrl)
          throw Error();
        core.verifyTrustListAccreditation({
          compactJws: trust,
          trustAnchorJwk: this.config.trustAnchorJwk,
          issuerDid: this.config.issuerDid,
          credentialType: EDUCATION_TYPE,
          issuerJwk: this.config.issuerJwk,
          nowUnixSeconds: now,
        });
        expiries.push(document.exp);
      } else {
        for (let i = 0; i < authorityUrls.length; i++) {
          const compact =
            bytes[
              permissionUrls.length + this.config.statusSources.length + i
            ]!;
          const verified = core.verifyCompactJwsJson({
            compactJws: compact,
            publicJwk: this.config.trustAnchorJwk,
          });
          const document = verified.payload as core.IssuerAuthorizations;
          if (
            verified.header.typ !== "issuer-authorizations+jwt" ||
            document.version !== 1 ||
            document.issuer !== scalar.registryDid ||
            document.id !== authorityUrls[i] ||
            !Number.isSafeInteger(document.iat) ||
            !Number.isSafeInteger(document.exp) ||
            document.iat > now ||
            document.exp <= now ||
            document.iat >= document.exp ||
            document.exp - document.iat > 86400 ||
            !Array.isArray(document.authorizations) ||
            document.authorizations.length > 64
          )
            throw Error();
          // Signed withdrawal removes positive members. Every accepted member below
          // is authenticated by the core, independently of its DID lookup hint.
          const policy = scalar.definitions[i]!;
          const members: CredentialKey[] = [];
          for (const hint of document.authorizations) {
            if (
              hint.credential_issuer_did !== this.config.issuerDid ||
              hint.definition?.id !== policy.definitionId ||
              hint.definition.version !== policy.definitionVersion ||
              hint.definition.credential_type !== policy.credentialType ||
              hint.status !== "active" || hint.key_state === "withdrawn"
            ) continue;
            const keyId = hint.credential_issuer_key_id;
            // Unchanged legacy publication never adds a DID fetch or another key.
            if (hint.key_state === undefined && keyId !== scalar.issuerKeyId) continue;
            let publicJwk: PublicJwk;
            if (keyId === scalar.issuerKeyId) publicJwk = this.config.issuerJwk;
            else {
              if (
                typeof keyId !== "string" ||
                !keyId.startsWith(this.config.issuerDid + "#") ||
                !/^[A-Za-z0-9._-]{1,128}$/.test(keyId.slice(this.config.issuerDid.length + 1))
              ) throw Error();
              const url = core.didWebToHttpsUrl(this.config.issuerDid);
              issuerDocument ??= await this.fetcher(url);
              if (typeof issuerDocument !== "string" || Buffer.byteLength(issuerDocument) > 262144)
                throw Error();
              publicJwk = core.resolveDidWebKey({
                issuerDid: this.config.issuerDid,
                kid: keyId,
                resolverResponses: { [url]: issuerDocument },
              });
            }
            let grant: core.IssuerAuthorization;
            try {
              grant = core.verifyIssuerAuthorization({
                compactJws: compact,
                trustAnchorJwk: this.config.trustAnchorJwk,
                nowUnixSeconds: now,
                request: {
                  registry_did: scalar.registryDid,
                  credential_issuer_did: this.config.issuerDid,
                  credential_issuer_key_id: keyId,
                  credential_issuer_public_jwk: publicJwk,
                  definition_id: policy.definitionId,
                  definition_version: policy.definitionVersion,
                  credential_type: policy.credentialType,
                  purpose: "verification",
                },
              });
            } catch (error) {
              if (hint.key_state === undefined) continue;
              throw error;
            }
            const thumbprint = core.publicJwkSha256Thumbprint(publicJwk);
            const statusAuthority = grant.status_authority;
            if (statusAuthority && this.config.statusSources.some((source) =>
              statusSourceKeyId(this.config, source) !== statusAuthority.key_id ||
              core.publicJwkSha256Thumbprint(source.publicJwk) !== statusAuthority.public_jwk_sha256_thumbprint
            )) throw Error();
            if (members.some((member) => member.keyId === keyId)) throw Error();
            members.push({ keyId, publicJwk, thumbprint, definition: grant.definition });
          }
          members.sort((a, b) => a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0);
          credentialKeys.set(policy.configurationId, members);
          authorizations.set(policy.configurationId, compact);
          expiries.push(document.exp);
        }
      }
      const permissions = new Map<string, string>();
      for (let i = 0; i < permissionUrls.length; i++) {
        const verified = core.verifyCompactJwsJson({
          compactJws: bytes[i]!,
          publicJwk: this.config.trustAnchorJwk,
        });
        const document = verified.payload as {
          version: number;
          issuer: string;
          id: string;
          iat: number;
          exp: number;
          permissions: unknown[];
        };
        if (document.version !== 1)
          throw new VerificationError("PERMISSION_VERSION_UNSUPPORTED", 503);
        if (
          verified.header.typ !== "scoped-verifier-permissions+jwt" ||
          document.issuer !== trustDid ||
          document.id !== permissionUrls[i] ||
          !Array.isArray(document.permissions) ||
          document.permissions.length > (scalar ? 256 : 2) ||
          !Number.isSafeInteger(document.iat) ||
          !Number.isSafeInteger(document.exp) ||
          document.iat > now ||
          document.exp <= now ||
          document.exp - document.iat > (scalar ? 86400 : 300) ||
          document.iat >= document.exp
        )
          throw Error();
        expiries.push(document.exp);
        permissions.set(permissionUrls[i]!, bytes[i]!);
      }
      const statuses = new Map<string, string>();
      for (let i = 0; i < this.config.statusSources.length; i++) {
        const source = this.config.statusSources[i]!;
        const compact = bytes[i + permissionUrls.length]!;
        const [header, status] = core.verifyBitstringStatusListCredentialAt({
          compactJws: compact,
          statusListJwk: source.publicJwk,
          nowUnixSeconds: now,
        });
        if (
          status.issuer !== this.config.issuerDid ||
          status.credentialSubject.id !== source.url + "#list" ||
          status.credentialSubject.statusPurpose !== source.purpose ||
          (statusSourceKeyId(this.config, source) !== undefined &&
            header.kid !== statusSourceKeyId(this.config, source)) ||
          !status.validUntil
        )
          throw Error();
        const expiry = Date.parse(status.validUntil) / 1000;
        if (!Number.isFinite(expiry)) throw Error();
        expiries.push(expiry);
        statuses.set(source.url, compact);
      }
      this.snapshot = {
        trust,
        authorizations,
        credentialKeys,
        permissions,
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
  permit(profile: Profile, configurationId?: string): DisclosureScope {
    const snapshot = this.current();
    let scope: DisclosureScope;
    let permissionUrl = this.permissionsUrl;
    if (this.config.scalar) {
      const policy = this.config.scalar.definitions.find(
        (entry) => entry.configurationId === configurationId,
      );
      const configuredProfile = policy?.profiles.find(
        (entry) => entry.name === profile,
      );
      if (!policy || !configuredProfile)
        throw new VerificationError("SCOPE_NOT_PERMITTED", 403);
      permissionUrl =
        this.config.registryOrigin +
        `/scoped-verifier-permissions/${configuredProfile.permissionId}.jwt`;
      const compact = snapshot.authorizations.get(policy.configurationId)!;
      const members = snapshot.credentialKeys.get(policy.configurationId)!;
      if (members.length === 0) throw new VerificationError("ISSUER_NOT_AUTHORIZED", 403);
      const definition = members[0]!.definition;
      const registered = definition.profiles.find(
        (entry) => entry.name === profile,
      );
      if (!registered) throw new VerificationError("SCOPE_NOT_PERMITTED", 403);
      scope = {
        definitionId: definition.id,
        definitionVersion: definition.version,
        credentialType: definition.credential_type,
        claimPaths: registered.claim_paths,
        authorizationPath: `/issuer-authorizations/${policy.authorizationId}.jwt`,
        permissionPath: `/scoped-verifier-permissions/${configuredProfile.permissionId}.jwt`,
        compactAuthorization: compact,
        definition,
        credentialKeys: members,
      };
    } else {
      if (
        configurationId !== undefined ||
        !Object.hasOwn(EDUCATION_PROFILES, profile)
      )
        throw new VerificationError("SCOPE_NOT_PERMITTED", 403);
      scope = {
        definitionId: "urn:credworks:education",
        definitionVersion: "1",
        credentialType: EDUCATION_TYPE,
        claimPaths:
          EDUCATION_PROFILES[profile as keyof typeof EDUCATION_PROFILES],
      };
    }
    try {
      core.verifyScopedVerifierPermission({
        compactJws: snapshot.permissions.get(permissionUrl)!,
        trustAnchorJwk: this.config.trustAnchorJwk,
        request: {
          credential_issuer_did: this.config.issuerDid,
          definition_id: scope.definitionId,
          definition_version: scope.definitionVersion,
          credential_type: scope.credentialType,
          verifier_did: this.identity.did,
          verifier_origin: new URL(core.didWebToHttpsUrl(this.identity.did))
            .origin,
          verifier_public_jwk: this.identity.publicJwk,
          profile_name: profile,
          claim_paths: scope.claimPaths,
        },
        nowUnixSeconds: this.now(),
      });
    } catch {
      throw new VerificationError("SCOPE_NOT_PERMITTED", 403);
    }
    return scope;
  }
  status(status: CredentialStatus, credential?: CredentialPin) {
    const snapshot = this.current();
    const source = this.config.statusSources.find(
      (source) =>
        source.url === status.statusListCredential &&
        source.purpose === status.statusPurpose,
    );
    if (!source)
      throw new VerificationError("STATUS_DESTINATION_UNAUTHORIZED", 400);
    const compact = snapshot.statuses.get(source.url)!;
    const revoked = this.revoked.check(status, compact, snapshot.freshUntil, credential);
    // Filesystem contention/publication can cross a signed or cache deadline.
    this.current();
    core.resolveCredentialStatusAt({
      status,
      resolverResponses: { [source.url]: compact },
      statusListJwk: source.publicJwk,
      nowUnixSeconds: this.now(),
    });
    if (revoked) throw new VerificationError("STATUS_CHECK_FAILED", 403);
  }
}
