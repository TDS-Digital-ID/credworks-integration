import {
  declaredPath,
  materializedBusinessSubject,
  subjectValue,
} from "./subject-paths.js";
import { signIssuerStatus } from "./issuer-status.js";
import { isDeepStrictEqual } from "node:util";
import { timingSafeEqual } from "node:crypto";
import type { HolderBinding, Sessions } from "./sessions.js";
import {
  verifyHolderProof,
  verifyWalletInstanceAttestation,
} from "@unsw-vc/issuer-protocol";
import * as core from "@unsw-vc/identity-core-node";
import type { RuntimeIdentity } from "./runtime.js";
import {
  fetchEvidence,
  VerificationError,
  type EvidenceFetcher,
} from "./evidence-cache.js";
import { IssuerState } from "./issuer-state.js";
import {
  IssuerKeys,
  credentialPublicKey,
  assertCredentialKeySelection,
  type CredentialKeyState,
} from "./issuer-keys.js";
export type IssuerConfig = {
  databaseUrl: string;
  registryOrigin: string;
  registryDid: string;
  trustAnchorJwk: core.PublicJwk;
  definitions: {
    configurationId: string;
    authorizationId: string;
    definitionId: string;
    definitionVersion: string;
    credentialType: string;
  }[];
  walletProviderDid: string;
  walletProviderJwk: core.PublicJwk;
};
export class IssuerProtocolFailure extends Error {
  constructor(
    readonly code: string,
    readonly status = 400,
  ) {
    super(code);
  }
}
export class Issuer {
  readonly state: IssuerState;
  readonly keys?: IssuerKeys;
  private keyHistory: CredentialKeyState | null = null;
  private async refreshKeys() {
    this.keyHistory = (await this.keys?.ready()) ?? null;
  }
  private keyForRecord(record: {
    signingKeyId: string | null;
    signingThumbprint: string | null;
  }) {
    return {
      keyId: record.signingKeyId ?? this.identity.keyId,
      publicJwk: credentialPublicKey(
        this.keyHistory,
        this.identity,
        record.signingKeyId,
        record.signingThumbprint,
      ),
    };
  }
  private selectedKey(record?: {
    signingKeyId: string | null;
    signingThumbprint: string | null;
  }) {
    const keyId =
      record?.signingKeyId ??
      this.keyHistory?.selectedKeyId ??
      this.identity.keyId;
    return {
      keyId,
      publicJwk: assertCredentialKeySelection(
        this.keyHistory,
        this.identity,
        record ? record.signingKeyId : keyId,
        record
          ? record.signingThumbprint
          : (this.keyHistory?.keys.find((key) => key.keyId === keyId)
              ?.thumbprint ??
            core.publicJwkSha256Thumbprint(this.identity.publicJwk)),
      ),
    };
  }
  constructor(
    readonly config: IssuerConfig,
    readonly origin: string,
    readonly identity: RuntimeIdentity,
    readonly clock: () => number,
    readonly fetcher: EvidenceFetcher = fetchEvidence,
    private readonly validateBinding?: (binding: HolderBinding) => void,
    storage?: { stateDir: string; unlockKey: string },
  ) {
    this.state = new IssuerState(config.databaseUrl);
    if (storage)
      this.keys = new IssuerKeys(
        this.state,
        identity,
        storage.stateDir,
        storage.unlockKey,
      );
  }
  async start() {
    await this.state.assertIdentity(this.origin, this.identity);
    await this.refreshKeys();
    await this.state.assertConsistent(this.identity, this.origin);
    await this.state.reconcileRenewals(this.origin, this.identity, this.clock);
  }
  private async registryDocument(path: string) {
    try {
      return await this.fetcher(`${this.config.registryOrigin}${path}`);
    } catch {
      throw new VerificationError("ISSUER_AUTHORITY_UNAVAILABLE", 503);
    }
  }
  async authorization(configurationId: string) {
    const configured = this.config.definitions.find(
      (entry) => entry.configurationId === configurationId,
    );
    if (!configured)
      throw new VerificationError("ISSUER_CONFIGURATION_UNKNOWN");
    return this.registryDocument(
      `/issuer-authorizations/${configured.authorizationId}.jwt`,
    );
  }
  verifyDefinition(
    configurationId: string,
    compactJws: string,
    key = this.selectedKey(),
    purpose: "issuance" | "verification" = "issuance",
  ) {
    return this.verifyKeyDefinition(configurationId, compactJws, key, purpose)
      .definition;
  }
  private verifyKeyDefinition(
    configurationId: string,
    compactJws: string,
    key: { keyId: string; publicJwk: core.PublicJwk },
    purpose: "issuance" | "verification" = "issuance",
  ) {
    const configured = this.config.definitions.find(
      (entry) => entry.configurationId === configurationId,
    );
    if (!configured)
      throw new VerificationError("ISSUER_CONFIGURATION_UNKNOWN");
    const url = `${this.config.registryOrigin}/issuer-authorizations/${configured.authorizationId}.jwt`;
    try {
      const verified = core.verifyCompactJwsJson({
        compactJws,
        publicJwk: this.config.trustAnchorJwk,
      });
      if ((verified.payload as { id?: unknown }).id !== url)
        throw Error("publication mismatch");
      const result = core.verifyIssuerAuthorization({
        compactJws,
        trustAnchorJwk: this.config.trustAnchorJwk,
        request: {
          registry_did: this.config.registryDid,
          credential_issuer_did: this.identity.did,
          credential_issuer_key_id: key.keyId,
          credential_issuer_public_jwk: key.publicJwk,
          definition_id: configured.definitionId,
          definition_version: configured.definitionVersion,
          credential_type: configured.credentialType,
          purpose,
        },
        nowUnixSeconds: this.clock(),
      });
      if (
        result.status_authority &&
        (result.status_authority.key_id !== this.identity.keyId ||
          result.status_authority.public_jwk_sha256_thumbprint !==
            core.publicJwkSha256Thumbprint(this.identity.publicJwk))
      )
        throw Error("status authority mismatch");
      return result;
    } catch {
      throw new VerificationError("ISSUER_AUTHORITY_UNAVAILABLE", 503);
    }
  }
  async keyManagement(operation: string, input?: unknown) {
    if (!this.keys)
      throw new VerificationError("ISSUER_KEY_STATE_UNAVAILABLE", 503);
    if (operation === "inspect") return this.keys.inspect();
    if (operation === "stage") return this.keys.stage(input);
    if (operation === "proof")
      return this.keys.proof(input, this.config.registryOrigin, this.clock);
    if (operation === "abandon") return this.keys.abandon(input);
    if (operation !== "activate")
      throw new VerificationError("ISSUER_KEY_BAD_REQUEST");
    const candidate = await this.keys.candidate(input);
    const documents = await Promise.all(
      this.config.definitions.map(async (definition) => ({
        id: definition.configurationId,
        compact: await this.authorization(definition.configurationId),
      })),
    );
    return this.keys.activate(input, (key) => {
      if (
        key.keyId !== candidate.keyId ||
        !key.publicJwk ||
        key.thumbprint !== candidate.thumbprint
      )
        throw new VerificationError("ISSUER_KEY_CONFLICT", 409);
      for (const document of documents) {
        const grant = this.verifyKeyDefinition(document.id, document.compact, {
          keyId: key.keyId,
          publicJwk: key.publicJwk,
        });
        if (
          grant.key_state !== "current" ||
          grant.status_authority?.key_id !== this.identity.keyId ||
          grant.status_authority.public_jwk_sha256_thumbprint !==
            core.publicJwkSha256Thumbprint(this.identity.publicJwk)
        )
          throw new VerificationError("ISSUER_AUTHORITY_UNAVAILABLE", 503);
      }
    });
  }
  private assertBinding(binding: HolderBinding | null) {
    if (!binding) return;
    if (!this.validateBinding)
      throw new VerificationError("ISSUER_BINDING_UNAVAILABLE", 503);
    this.validateBinding(binding);
  }
  async createOffer(
    input: unknown,
    link?: { sessions: Sessions; id: string; capability: unknown },
  ) {
    await this.refreshKeys();
    const value = input as Record<string, unknown>;
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.keys(value).sort().join() !==
        (link
          ? "claims,configuration_id,interaction_id,offer_expires_at,valid_from,valid_until"
          : "claims,configuration_id,offer_expires_at,recipient_jwk_thumbprint,valid_from,valid_until") ||
      typeof value.configuration_id !== "string" ||
      (link
        ? typeof value.interaction_id !== "string" ||
          value.interaction_id.length < 1 ||
          value.interaction_id.length > 128 ||
          typeof link.capability !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/.test(link.capability)
        : typeof value.recipient_jwk_thumbprint !== "string" ||
          !/^[A-Za-z0-9_-]{43}$/.test(value.recipient_jwk_thumbprint))
    )
      throw new VerificationError("ISSUER_OFFER_BAD_REQUEST");
    let existing = link ? await this.state.linkedOffer(link.id) : undefined;
    const correlationHash = link
      ? core.sha256B64Url(link.capability as string)
      : undefined;
    const validateExisting = () => {
      if (
        existing &&
        (!existing.verificationCorrelationHash ||
          !timingSafeEqual(
            Buffer.from(existing.verificationCorrelationHash),
            Buffer.from(correlationHash!),
          ) ||
          !isDeepStrictEqual(existing.verificationInput, value) ||
          existing.verificationBinding?.interactionId !== value.interaction_id)
      )
        throw new VerificationError("ISSUER_BINDING_MISMATCH", 409);
      if (existing) {
        this.assertBinding(existing.verificationBinding);
        if (existing.phase !== "offered")
          throw new VerificationError("ISSUER_OFFER_CONSUMED", 409);
      }
    };
    validateExisting();
    const configured = this.config.definitions.find(
      (entry) => entry.configurationId === value.configuration_id,
    );
    if (!configured)
      throw new VerificationError("ISSUER_CONFIGURATION_UNKNOWN");
    const signing = this.selectedKey(existing);
    const authorization = await this.authorization(configured.configurationId);
    const definition = this.verifyDefinition(
      value.configuration_id,
      authorization,
      signing,
    );
    if (existing && !isDeepStrictEqual(existing.definition, definition))
      throw new VerificationError("ISSUER_BINDING_MISMATCH", 409);
    const now = this.clock();
    const from = value.valid_from as number,
      until = value.valid_until as number,
      expires = value.offer_expires_at as number;
    if (
      ![from, until, expires].every(Number.isSafeInteger) ||
      from > now ||
      until <= now ||
      until <= from ||
      until - from > definition.max_validity_seconds ||
      expires <= now ||
      expires > now + 600 ||
      expires > until
    )
      throw new VerificationError("ISSUER_VALIDITY_INVALID");
    try {
      core.validateScalarSubject({
        definition,
        subject: value.claims as Record<string, unknown>,
        mode: "complete",
      });
    } catch {
      throw new VerificationError("ISSUER_VALUES_INVALID");
    }
    let binding = existing?.verificationBinding ?? null;
    if (link && !existing) {
      try {
        binding = link.sessions.link(
          link.id,
          link.capability,
          value.interaction_id as string,
          value,
        );
      } catch (error) {
        // Another authenticated request may commit during the authority fetch.
        // A consumed live session is recoverable only through that durable link.
        if (
          !(error instanceof VerificationError) ||
          error.code !== "RESULT_CONSUMED"
        )
          throw error;
        existing = await this.state.linkedOffer(link.id);
        if (!existing) throw error;
        validateExisting();
        if (!isDeepStrictEqual(existing.definition, definition))
          throw new VerificationError("ISSUER_BINDING_MISMATCH", 409);
        binding = existing.verificationBinding;
      }
    }
    this.assertBinding(binding);
    const id = existing?.id ?? core.randomUrlSafe(16),
      code = link
        ? core.sha256B64Url(
            JSON.stringify([
              "credworks-linked-offer-v1",
              this.identity.did,
              link.id,
              link.capability,
            ]),
          )
        : core.randomUrlSafe(32);
    if (existing && existing.codeHash !== core.sha256B64Url(code))
      throw new VerificationError("ISSUER_BINDING_MISMATCH", 409);
    const effectiveExpires = binding
      ? Math.min(expires, Math.floor(binding.expiresAt))
      : expires;
    const offer = await this.state.createOffer(
      {
        id,
        codeHash: core.sha256B64Url(code),
        signingKeyId: signing.keyId,
        signingThumbprint: core.publicJwkSha256Thumbprint(signing.publicJwk),
        expiresAt: effectiveExpires,
        configurationId: value.configuration_id,
        definition,
        claims: value.claims,
        validFrom: from,
        validUntil: until,
        recipientThumbprint:
          binding?.holderThumbprint ??
          (value.recipient_jwk_thumbprint as string),
        phase: "offered",
        ...(link
          ? {
              verificationId: link.id,
              verificationCorrelationHash: correlationHash,
              verificationBinding: binding,
              verificationInput: value,
            }
          : {}),
      },
      () => {
        this.verifyDefinition(
          value.configuration_id as string,
          authorization,
          signing,
        );
        this.assertBinding(binding);
        const current = this.clock();
        if (until <= current || effectiveExpires <= current)
          throw new VerificationError("ISSUER_VALIDITY_INVALID");
      },
      this.identity,
    );
    if (link) link.sessions.linked(link.id, link.capability);
    return {
      credential_offer_uri: `${this.origin}/oid4vci/offers/${offer.id}?code=${code}`,
      expires_at: offer.expiresAt,
      pre_authorized_code: code,
    };
  }
  private renewalPredecessor(
    predecessor: Awaited<ReturnType<IssuerState["offer"]>>,
    authorization?: string,
  ) {
    if (
      !predecessor ||
      predecessor.phase !== "issued" ||
      !predecessor.committedCredential
    )
      throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
    // New issuance requires positive predecessor authority; retirement needs ledger integrity only.
    if (
      authorization !== undefined &&
      !isDeepStrictEqual(
        this.verifyDefinition(
          predecessor.configurationId,
          authorization,
          this.keyForRecord(predecessor),
          "verification",
        ),
        predecessor.definition,
      )
    )
      throw new VerificationError("ISSUER_AUTHORITY_UNAVAILABLE", 503);
    try {
      const signing = this.keyForRecord(predecessor);
      if (
        core.verifyCompactJwsJson({
          compactJws: predecessor.committedCredential.split("~")[0]!,
          publicJwk: signing.publicJwk,
        }).header.kid !== signing.keyId
      )
        throw Error("credential key mismatch");
      const definition =
        predecessor.definition as core.ScalarCredentialDefinition;
      const verified = core.verifySdJwtCredential({
        compactSdJwt: predecessor.committedCredential,
        issuerJwk: signing.publicJwk,
        options: {
          now_unix_seconds: predecessor.validFrom,
          required_claims: definition.claims
            .filter((claim) => claim.required)
            .map(declaredPath),
          format: "w3c_vc_data_model",
        },
      }).processed_payload as {
        id?: unknown;
        iss?: unknown;
        exp?: unknown;
        credentialDefinition?: unknown;
        credentialSubject?: unknown;
        credentialStatus?: core.CredentialStatus;
        cnf?: { jwk?: core.PublicJwk };
      };
      const subject = materializedBusinessSubject(
        definition,
        verified.credentialSubject,
      );
      core.validateScalarSubject({ definition, subject, mode: "complete" });
      if (
        verified.id !== `${this.origin}/credentials/${predecessor.id}` ||
        verified.iss !== this.identity.did ||
        verified.exp !== predecessor.validUntil ||
        !isDeepStrictEqual(verified.credentialDefinition, {
          id: definition.id,
          version: definition.version,
        }) ||
        !isDeepStrictEqual(subject, predecessor.claims) ||
        !verified.cnf?.jwk ||
        core.publicJwkSha256Thumbprint(verified.cnf.jwk) !==
          predecessor.recipientThumbprint
      )
        throw Error();
      return verified;
    } catch {
      throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
    }
  }
  async createRenewal(input: unknown, correlation: string | undefined) {
    await this.refreshKeys();
    const value = input as Record<string, unknown>;
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.keys(value).sort().join() !==
        "claims,configuration_id,offer_expires_at,predecessor_issuance_id,valid_from,valid_until,version" ||
      value.version !== 1 ||
      typeof value.predecessor_issuance_id !== "string" ||
      !/^[A-Za-z0-9_-]{22}$/.test(value.predecessor_issuance_id) ||
      typeof value.configuration_id !== "string" ||
      !correlation ||
      !/^[A-Za-z0-9_-]{43}$/.test(correlation)
    )
      throw new VerificationError("ISSUER_RENEWAL_BAD_REQUEST");
    const derive = (domain: string) =>
      core.sha256B64Url(
        JSON.stringify([domain, this.identity.did, correlation]),
      );
    const capability = derive("credworks-renewal-read-v1");
    const existing = await this.state.correlatedRenewal(
      derive("credworks-renewal-correlation-v1"),
    );
    if (existing) {
      if (!isDeepStrictEqual(existing.input, value))
        throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
      return {
        version: 1,
        renewal_id: existing.id,
        status: existing.phase,
        renewal_request_uri: `${this.origin}/partner-renewals/${existing.id}?capability=${capability}`,
        expires_at: existing.expiresAt,
      };
    }
    const configured = this.config.definitions.find(
      (entry) => entry.configurationId === value.configuration_id,
    );
    if (!configured)
      throw new VerificationError("ISSUER_CONFIGURATION_UNKNOWN");
    const signing = this.selectedKey();
    const authorization = await this.authorization(configured.configurationId);
    const definition = this.verifyDefinition(
      configured.configurationId,
      authorization,
      signing,
    );
    const predecessor = await this.state.offer(value.predecessor_issuance_id);
    if (!predecessor)
      throw new VerificationError("ISSUER_RENEWAL_NOT_FOUND", 404);
    this.renewalPredecessor(predecessor, authorization);
    if (!isDeepStrictEqual(predecessor.definition, definition))
      throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
    const now = this.clock(),
      from = value.valid_from as number,
      until = value.valid_until as number,
      expires = value.offer_expires_at as number;
    if (
      ![from, until, expires].every(Number.isSafeInteger) ||
      from > now ||
      until <= now ||
      until <= from ||
      until - from > definition.max_validity_seconds ||
      expires <= now ||
      expires > now + 600 ||
      expires > until
    )
      throw new VerificationError("ISSUER_VALIDITY_INVALID");
    try {
      core.validateScalarSubject({
        definition,
        subject: value.claims as Record<string, unknown>,
        mode: "complete",
      });
    } catch {
      throw new VerificationError("ISSUER_VALUES_INVALID");
    }
    const renewal = await this.state.createRenewal(
      {
        id: derive("credworks-renewal-id-v1").slice(0, 22),
        signingKeyId: signing.keyId,
        signingThumbprint: core.publicJwkSha256Thumbprint(signing.publicJwk),
        correlationHash: derive("credworks-renewal-correlation-v1"),
        capabilityHash: core.sha256B64Url(capability),
        predecessorId: predecessor.id,
        livePredecessorId: predecessor.id,
        input: value,
        definition,
        recipientThumbprint: predecessor.recipientThumbprint,
        expiresAt: expires,
        phase: "awaiting_holder",
      },
      this.origin,
      this.identity,
      this.clock,
      (latest) => {
        this.renewalPredecessor(latest, authorization);
        this.verifyDefinition(
          configured.configurationId,
          authorization,
          signing,
        );
        if (!isDeepStrictEqual(latest.definition, definition))
          throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
        if (until <= this.clock())
          throw new VerificationError("ISSUER_VALIDITY_INVALID");
      },
    );
    return {
      version: 1,
      renewal_id: renewal.id,
      status: renewal.phase,
      renewal_request_uri: `${this.origin}/partner-renewals/${renewal.id}?capability=${capability}`,
      expires_at: renewal.expiresAt,
    };
  }
  async renewalRequest(id: string, query: URLSearchParams) {
    await this.refreshKeys();
    const capability = query.get("capability");
    if (
      query.size !== 1 ||
      !capability ||
      !/^[A-Za-z0-9_-]{43}$/.test(capability)
    )
      throw new VerificationError("ISSUER_RENEWAL_BAD_REQUEST");
    const renewal = await this.state.renewal(id);
    if (
      !renewal ||
      !timingSafeEqual(
        Buffer.from(renewal.capabilityHash),
        Buffer.from(core.sha256B64Url(capability)),
      )
    )
      throw new VerificationError("ISSUER_RENEWAL_NOT_FOUND", 404);
    if (renewal.phase !== "awaiting_holder")
      throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
    if (renewal.expiresAt <= this.clock())
      throw new VerificationError("ISSUER_RENEWAL_EXPIRED", 410);
    const signing = this.selectedKey(renewal);
    const predecessor = await this.state.offer(renewal.predecessorId);
    const authorization = await this.authorization(
      renewal.input.configuration_id as string,
    );
    const verified = this.renewalPredecessor(predecessor, authorization);
    const definition = renewal.definition as core.ScalarCredentialDefinition;
    const currentDefinition = this.verifyDefinition(
      renewal.input.configuration_id as string,
      authorization,
      signing,
    );
    if (!isDeepStrictEqual(currentDefinition, definition))
      throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
    const status = await this.state.issuanceStatus(
      renewal.predecessorId,
      this.origin,
      this.identity,
      this.clock,
      false,
    );
    if (status.state !== "active")
      throw new VerificationError("ISSUER_RENEWAL_NOT_CONFIRMABLE", 409);
    if (renewal.expiresAt <= this.clock())
      throw new VerificationError("ISSUER_RENEWAL_EXPIRED", 410);
    return {
      version: 1,
      renewal_id: id,
      credential_issuer: this.origin,
      configuration_id: renewal.input.configuration_id,
      definition: {
        id: definition.id,
        version: definition.version,
        credential_type: definition.credential_type,
      },
      predecessor: {
        credential_id: verified.id,
        status_list_credential: verified.credentialStatus!.statusListCredential,
        status_list_index: verified.credentialStatus!.statusListIndex,
        status_purpose: verified.credentialStatus!.statusPurpose,
      },
      claims: renewal.input.claims,
      valid_from: renewal.input.valid_from,
      valid_until: renewal.input.valid_until,
      expires_at: renewal.expiresAt,
      authorize_uri: `${this.origin}/partner-renewals/${id}/authorize`,
      cancel_uri: `${this.origin}/partner-renewals/${id}/cancel`,
    };
  }
  async authorizeRenewal(id: string, input: unknown) {
    await this.refreshKeys();
    const body = input as {
      version?: unknown;
      capability?: unknown;
      proof?: { proof_type?: unknown; jwt?: unknown };
    };
    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body) ||
      Object.keys(body).sort().join() !== "capability,proof,version" ||
      body.version !== 1 ||
      typeof body.capability !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(body.capability) ||
      !body.proof ||
      Object.keys(body.proof).sort().join() !== "jwt,proof_type" ||
      body.proof.proof_type !== "jwt" ||
      typeof body.proof.jwt !== "string"
    )
      throw new VerificationError("ISSUER_RENEWAL_BAD_REQUEST");
    const renewal = await this.state.renewal(id);
    if (
      !renewal ||
      !timingSafeEqual(
        Buffer.from(renewal.capabilityHash),
        Buffer.from(core.sha256B64Url(body.capability)),
      )
    )
      throw new VerificationError("ISSUER_RENEWAL_NOT_FOUND", 404);
    const signing = this.selectedKey(renewal);
    const predecessor = await this.state.offer(renewal.predecessorId);
    const configurationId = renewal.input.configuration_id as string;
    const authorization = await this.authorization(configurationId);
    const complete = this.renewalPredecessor(predecessor, authorization);
    const audience = `${this.origin}/partner-renewals/${id}/authorize`;
    const validate = (latest: NonNullable<typeof predecessor>) => {
      const verified = this.renewalPredecessor(latest, authorization);
      if (
        !isDeepStrictEqual(
          this.verifyDefinition(configurationId, authorization, signing),
          renewal.definition,
        )
      )
        throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
      try {
        return verifyHolderProof({
          core,
          proofJwt: body.proof!.jwt as string,
          holderPublicJwk: verified.cnf!.jwk!,
          expectedAudience: audience,
          nowUnixSeconds: this.clock(),
          maxAgeSeconds: 300,
          maxFutureSkewSeconds: 5,
        });
      } catch {
        throw new VerificationError("ISSUER_RENEWAL_INVALID_PROOF");
      }
    };
    const nonce = validate(predecessor!);
    const code = core.sha256B64Url(
      JSON.stringify(["credworks-renewal-offer-v1", body.capability]),
    );
    const successorId = core
      .sha256B64Url(JSON.stringify(["credworks-renewal-successor-v1", id]))
      .slice(0, 22);
    await this.state.authorizeRenewal(
      renewal,
      core.sha256B64Url(nonce),
      {
        id: successorId,
        codeHash: core.sha256B64Url(code),
        signingKeyId: renewal.signingKeyId,
        signingThumbprint: renewal.signingThumbprint,
        configurationId,
        definition: renewal.definition,
        claims: renewal.input.claims as Record<string, unknown>,
        validFrom: renewal.input.valid_from as number,
        validUntil: renewal.input.valid_until as number,
        expiresAt: renewal.expiresAt,
        recipientThumbprint: core.publicJwkSha256Thumbprint(complete.cnf!.jwk!),
        phase: "offered",
      },
      core.randomUrlSafe(32),
      this.origin,
      this.identity,
      this.clock,
      validate,
    );
    return {
      version: 1,
      renewal_id: id,
      credential_offer_uri: `${this.origin}/oid4vci/offers/${successorId}?code=${code}`,
      pre_authorized_code: code,
      expires_at: renewal.expiresAt,
    };
  }
  async renewalOperation(
    id: string,
    action: "confirm" | "cancel" | "status",
    input: unknown,
    receiptId?: string,
    successorId?: string,
  ) {
    await this.refreshKeys();
    const body = input as {
      version?: unknown;
      event?: unknown;
      proof?: { proof_type?: unknown; jwt?: unknown };
    };
    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body) ||
      Object.keys(body).sort().join() !==
        (action === "confirm" ? "event,proof,version" : "proof,version") ||
      body.version !== 1 ||
      (action === "confirm" && body.event !== "credential_accepted") ||
      !body.proof ||
      Object.keys(body.proof).sort().join() !== "jwt,proof_type" ||
      body.proof.proof_type !== "jwt" ||
      typeof body.proof.jwt !== "string"
    )
      throw new VerificationError("ISSUER_RENEWAL_BAD_REQUEST");
    const renewal = await this.state.renewal(id);
    if (!renewal) throw new VerificationError("ISSUER_RENEWAL_NOT_FOUND", 404);
    if (
      action === "confirm" &&
      (receiptId !== renewal.receiptId || successorId !== renewal.successorId)
    )
      throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
    const predecessor = await this.state.offer(renewal.predecessorId);
    const audience =
      action === "confirm"
        ? `${this.origin}/partner-renewals/${id}/receipts/${receiptId}/successors/${successorId}/confirm`
        : `${this.origin}/partner-renewals/${id}/${action}`;
    const configurationId = renewal.input.configuration_id as string;
    const authorization =
      action === "confirm" && renewal.phase === "awaiting_receipt"
        ? await this.authorization(configurationId)
        : undefined;
    const successor =
      action === "confirm" &&
      renewal.phase === "awaiting_receipt" &&
      renewal.successorId
        ? await this.state.offer(renewal.successorId)
        : undefined;
    if (
      action === "confirm" &&
      renewal.phase === "awaiting_receipt" &&
      (!successor || successor.phase !== "issued")
    )
      throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
    const validate = (
      latest: NonNullable<typeof predecessor>,
      current: typeof renewal,
    ) => {
      const verified = this.renewalPredecessor(latest);
      if (action === "confirm" && current.phase === "awaiting_receipt") {
        if (
          !authorization ||
          !isDeepStrictEqual(
            this.verifyDefinition(
              configurationId,
              authorization,
              this.keyForRecord(successor!),
              "verification",
            ),
            current.definition,
          )
        )
          throw new VerificationError("ISSUER_AUTHORITY_UNAVAILABLE", 503);
      }
      try {
        return verifyHolderProof({
          core,
          proofJwt: body.proof!.jwt as string,
          holderPublicJwk: verified.cnf!.jwk!,
          expectedAudience: audience,
          nowUnixSeconds: this.clock(),
          maxAgeSeconds: 300,
          maxFutureSkewSeconds: 5,
        });
      } catch {
        throw new VerificationError("ISSUER_RENEWAL_INVALID_PROOF");
      }
    };
    const nonce = validate(predecessor!, renewal);
    const result = await this.state.renewalAction(
      renewal,
      action,
      core.sha256B64Url(nonce),
      this.origin,
      this.identity,
      this.clock,
      validate,
      receiptId,
      successorId,
    );
    return {
      version: 1,
      renewal_id: id,
      status: result.phase,
      predecessor_credential_id: `${this.origin}/credentials/${result.predecessorId}`,
      ...(result.successorId
        ? {
            successor_credential_id: `${this.origin}/credentials/${result.successorId}`,
          }
        : {}),
      ...(result.receiptId ? { receipt_id: result.receiptId } : {}),
      confirmed_at: result.confirmedAt,
      completed_at: result.completedAt,
    };
  }

  async retrieveOffer(id: string, query: URLSearchParams) {
    await this.refreshKeys();
    if (
      query.size !== 1 ||
      !query.has("code") ||
      !/^[A-Za-z0-9_-]{43}$/.test(query.get("code")!)
    )
      throw new IssuerProtocolFailure("invalid_grant");
    const code = query.get("code")!,
      offer = await this.state.offer(id);
    if (
      !offer ||
      offer.codeHash !== core.sha256B64Url(code) ||
      offer.phase !== "offered" ||
      offer.expiresAt <= this.clock()
    )
      throw new IssuerProtocolFailure("invalid_grant");
    const signing = this.selectedKey(offer);
    this.assertBinding(offer.verificationBinding);
    if (offer.verificationBinding)
      this.verifyDefinition(
        offer.configurationId,
        await this.authorization(offer.configurationId),
        signing,
      );
    return {
      credential_issuer: this.origin,
      credential_configuration_ids: [offer.configurationId],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": code,
        },
      },
    };
  }
  async token(form: URLSearchParams) {
    await this.refreshKeys();
    if (
      form.size !== 2 ||
      form.get("grant_type") !==
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" ||
      !/^[A-Za-z0-9_-]{43}$/.test(form.get("pre-authorized_code") ?? "")
    )
      throw new IssuerProtocolFailure("invalid_grant");
    const token = core.randomUrlSafe(32);
    const codeHash = core.sha256B64Url(form.get("pre-authorized_code")!);
    const offer = await this.state.codeOffer(codeHash);
    const authorization = offer?.verificationBinding
      ? await this.authorization(offer.configurationId)
      : undefined;
    const expiry = await this.state.redeem(
      codeHash,
      core.sha256B64Url(token),
      this.clock,
      (stored) => {
        this.selectedKey(stored);
        this.assertBinding(stored.verificationBinding);
        if (stored.verificationBinding)
          this.verifyDefinition(
            stored.configurationId,
            authorization!,
            this.keyForRecord(stored),
          );
      },
    );
    if (
      !expiry ||
      expiry.tokenExpiresAt <= this.clock() ||
      expiry.offerExpiresAt <= this.clock()
    )
      throw new IssuerProtocolFailure("invalid_grant");
    return {
      access_token: token,
      token_type: "Bearer",
      expires_in: expiry.tokenExpiresAt - this.clock(),
    };
  }
  async nonce() {
    const nonce = core.randomUrlSafe(32),
      now = this.clock();
    await this.state.nonce(core.sha256B64Url(nonce), now + 300, this.clock);
    return { c_nonce: nonce, c_nonce_expires_in: now + 300 - this.clock() };
  }
  async credential(bearer: string | undefined, input: unknown) {
    await this.refreshKeys();
    if (!bearer || !/^Bearer [A-Za-z0-9_-]{43}$/.test(bearer))
      throw new IssuerProtocolFailure("invalid_token", 401);
    const body = input as {
      credential_configuration_id?: unknown;
      proofs?: { jwt?: unknown };
      wallet_instance_attestation?: unknown;
      holder_public_jwk?: core.PublicJwk;
    };
    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body) ||
      Object.keys(body).some(
        (field) =>
          ![
            "credential_configuration_id",
            "proofs",
            "wallet_instance_attestation",
            "holder_public_jwk",
          ].includes(field),
      ) ||
      typeof body.credential_configuration_id !== "string" ||
      !body.proofs ||
      Object.keys(body.proofs).join() !== "jwt" ||
      !Array.isArray(body.proofs.jwt) ||
      body.proofs.jwt.length !== 1 ||
      typeof body.proofs.jwt[0] !== "string" ||
      typeof body.wallet_instance_attestation !== "string"
    )
      throw new IssuerProtocolFailure("invalid_request");
    const offer = await this.state.tokenOffer(
      core.sha256B64Url(bearer.slice(7)),
    );
    if (
      !offer ||
      offer.configurationId !== body.credential_configuration_id ||
      !offer.tokenExpiresAt ||
      offer.tokenExpiresAt <= this.clock()
    )
      throw new IssuerProtocolFailure("invalid_token", 401);
    const signing = this.keyForRecord(offer);
    if (offer.phase !== "issued") this.selectedKey(offer);
    this.assertBinding(offer.verificationBinding);
    const configured = this.config.definitions.find(
      (entry) => entry.configurationId === body.credential_configuration_id,
    );
    if (!configured)
      throw new IssuerProtocolFailure("invalid_credential_request");
    const authorization = await this.authorization(configured.configurationId);
    const definition = this.verifyDefinition(
      body.credential_configuration_id,
      authorization,
      signing,
      offer.phase === "issued" ? "verification" : "issuance",
    );
    if (!isDeepStrictEqual(definition, offer.definition))
      throw new IssuerProtocolFailure("invalid_credential_request");
    const trust = await this.registryDocument("/trust-list.jwt");
    const now = this.clock();
    const proof = body.proofs.jwt[0];
    let holder: core.PublicJwk, nonce: string;
    try {
      const encoded = proof.split(".")[0]!;
      const headerKey = JSON.parse(
        Buffer.from(encoded, "base64url").toString("utf8"),
      ).jwk as core.PublicJwk | undefined;
      holder = body.holder_public_jwk ?? headerKey!;
      if (
        headerKey &&
        body.holder_public_jwk &&
        core.publicJwkSha256Thumbprint(headerKey) !==
          core.publicJwkSha256Thumbprint(body.holder_public_jwk)
      )
        throw Error("key mismatch");
      if (
        !holder ||
        Object.keys(holder).some(
          (field) => !["kty", "crv", "x", "y", "kid"].includes(field),
        ) ||
        holder.kty !== "EC" ||
        holder.crv !== "P-256"
      )
        throw Error("key invalid");
      nonce = verifyHolderProof({
        core,
        proofJwt: proof,
        holderPublicJwk: holder,
        expectedAudience: this.origin,
        nowUnixSeconds: now,
        maxAgeSeconds: 300,
        maxFutureSkewSeconds: 5,
      });
      if (core.publicJwkSha256Thumbprint(holder) !== offer.recipientThumbprint)
        throw Error("recipient invalid");
    } catch {
      throw new IssuerProtocolFailure("invalid_proof");
    }
    try {
      core.verifyTrustListAccreditation({
        compactJws: trust,
        trustAnchorJwk: this.config.trustAnchorJwk,
        issuerDid: this.config.walletProviderDid,
        credentialType: "WalletInstanceAttestation",
        issuerJwk: this.config.walletProviderJwk,
        nowUnixSeconds: now,
      });
      const method = verifyWalletInstanceAttestation({
        core,
        compactJws: body.wallet_instance_attestation,
        providerPublicJwk: this.config.walletProviderJwk,
        providerDid: this.config.walletProviderDid,
        expectedAudience: this.origin,
        holderPublicJwk: holder,
        nowUnixSeconds: now,
      });
      if (method !== "mock_platform_attestation")
        throw Error("partner WIA method refused");
    } catch {
      throw new IssuerProtocolFailure("invalid_wallet_instance_attestation");
    }
    const result = await this.state.issue({
      origin: this.origin,
      identity: this.identity,
      tokenHash: core.sha256B64Url(bearer.slice(7)),
      nonceHash: core.sha256B64Url(nonce),
      recipient: core.publicJwkSha256Thumbprint(holder),
      clock: this.clock,
      validateAuthority: (stored) => {
        this.assertBinding(offer.verificationBinding);
        this.verifyDefinition(
          body.credential_configuration_id as string,
          authorization,
          this.keyForRecord(stored),
          stored.phase === "issued" ? "verification" : "issuance",
        );
        try {
          const current = this.clock();
          core.verifyTrustListAccreditation({
            compactJws: trust,
            trustAnchorJwk: this.config.trustAnchorJwk,
            issuerDid: this.config.walletProviderDid,
            credentialType: "WalletInstanceAttestation",
            issuerJwk: this.config.walletProviderJwk,
            nowUnixSeconds: current,
          });
          const method = verifyWalletInstanceAttestation({
            core,
            compactJws: body.wallet_instance_attestation as string,
            providerPublicJwk: this.config.walletProviderJwk,
            providerDid: this.config.walletProviderDid,
            expectedAudience: this.origin,
            holderPublicJwk: holder,
            nowUnixSeconds: current,
          });
          if (method !== "mock_platform_attestation")
            throw Error("partner WIA method refused");
        } catch {
          throw new IssuerProtocolFailure(
            "invalid_wallet_instance_attestation",
          );
        }
        try {
          verifyHolderProof({
            core,
            proofJwt: proof,
            holderPublicJwk: holder,
            expectedAudience: this.origin,
            nowUnixSeconds: this.clock(),
            maxAgeSeconds: 300,
            maxFutureSkewSeconds: 5,
          });
        } catch {
          throw new IssuerProtocolFailure("invalid_proof");
        }
      },
      configurationId: body.credential_configuration_id,
      sign: (stored, index, previousStatus) => {
        if (
          !isDeepStrictEqual(stored.definition, offer.definition) ||
          !isDeepStrictEqual(stored.claims, offer.claims) ||
          stored.validFrom !== offer.validFrom ||
          stored.validUntil !== offer.validUntil ||
          stored.recipientThumbprint !== offer.recipientThumbprint
        )
          throw new IssuerProtocolFailure("invalid_credential_request");
        core.validateScalarSubject({
          definition,
          subject: stored.claims as Record<string, unknown>,
          mode: "complete",
        });
        const credentialId = `${this.origin}/credentials/${stored.id}`;
        const claims = stored.claims as Record<string, unknown>;
        const statusUrl = `${this.origin}/oid4vci/status/revocation.jwt`;
        const disclosureSpecs = definition.claims.flatMap((claim) => {
          const path = declaredPath(claim);
          return subjectValue(claims, path) === undefined
            ? []
            : [
                {
                  object_path: path.slice(0, -1),
                  claim_name: path.at(-1)!,
                },
              ];
        });
        const credential = core.issueSdJwtWithFormat({
          payload: {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            id: credentialId,
            iss: this.identity.did,
            issuer: this.identity.did,
            type: ["VerifiableCredential", definition.credential_type],
            credentialDefinition: {
              id: definition.id,
              version: definition.version,
            },
            iat: stored.validFrom,
            exp: stored.validUntil,
            validFrom: new Date(stored.validFrom * 1000).toISOString(),
            validUntil: new Date(stored.validUntil * 1000).toISOString(),
            cnf: { jwk: holder },
            credentialStatus: {
              id: `${statusUrl}#${index}`,
              type: "BitstringStatusListEntry",
              statusPurpose: "revocation",
              statusListIndex: String(index),
              statusListCredential: statusUrl,
            },
            credentialSubject: claims,
          },
          disclosureSpecs,
          salts: disclosureSpecs.map(() => core.randomUrlSafe(16)),
          header: {
            alg: "ES256",
            typ: "vc+sd-jwt",
            kid: stored.signingKeyId ?? this.identity.keyId,
          },
          keyId: stored.signingKeyId ?? this.identity.keyId,
          format: "w3c_vc_data_model",
        });
        const status = signIssuerStatus(
          this.origin,
          this.identity,
          this.clock(),
          this.statusPayload(previousStatus).credentialSubject.encodedList,
        );
        return { credential: credential.compact, credentialId, status };
      },
    });
    if (result.error) throw new IssuerProtocolFailure(result.error);
    const renewal = await this.state.successorRenewal(offer.id);
    return {
      credentials: [{ credential: result.credential }],
      ...(renewal
        ? {
            x_credworks_renewal: {
              version: 1,
              renewal_id: renewal.id,
              predecessor_credential_id: `${this.origin}/credentials/${renewal.predecessorId}`,
              successor_credential_id: `${this.origin}/credentials/${offer.id}`,
              receipt_id: renewal.receiptId,
              status: "pending_confirmation",
              confirm_uri: `${this.origin}/partner-renewals/${renewal.id}/receipts/${renewal.receiptId}/successors/${offer.id}/confirm`,
              status_uri: `${this.origin}/partner-renewals/${renewal.id}/status`,
              cancel_uri: `${this.origin}/partner-renewals/${renewal.id}/cancel`,
            },
          }
        : {}),
    };
  }
  private statusPayload(compactJws: string) {
    core.verifyBitstringStatusListCredential({
      compactJws,
      statusListJwk: this.identity.publicJwk,
    });
    const decoded = core.verifyCompactJwsJson({
      compactJws,
      publicJwk: this.identity.publicJwk,
    });
    const payload =
      decoded.payload as core.BitstringStatusListCredentialPayload;
    if (
      payload.issuer !== this.identity.did ||
      payload.credentialSubject.id !==
        `${this.origin}/oid4vci/status/revocation.jwt#list` ||
      payload.credentialSubject.statusPurpose !== "revocation"
    )
      throw Error("status state invalid");
    return payload;
  }
  async issuanceStatus(id: string, input?: unknown) {
    if (input !== undefined) {
      if (
        !input ||
        typeof input !== "object" ||
        Array.isArray(input) ||
        Object.keys(input).length !== 1 ||
        !Object.hasOwn(input, "state")
      )
        throw new VerificationError("ISSUER_STATUS_BAD_REQUEST");
      if ((input as { state: unknown }).state !== "revoked")
        throw new VerificationError("ISSUER_STATUS_UNSUPPORTED");
    }
    return this.state.issuanceStatus(
      id,
      this.origin,
      this.identity,
      this.clock,
      input !== undefined,
    );
  }
  async status() {
    let signed: string | undefined;
    try {
      signed = await this.state.status(
        this.origin,
        this.identity,
        (previous) => {
          const payload = this.statusPayload(previous);
          const now = this.clock();
          return signIssuerStatus(
            this.origin,
            this.identity,
            now,
            payload.credentialSubject.encodedList,
          );
        },
      );
    } catch {
      throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
    }
    if (!signed) throw new IssuerProtocolFailure("status_not_found", 404);
    const payload = core.verifyCompactJwsJson({
      compactJws: signed,
      publicJwk: this.identity.publicJwk,
    }).payload as core.BitstringStatusListCredentialPayload;
    if (
      !payload.validUntil ||
      Date.parse(payload.validUntil) <= this.clock() * 1000
    )
      throw new IssuerProtocolFailure("temporarily_unavailable", 503);
    return signed;
  }
  async metadata() {
    await this.refreshKeys();
    const configurations: Record<string, unknown> = {};
    const documents = await Promise.all(
      this.config.definitions.map(async (entry) => ({
        entry,
        compact: await this.authorization(entry.configurationId),
      })),
    );
    // All asynchronous work finishes before these exact signed authorities are
    // checked together against the current clock.
    for (const { entry, compact } of documents) {
      const definition = this.verifyDefinition(entry.configurationId, compact);
      configurations[entry.configurationId] = {
        format: "vc+sd-jwt",
        credworks_issuer_authorization: {
          path: `/issuer-authorizations/${entry.authorizationId}.jwt`,
          definition_id: entry.definitionId,
          definition_version: entry.definitionVersion,
        },
        scope: entry.configurationId,
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: ["ES256"] },
        },
        credential_definition: {
          type: ["VerifiableCredential", definition.credential_type],
        },
        credentialDefinition: {
          id: definition.id,
          version: definition.version,
        },
      };
    }
    return {
      credential_issuer: this.origin,
      credential_endpoint: `${this.origin}/oid4vci/credential`,
      nonce_endpoint: `${this.origin}/oid4vci/nonce`,
      authorization_servers: [this.origin],
      credential_configurations_supported: configurations,
    };
  }
}
