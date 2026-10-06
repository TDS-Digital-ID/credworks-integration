import { VerificationError } from "./evidence-cache.js";
import { signIssuerStatus } from "./issuer-status.js";
import { isDeepStrictEqual } from "node:util";
import { declaredPath, materializedBusinessSubject } from "./subject-paths.js";
import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { eq, sql, lte } from "drizzle-orm";
import * as core from "@unsw-vc/identity-core-node";
import {
  issuerIdentity,
  issuerOffers,
  issuerNonces,
  issuerStatus,
  issuerRenewals,
} from "./issuer-schema.js";
import {
  credentialPublicKey,
  assertCredentialKeySelection,
  type CredentialKeyState,
} from "./issuer-keys.js";
import type { RuntimeIdentity } from "./runtime.js";
type IssuerTransaction = Parameters<
  Parameters<IssuerState["db"]["transaction"]>[0]
>[0];

function assertIdentityRow(
  row: typeof issuerIdentity.$inferSelect | undefined,
  origin: string,
  identity: RuntimeIdentity,
) {
  if (
    !row ||
    row.singleton !== 1 ||
    row.origin !== origin ||
    row.did !== identity.did ||
    row.keyId !== identity.keyId ||
    row.publicThumbprint !== core.publicJwkSha256Thumbprint(identity.publicJwk)
  )
    throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
}

// The existing core remains the status interpreter. Reconstructing its canonical
// list from every retained allocation also detects missing/unallocated bits.
// ponytail: bounded by the existing 10,000-offer ceiling; use a batch core
// status-read API if this ledger bound grows, rather than another bit decoder.
function revokedIndices(
  stored: typeof issuerStatus.$inferSelect,
  offers: (typeof issuerOffers.$inferSelect)[],
  origin: string,
  identity: RuntimeIdentity,
  keys: CredentialKeyState | null,
) {
  const [, payload] = core.verifyBitstringStatusListCredential({
    compactJws: stored.signedCredential,
    statusListJwk: identity.publicJwk,
  });
  const url = `${origin}/oid4vci/status/revocation.jwt`;
  if (
    payload.issuer !== identity.did ||
    payload.credentialSubject.id !== `${url}#list` ||
    payload.credentialSubject.statusPurpose !== "revocation"
  )
    throw Error("issuer status identity unavailable");
  const issued = offers.filter((offer) => offer.phase === "issued");
  if (stored.nextIndex !== issued.length)
    throw Error("issuer status allocations unavailable");
  const revoked: number[] = [];
  for (const offer of offers) {
    if (offer.phase !== "issued") {
      if (offer.revokedAt !== null)
        throw Error("issuer status history unavailable");
      continue;
    }
    const index = offer.statusIndex;
    if (
      index === null ||
      index < 0 ||
      index >= stored.nextIndex ||
      offer.credentialId !== `${origin}/credentials/${offer.id}`
    )
      throw Error("issuer status allocations unavailable");
    if (!offer.committedCredential)
      throw Error("issuer credential status unavailable");
    const credential = core.verifyCompactJwsJson({
      compactJws: offer.committedCredential.split("~")[0]!,
      publicJwk: credentialPublicKey(
        keys,
        identity,
        offer.signingKeyId,
        offer.signingThumbprint,
      ),
    });
    const issuedPayload = credential.payload as {
      id?: unknown;
      iss?: unknown;
      credentialStatus?: Partial<core.CredentialStatus>;
    };
    const issuedStatus = issuedPayload.credentialStatus;
    if (
      credential.header.kid !== (offer.signingKeyId ?? identity.keyId) ||
      credential.header.typ !== "vc+sd-jwt" ||
      issuedPayload.id !== offer.credentialId ||
      issuedPayload.iss !== identity.did ||
      issuedStatus?.id !== `${url}#${index}` ||
      issuedStatus.type !== "BitstringStatusListEntry" ||
      issuedStatus.statusPurpose !== "revocation" ||
      issuedStatus.statusListIndex !== String(index) ||
      issuedStatus.statusListCredential !== url
    )
      throw Error("issuer credential status unavailable");
    const resolved = core.resolveCredentialStatus({
      status: {
        id: `${url}#${index}`,
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: String(index),
        statusListCredential: url,
      },
      resolverResponses: { [url]: stored.signedCredential },
      statusListJwk: identity.publicJwk,
    });
    if (
      offer.revokedAt !== null &&
      (!Number.isSafeInteger(offer.revokedAt) ||
        offer.revokedAt < 0 ||
        !resolved.revoked)
    )
      throw Error("issuer status history unavailable");
    if (resolved.revoked) revoked.push(index);
  }
  if (
    core.encodeBitstringStatusList(131072, revoked) !==
    payload.credentialSubject.encodedList
  )
    throw Error("issuer status allocations unavailable");
  return revoked;
}

export async function bootstrapIssuerState(
  databaseUrl: string,
  origin: string,
  identity: RuntimeIdentity,
) {
  const pool = new Pool({
    connectionString: databaseUrl,
    max: 2,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    query_timeout: 6000,
  });
  try {
    await drizzle(pool).transaction(async (tx) => {
      // Shared with both offer and nonce allocation: no retained protocol state
      // may be reinterpreted as a fresh issuer ledger.
      await tx.execute(sql`select pg_advisory_xact_lock(368,1)`);
      for (const table of [
        issuerIdentity,
        issuerStatus,
        issuerOffers,
        issuerNonces,
        issuerRenewals,
      ]) {
        const rows = await tx
          .select({ present: sql<number>`1` })
          .from(table)
          .limit(1);
        if (rows.length) throw Error("issuer state already exists");
      }
      await tx.insert(issuerIdentity).values({
        singleton: 1,
        origin,
        did: identity.did,
        keyId: identity.keyId,
        publicThumbprint: core.publicJwkSha256Thumbprint(identity.publicJwk),
      });
      await tx.insert(issuerStatus).values({
        singleton: 1,
        nextIndex: 0,
        signedCredential: signIssuerStatus(
          origin,
          identity,
          Math.floor(Date.now() / 1000),
        ),
      });
    });
  } finally {
    await pool.end();
  }
}
export class IssuerState {
  readonly pool: Pool;
  readonly db;
  constructor(databaseUrl: string) {
    this.pool = new Pool({
      connectionString: databaseUrl,
      max: 4,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
    });
    this.db = drizzle(this.pool);
  }
  async assertIdentity(origin: string, identity: RuntimeIdentity) {
    const rows = await this.db.select().from(issuerIdentity);
    const row = rows[0];
    if (
      rows.length !== 1 ||
      !row ||
      row.singleton !== 1 ||
      row.origin !== origin ||
      row.did !== identity.did ||
      row.keyId !== identity.keyId ||
      row.publicThumbprint !==
        core.publicJwkSha256Thumbprint(identity.publicJwk)
    )
      throw Error("issuer state identity unavailable");
  }
  async assertConsistent(identity: RuntimeIdentity, origin: string) {
    try {
      await this.db.transaction(async (tx) => {
        const [bound] = await tx
          .select()
          .from(issuerIdentity)
          .where(eq(issuerIdentity.singleton, 1))
          .for("update");
        assertIdentityRow(bound, origin, identity);
        const offers = await tx.select().from(issuerOffers).limit(10001);
        if (offers.length > 10000) throw Error();
        const [status] = await tx
          .select()
          .from(issuerStatus)
          .where(eq(issuerStatus.singleton, 1));
        let maximum = -1;
        for (const offer of offers) {
          credentialPublicKey(
            bound!.credentialKeys,
            identity,
            offer.signingKeyId,
            offer.signingThumbprint,
          );
          const linked = [
            offer.verificationId,
            offer.verificationCorrelationHash,
            offer.verificationBinding,
            offer.verificationInput,
          ].some((value) => value !== null);
          if (linked) {
            const binding = offer.verificationBinding,
              input = offer.verificationInput;
            if (
              !offer.verificationId ||
              !/^[A-Za-z0-9_-]{43}$/.test(offer.verificationId) ||
              !offer.verificationCorrelationHash ||
              !/^[A-Za-z0-9_-]{43}$/.test(offer.verificationCorrelationHash) ||
              !binding ||
              !input ||
              !Number.isFinite(binding.expiresAt) ||
              binding.verifierDid !== identity.did ||
              binding.verifierThumbprint !==
                core.publicJwkSha256Thumbprint(identity.publicJwk) ||
              binding.holderThumbprint !== offer.recipientThumbprint ||
              !/^[A-Za-z0-9_-]{43}$/.test(binding.issuerThumbprint) ||
              typeof binding.interactionId !== "string" ||
              binding.interactionId.length < 1 ||
              binding.interactionId.length > 128 ||
              typeof binding.profile !== "string" ||
              (binding.configurationId !== undefined &&
                (typeof binding.configurationId !== "string" ||
                  typeof binding.issuerKeyId !== "string")) ||
              !binding.scope ||
              !binding.credentialStatus ||
              input.interaction_id !== binding.interactionId ||
              input.configuration_id !== offer.configurationId ||
              !isDeepStrictEqual(input.claims, offer.claims) ||
              input.valid_from !== offer.validFrom ||
              input.valid_until !== offer.validUntil ||
              !Number.isSafeInteger(input.offer_expires_at) ||
              offer.expiresAt !==
                Math.min(
                  input.offer_expires_at as number,
                  Math.floor(binding.expiresAt),
                )
            )
              throw Error();
          }
          core.validateScalarDefinition(
            offer.definition as core.ScalarCredentialDefinition,
          );
          core.validateScalarSubject({
            definition: offer.definition as core.ScalarCredentialDefinition,
            subject: offer.claims as Record<string, unknown>,
            mode: "complete",
          });
          if (
            !["offered", "redeemed", "issued", "failed"].includes(
              offer.phase,
            ) ||
            !/^[A-Za-z0-9_-]{43}$/.test(offer.codeHash) ||
            !/^[A-Za-z0-9_-]{43}$/.test(offer.recipientThumbprint) ||
            offer.validUntil <= offer.validFrom ||
            offer.validUntil - offer.validFrom >
              (offer.definition as core.ScalarCredentialDefinition)
                .max_validity_seconds ||
            offer.expiresAt > offer.validUntil
          )
            throw Error();
          if (
            ["redeemed", "issued"].includes(offer.phase) &&
            (!offer.tokenHash ||
              !/^[A-Za-z0-9_-]{43}$/.test(offer.tokenHash) ||
              !offer.tokenExpiresAt ||
              offer.tokenExpiresAt > offer.validUntil)
          )
            throw Error();
          if (offer.phase === "issued") {
            if (
              !offer.committedCredential ||
              !offer.credentialId ||
              offer.statusIndex === null ||
              offer.statusIndex < 0 ||
              !offer.completedNonceHash
            )
              throw Error();
            const verified = core.verifyCompactJwsJson({
              compactJws: offer.committedCredential.split("~")[0]!,
              publicJwk: credentialPublicKey(
                bound!.credentialKeys,
                identity,
                offer.signingKeyId,
                offer.signingThumbprint,
              ),
            });
            if (verified.header.kid !== (offer.signingKeyId ?? identity.keyId))
              throw Error();
            const payload = verified.payload as {
              id?: unknown;
              iss?: unknown;
              exp?: unknown;
              credentialDefinition?: { id?: unknown; version?: unknown };
              credentialStatus?: { statusListIndex?: unknown };
            };
            const definition =
              offer.definition as core.ScalarCredentialDefinition;
            if (
              payload.id !== offer.credentialId ||
              payload.iss !== identity.did ||
              payload.exp !== offer.validUntil ||
              payload.credentialDefinition?.id !== definition.id ||
              payload.credentialDefinition?.version !== definition.version ||
              payload.credentialStatus?.statusListIndex !==
                String(offer.statusIndex)
            )
              throw Error();
            const complete = core.verifySdJwtCredential({
              compactSdJwt: offer.committedCredential,
              issuerJwk: credentialPublicKey(
                bound!.credentialKeys,
                identity,
                offer.signingKeyId,
                offer.signingThumbprint,
              ),
              options: {
                now_unix_seconds: offer.validFrom,
                required_claims: definition.claims
                  .filter((claim) => claim.required)
                  .map(declaredPath),
                format: "w3c_vc_data_model",
              },
            }).processed_payload as {
              credentialSubject?: unknown;
              cnf?: { jwk?: core.PublicJwk };
            };
            const completeClaims = materializedBusinessSubject(
              definition,
              complete.credentialSubject,
            );
            core.validateScalarSubject({
              definition,
              subject: completeClaims,
              mode: "complete",
            });
            if (
              !isDeepStrictEqual(completeClaims, offer.claims) ||
              !complete.cnf?.jwk ||
              core.publicJwkSha256Thumbprint(complete.cnf.jwk) !==
                offer.recipientThumbprint
            )
              throw Error();
            maximum = Math.max(maximum, offer.statusIndex);
          } else if (
            offer.committedCredential ||
            offer.credentialId ||
            offer.statusIndex !== null ||
            offer.completedNonceHash
          )
            throw Error();
        }
        if (!status || status.nextIndex <= maximum) throw Error();
        if (status) {
          if (
            !Number.isInteger(status.nextIndex) ||
            status.nextIndex < 0 ||
            status.nextIndex > 131072
          )
            throw Error();
          core.verifyBitstringStatusListCredential({
            compactJws: status.signedCredential,
            statusListJwk: identity.publicJwk,
          });
          const publicStatus = core.verifyCompactJwsJson({
            compactJws: status.signedCredential,
            publicJwk: identity.publicJwk,
          }).payload as core.BitstringStatusListCredentialPayload;
          if (
            publicStatus.issuer !== identity.did ||
            publicStatus.credentialSubject.id !==
              `${origin}/oid4vci/status/revocation.jwt#list` ||
            publicStatus.credentialSubject.statusPurpose !== "revocation"
          )
            throw Error();
          const revoked = revokedIndices(
            status,
            offers,
            origin,
            identity,
            bound!.credentialKeys,
          );
          const renewals = await tx.select().from(issuerRenewals).limit(10001);
          if (renewals.length > 10000) throw Error();
          for (const renewal of renewals) {
            credentialPublicKey(
              bound!.credentialKeys,
              identity,
              renewal.signingKeyId,
              renewal.signingThumbprint,
            );
            const predecessor = offers.find(
              (offer) => offer.id === renewal.predecessorId,
            );
            const successor = offers.find(
              (offer) => offer.id === renewal.successorId,
            );
            const closed = ["cancelled", "expired", "completed"].includes(
              renewal.phase,
            );
            const confirmed = ["retiring", "completed"].includes(renewal.phase);
            if (
              !predecessor ||
              predecessor.phase !== "issued" ||
              !/^[A-Za-z0-9_-]{22}$/.test(renewal.id) ||
              ![
                "awaiting_holder",
                "awaiting_receipt",
                "retiring",
                "completed",
                "cancelled",
                "expired",
              ].includes(renewal.phase) ||
              !/^[A-Za-z0-9_-]{43}$/.test(renewal.correlationHash) ||
              !/^[A-Za-z0-9_-]{43}$/.test(renewal.capabilityHash) ||
              !isDeepStrictEqual(renewal.definition, predecessor.definition) ||
              renewal.recipientThumbprint !== predecessor.recipientThumbprint ||
              renewal.input.version !== 1 ||
              renewal.input.predecessor_issuance_id !== predecessor.id ||
              renewal.input.offer_expires_at !== renewal.expiresAt ||
              (closed
                ? renewal.livePredecessorId !== null
                : renewal.livePredecessorId !== predecessor.id) ||
              (confirmed
                ? !Number.isSafeInteger(renewal.confirmedAt) ||
                  renewal.confirmedAt! < 0
                : renewal.confirmedAt !== null) ||
              (renewal.phase === "completed"
                ? !Number.isSafeInteger(renewal.completedAt) ||
                  renewal.completedAt! < renewal.confirmedAt! ||
                  !revoked.includes(predecessor.statusIndex!)
                : renewal.completedAt !== null)
            )
              throw Error();
            core.validateScalarSubject({
              definition: renewal.definition as core.ScalarCredentialDefinition,
              subject: renewal.input.claims as Record<string, unknown>,
              mode: "complete",
            });
            if (renewal.successorId) {
              if (
                !successor ||
                !renewal.receiptId ||
                !/^[A-Za-z0-9_-]{43}$/.test(renewal.receiptId) ||
                renewal.phase === "awaiting_holder" ||
                successor.configurationId !== renewal.input.configuration_id ||
                !isDeepStrictEqual(successor.definition, renewal.definition) ||
                !isDeepStrictEqual(successor.claims, renewal.input.claims) ||
                successor.validFrom !== renewal.input.valid_from ||
                successor.validUntil !== renewal.input.valid_until ||
                successor.expiresAt !== renewal.expiresAt ||
                successor.recipientThumbprint !== renewal.recipientThumbprint ||
                successor.signingKeyId !== renewal.signingKeyId ||
                successor.signingThumbprint !== renewal.signingThumbprint ||
                (confirmed && successor.phase !== "issued") ||
                (["cancelled", "expired"].includes(renewal.phase) &&
                  (successor.phase === "issued"
                    ? !revoked.includes(successor.statusIndex!)
                    : successor.phase !== "failed"))
              )
                throw Error();
            } else if (
              renewal.receiptId !== null ||
              !["awaiting_holder", "cancelled", "expired"].includes(
                renewal.phase,
              )
            )
              throw Error();
          }
        }
      });
    } catch {
      throw Error("issuer state unavailable");
    }
  }
  async issuanceStatus(
    id: string,
    origin: string,
    identity: RuntimeIdentity,
    clock: () => number,
    revoke: boolean,
  ) {
    return this.db.transaction(async (tx) => {
      const [offer] = await tx
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.id, id))
        .for("update");
      if (!offer) throw new VerificationError("ISSUER_ISSUANCE_NOT_FOUND", 404);
      if (offer.phase !== "issued")
        throw new VerificationError("ISSUER_ISSUANCE_NOT_ISSUED", 409);
      // Match issuance lock order. Never update an offer while holding only the
      // identity lock: issuance may already hold that offer and be waiting here.
      const [bound] = await tx
        .select()
        .from(issuerIdentity)
        .where(eq(issuerIdentity.singleton, 1))
        .for("update");
      assertIdentityRow(bound, origin, identity);
      const [stored] = await tx
        .select()
        .from(issuerStatus)
        .where(eq(issuerStatus.singleton, 1));
      if (!stored) throw Error("issuer state unavailable");
      const offers = await tx.select().from(issuerOffers).limit(10001);
      if (offers.length > 10000) throw Error("issuer state unavailable");
      const indices = revokedIndices(
        stored,
        offers,
        origin,
        identity,
        bound!.credentialKeys,
      );
      const revoked = indices.includes(offer.statusIndex!);
      let revokedAt = offer.revokedAt;
      if (revoke && !revoked) {
        revokedAt = clock();
        indices.push(offer.statusIndex!);
        const signedCredential = signIssuerStatus(
          origin,
          identity,
          revokedAt,
          core.encodeBitstringStatusList(131072, indices),
        );
        await tx
          .update(issuerStatus)
          .set({ signedCredential })
          .where(eq(issuerStatus.singleton, 1));
        await tx
          .update(issuerOffers)
          .set({ revokedAt })
          .where(eq(issuerOffers.id, id));
      }
      return {
        issuance_id: id,
        credential_id: offer.credentialId!,
        state: revoked || revoke ? "revoked" : "active",
        revoked_at: revokedAt,
        status_list_credential: `${origin}/oid4vci/status/revocation.jwt`,
        status_list_index: String(offer.statusIndex),
      };
    });
  }
  async createRenewal(
    value: typeof issuerRenewals.$inferInsert,
    origin: string,
    identity: RuntimeIdentity,
    clock: () => number,
    validate: (predecessor: typeof issuerOffers.$inferSelect) => void,
  ) {
    return this.db.transaction(async (tx) => {
      const [predecessor] = await tx
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.id, value.predecessorId))
        .for("update");
      if (!predecessor)
        throw new VerificationError("ISSUER_RENEWAL_NOT_FOUND", 404);
      if (predecessor.phase !== "issued")
        throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
      const [existing] = await tx
        .select()
        .from(issuerRenewals)
        .where(eq(issuerRenewals.correlationHash, value.correlationHash))
        .for("update");
      if (
        existing &&
        (!isDeepStrictEqual(existing.input, value.input) ||
          existing.predecessorId !== value.predecessorId)
      )
        throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
      if (existing) return existing;
      const [live] = await tx
        .select()
        .from(issuerRenewals)
        .where(eq(issuerRenewals.livePredecessorId, value.predecessorId))
        .for("update");
      const successor = live?.successorId
        ? (
            await tx
              .select()
              .from(issuerOffers)
              .where(eq(issuerOffers.id, live.successorId))
              .for("update")
          )[0]
        : undefined;
      const expired =
        live &&
        ["awaiting_holder", "awaiting_receipt"].includes(live.phase) &&
        live.expiresAt <= clock() &&
        successor?.phase !== "issued";
      if (live && !expired)
        throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
      const [bound] = await tx
        .select()
        .from(issuerIdentity)
        .where(eq(issuerIdentity.singleton, 1))
        .for("update");
      assertIdentityRow(bound, origin, identity);
      assertCredentialKeySelection(
        bound!.credentialKeys,
        identity,
        value.signingKeyId ?? null,
        value.signingThumbprint ?? null,
      );
      const [status] = await tx
        .select()
        .from(issuerStatus)
        .where(eq(issuerStatus.singleton, 1));
      if (!status) throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      const offers = await tx.select().from(issuerOffers).limit(10001);
      if (offers.length > 10000)
        throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      if (
        revokedIndices(
          status,
          offers,
          origin,
          identity,
          bound!.credentialKeys,
        ).includes(predecessor.statusIndex!)
      )
        throw new VerificationError("ISSUER_RENEWAL_NOT_CONFIRMABLE", 409);
      validate(predecessor);
      if (expired) {
        if (successor)
          await tx
            .update(issuerOffers)
            .set({ phase: "failed", tokenHash: null, tokenExpiresAt: null })
            .where(eq(issuerOffers.id, successor.id));
        await tx
          .update(issuerRenewals)
          .set({ phase: "expired", livePredecessorId: null })
          .where(eq(issuerRenewals.id, live.id));
      }
      const [count] = await tx
        .select({ count: sql<number>`count(*)::int` })
        .from(issuerRenewals);
      if (!count || count.count >= 10000)
        throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      if (value.expiresAt <= clock())
        throw new VerificationError("ISSUER_RENEWAL_EXPIRED", 410);
      const [created] = await tx
        .insert(issuerRenewals)
        .values(value)
        .returning();
      validate(predecessor);
      if (value.expiresAt <= clock())
        throw new VerificationError("ISSUER_RENEWAL_EXPIRED", 410);
      return created!;
    });
  }
  async renewal(id: string) {
    return (
      await this.db
        .select()
        .from(issuerRenewals)
        .where(eq(issuerRenewals.id, id))
    )[0];
  }
  async successorRenewal(id: string) {
    return (
      await this.db
        .select()
        .from(issuerRenewals)
        .where(eq(issuerRenewals.successorId, id))
    )[0];
  }
  async correlatedRenewal(hash: string) {
    return (
      await this.db
        .select()
        .from(issuerRenewals)
        .where(eq(issuerRenewals.correlationHash, hash))
    )[0];
  }
  private async renewalLedger(
    tx: IssuerTransaction,
    origin: string,
    identity: RuntimeIdentity,
  ) {
    const [bound] = await tx
      .select()
      .from(issuerIdentity)
      .where(eq(issuerIdentity.singleton, 1))
      .for("update");
    assertIdentityRow(bound, origin, identity);
    const [stored] = await tx
      .select()
      .from(issuerStatus)
      .where(eq(issuerStatus.singleton, 1));
    const offers = await tx.select().from(issuerOffers).limit(10001);
    if (!stored || offers.length > 10000)
      throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
    return {
      indices: revokedIndices(
        stored,
        offers,
        origin,
        identity,
        bound!.credentialKeys,
      ),
      offers,
    };
  }
  private async retireRenewalIssuance(
    tx: IssuerTransaction,
    offer: typeof issuerOffers.$inferSelect,
    indices: number[],
    origin: string,
    identity: RuntimeIdentity,
    clock: () => number,
  ) {
    if (offer.phase !== "issued" || offer.statusIndex === null)
      throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
    if (indices.includes(offer.statusIndex)) return;
    indices.push(offer.statusIndex);
    const revokedAt = clock();
    const signedCredential = signIssuerStatus(
      origin,
      identity,
      revokedAt,
      core.encodeBitstringStatusList(131072, indices),
    );
    await tx
      .update(issuerStatus)
      .set({ signedCredential })
      .where(eq(issuerStatus.singleton, 1));
    await tx
      .update(issuerOffers)
      .set({ revokedAt })
      .where(eq(issuerOffers.id, offer.id));
  }
  async renewalAction(
    initial: typeof issuerRenewals.$inferSelect,
    action: "confirm" | "cancel" | "status",
    nonceHash: string,
    origin: string,
    identity: RuntimeIdentity,
    clock: () => number,
    validate: (
      predecessor: typeof issuerOffers.$inferSelect,
      renewal: typeof issuerRenewals.$inferSelect,
    ) => void,
    receiptId?: string,
    successorId?: string,
  ) {
    const result = await this.db.transaction(async (tx) => {
      const [predecessor] = await tx
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.id, initial.predecessorId))
        .for("update");
      const [renewal] = await tx
        .select()
        .from(issuerRenewals)
        .where(eq(issuerRenewals.id, initial.id))
        .for("update");
      if (
        !predecessor ||
        !renewal ||
        renewal.predecessorId !== initial.predecessorId
      )
        throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      const successor = renewal.successorId
        ? (
            await tx
              .select()
              .from(issuerOffers)
              .where(eq(issuerOffers.id, renewal.successorId))
              .for("update")
          )[0]
        : undefined;
      const [nonce] = await tx
        .select()
        .from(issuerNonces)
        .where(eq(issuerNonces.hash, nonceHash))
        .for("update");
      const fresh = () => {
        if (!nonce || nonce.phase !== "active" || nonce.expiresAt <= clock())
          throw new VerificationError("ISSUER_RENEWAL_INVALID_PROOF");
        validate(predecessor, renewal);
      };
      fresh();
      const ledger = await this.renewalLedger(tx, origin, identity);
      let updated: typeof renewal | undefined = renewal;
      if (action === "confirm") {
        if (
          renewal.receiptId !== receiptId ||
          renewal.successorId !== successorId
        )
          throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
        if (["cancelled", "expired", "awaiting_holder"].includes(renewal.phase))
          throw new VerificationError("ISSUER_RENEWAL_NOT_CONFIRMABLE", 409);
        if (renewal.phase === "awaiting_receipt") {
          if (
            !successor ||
            successor.phase !== "issued" ||
            successor.validUntil <= clock() ||
            ledger.indices.includes(successor.statusIndex!)
          )
            throw new VerificationError("ISSUER_RENEWAL_NOT_CONFIRMABLE", 409);
          [updated] = await tx
            .update(issuerRenewals)
            .set({ phase: "retiring", confirmedAt: clock() })
            .where(eq(issuerRenewals.id, renewal.id))
            .returning();
        }
      } else if (action === "cancel") {
        if (["retiring", "completed"].includes(renewal.phase))
          throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
        if (!["cancelled", "expired"].includes(renewal.phase)) {
          if (successor?.phase === "issued")
            await this.retireRenewalIssuance(
              tx,
              successor,
              ledger.indices,
              origin,
              identity,
              clock,
            );
          else if (successor)
            await tx
              .update(issuerOffers)
              .set({ phase: "failed", tokenHash: null, tokenExpiresAt: null })
              .where(eq(issuerOffers.id, successor.id));
          [updated] = await tx
            .update(issuerRenewals)
            .set({ phase: "cancelled", livePredecessorId: null })
            .where(eq(issuerRenewals.id, renewal.id))
            .returning();
        }
      }
      fresh();
      if (
        action === "confirm" &&
        renewal.phase === "awaiting_receipt" &&
        successor!.validUntil <= clock()
      )
        throw new VerificationError("ISSUER_RENEWAL_NOT_CONFIRMABLE", 409);
      await tx
        .update(issuerNonces)
        .set({ phase: "consumed" })
        .where(eq(issuerNonces.hash, nonceHash));
      fresh();
      return updated!;
    });
    return result.phase === "retiring"
      ? await this.completeRenewal(result.id, origin, identity, clock)
      : result;
  }
  async completeRenewal(
    id: string,
    origin: string,
    identity: RuntimeIdentity,
    clock: () => number,
  ) {
    const initial = await this.renewal(id);
    if (!initial) throw new VerificationError("ISSUER_RENEWAL_NOT_FOUND", 404);
    return this.db.transaction(async (tx) => {
      const [predecessor] = await tx
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.id, initial.predecessorId))
        .for("update");
      const [renewal] = await tx
        .select()
        .from(issuerRenewals)
        .where(eq(issuerRenewals.id, id))
        .for("update");
      if (!predecessor || !renewal)
        throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      if (renewal.phase === "completed") return renewal;
      if (
        renewal.phase !== "retiring" ||
        renewal.confirmedAt === null ||
        !renewal.successorId ||
        !renewal.receiptId
      )
        throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      const ledger = await this.renewalLedger(tx, origin, identity);
      await this.retireRenewalIssuance(
        tx,
        predecessor,
        ledger.indices,
        origin,
        identity,
        clock,
      );
      const [completed] = await tx
        .update(issuerRenewals)
        .set({
          phase: "completed",
          livePredecessorId: null,
          completedAt: clock(),
        })
        .where(eq(issuerRenewals.id, id))
        .returning();
      return completed!;
    });
  }
  async reconcileRenewals(
    origin: string,
    identity: RuntimeIdentity,
    clock: () => number,
  ) {
    const pending = await this.db
      .select()
      .from(issuerRenewals)
      .where(eq(issuerRenewals.phase, "retiring"))
      .limit(10001);
    if (pending.length > 10000)
      throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
    for (const row of pending)
      await this.completeRenewal(row.id, origin, identity, clock);
  }
  async authorizeRenewal(
    initial: typeof issuerRenewals.$inferSelect,
    nonceHash: string,
    successor: typeof issuerOffers.$inferInsert,
    receiptId: string,
    origin: string,
    identity: RuntimeIdentity,
    clock: () => number,
    validate: (predecessor: typeof issuerOffers.$inferSelect) => void,
  ) {
    return this.db.transaction(async (tx) => {
      const [predecessor] = await tx
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.id, initial.predecessorId))
        .for("update");
      const [renewal] = await tx
        .select()
        .from(issuerRenewals)
        .where(eq(issuerRenewals.id, initial.id))
        .for("update");
      if (
        !predecessor ||
        !renewal ||
        renewal.predecessorId !== initial.predecessorId ||
        !isDeepStrictEqual(initial.input, renewal.input) ||
        !isDeepStrictEqual(initial.definition, renewal.definition)
      )
        throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
      if (!["awaiting_holder", "awaiting_receipt"].includes(renewal.phase))
        throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
      if (renewal.expiresAt <= clock())
        throw new VerificationError("ISSUER_RENEWAL_EXPIRED", 410);
      const [nonce] = await tx
        .select()
        .from(issuerNonces)
        .where(eq(issuerNonces.hash, nonceHash))
        .for("update");
      const fresh = () => {
        if (!nonce || nonce.phase !== "active" || nonce.expiresAt <= clock())
          throw new VerificationError("ISSUER_RENEWAL_INVALID_PROOF");
        if (renewal.expiresAt <= clock())
          throw new VerificationError("ISSUER_RENEWAL_EXPIRED", 410);
        validate(predecessor);
      };
      fresh();
      const [bound] = await tx
        .select()
        .from(issuerIdentity)
        .where(eq(issuerIdentity.singleton, 1))
        .for("update");
      assertIdentityRow(bound, origin, identity);
      assertCredentialKeySelection(
        bound!.credentialKeys,
        identity,
        renewal.signingKeyId,
        renewal.signingThumbprint,
      );
      if (
        successor.signingKeyId !== renewal.signingKeyId ||
        successor.signingThumbprint !== renewal.signingThumbprint
      )
        throw new VerificationError("ISSUER_RENEWAL_BINDING_MISMATCH", 409);
      const [status] = await tx
        .select()
        .from(issuerStatus)
        .where(eq(issuerStatus.singleton, 1));
      const offers = await tx.select().from(issuerOffers).limit(10001);
      if (!status || offers.length > 10000)
        throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      if (
        revokedIndices(
          status,
          offers,
          origin,
          identity,
          bound!.credentialKeys,
        ).includes(predecessor.statusIndex!)
      )
        throw new VerificationError("ISSUER_RENEWAL_NOT_CONFIRMABLE", 409);
      if (renewal.successorId) {
        const offer = offers.find((value) => value.id === renewal.successorId);
        if (!offer || offer.phase !== "offered" || offer.expiresAt <= clock())
          throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
      } else {
        if (offers.length >= 10000)
          throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
        await tx.insert(issuerOffers).values(successor);
        await tx
          .update(issuerRenewals)
          .set({
            phase: "awaiting_receipt",
            successorId: successor.id,
            receiptId,
          })
          .where(eq(issuerRenewals.id, renewal.id));
      }
      fresh();
      await tx
        .update(issuerNonces)
        .set({ phase: "consumed" })
        .where(eq(issuerNonces.hash, nonceHash));
      fresh();
    });
  }

  async createOffer(
    value: typeof issuerOffers.$inferInsert,
    validate: () => void,
    identity: RuntimeIdentity,
  ) {
    const offer = await this.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(368,1)`);
      // A linked retry may race redemption/issuance after authority was fetched.
      // Lock its retained offer before identity, matching issuance/revocation.
      const existing = value.verificationId
        ? (
            await tx
              .select()
              .from(issuerOffers)
              .where(eq(issuerOffers.verificationId, value.verificationId))
              .for("update")
          )[0]
        : undefined;
      const [binding] = await tx
        .select()
        .from(issuerIdentity)
        .where(eq(issuerIdentity.singleton, 1))
        .for("update");
      if (!binding) throw Error("issuer state unavailable");
      assertCredentialKeySelection(
        binding.credentialKeys,
        identity,
        value.signingKeyId ?? null,
        value.signingThumbprint ?? null,
      );
      if (existing) {
        if (
          existing.verificationCorrelationHash !==
            value.verificationCorrelationHash ||
          !isDeepStrictEqual(
            existing.verificationInput,
            value.verificationInput,
          ) ||
          !isDeepStrictEqual(
            existing.verificationBinding,
            value.verificationBinding,
          )
        )
          throw new VerificationError("ISSUER_BINDING_MISMATCH", 409);
        if (existing.phase !== "offered")
          throw new VerificationError("ISSUER_OFFER_CONSUMED", 409);
        validate();
        return existing;
      }
      const [count] = await tx
        .select({ count: sql<number>`count(*)::int` })
        .from(issuerOffers);
      if (!count || count.count >= 10000)
        throw Error("issuer offer capacity reached");
      validate();
      const [created] = await tx.insert(issuerOffers).values(value).returning();
      validate();
      return created!;
    });
    validate();
    return offer;
  }
  async linkedOffer(id: string) {
    return (
      await this.db
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.verificationId, id))
    )[0];
  }
  async offer(id: string) {
    return (
      await this.db.select().from(issuerOffers).where(eq(issuerOffers.id, id))
    )[0];
  }
  async redeem(
    codeHash: string,
    tokenHash: string,
    clock: () => number,
    validate: (offer: typeof issuerOffers.$inferSelect) => void = () => {},
  ) {
    let assertBinding = () => {};
    const result = await this.db.transaction(async (tx) => {
      const [offer] = await tx
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.codeHash, codeHash))
        .for("update");
      const now = clock();
      if (
        !offer ||
        offer.phase !== "offered" ||
        offer.expiresAt <= now ||
        offer.validUntil <= now
      )
        return undefined;
      const [bound] = await tx
        .select()
        .from(issuerIdentity)
        .where(eq(issuerIdentity.singleton, 1))
        .for("update");
      if (!bound) throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      if (bound.credentialKeys?.pending)
        throw new VerificationError("ISSUER_KEY_STAGING", 409);
      if (
        (offer.signingKeyId ?? bound.keyId) !==
        (bound.credentialKeys?.selectedKeyId ?? bound.keyId)
      )
        throw new VerificationError("ISSUER_KEY_SELECTION_CONFLICT", 409);
      assertBinding = () => validate(offer);
      assertBinding();
      const expires = Math.min(
        now + 300,
        offer.validUntil,
        Math.floor(offer.verificationBinding?.expiresAt ?? Infinity),
      );
      await tx
        .update(issuerOffers)
        .set({ phase: "redeemed", tokenHash, tokenExpiresAt: expires })
        .where(eq(issuerOffers.id, offer.id));
      if (offer.expiresAt <= clock() || offer.validUntil <= clock())
        throw new VerificationError("INVALID_GRANT");
      assertBinding();
      return { tokenExpiresAt: expires, offerExpiresAt: offer.expiresAt };
    });
    if (result) assertBinding();
    return result;
  }
  async tokenOffer(hash: string) {
    return (
      await this.db
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.tokenHash, hash))
    )[0];
  }
  async codeOffer(hash: string) {
    return (
      await this.db
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.codeHash, hash))
    )[0];
  }
  async nonce(hash: string, expiresAt: number, clock: () => number) {
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(368,1)`);
      await tx.delete(issuerNonces).where(lte(issuerNonces.expiresAt, clock()));
      const [count] = await tx
        .select({ count: sql<number>`count(*)::int` })
        .from(issuerNonces);
      if (!count || count.count >= 1024) throw Error("nonce capacity");
      await tx
        .insert(issuerNonces)
        .values({ hash, expiresAt, phase: "active" });
      if (expiresAt <= clock()) throw new VerificationError("INVALID_PROOF");
    });
    if (expiresAt <= clock()) throw new VerificationError("INVALID_PROOF");
  }
  async issue(input: {
    origin: string;
    identity: RuntimeIdentity;
    tokenHash: string;
    nonceHash: string;
    recipient: string;
    clock: () => number;
    validateAuthority: (offer: typeof issuerOffers.$inferSelect) => void;
    configurationId: string;
    sign: (
      offer: typeof issuerOffers.$inferSelect,
      index: number,
      signedStatus: string,
    ) => { credential: string; credentialId: string; status: string };
  }) {
    let assertFresh = () => {};
    const retainedOffer = await this.tokenOffer(input.tokenHash);
    const retainedRenewal = retainedOffer
      ? await this.successorRenewal(retainedOffer.id)
      : undefined;
    const result = await this.db.transaction(async (tx) => {
      // All renewal writers lock predecessor -> operation -> successor -> nonce
      // -> identity. Ordinary issuance retains its existing lock order.
      let renewal: typeof issuerRenewals.$inferSelect | undefined;
      let predecessor: typeof issuerOffers.$inferSelect | undefined;
      if (retainedRenewal) {
        [predecessor] = await tx
          .select()
          .from(issuerOffers)
          .where(eq(issuerOffers.id, retainedRenewal.predecessorId))
          .for("update");
        [renewal] = await tx
          .select()
          .from(issuerRenewals)
          .where(eq(issuerRenewals.id, retainedRenewal.id))
          .for("update");
        if (
          !predecessor ||
          !renewal ||
          renewal.successorId !== retainedOffer!.id ||
          renewal.phase !== "awaiting_receipt"
        )
          throw new VerificationError("ISSUER_RENEWAL_CONFLICT", 409);
      }
      const [offer] = await tx
        .select()
        .from(issuerOffers)
        .where(eq(issuerOffers.tokenHash, input.tokenHash))
        .for("update");
      let now = input.clock();
      if (offer) input.validateAuthority(offer);
      if (
        !offer ||
        !offer.tokenExpiresAt ||
        offer.tokenExpiresAt <= now ||
        offer.validUntil <= now ||
        offer.recipientThumbprint !== input.recipient ||
        offer.configurationId !== input.configurationId
      )
        return { error: "invalid_token" } as const;
      const [nonce] = await tx
        .select()
        .from(issuerNonces)
        .where(eq(issuerNonces.hash, input.nonceHash))
        .for("update");
      now = input.clock();
      if (offer.tokenExpiresAt <= now || offer.validUntil <= now)
        return { error: "invalid_token" } as const;
      if (!nonce || nonce.expiresAt <= now)
        return { error: "invalid_proof" } as const;
      input.validateAuthority(offer);
      assertFresh = () => {
        const current = input.clock();
        if (offer.tokenExpiresAt! <= current || offer.validUntil <= current)
          throw new VerificationError("INVALID_TOKEN");
        if (nonce.expiresAt <= current)
          throw new VerificationError("INVALID_PROOF");
        if (renewal && offer.phase !== "issued" && renewal.expiresAt <= current)
          throw new VerificationError("ISSUER_RENEWAL_EXPIRED", 410);
        input.validateAuthority(offer);
      };
      assertFresh();
      if (offer.phase === "issued") {
        if (
          offer.completedNonceHash !== input.nonceHash ||
          !offer.committedCredential ||
          !offer.credentialId ||
          offer.statusIndex === null
        )
          return { error: "invalid_proof" } as const;
        return { credential: offer.committedCredential } as const;
      }
      if (offer.phase !== "redeemed" || nonce.phase !== "active")
        return { error: "invalid_proof" } as const;
      const [bound] = await tx
        .select()
        .from(issuerIdentity)
        .where(eq(issuerIdentity.singleton, 1))
        .for("update");
      now = input.clock();
      assertIdentityRow(bound, input.origin, input.identity);
      assertCredentialKeySelection(
        bound!.credentialKeys,
        input.identity,
        offer.signingKeyId,
        offer.signingThumbprint,
      );
      input.validateAuthority(offer);
      if (offer.tokenExpiresAt <= now || offer.validUntil <= now)
        return { error: "invalid_token" } as const;
      if (nonce.expiresAt <= now) return { error: "invalid_proof" } as const;
      const [status] = await tx
        .select()
        .from(issuerStatus)
        .where(eq(issuerStatus.singleton, 1));
      if (!status) throw Error("issuer state unavailable");
      const offers = await tx.select().from(issuerOffers).limit(10001);
      try {
        if (offers.length > 10000) throw Error();
        const revoked = revokedIndices(
          status,
          offers,
          input.origin,
          input.identity,
          bound!.credentialKeys,
        );
        if (predecessor && revoked.includes(predecessor.statusIndex!))
          throw new VerificationError("ISSUER_RENEWAL_NOT_CONFIRMABLE", 409);
      } catch (error) {
        if (error instanceof VerificationError) throw error;
        throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      }
      assertFresh();
      const index = status.nextIndex;
      if (index >= 131072) return { error: "temporarily_unavailable" } as const;
      const signed = input.sign(offer, index, status.signedCredential);
      await tx
        .insert(issuerStatus)
        .values({
          singleton: 1,
          nextIndex: index + 1,
          signedCredential: signed.status,
        })
        .onConflictDoUpdate({
          target: issuerStatus.singleton,
          set: { nextIndex: index + 1, signedCredential: signed.status },
        });
      await tx
        .update(issuerNonces)
        .set({ phase: "consumed" })
        .where(eq(issuerNonces.hash, input.nonceHash));
      await tx
        .update(issuerOffers)
        .set({
          phase: "issued",
          committedCredential: signed.credential,
          credentialId: signed.credentialId,
          statusIndex: index,
          completedNonceHash: input.nonceHash,
        })
        .where(eq(issuerOffers.id, offer.id));
      assertFresh();
      return { credential: signed.credential } as const;
    });
    if (result.credential) assertFresh();
    return result;
  }
  async status(
    origin: string,
    identity: RuntimeIdentity,
    refresh: (signed: string) => string,
  ) {
    return this.db.transaction(async (tx) => {
      const [bound] = await tx
        .select()
        .from(issuerIdentity)
        .where(eq(issuerIdentity.singleton, 1))
        .for("update");
      assertIdentityRow(bound, origin, identity);
      const [stored] = await tx
        .select()
        .from(issuerStatus)
        .where(eq(issuerStatus.singleton, 1));
      if (!stored) throw new VerificationError("ISSUER_STATE_UNAVAILABLE", 503);
      const offers = await tx.select().from(issuerOffers).limit(10001);
      if (offers.length > 10000) throw Error("issuer state unavailable");
      revokedIndices(stored, offers, origin, identity, bound!.credentialKeys);
      const signed = refresh(stored.signedCredential);
      await tx
        .update(issuerStatus)
        .set({ signedCredential: signed })
        .where(eq(issuerStatus.singleton, 1));
      return signed;
    });
  }
  private closed?: Promise<void>;
  close() {
    return (this.closed ??= this.pool.end());
  }
}
