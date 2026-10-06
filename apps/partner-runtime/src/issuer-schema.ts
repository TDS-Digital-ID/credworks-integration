import { pgTable, text, integer, jsonb } from "drizzle-orm/pg-core";
import type { HolderBinding } from "./sessions.js";
import type { CredentialKeyState } from "./issuer-keys.js";

export const issuerIdentity = pgTable("partner_issuer_identity", {
  singleton: integer("singleton").primaryKey(),
  origin: text("origin").notNull(),
  did: text("did").notNull(),
  keyId: text("key_id").notNull(),
  publicThumbprint: text("public_thumbprint").notNull(),
  credentialKeys: jsonb("credential_keys").$type<CredentialKeyState>(),
});
export const issuerOffers = pgTable("partner_issuer_offers", {
  id: text("id").primaryKey(),
  codeHash: text("code_hash").notNull().unique(),
  expiresAt: integer("expires_at").notNull(),
  configurationId: text("configuration_id").notNull(),
  definition: jsonb("definition").notNull(),
  claims: jsonb("claims").notNull(),
  validFrom: integer("valid_from").notNull(),
  validUntil: integer("valid_until").notNull(),
  recipientThumbprint: text("recipient_thumbprint").notNull(),
  signingKeyId: text("signing_key_id"),
  signingThumbprint: text("signing_thumbprint"),
  phase: text("phase").notNull(),
  tokenHash: text("token_hash").unique(),
  tokenExpiresAt: integer("token_expires_at"),
  committedCredential: text("committed_credential"),
  credentialId: text("credential_id").unique(),
  statusIndex: integer("status_index").unique(),
  completedNonceHash: text("completed_nonce_hash"),
  revokedAt: integer("revoked_at"),
  verificationId: text("verification_id").unique(),
  verificationCorrelationHash: text("verification_correlation_hash"),
  verificationBinding: jsonb("verification_binding").$type<HolderBinding>(),
  verificationInput:
    jsonb("verification_input").$type<Record<string, unknown>>(),
});
export const issuerNonces = pgTable("partner_issuer_nonces", {
  hash: text("hash").primaryKey(),
  expiresAt: integer("expires_at").notNull(),
  phase: text("phase").notNull(),
});
export const issuerStatus = pgTable("partner_issuer_status", {
  singleton: integer("singleton").primaryKey(),
  nextIndex: integer("next_index").notNull(),
  signedCredential: text("signed_credential").notNull(),
});

export const issuerRenewals = pgTable("partner_issuer_renewals", {
  id: text("id").primaryKey(),
  correlationHash: text("correlation_hash").notNull().unique(),
  capabilityHash: text("capability_hash").notNull(),
  predecessorId: text("predecessor_id")
    .notNull()
    .references(() => issuerOffers.id),
  livePredecessorId: text("live_predecessor_id")
    .unique()
    .references(() => issuerOffers.id),
  successorId: text("successor_id")
    .unique()
    .references(() => issuerOffers.id),
  input: jsonb("input").$type<Record<string, unknown>>().notNull(),
  definition: jsonb("definition").notNull(),
  recipientThumbprint: text("recipient_thumbprint").notNull(),
  signingKeyId: text("signing_key_id"),
  signingThumbprint: text("signing_thumbprint"),
  expiresAt: integer("expires_at").notNull(),
  phase: text("phase").notNull(),
  receiptId: text("receipt_id").unique(),
  confirmedAt: integer("confirmed_at"),
  completedAt: integer("completed_at"),
});
