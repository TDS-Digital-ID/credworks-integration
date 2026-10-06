CREATE TABLE "partner_issuer_identity" (
	"singleton" integer PRIMARY KEY NOT NULL,
	"origin" text NOT NULL,
	"did" text NOT NULL,
	"key_id" text NOT NULL,
	"public_thumbprint" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "partner_issuer_nonces" (
	"hash" text PRIMARY KEY NOT NULL,
	"expires_at" integer NOT NULL,
	"phase" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "partner_issuer_offers" (
	"id" text PRIMARY KEY NOT NULL,
	"code_hash" text NOT NULL,
	"expires_at" integer NOT NULL,
	"configuration_id" text NOT NULL,
	"definition" jsonb NOT NULL,
	"claims" jsonb NOT NULL,
	"valid_from" integer NOT NULL,
	"valid_until" integer NOT NULL,
	"recipient_thumbprint" text NOT NULL,
	"phase" text NOT NULL,
	"token_hash" text,
	"token_expires_at" integer,
	"committed_credential" text,
	"credential_id" text,
	"status_index" integer,
	"completed_nonce_hash" text,
	CONSTRAINT "partner_issuer_offers_code_hash_unique" UNIQUE("code_hash"),
	CONSTRAINT "partner_issuer_offers_token_hash_unique" UNIQUE("token_hash"),
	CONSTRAINT "partner_issuer_offers_credential_id_unique" UNIQUE("credential_id"),
	CONSTRAINT "partner_issuer_offers_status_index_unique" UNIQUE("status_index")
);
--> statement-breakpoint
CREATE TABLE "partner_issuer_status" (
	"singleton" integer PRIMARY KEY NOT NULL,
	"next_index" integer NOT NULL,
	"signed_credential" text NOT NULL
);
