ALTER TABLE "partner_issuer_identity" ADD COLUMN "credential_keys" jsonb;--> statement-breakpoint
ALTER TABLE "partner_issuer_offers" ADD COLUMN "signing_key_id" text;--> statement-breakpoint
ALTER TABLE "partner_issuer_offers" ADD COLUMN "signing_thumbprint" text;--> statement-breakpoint
ALTER TABLE "partner_issuer_renewals" ADD COLUMN "signing_key_id" text;--> statement-breakpoint
ALTER TABLE "partner_issuer_renewals" ADD COLUMN "signing_thumbprint" text;--> statement-breakpoint
UPDATE "partner_issuer_offers" SET "signing_key_id" = i."key_id", "signing_thumbprint" = i."public_thumbprint" FROM "partner_issuer_identity" i WHERE i."singleton" = 1;--> statement-breakpoint
UPDATE "partner_issuer_renewals" SET "signing_key_id" = i."key_id", "signing_thumbprint" = i."public_thumbprint" FROM "partner_issuer_identity" i WHERE i."singleton" = 1;
