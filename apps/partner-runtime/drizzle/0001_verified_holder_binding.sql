ALTER TABLE "partner_issuer_offers" ADD COLUMN "verification_id" text;--> statement-breakpoint
ALTER TABLE "partner_issuer_offers" ADD COLUMN "verification_correlation_hash" text;--> statement-breakpoint
ALTER TABLE "partner_issuer_offers" ADD COLUMN "verification_binding" jsonb;--> statement-breakpoint
ALTER TABLE "partner_issuer_offers" ADD COLUMN "verification_input" jsonb;--> statement-breakpoint
ALTER TABLE "partner_issuer_offers" ADD CONSTRAINT "partner_issuer_offers_verification_id_unique" UNIQUE("verification_id");