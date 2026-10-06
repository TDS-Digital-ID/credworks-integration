CREATE TABLE "partner_issuer_renewals" (
	"id" text PRIMARY KEY NOT NULL,
	"correlation_hash" text NOT NULL,
	"capability_hash" text NOT NULL,
	"predecessor_id" text NOT NULL,
	"live_predecessor_id" text,
	"successor_id" text,
	"input" jsonb NOT NULL,
	"definition" jsonb NOT NULL,
	"recipient_thumbprint" text NOT NULL,
	"expires_at" integer NOT NULL,
	"phase" text NOT NULL,
	"receipt_id" text,
	"confirmed_at" integer,
	"completed_at" integer,
	CONSTRAINT "partner_issuer_renewals_correlation_hash_unique" UNIQUE("correlation_hash"),
	CONSTRAINT "partner_issuer_renewals_live_predecessor_id_unique" UNIQUE("live_predecessor_id"),
	CONSTRAINT "partner_issuer_renewals_successor_id_unique" UNIQUE("successor_id"),
	CONSTRAINT "partner_issuer_renewals_receipt_id_unique" UNIQUE("receipt_id")
);
--> statement-breakpoint
ALTER TABLE "partner_issuer_renewals" ADD CONSTRAINT "partner_issuer_renewals_predecessor_id_partner_issuer_offers_id_fk" FOREIGN KEY ("predecessor_id") REFERENCES "public"."partner_issuer_offers"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "partner_issuer_renewals" ADD CONSTRAINT "partner_issuer_renewals_live_predecessor_id_partner_issuer_offers_id_fk" FOREIGN KEY ("live_predecessor_id") REFERENCES "public"."partner_issuer_offers"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "partner_issuer_renewals" ADD CONSTRAINT "partner_issuer_renewals_successor_id_partner_issuer_offers_id_fk" FOREIGN KEY ("successor_id") REFERENCES "public"."partner_issuer_offers"("id") ON DELETE no action ON UPDATE no action;