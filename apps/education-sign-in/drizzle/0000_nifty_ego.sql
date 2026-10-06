CREATE TABLE "education_accounts" (
	"id" uuid PRIMARY KEY NOT NULL,
	"issuer" text NOT NULL,
	"student_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "education_account_identity" UNIQUE("issuer","student_id")
);
