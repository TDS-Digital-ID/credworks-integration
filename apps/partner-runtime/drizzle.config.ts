import { defineConfig } from "drizzle-kit";
const url = process.env.PARTNER_ISSUER_DATABASE_URL;
if (!url) throw Error("PARTNER_ISSUER_DATABASE_URL is required");
export default defineConfig({
  dialect: "postgresql",
  dbCredentials: { url },
  out: "./drizzle",
  schema: "./src/issuer-schema.ts",
  strict: true,
});
