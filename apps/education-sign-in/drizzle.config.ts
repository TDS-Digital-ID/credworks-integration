import { defineConfig } from "drizzle-kit";
export default defineConfig({
  dialect: "postgresql",
  schema: "./src/accounts.ts",
  out: "./drizzle",
  strict: true,
  dbCredentials: { url: process.env.EDUCATION_APP_DATABASE_URL ?? "" },
});
