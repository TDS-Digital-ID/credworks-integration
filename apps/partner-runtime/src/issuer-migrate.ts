import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { fileURLToPath } from "node:url";
const connectionString = process.env.PARTNER_ISSUER_DATABASE_URL;
if (!connectionString) throw Error("PARTNER_ISSUER_DATABASE_URL is required");
const pool = new Pool({
  connectionString,
  max: 2,
  connectionTimeoutMillis: 5000,
  statement_timeout: 5000,
  query_timeout: 6000,
});
try {
  await migrate(drizzle(pool), {
    migrationsFolder: fileURLToPath(new URL("../drizzle", import.meta.url)),
    migrationsSchema: "partner_runtime_migrations",
    migrationsTable: "issuer_migrations",
  });
} finally {
  await pool.end();
}
