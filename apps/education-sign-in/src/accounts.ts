import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { pgTable, text, uuid, timestamp, unique } from "drizzle-orm/pg-core";
import { and, eq } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
export const accounts = pgTable(
  "education_accounts",
  {
    id: uuid("id").primaryKey(),
    issuer: text("issuer").notNull(),
    studentId: text("student_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    unique("education_account_identity").on(table.issuer, table.studentId),
  ],
);
export async function openAccounts(database: string) {
  const pool = new Pool({
    connectionString: database,
    max: 5,
    connectionTimeoutMillis: 3000,
    statement_timeout: 3000,
    query_timeout: 4000,
  });
  const db = drizzle(pool);
  try {
    await migrate(db, {
      migrationsFolder: fileURLToPath(new URL("../drizzle", import.meta.url)),
    });
  } catch (error) {
    await pool.end();
    throw error;
  }
  return {
    async account(issuer: string, studentId: string) {
      const inserted = await db
        .insert(accounts)
        .values({ id: randomUUID(), issuer, studentId })
        .onConflictDoNothing()
        .returning({ id: accounts.id });
      if (inserted[0]) return inserted[0].id;
      const [existing] = await db
        .select({ id: accounts.id })
        .from(accounts)
        .where(
          and(eq(accounts.issuer, issuer), eq(accounts.studentId, studentId)),
        )
        .limit(1);
      if (!existing) throw Error("account unavailable");
      return existing.id;
    },
    close: () => pool.end(),
  };
}
