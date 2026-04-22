/**
 * Postgres connection pool and migration runner.
 * Only active when DATABASE_URL is set; otherwise all functions are no-ops.
 */

import pg from "pg";
import { readFileSync, readdirSync } from "fs";
import { join } from "path";

let pool: pg.Pool | null = null;

export function isDbConfigured(): boolean {
  return !!process.env.DATABASE_URL;
}

export function getPool(): pg.Pool {
  if (!pool) {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is not set");
    }
    pool = new pg.Pool({
      connectionString: process.env.DATABASE_URL,
      max: parseInt(process.env.PG_POOL_MAX || "10", 10),
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
  }
  return pool;
}

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  return getPool().query<T>(text, params);
}

export async function runMigrations(): Promise<void> {
  if (!isDbConfigured()) return;

  const client = await getPool().connect();
  try {
    // Ensure schema_migrations table exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version   INTEGER PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    // Check which migrations have been applied
    const applied = await client.query<{ version: number }>(
      "SELECT version FROM schema_migrations ORDER BY version",
    );
    const appliedVersions = new Set(applied.rows.map((r) => r.version));

    // Discover all migration files (NNN-name.sql, sorted by number)
    const migrationsDir = join(
      import.meta.dirname ?? process.cwd(),
      "migrations",
    );
    const files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith(".sql") && /^\d{3}-/.test(f))
      .sort();

    for (const file of files) {
      const version = parseInt(file.slice(0, 3), 10);
      if (appliedVersions.has(version)) continue;

      const sql = readFileSync(join(migrationsDir, file), "utf-8");
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query(
          "INSERT INTO schema_migrations (version) VALUES ($1)",
          [version],
        );
        await client.query("COMMIT");
        console.log(`  Migration ${file} applied successfully`);
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      }
    }
  } finally {
    client.release();
  }
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
