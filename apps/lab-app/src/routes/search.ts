import type { DatabaseSync } from 'node:sqlite';
import '../types.js';

/**
 * Searches incidents by keyword matching title or description.
 *
 * SECURITY VULNERABILITY (CWE-89 / OWASP A03:2021 - SQL Injection):
 * Direct string interpolation of the user-supplied query string into the raw SQL query
 * allows arbitrary SQL execution (e.g., UNION SELECT credential extraction or boolean bypass).
 */
export function searchIncidents(db: DatabaseSync, query: string): Record<string, any>[] {
  // FLURRED / VULNERABLE: Direct string interpolation into raw SQL statement
  const rawSql = `SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE title LIKE '%${query}%' OR description LIKE '%${query}%'`;
  const stmt = db.prepare(rawSql);
  return stmt.all();
}
