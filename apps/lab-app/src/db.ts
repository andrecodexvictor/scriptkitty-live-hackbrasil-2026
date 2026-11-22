import { DatabaseSync } from 'node:sqlite';
import './types.js';

/**
 * Creates and initializes the SQLite database with seed data.
 * Defaults to in-memory (`:memory:`) for test isolation and performance.
 */
export function createDatabase(dbPath: string = ':memory:'): DatabaseSync {
  const db = new DatabaseSync(dbPath);

  // Initialize schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'auditor', 'user')),
      api_key TEXT NOT NULL,
      email TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      classification TEXT NOT NULL CHECK(classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
      description TEXT NOT NULL,
      system_target TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    );

    CREATE VIEW IF NOT EXISTS incident_reports AS SELECT * FROM incidents;

    CREATE TABLE IF NOT EXISTS diagnostic_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host TEXT NOT NULL,
      status TEXT NOT NULL,
      output TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  // Seed users table
  const insertUser = db.prepare(`
    INSERT OR IGNORE INTO users (id, username, role, api_key, email, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  insertUser.run(1, 'secops-admin', 'admin', 'sk_live_admin_secret_9988aabbcc', 'admin@scriptkitty.internal', '2026-11-01T00:00:00Z');
  insertUser.run(2, 'alice-dev', 'user', 'sk_live_alice_key_1122334455', 'alice@scriptkitty.internal', '2026-11-01T00:00:00Z');
  insertUser.run(3, 'bob-ops', 'user', 'sk_live_bob_key_5566778899', 'bob@scriptkitty.internal', '2026-11-01T00:00:00Z');

  // Seed incidents table
  const insertIncident = db.prepare(`
    INSERT OR IGNORE INTO incidents (id, owner_id, title, severity, classification, description, system_target, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertIncident.run(
    101,
    2,
    'API Gateway Latency Spike',
    'MEDIUM',
    'INTERNAL',
    'Minor latency spike observed in staging cluster.',
    'gateway.staging.internal',
    '2026-11-02T10:00:00Z'
  );

  insertIncident.run(
    102,
    3,
    'Production Database Breach Assessment',
    'CRITICAL',
    'RESTRICTED',
    'Root credentials exposed in backup artifact. Database master key: DB_MASTER_SECRET_2026',
    'db-master.prod.internal',
    '2026-11-03T14:30:00Z'
  );

  insertIncident.run(
    103,
    1,
    'Quarterly Firewall Rule Audit',
    'LOW',
    'PUBLIC',
    'Scheduled routine audit of edge firewall rules.',
    'firewall.edge.internal',
    '2026-11-04T08:00:00Z'
  );

  // Seed diagnostic_logs table
  const insertDiag = db.prepare(`
    INSERT OR IGNORE INTO diagnostic_logs (id, host, status, output, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  insertDiag.run(1, '127.0.0.1', 'SUCCESS', 'Ping OK', '2026-11-01T00:00:00Z');

  return db;
}
