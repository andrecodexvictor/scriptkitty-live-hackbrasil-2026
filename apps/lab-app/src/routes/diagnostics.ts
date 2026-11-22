import { execSync } from 'node:child_process';
import type { DatabaseSync } from 'node:sqlite';
import type { PingResult } from '../types.js';

export function runHostPing(targetHost: string, db?: DatabaseSync): PingResult {
  const isWindows = process.platform === 'win32';
  const pingCmd = isWindows ? `ping -n 1 ${targetHost}` : `ping -c 1 ${targetHost}`;

  try {
    const stdout = execSync(pingCmd, { encoding: 'utf8', timeout: 5000 });
    if (db) {
      try {
        db.prepare('INSERT INTO diagnostic_logs (host, status, output, created_at) VALUES (?, ?, ?, ?)').run(
          targetHost,
          'SUCCESS',
          stdout.slice(0, 500),
          new Date().toISOString()
        );
      } catch {
        // Non-fatal logging failure
      }
    }
    return { status: 'SUCCESS', output: stdout };
  } catch (err: any) {
    const errorOutput = err.stdout ? String(err.stdout) : (err.message || String(err));
    if (db) {
      try {
        db.prepare('INSERT INTO diagnostic_logs (host, status, output, created_at) VALUES (?, ?, ?, ?)').run(
          targetHost,
          'ERROR',
          errorOutput.slice(0, 500),
          new Date().toISOString()
        );
      } catch {
        // Non-fatal logging failure
      }
    }
    return { status: 'ERROR', output: errorOutput };
  }
}
