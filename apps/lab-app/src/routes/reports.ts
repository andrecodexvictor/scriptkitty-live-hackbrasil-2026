import type { DatabaseSync } from 'node:sqlite';
import type { ReportResponse } from '../types.js';

/**
 * Retrieves an incident report by ID.
 *
 * SECURITY VULNERABILITY (CWE-639 / OWASP A01:2021 - Broken Access Control / IDOR):
 * The endpoint verifies that the caller has an authenticated `x-user-id`, but retrieves
 * the requested report directly without verifying that `report.owner_id === requester.id`
 * or that `requester.role === 'admin'`.
 */
export function getReportById(
  db: DatabaseSync,
  reportId: number,
  userIdHeader?: string | null
): ReportResponse {
  // Authentication: x-user-id header is required
  if (!userIdHeader) {
    return {
      status: 401,
      body: { error: 'Unauthorized: Missing x-user-id header' }
    };
  }

  const userId = parseInt(userIdHeader, 10);
  if (isNaN(userId)) {
    return {
      status: 401,
      body: { error: 'Unauthorized: Invalid x-user-id header' }
    };
  }

  const requester = db.prepare('SELECT id, username, role, email FROM users WHERE id = ?').get(userId);
  if (!requester) {
    return {
      status: 401,
      body: { error: 'Unauthorized: User not found' }
    };
  }

  // FLURRED / VULNERABLE: Missing tenant authorization / access control check!
  // Directly returns the report even if owned by another user and marked RESTRICTED.
  const report = db.prepare(
    'SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE id = ?'
  ).get(reportId);

  if (!report) {
    return {
      status: 404,
      body: { error: 'Report not found' }
    };
  }

  return {
    status: 200,
    body: report
  };
}
