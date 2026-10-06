import { createHash } from 'node:crypto';
import { db, id } from './db.js';
import { permissionsFor } from './permissions.js';

// Support sessions: the only way a platform admin sees inside a school.
// One is started on purpose (with a reason), belongs to the sign-in
// session it was started from, lasts at most an hour, is read-only
// unless changes were explicitly allowed (support:write), and every
// request made through it is audited (tenant.js, audit.js).

export const SUPPORT_SESSION_TTL_MS = 60 * 60 * 1000;
const hashToken = token => createHash('sha256').update(String(token)).digest('hex');

/**
 * The open support session for this request's sign-in session, or null.
 * Re-checks every time that the person is still an active platform admin
 * allowed to support schools, and that the school is still active.
 */
export async function activeSupportSession(req) {
  if (req.supportSessionChecked) return req.supportSession ?? null;
  req.supportSessionChecked = true;
  if (!req.sessionToken || !req.user) return null;
  const row = await db.prepare(`
    SELECT ss.id, ss.school_id AS "schoolId", s.name AS "schoolName", ss.reason, ss.allow_changes AS "allowChanges",
      ss.started_at AS "startedAt", ss.expires_at AS "expiresAt", pa.role AS "platformRole"
    FROM support_sessions ss
    JOIN schools s ON s.id=ss.school_id AND s.status='ACTIVE'
    JOIN platform_admins pa ON pa.user_id=ss.platform_user_id AND pa.status='ACTIVE'
    WHERE ss.session_token_hash=? AND ss.platform_user_id=? AND ss.ended_at IS NULL AND ss.expires_at > ?`)
    .get(hashToken(req.sessionToken), req.user.id, Date.now());
  if (!row) return null;
  const permissions = permissionsFor(row.platformRole);
  if (!permissions.includes('support:start')) return null;
  req.supportSession = {
    ...row,
    startedAt: Number(row.startedAt),
    expiresAt: Number(row.expiresAt),
    // Changes need the permission both when the session started and now.
    allowChanges: Boolean(row.allowChanges) && permissions.includes('support:write'),
  };
  return req.supportSession;
}

/** Ends any open session for this sign-in session, then starts a new one. */
export async function startSupportSession({ userId, sessionToken, schoolId, reason, allowChanges, ip }) {
  await endSupportSession(sessionToken, 'REPLACED');
  const now = Date.now();
  const session = { id: id('support'), startedAt: now, expiresAt: now + SUPPORT_SESSION_TTL_MS };
  await db.prepare(`
    INSERT INTO support_sessions (id,platform_user_id,school_id,session_token_hash,reason,allow_changes,ip_address,started_at,expires_at)
    VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(session.id, userId, schoolId, hashToken(sessionToken), reason, allowChanges ? 1 : 0, ip ?? null, session.startedAt, session.expiresAt);
  return session;
}

/** Ends this sign-in session's open support session; returns it (or null if there was none). */
export async function endSupportSession(sessionToken, endReason = 'EXITED') {
  if (!sessionToken) return null;
  return await db.prepare(`
    UPDATE support_sessions SET ended_at=?, end_reason=? WHERE session_token_hash=? AND ended_at IS NULL
    RETURNING id, school_id AS "schoolId", started_at AS "startedAt"`)
    .get(Date.now(), endReason, hashToken(sessionToken)) || null;
}

/** Ends every open support session into a school (e.g. it was suspended) or by a person (disabled). */
export async function endSupportSessionsWhere({ schoolId, userId }, endReason) {
  if (schoolId) await db.prepare('UPDATE support_sessions SET ended_at=?, end_reason=? WHERE school_id=? AND ended_at IS NULL').run(Date.now(), endReason, schoolId);
  if (userId) await db.prepare('UPDATE support_sessions SET ended_at=?, end_reason=? WHERE platform_user_id=? AND ended_at IS NULL').run(Date.now(), endReason, userId);
}
