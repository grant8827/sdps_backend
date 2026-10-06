import { createHash } from 'node:crypto';
import { pool } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { requirePlatformPermission } from './permissions.js';

// Platform → Security Center: sign-in failures and lockouts, suspicious
// patterns, who holds an admin session right now (with a way to end
// one), two-step verification coverage, and recent security changes.
//
// Never returned: passwords or hashes, session tokens (a session is
// identified by the SHA-256 of its token, which can't be used to sign
// in), two-step secrets or recovery codes.

const hoursAgo = hours => new Date(Date.now() - hours * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
const SESSION_ID = `encode(sha256(convert_to(s.token, 'UTF8')), 'hex')`;

export const SECURITY_CHANGE_ACTIONS = [
  'PASSWORD_CHANGED', 'PASSWORD_RESET', 'PASSWORD_RESET_REQUESTED', 'ACCOUNT_SET_UP', 'ACCOUNT_LINK_SENT',
  'MFA_ENABLED', 'MFA_DISABLED', 'MFA_RESET', 'MFA_RECOVERY_CODES_REPLACED',
  'ROLE_CHANGED', 'PLATFORM_ADMIN_ADDED', 'PLATFORM_ADMIN_DISABLED', 'PLATFORM_ADMIN_REACTIVATED',
  'SESSION_ENDED_BY_PLATFORM', 'SUPPORT_SESSION_STARTED', 'LEGAL_HOLD_SET', 'LEGAL_HOLD_RELEASED',
];
const LOGIN_ACTIONS = { success: ['SIGNED_IN'], failed: ['SIGN_IN_FAILED'], locked: ['SIGN_IN_LOCKED_OUT'] };

/** Two-step verification coverage by group of active accounts. */
export async function mfaCoverage() {
  const { rows } = await pool.query(`
    WITH people AS (
      SELECT u.id, u.mfa_enabled_at IS NOT NULL AS mfa,
        CASE
          WHEN EXISTS (SELECT 1 FROM platform_admins pa WHERE pa.user_id=u.id AND pa.status='ACTIVE') THEN 'platformAdmins'
          WHEN EXISTS (SELECT 1 FROM memberships m JOIN schools sc ON sc.id=m.school_id AND sc.status='ACTIVE' WHERE m.user_id=u.id AND m.status='ACTIVE' AND m.role IN ('school_admin','staff'))
            OR EXISTS (SELECT 1 FROM district_memberships dm WHERE dm.user_id=u.id AND dm.status='ACTIVE') THEN 'schoolAdmins'
          WHEN EXISTS (SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.status='ACTIVE' AND m.role='teacher') THEN 'teachers'
          WHEN EXISTS (SELECT 1 FROM memberships m WHERE m.user_id=u.id AND m.status='ACTIVE' AND m.role='parent') THEN 'parents'
        END AS grp
      FROM users u WHERE u.active=1
    )
    SELECT grp, COUNT(*)::int AS total, COUNT(*) FILTER (WHERE mfa)::int AS "withMfa" FROM people WHERE grp IS NOT NULL GROUP BY grp`);
  const result = { platformAdmins: { total: 0, withMfa: 0 }, schoolAdmins: { total: 0, withMfa: 0 }, teachers: { total: 0, withMfa: 0 }, parents: { total: 0, withMfa: 0 } };
  for (const row of rows) result[row.grp] = { total: row.total, withMfa: row.withMfa };
  return result;
}

export function registerPlatformSecurity(router) {
  router.get('/security/overview', requirePlatformPermission('security:view'), asyncRoute(async (req, res) => {
    const day = hoursAgo(24);
    const week = hoursAgo(24 * 7);
    const { rows: [counts] } = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE action='SIGN_IN_FAILED' AND created_at >= $1)::int AS "failedDay",
        COUNT(*) FILTER (WHERE action='SIGN_IN_FAILED')::int AS "failedWeek",
        COUNT(*) FILTER (WHERE action='SIGN_IN_LOCKED_OUT' AND created_at >= $1)::int AS "lockoutsDay",
        COUNT(*) FILTER (WHERE action='SIGN_IN_LOCKED_OUT')::int AS "lockoutsWeek",
        COUNT(*) FILTER (WHERE action='MFA_CODE_FAILED')::int AS "mfaFailuresWeek",
        COUNT(*) FILTER (WHERE action='SIGNED_IN' AND created_at >= $1)::int AS "signInsDay"
      FROM audit_logs WHERE created_at >= $2 AND action IN ('SIGN_IN_FAILED','SIGN_IN_LOCKED_OUT','MFA_CODE_FAILED','SIGNED_IN')`, [day, week]);
    // Suspicious: one account name tried many times, or one address trying many account names.
    const { rows: targetedAccounts } = await pool.query(`
      SELECT details::jsonb->>'identifier' AS identifier, COUNT(*)::int AS failures, COUNT(DISTINCT ip_address)::int AS addresses
      FROM audit_logs WHERE action='SIGN_IN_FAILED' AND created_at >= $1
      GROUP BY 1 HAVING COUNT(*) >= 5 ORDER BY failures DESC LIMIT 10`, [day]);
    const { rows: sprayingAddresses } = await pool.query(`
      SELECT ip_address AS address, COUNT(*)::int AS failures, COUNT(DISTINCT details::jsonb->>'identifier')::int AS accounts
      FROM audit_logs WHERE action='SIGN_IN_FAILED' AND created_at >= $1 AND ip_address IS NOT NULL
      GROUP BY ip_address HAVING COUNT(DISTINCT details::jsonb->>'identifier') >= 3 ORDER BY accounts DESC LIMIT 10`, [day]);
    const { rows: [{ adminSessions }] } = await pool.query(`
      SELECT COUNT(DISTINCT s.user_id)::int AS "adminSessions" FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.expires_at > $1 AND (u.role='admin' OR EXISTS (SELECT 1 FROM platform_admins pa WHERE pa.user_id=u.id AND pa.status='ACTIVE'))`, [Date.now()]);
    res.json({
      ...counts,
      adminSessions,
      mfa: await mfaCoverage(),
      mfaRequiredForAdmins: process.env.REQUIRE_ADMIN_MFA !== 'false',
      suspicious: { targetedAccounts, sprayingAddresses },
    });
  }));

  // Who holds an admin-level session right now.
  router.get('/security/sessions', requirePlatformPermission('security:view'), asyncRoute(async (req, res) => {
    const { rows } = await pool.query(`
      SELECT ${SESSION_ID} AS id, u.id AS "userId", u.full_name AS "fullName", u.email, s.created_at AS "signedInAt", s.expires_at AS "expiresAt",
        pa.role AS "platformRole", u.mfa_enabled_at IS NOT NULL AS "mfaEnabled",
        (SELECT string_agg(DISTINCT sc.name, ', ') FROM memberships m JOIN schools sc ON sc.id=m.school_id
          WHERE m.user_id=u.id AND m.status='ACTIVE' AND m.role IN ('school_admin','staff')) AS schools,
        EXISTS (SELECT 1 FROM support_sessions ss WHERE ss.session_token_hash=${SESSION_ID} AND ss.ended_at IS NULL AND ss.expires_at > $1) AS "inSupportSession"
      FROM sessions s JOIN users u ON u.id=s.user_id
      LEFT JOIN platform_admins pa ON pa.user_id=u.id AND pa.status='ACTIVE'
      WHERE s.expires_at > $1 AND (u.role='admin' OR pa.user_id IS NOT NULL)
      ORDER BY s.created_at DESC LIMIT 200`, [Date.now()]);
    res.json(rows.map(r => ({ ...r, expiresAt: Number(r.expiresAt), current: r.id === sessionIdOf(req.sessionToken) })));
  }));

  // Sign someone out of one session (e.g. a lost laptop). A reason is required.
  router.post('/security/sessions/:id/end', requirePlatformPermission('user:disable'), asyncRoute(async (req, res) => {
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 500) : '';
    if (reason.length < 5) return res.status(400).json({ error: 'Please give a reason (at least 5 characters).' });
    if (req.params.id === sessionIdOf(req.sessionToken)) return res.status(400).json({ error: 'Use Log Out to end your own session.' });
    const { rows: [ended] } = await pool.query(`
      DELETE FROM sessions s WHERE ${SESSION_ID} = $1
      RETURNING s.user_id AS "userId", (SELECT full_name FROM users WHERE id=s.user_id) AS "fullName"`, [req.params.id]);
    if (!ended) return res.status(404).json({ error: 'That session has already ended.' });
    await pool.query(`UPDATE support_sessions SET ended_at=$1, end_reason='SESSION_ENDED' WHERE session_token_hash=$2 AND ended_at IS NULL`, [Date.now(), req.params.id]);
    await writeAudit({
      actor: req.user, actorRole: req.platformAdmin.role, action: 'SESSION_ENDED_BY_PLATFORM', targetType: 'user', targetId: ended.userId,
      targetLabel: ended.fullName, reason, ip: req.ip, requestId: req.requestId,
    });
    res.status(204).end();
  }));

  // Sign-in activity or security changes, newest first, keyset-paged.
  router.get('/security/events', requirePlatformPermission('security:view'), asyncRoute(async (req, res) => {
    const category = req.query.category === 'changes' ? 'changes' : 'logins';
    const actions = category === 'changes'
      ? SECURITY_CHANGE_ACTIONS
      : LOGIN_ACTIONS[req.query.outcome] ?? [...LOGIN_ACTIONS.success, ...LOGIN_ACTIONS.failed, ...LOGIN_ACTIONS.locked];
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
    const params = [actions];
    const filters = ['a.action = ANY($1)'];
    const search = typeof req.query.search === 'string' ? req.query.search.trim().slice(0, 100) : '';
    if (search) {
      params.push(search);
      filters.push(`(a.actor_name ILIKE '%' || $${params.length} || '%' OR a.target_label ILIKE '%' || $${params.length} || '%' OR a.details ILIKE '%' || $${params.length} || '%' OR a.ip_address = $${params.length})`);
    }
    if (req.query.beforeCreatedAt && req.query.beforeId) {
      params.push(String(req.query.beforeCreatedAt), String(req.query.beforeId));
      filters.push(`(a.created_at, a.id) < ($${params.length - 1}, $${params.length})`);
    }
    const { rows } = await pool.query(`
      SELECT a.id, a.created_at AS "createdAt", a.action, a.actor_name AS "actorName", a.actor_role AS "actorRole", a.target_label AS "targetLabel",
        a.ip_address AS "ipAddress", a.reason, s.name AS "schoolName",
        CASE WHEN a.action LIKE 'SIGN_IN%' THEN a.details::jsonb->>'identifier' END AS identifier
      FROM audit_logs a LEFT JOIN schools s ON s.id=a.school_id
      WHERE ${filters.join(' AND ')}
      ORDER BY a.created_at DESC, a.id DESC LIMIT ${limit + 1}`, params);
    res.json({ entries: rows.slice(0, limit), hasMore: rows.length > limit });
  }));
}

const sessionIdOf = token => (token ? createHash('sha256').update(String(token), 'utf8').digest('hex') : null);
