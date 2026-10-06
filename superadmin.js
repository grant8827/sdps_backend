import express from 'express';
import { db, id, pool, withTransaction, isUniqueViolation } from './db.js';
import { requireAuth, endAllSessions } from './auth.js';
import { asyncRoute } from './asyncRoute.js';
import { hit as hitLimit } from './rateLimit.js';
import { writeAudit } from './audit.js';
import { getPlatformAdmin, PLATFORM_ROLES, requirePlatformPermission } from './permissions.js';
import { activeSupportSession, endSupportSession, endSupportSessionsWhere, startSupportSession } from './supportSessions.js';
import { createAccountLink, unusablePasswordHash } from './accountLinks.js';
import { sendInviteEmail } from './mailer.js';
import { registerPlatformInsights } from './platformInsights.js';
import { registerPlatformOperations } from './platformOperations.js';
import { registerPlatformSecurity } from './platformSecurity.js';
import { registerPlatformCompliance } from './platformCompliance.js';
import { registerPlatformNotifications } from './notifications.js';
import { registerPlatformReports } from './platformReports.js';
import { registerPlatformBilling } from './platformBilling.js';
import { registerPlatformSystem } from './platformSystem.js';

// /api/superadmin/* — the platform administration API (Phase 1: schools,
// platform admins, cross-school audit search, support sessions). Every
// route needs sign-in plus a named permission (permissions.js); none of
// them returns passwords, hashes, tokens or two-step secrets. School data
// itself is only reachable through a support session.

export const superadmin = express.Router();
superadmin.use(requireAuth);

// A generous per-person ceiling so a stuck script or a stolen session
// can't hammer the cross-school queries (shared across servers, rateLimit.js).
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 300;
superadmin.use(asyncRoute(async (req, res, next) => {
  if ((await hitLimit(`platform:${req.user.id}`, RATE_WINDOW_MS)) > RATE_MAX) return res.status(429).json({ error: 'Too many requests. Please wait a minute.' });
  next();
}));

const NOW_UTC = `to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')`;
const SCHOOL_STATUSES = ['ACTIVE', 'SUSPENDED', 'ARCHIVED'];

// ---- small input helpers ---------------------------------------------------

const text = (value, max = 200) => (typeof value === 'string' ? value.trim().slice(0, max) : '');
const page = query => {
  const pageNumber = Math.max(1, Number.parseInt(query.page, 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(query.pageSize, 10) || 25));
  return { pageNumber, pageSize, offset: (pageNumber - 1) * pageSize };
};
/** A reason is required for high-risk actions: 5–500 characters. */
function requireReason(req, res) {
  const reason = text(req.body?.reason, 500);
  if (reason.length < 5) { res.status(400).json({ error: 'Please give a reason (at least 5 characters).' }); return null; }
  return reason;
}
const audit = (req, entry) => writeAudit({ actor: req.user, actorRole: req.platformAdmin?.role, ip: req.ip, requestId: req.requestId, ...entry });

// ---- who am I --------------------------------------------------------------

superadmin.get('/me', asyncRoute(async (req, res) => {
  const admin = await getPlatformAdmin(req.user.id);
  if (!admin) return res.status(403).json({ error: 'Platform administrator access required' });
  const support = await activeSupportSession(req);
  res.json({
    role: admin.role,
    permissions: admin.permissions,
    supportSession: support && {
      id: support.id, schoolId: support.schoolId, schoolName: support.schoolName, reason: support.reason,
      allowChanges: support.allowChanges, startedAt: support.startedAt, expiresAt: support.expiresAt,
    },
  });
}));

// Dashboard, Needs Attention and the school detail tabs (platformInsights.js).
registerPlatformInsights(superadmin);
registerPlatformOperations(superadmin);
registerPlatformSecurity(superadmin);
registerPlatformCompliance(superadmin);
registerPlatformNotifications(superadmin);
registerPlatformReports(superadmin);
registerPlatformBilling(superadmin);
registerPlatformSystem(superadmin);

// ---- schools -----------------------------------------------------------------

const SORTS = { name: 's.name', created: 's.created_at', status: 's.status' };

superadmin.get('/schools', requirePlatformPermission('school:view'), asyncRoute(async (req, res) => {
  const { pageNumber, pageSize, offset } = page(req.query);
  const search = text(req.query.search, 100);
  const status = SCHOOL_STATUSES.includes(req.query.status) ? req.query.status : null;
  const sort = SORTS[req.query.sort] ?? SORTS.name;
  const dir = req.query.dir === 'desc' ? 'DESC' : 'ASC';
  const where = `WHERE ($1::text IS NULL OR s.name ILIKE '%' || $1 || '%' OR s.code ILIKE '%' || $1 || '%')
    AND ($2::text IS NULL OR s.status = $2)`;
  const params = [search || null, status];
  const { rows: [{ total }] } = await rawQuery(`SELECT COUNT(*)::int AS total FROM schools s ${where}`, params);
  const { rows: schools } = await rawQuery(`
    SELECT s.id, s.name, s.code, s.status, s.created_at AS "createdAt", s.suspended_at AS "suspendedAt",
      s.suspended_reason AS "suspendedReason", o.name AS "organizationName"
    FROM schools s JOIN organizations o ON o.id=s.organization_id
    ${where}
    ORDER BY ${sort} ${dir}, s.id
    LIMIT ${pageSize} OFFSET ${offset}`, params);
  // Counts for just this page's schools, one grouped query per kind (no N+1).
  const counts = await schoolCounts(schools.map(s => s.id));
  res.json({ items: schools.map(s => ({ ...s, ...counts.get(s.id) })), total, page: pageNumber, pageSize });
}));

// Postgres-style $n placeholders, for queries built from optional filters.
const rawQuery = (sql, params) => pool.query(sql, params);

async function schoolCounts(schoolIds) {
  const result = new Map(schoolIds.map(schoolId => [schoolId, { students: 0, staff: 0, parents: 0, locations: 0 }]));
  if (schoolIds.length === 0) return result;
  const queries = {
    students: `SELECT school_id AS id, COUNT(*)::int AS n FROM students WHERE school_id = ANY($1) AND status <> 'ARCHIVED' GROUP BY school_id`,
    staff: `SELECT school_id AS id, COUNT(DISTINCT user_id)::int AS n FROM memberships WHERE school_id = ANY($1) AND role IN ('teacher','school_admin','staff') AND status='ACTIVE' GROUP BY school_id`,
    parents: `SELECT school_id AS id, COUNT(DISTINCT user_id)::int AS n FROM memberships WHERE school_id = ANY($1) AND role='parent' AND status='ACTIVE' GROUP BY school_id`,
    locations: `SELECT school_id AS id, COUNT(*)::int AS n FROM campuses WHERE school_id = ANY($1) AND status <> 'ARCHIVED' GROUP BY school_id`,
  };
  await Promise.all(Object.entries(queries).map(async ([key, sql]) => {
    for (const row of (await rawQuery(sql, [schoolIds])).rows) result.get(row.id)[key] = row.n;
  }));
  return result;
}

superadmin.get('/schools/:id', requirePlatformPermission('school:view'), asyncRoute(async (req, res) => {
  const school = await db.prepare(`
    SELECT s.id, s.name, s.code, s.status, s.timezone, s.created_at AS "createdAt", s.suspended_at AS "suspendedAt",
      s.suspended_reason AS "suspendedReason", s.archived_at AS "archivedAt", s.start_time AS "startTime",
      s.dismissal_time AS "dismissalTime", o.id AS "organizationId", o.name AS "organizationName"
    FROM schools s JOIN organizations o ON o.id=s.organization_id WHERE s.id=?`).get(req.params.id);
  if (!school) return res.status(404).json({ error: 'School not found' });
  const [counts, locations, admins, activeYear, classCount] = await Promise.all([
    schoolCounts([school.id]),
    db.prepare(`
      SELECT id, name, address, status, latitude IS NOT NULL AND longitude IS NOT NULL AS "mapped", geofence_radius AS "geofenceRadius",
        start_time AS "startTime", dismissal_time AS "dismissalTime", created_at AS "createdAt"
      FROM campuses WHERE school_id=? AND status <> 'ARCHIVED' ORDER BY created_at, id`).all(school.id),
    db.prepare(`
      SELECT u.id, u.full_name AS "fullName", u.email, u.active = 1 AS "accountActive", m.status,
        u.mfa_enabled_at IS NOT NULL AS "mfaEnabled", u.needs_password_setup = 1 AS "needsSetup"
      FROM memberships m JOIN users u ON u.id=m.user_id
      WHERE m.school_id=? AND m.role='school_admin' AND m.status <> 'ARCHIVED' ORDER BY u.full_name`).all(school.id),
    db.prepare(`SELECT id, name FROM school_years WHERE school_id=? AND status='ACTIVE'`).get(school.id),
    db.prepare(`SELECT COUNT(*)::int AS n FROM classes c JOIN school_years y ON y.id=c.school_year_id AND y.status='ACTIVE' WHERE c.school_id=?`).get(school.id),
  ]);
  const schoolCountsRow = counts.get(school.id);
  // What a school still has to do before drop-off and pick-up work well.
  const setup = [
    { key: 'admin', label: 'Has an active administrator', done: admins.some(a => a.status === 'ACTIVE') },
    { key: 'location', label: 'Has a location mapped for drop-off/pick-up', done: locations.some(l => l.mapped) },
    { key: 'hours', label: 'School hours are set', done: Boolean(school.startTime || locations.some(l => l.startTime)) },
    { key: 'year', label: 'Has an active school year', done: Boolean(activeYear) },
    { key: 'classes', label: 'Has classes this year', done: classCount.n > 0 },
    { key: 'staff', label: 'Has teachers or staff', done: schoolCountsRow.staff > admins.length },
    { key: 'students', label: 'Has students', done: schoolCountsRow.students > 0 },
  ];
  await audit(req, { schoolId: school.id, action: 'PLATFORM_SCHOOL_VIEWED', targetType: 'school', targetId: school.id, targetLabel: school.name });
  res.json({ ...school, counts: schoolCountsRow, locations, admins, activeYear: activeYear ?? null, setup });
}));

const codeFromSchoolName = name => name.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8) || 'SCHOOL';

// Creates a school with its first location, an active school year, and
// its first administrator, who gets an email to choose their own password.
superadmin.post('/schools', requirePlatformPermission('school:create'), asyncRoute(async (req, res) => {
  const name = text(req.body.name, 120);
  const campusName = text(req.body.campusName, 120) || 'Main Campus';
  const campusAddress = text(req.body.campusAddress, 300);
  const adminFullName = text(req.body.adminFullName, 120);
  const adminEmail = text(req.body.adminEmail, 254).toLowerCase();
  const timezone = text(req.body.timezone, 60) || 'America/New_York';
  if (!name || !adminFullName || !adminEmail.includes('@')) {
    return res.status(400).json({ error: 'School name, the administrator\'s name, and a valid email are required.' });
  }
  try {
    const created = await withTransaction(async () => {
      if (await db.prepare('SELECT 1 FROM users WHERE LOWER(email)=?').get(adminEmail)) {
        throw new Error('That email already has an SDPMPlus account. Use a different email for the new school\'s administrator.');
      }
      let code = codeFromSchoolName(name);
      for (let attempt = 0; await db.prepare('SELECT 1 FROM schools WHERE LOWER(code)=LOWER(?)').get(code); attempt++) {
        if (attempt > 20) throw new Error('Could not allocate a school code. Try a slightly different name.');
        code = `${codeFromSchoolName(name).slice(0, 6)}${Math.floor(100 + Math.random() * 900)}`;
      }
      const organizationId = id('org');
      const schoolId = id('school');
      const userId = id('admin');
      await db.prepare('INSERT INTO organizations (id,name) VALUES (?,?)').run(organizationId, name);
      await db.prepare('INSERT INTO schools (id,organization_id,name,code,timezone) VALUES (?,?,?,?,?)').run(schoolId, organizationId, name, code, timezone);
      await db.prepare('INSERT INTO campuses (id,school_id,name,address) VALUES (?,?,?,?)').run(id('campus'), schoolId, campusName, campusAddress || null);
      await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,needs_password_setup,role) VALUES (?,?,?,?,1,'admin')`)
        .run(userId, adminFullName, adminEmail, unusablePasswordHash());
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,NULL,'school_admin')`).run(id('membership'), userId, schoolId);
      const now = new Date();
      const startYear = now.getMonth() >= 6 ? now.getFullYear() : now.getFullYear() - 1;
      await db.prepare(`INSERT INTO school_years (id,school_id,name,starts_on,ends_on,status) VALUES (?,?,?,?,?,'ACTIVE')`)
        .run(id('year'), schoolId, `${startYear}-${startYear + 1}`, `${startYear}-08-01`, `${startYear + 1}-06-30`);
      return { schoolId, userId, code };
    });
    const link = await createAccountLink(created.userId, 'INVITE');
    const { sent } = await sendInviteEmail({ to: adminEmail, fullName: adminFullName, schoolName: name, roleLabel: 'an administrator', link });
    await audit(req, {
      schoolId: created.schoolId, action: 'SCHOOL_CREATED', targetType: 'school', targetId: created.schoolId, targetLabel: name,
      details: { code: created.code, adminEmail, campusName },
    });
    await audit(req, { schoolId: created.schoolId, action: 'ADMINISTRATOR_CREATED', targetType: 'user', targetId: created.userId, targetLabel: adminFullName, details: { email: adminEmail } });
    res.status(201).json({ id: created.schoolId, code: created.code, emailSent: sent, ...(sent ? {} : { setupLink: link }) });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'That email or school code is already in use.' : error.message });
  }
}));

superadmin.patch('/schools/:id', requirePlatformPermission('school:update'), asyncRoute(async (req, res) => {
  const school = await db.prepare('SELECT id, name, timezone FROM schools WHERE id=?').get(req.params.id);
  if (!school) return res.status(404).json({ error: 'School not found' });
  const name = req.body.name !== undefined ? text(req.body.name, 120) : school.name;
  const timezone = req.body.timezone !== undefined ? text(req.body.timezone, 60) : school.timezone;
  if (!name) return res.status(400).json({ error: 'School name is required.' });
  await db.prepare(`UPDATE schools SET name=?, timezone=?, updated_at=${NOW_UTC} WHERE id=?`).run(name, timezone, school.id);
  await audit(req, {
    schoolId: school.id, action: 'SCHOOL_UPDATED', targetType: 'school', targetId: school.id, targetLabel: name,
    details: { before: { name: school.name, timezone: school.timezone }, after: { name, timezone } },
  });
  res.status(204).end();
}));

// Suspending stops everyone in the school from signing in (their only
// school is no longer ACTIVE — see getMemberships / canSignIn) and ends
// support sessions into it. Nothing is deleted.
superadmin.post('/schools/:id/suspend', requirePlatformPermission('school:suspend'), asyncRoute(async (req, res) => {
  const reason = requireReason(req, res);
  if (!reason) return;
  const school = await db.prepare(`UPDATE schools SET status='SUSPENDED', suspended_at=${NOW_UTC}, suspended_reason=?, updated_at=${NOW_UTC} WHERE id=? AND status='ACTIVE' RETURNING id, name`).get(reason, req.params.id);
  if (!school) return res.status(409).json({ error: 'Only an active school can be suspended.' });
  await endSupportSessionsWhere({ schoolId: school.id }, 'SCHOOL_SUSPENDED');
  await audit(req, { schoolId: school.id, action: 'SCHOOL_SUSPENDED', targetType: 'school', targetId: school.id, targetLabel: school.name, reason });
  res.status(204).end();
}));

superadmin.post('/schools/:id/reactivate', requirePlatformPermission('school:suspend'), asyncRoute(async (req, res) => {
  const reason = requireReason(req, res);
  if (!reason) return;
  // An archived school needs the archive permission to come back.
  const current = await db.prepare('SELECT status FROM schools WHERE id=?').get(req.params.id);
  if (!current) return res.status(404).json({ error: 'School not found' });
  if (current.status === 'ARCHIVED' && !req.platformAdmin.permissions.includes('school:archive')) {
    return res.status(403).json({ error: "Your platform role doesn't allow restoring an archived school" });
  }
  const school = await db.prepare(`UPDATE schools SET status='ACTIVE', suspended_at=NULL, suspended_reason=NULL, archived_at=NULL, updated_at=${NOW_UTC} WHERE id=? AND status IN ('SUSPENDED','ARCHIVED') RETURNING id, name`).get(req.params.id);
  if (!school) return res.status(409).json({ error: 'This school is already active.' });
  await audit(req, { schoolId: school.id, action: 'SCHOOL_REACTIVATED', targetType: 'school', targetId: school.id, targetLabel: school.name, reason, details: { from: current.status } });
  res.status(204).end();
}));

// Archiving is the end of the road short of deletion: only from SUSPENDED,
// super admins only, and still reversible.
superadmin.post('/schools/:id/archive', requirePlatformPermission('school:archive'), asyncRoute(async (req, res) => {
  const reason = requireReason(req, res);
  if (!reason) return;
  const school = await db.prepare(`UPDATE schools SET status='ARCHIVED', archived_at=${NOW_UTC}, updated_at=${NOW_UTC} WHERE id=? AND status='SUSPENDED' RETURNING id, name`).get(req.params.id);
  if (!school) return res.status(409).json({ error: 'Suspend the school before archiving it.' });
  await audit(req, { schoolId: school.id, action: 'SCHOOL_ARCHIVED', targetType: 'school', targetId: school.id, targetLabel: school.name, reason });
  res.status(204).end();
}));

// ---- audit log search across schools ---------------------------------------------

superadmin.get('/audit-logs', requirePlatformPermission('audit:view'), asyncRoute(async (req, res) => {
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
  const filters = [];
  const params = [];
  const add = (sql, value) => { params.push(value); filters.push(sql.replace('$?', `$${params.length}`)); };
  if (req.query.schoolId) add('a.school_id = $?', String(req.query.schoolId));
  if (req.query.action) add('a.action = $?', String(req.query.action));
  if (req.query.actorId) add('a.actor_user_id = $?', String(req.query.actorId));
  const actor = text(req.query.actor, 100);
  if (actor) add(`a.actor_name ILIKE '%' || $? || '%'`, actor);
  if (/^\d{4}-\d{2}-\d{2}$/.test(req.query.from ?? '')) add('a.created_at >= $?', `${req.query.from} 00:00:00`);
  if (/^\d{4}-\d{2}-\d{2}$/.test(req.query.to ?? '')) add('a.created_at <= $?', `${req.query.to} 23:59:59`);
  // Keyset paging: (created_at, id) of the last entry already shown.
  if (req.query.beforeCreatedAt && req.query.beforeId) {
    params.push(String(req.query.beforeCreatedAt), String(req.query.beforeId));
    filters.push(`(a.created_at, a.id) < ($${params.length - 1}, $${params.length})`);
  }
  const { rows } = await rawQuery(`
    SELECT a.id, a.created_at AS "createdAt", a.school_id AS "schoolId", s.name AS "schoolName", a.actor_user_id AS "actorId",
      a.actor_name AS "actorName", a.actor_role AS "actorRole", a.action, a.target_type AS "targetType", a.target_id AS "targetId",
      a.target_label AS "targetLabel", a.details, a.ip_address AS "ipAddress", a.reason, a.request_id AS "requestId",
      a.support_session_id AS "supportSessionId"
    FROM audit_logs a LEFT JOIN schools s ON s.id=a.school_id
    ${filters.length ? `WHERE ${filters.join(' AND ')}` : ''}
    ORDER BY a.created_at DESC, a.id DESC LIMIT ${limit + 1}`, params);
  const entries = rows.slice(0, limit).map(row => ({ ...row, details: row.details ? safeJson(row.details) : null }));
  res.json({ entries, hasMore: rows.length > limit });
}));

superadmin.get('/audit-logs/actions', requirePlatformPermission('audit:view'), asyncRoute(async (req, res) => {
  res.json((await db.prepare('SELECT DISTINCT action FROM audit_logs ORDER BY action').all()).map(r => r.action));
}));

function safeJson(value) {
  try { return JSON.parse(value); } catch { return null; }
}

// ---- platform administrators -------------------------------------------------------

superadmin.get('/admins', requirePlatformPermission('platform_admin:manage'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`
    SELECT u.id, u.full_name AS "fullName", u.email, pa.role, pa.status, pa.created_at AS "createdAt",
      u.mfa_enabled_at IS NOT NULL AS "mfaEnabled", u.needs_password_setup = 1 AS "needsSetup"
    FROM platform_admins pa JOIN users u ON u.id=pa.user_id ORDER BY pa.status, u.full_name`).all());
}));

superadmin.post('/admins', requirePlatformPermission('platform_admin:manage'), asyncRoute(async (req, res) => {
  const email = text(req.body.email, 254).toLowerCase();
  const fullName = text(req.body.fullName, 120);
  const role = req.body.role;
  if (!email.includes('@') || !PLATFORM_ROLES.includes(role)) return res.status(400).json({ error: 'A valid email and platform role are required.' });
  let user = await db.prepare('SELECT id, full_name AS "fullName" FROM users WHERE LOWER(email)=?').get(email);
  let link = null;
  if (!user) {
    if (!fullName) return res.status(400).json({ error: 'Enter their name — they don\'t have an SDPMPlus account yet.' });
    user = { id: id('platform'), fullName };
    await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,needs_password_setup,role) VALUES (?,?,?,?,1,'admin')`)
      .run(user.id, fullName, email, unusablePasswordHash());
    link = await createAccountLink(user.id, 'INVITE');
  }
  const added = await db.prepare(`INSERT INTO platform_admins (user_id,role,created_by_user_id) VALUES (?,?,?) ON CONFLICT (user_id) DO NOTHING`).run(user.id, role, req.user.id);
  if (added.changes === 0) return res.status(409).json({ error: 'That person is already a platform administrator.' });
  let sent = true;
  if (link) ({ sent } = await sendInviteEmail({ to: email, fullName: user.fullName, schoolName: 'SDPMPlus', roleLabel: `a platform administrator (${role})`, link }));
  await audit(req, { action: 'PLATFORM_ADMIN_ADDED', targetType: 'user', targetId: user.id, targetLabel: user.fullName, details: { email, role } });
  res.status(201).json({ id: user.id, emailSent: link ? sent : undefined, ...(link && !sent ? { setupLink: link } : {}) });
}));

superadmin.patch('/admins/:userId', requirePlatformPermission('platform_admin:manage'), asyncRoute(async (req, res) => {
  if (req.params.userId === req.user.id) return res.status(400).json({ error: 'Ask another super admin to change your own platform access.' });
  const current = await db.prepare(`SELECT pa.role, pa.status, u.full_name AS "fullName" FROM platform_admins pa JOIN users u ON u.id=pa.user_id WHERE pa.user_id=?`).get(req.params.userId);
  if (!current) return res.status(404).json({ error: 'Platform administrator not found' });
  const role = req.body.role ?? current.role;
  const status = req.body.status ?? current.status;
  if (!PLATFORM_ROLES.includes(role) || !['ACTIVE', 'DISABLED'].includes(status)) return res.status(400).json({ error: 'Invalid role or status.' });
  const reason = requireReason(req, res);
  if (!reason) return;
  // Never leave the platform without an active super admin.
  if (current.role === 'SUPER_ADMIN' && current.status === 'ACTIVE' && (role !== 'SUPER_ADMIN' || status !== 'ACTIVE')) {
    const { n } = await db.prepare(`SELECT COUNT(*)::int AS n FROM platform_admins WHERE role='SUPER_ADMIN' AND status='ACTIVE'`).get();
    if (n <= 1) return res.status(409).json({ error: 'There must always be at least one active super admin.' });
  }
  await db.prepare(`UPDATE platform_admins SET role=?, status=?, updated_at=${NOW_UTC} WHERE user_id=?`).run(role, status, req.params.userId);
  if (status === 'DISABLED' || role !== current.role) {
    await endSupportSessionsWhere({ userId: req.params.userId }, status === 'DISABLED' ? 'ACCESS_DISABLED' : 'ROLE_CHANGED');
    if (status === 'DISABLED') await endAllSessions(req.params.userId);
  }
  const action = status !== current.status ? (status === 'DISABLED' ? 'PLATFORM_ADMIN_DISABLED' : 'PLATFORM_ADMIN_REACTIVATED') : 'ROLE_CHANGED';
  await audit(req, { action, targetType: 'user', targetId: req.params.userId, targetLabel: current.fullName, reason, details: { before: { role: current.role, status: current.status }, after: { role, status } } });
  res.status(204).end();
}));

// ---- support sessions ---------------------------------------------------------------

superadmin.post('/support-sessions', requirePlatformPermission('support:start'), asyncRoute(async (req, res) => {
  const reason = requireReason(req, res);
  if (!reason) return;
  const allowChanges = req.body.allowChanges === true;
  if (allowChanges && !req.platformAdmin.permissions.includes('support:write')) {
    return res.status(403).json({ error: "Your platform role allows read-only support sessions only" });
  }
  const school = await db.prepare(`SELECT id, name FROM schools WHERE id=? AND status='ACTIVE'`).get(String(req.body.schoolId ?? ''));
  if (!school) return res.status(404).json({ error: 'Active school not found' });
  const session = await startSupportSession({ userId: req.user.id, sessionToken: req.sessionToken, schoolId: school.id, reason, allowChanges, ip: req.ip });
  // Filed under the school too, so its own admins can see who looked in and why.
  await audit(req, {
    schoolId: school.id, action: 'SUPPORT_SESSION_STARTED', targetType: 'school', targetId: school.id, targetLabel: school.name,
    reason, supportSessionId: session.id, details: { allowChanges, expiresAt: new Date(session.expiresAt).toISOString() },
  });
  res.status(201).json({ id: session.id, schoolId: school.id, schoolName: school.name, allowChanges, startedAt: session.startedAt, expiresAt: session.expiresAt });
}));

// Ending needs no permission check beyond sign-in: anyone can leave their own session.
superadmin.post('/support-sessions/end', asyncRoute(async (req, res) => {
  const ended = await endSupportSession(req.sessionToken, 'EXITED');
  if (ended) {
    const school = await db.prepare('SELECT name FROM schools WHERE id=?').get(ended.schoolId);
    await writeAudit({
      schoolId: ended.schoolId, actor: req.user, actorRole: (await getPlatformAdmin(req.user.id))?.role ?? null, action: 'SUPPORT_SESSION_ENDED',
      targetType: 'school', targetId: ended.schoolId, targetLabel: school?.name ?? null, ip: req.ip, requestId: req.requestId, supportSessionId: ended.id,
      details: { minutes: Math.round((Date.now() - Number(ended.startedAt)) / 60000) },
    });
  }
  res.status(204).end();
}));

