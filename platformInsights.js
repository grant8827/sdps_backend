import { db, pool } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { emailConfigured } from './mailer.js';
import { requirePlatformPermission } from './permissions.js';
import { billingProblems } from './platformBilling.js';

// Platform dashboard, Needs Attention, and the per-school detail tabs
// (registered onto the /api/superadmin router by superadmin.js).
//
// Every number is an aggregate query bounded by date or LIMIT — nothing
// loads individual records to count them. "Today" and the 30-day charts
// use one platform time zone (PLATFORM_TIMEZONE, default US Eastern);
// timestamps are stored in UTC and converted in SQL. Attendance dates
// are already school-local dates.

export const PLATFORM_TZ = (() => {
  const tz = process.env.PLATFORM_TIMEZONE || 'America/New_York';
  try { new Intl.DateTimeFormat('en-CA', { timeZone: tz }); return tz; } catch { return 'America/New_York'; }
})();
const CHART_DAYS = 30;
export const localDate = (date = new Date()) => new Intl.DateTimeFormat('en-CA', { timeZone: PLATFORM_TZ }).format(date);
export const daysAgo = (dateStr, days) => {
  const d = new Date(`${dateStr}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString().slice(0, 10);
};
// UTC 'YYYY-MM-DD HH24:MI:SS' of a local date's midnight, for range filters on UTC text columns.
const UTC_OF_LOCAL_MIDNIGHT = `to_char(($1::date::timestamp AT TIME ZONE $2) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')`;
const localDay = column => `to_char((${column}::timestamp AT TIME ZONE 'UTC') AT TIME ZONE $3, 'YYYY-MM-DD')`;

export async function utcBounds(fromDate, toDateExclusive) {
  const { rows: [from] } = await pool.query(`SELECT ${UTC_OF_LOCAL_MIDNIGHT} AS t`, [fromDate, PLATFORM_TZ]);
  const { rows: [to] } = await pool.query(`SELECT ${UTC_OF_LOCAL_MIDNIGHT} AS t`, [toDateExclusive, PLATFORM_TZ]);
  return [from.t, to.t];
}

// Recomputing every chart on each page load is wasteful; one minute is
// fresh enough for a platform overview.
const CACHE_MS = 60 * 1000;
let dashboardCache = null; // { at, key, value }

async function buildDashboard() {
  const today = localDate();
  const tomorrow = daysAgo(today, -1);
  const chartStart = daysAgo(today, CHART_DAYS - 1);
  const [todayStart, todayEnd] = await utcBounds(today, tomorrow);
  const [chartStartUtc] = await utcBounds(chartStart, tomorrow);

  const { rows: [totals] } = await pool.query(`
    SELECT
      (SELECT COUNT(*)::int FROM schools WHERE status <> 'ARCHIVED') AS "totalSchools",
      (SELECT COUNT(*)::int FROM schools WHERE status = 'ACTIVE') AS "activeSchools",
      (SELECT COUNT(*)::int FROM schools WHERE status = 'SUSPENDED') AS "suspendedSchools",
      (SELECT COUNT(*)::int FROM students st JOIN schools s ON s.id=st.school_id AND s.status='ACTIVE' WHERE st.status <> 'ARCHIVED') AS "students",
      (SELECT COUNT(DISTINCT m.user_id)::int FROM memberships m JOIN schools s ON s.id=m.school_id AND s.status='ACTIVE'
        WHERE m.role='parent' AND m.status='ACTIVE') AS "parents",
      (SELECT COUNT(DISTINCT m.user_id)::int FROM memberships m JOIN schools s ON s.id=m.school_id AND s.status='ACTIVE'
        WHERE m.role IN ('teacher','school_admin','staff') AND m.status='ACTIVE') AS "staff",
      -- Signed in within the last 24 hours = holds a live session (sessions last a day).
      (SELECT COUNT(DISTINCT user_id)::int FROM sessions WHERE expires_at > $1) AS "activeUsers"`, [Date.now()]);

  const { rows: [ops] } = await pool.query(`
    SELECT
      COUNT(*) FILTER (WHERE request_type='DROP_OFF' AND status='APPROVED' AND approved_at >= $1 AND approved_at < $2)::int AS "dropOffs",
      COUNT(*) FILTER (WHERE request_type='PICK_UP' AND status='APPROVED' AND approved_at >= $1 AND approved_at < $2)::int AS "pickUps",
      COUNT(*) FILTER (WHERE request_type='DROP_OFF' AND status='PENDING')::int AS "pendingDropOffs",
      COUNT(*) FILTER (WHERE request_type='PICK_UP' AND status='PENDING')::int AS "pendingPickUps",
      COUNT(*) FILTER (WHERE verification_method='ADMIN_OVERRIDE' AND approved_at >= $1 AND approved_at < $2)::int AS "overrides"
    FROM queue_items WHERE status='PENDING' OR approved_at >= $1`, [todayStart, todayEnd]);
  const { rows: attendanceToday } = await pool.query(`SELECT status, COUNT(*)::int AS n FROM attendance_records WHERE date=$1 GROUP BY status`, [today]);
  const { rows: [{ lockouts }] } = await pool.query(`SELECT COUNT(*)::int AS lockouts FROM audit_logs WHERE action='PICKUP_CODE_LOCKED_OUT' AND created_at >= $1 AND created_at < $2`, [todayStart, todayEnd]);
  const attendanceCount = status => attendanceToday.find(r => r.status === status)?.n ?? 0;

  // 30-day series, one row per local day.
  const series = async (sql, params) => Object.fromEntries((await pool.query(sql, params)).rows.map(r => [r.day, r]));
  const queueByDay = await series(`
    SELECT ${localDay('approved_at')} AS day,
      COUNT(*) FILTER (WHERE request_type='DROP_OFF')::int AS "dropOffs",
      COUNT(*) FILTER (WHERE request_type='PICK_UP')::int AS "pickUps"
    FROM queue_items WHERE status='APPROVED' AND approved_at >= $1 AND approved_at < $2 GROUP BY 1`, [chartStartUtc, todayEnd, PLATFORM_TZ]);
  const activeSchoolsByDay = await series(`
    SELECT ${localDay('requested_at')} AS day, COUNT(DISTINCT school_id)::int AS "activeSchools"
    FROM queue_items WHERE requested_at >= $1 AND requested_at < $2 GROUP BY 1`, [chartStartUtc, todayEnd, PLATFORM_TZ]);
  const usageByDay = await series(`
    SELECT ${localDay('created_at')} AS day, COUNT(DISTINCT actor_user_id)::int AS "signedIn"
    FROM audit_logs WHERE action='SIGNED_IN' AND created_at >= $1 AND created_at < $2 GROUP BY 1`, [chartStartUtc, todayEnd, PLATFORM_TZ]);
  const attendanceByDay = await series(`
    SELECT date AS day,
      COUNT(*) FILTER (WHERE status='PRESENT')::int AS present,
      COUNT(*) FILTER (WHERE status <> 'PRESENT' AND status NOT IN ('HOLIDAY','WEEKEND'))::int AS absent
    FROM attendance_records WHERE date >= $1 AND date <= $2 GROUP BY date`, [chartStart, today]);

  const days = Array.from({ length: CHART_DAYS }, (_, i) => daysAgo(today, CHART_DAYS - 1 - i));
  const daily = days.map(day => ({
    date: day,
    dropOffs: queueByDay[day]?.dropOffs ?? 0,
    pickUps: queueByDay[day]?.pickUps ?? 0,
    present: attendanceByDay[day]?.present ?? 0,
    absent: attendanceByDay[day]?.absent ?? 0,
    activeSchools: activeSchoolsByDay[day]?.activeSchools ?? 0,
    signedIn: usageByDay[day]?.signedIn ?? 0,
  }));

  return {
    timezone: PLATFORM_TZ,
    today,
    totals,
    operations: {
      ...ops,
      present: attendanceCount('PRESENT'),
      absent: attendanceCount('ABSENT') + attendanceCount('SICK'),
      exceptions: ops.overrides + lockouts,
      pickupLockouts: lockouts,
    },
    daily,
    generatedAt: new Date().toISOString(),
  };
}

// ---- Needs Attention ------------------------------------------------------------

async function buildNeedsAttention() {
  const items = [];
  const dayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
  const weekAgo = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
  const halfHourAgo = new Date(Date.now() - 30 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
  const threeDaysAgo = new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);

  if (!emailConfigured()) {
    items.push({
      id: 'email-not-configured', severity: 'critical', category: 'Notifications',
      title: "Email sending isn't set up",
      detail: 'Invites, password resets and message notifications are not being emailed. Set the SMTP_* settings on the server.',
      link: null,
    });
  }

  // Schools that can't run drop-off/pick-up properly yet.
  const { rows: setupGaps } = await pool.query(`
    SELECT s.id, s.name,
      NOT EXISTS (SELECT 1 FROM memberships m WHERE m.school_id=s.id AND m.role='school_admin' AND m.status='ACTIVE') AS "noAdmin",
      NOT EXISTS (SELECT 1 FROM campuses c WHERE c.school_id=s.id AND c.status <> 'ARCHIVED' AND c.latitude IS NOT NULL) AS "noMappedLocation",
      NOT EXISTS (SELECT 1 FROM school_years y WHERE y.school_id=s.id AND y.status='ACTIVE') AS "noActiveYear"
    FROM schools s WHERE s.status='ACTIVE'`);
  for (const school of setupGaps) {
    const gaps = [school.noAdmin && 'no active administrator', school.noMappedLocation && 'no location mapped for drop-off/pick-up', school.noActiveYear && 'no active school year'].filter(Boolean);
    if (gaps.length) {
      items.push({
        id: `setup-${school.id}`, severity: school.noAdmin ? 'high' : 'medium', category: 'School setup',
        title: `${school.name} hasn't finished setup`, detail: `Missing: ${gaps.join(', ')}.`, link: `/platform/schools/${school.id}`,
      });
    }
  }

  const { rows: stalledInvites } = await pool.query(`
    SELECT s.id, s.name, COUNT(*)::int AS n FROM memberships m
    JOIN users u ON u.id=m.user_id AND u.needs_password_setup=1 AND u.created_at < $1
    JOIN schools s ON s.id=m.school_id AND s.status='ACTIVE'
    WHERE m.role='school_admin' AND m.status='ACTIVE' GROUP BY s.id, s.name ORDER BY n DESC LIMIT 20`, [weekAgo]);
  for (const school of stalledInvites) {
    items.push({
      id: `invite-${school.id}`, severity: 'medium', category: 'School setup',
      title: `${school.name}: administrator hasn't accepted their invite`,
      detail: `${school.n} administrator account(s) invited over a week ago still haven't set a password.`, link: `/platform/schools/${school.id}`,
    });
  }

  // Sign-in security, last 24 hours. Identifiers are what was typed at
  // sign-in (an email), never a password.
  const { rows: lockouts } = await pool.query(`
    SELECT details::jsonb->>'identifier' AS identifier, COUNT(*)::int AS n FROM audit_logs
    WHERE action='SIGN_IN_LOCKED_OUT' AND created_at >= $1 GROUP BY 1 ORDER BY n DESC LIMIT 10`, [dayAgo]);
  if (lockouts.length) {
    items.push({
      id: 'locked-accounts', severity: 'high', category: 'Security',
      title: `${lockouts.length} account name(s) locked out after repeated wrong passwords`,
      detail: lockouts.map(l => l.identifier || 'unknown').join(', '), link: '/platform/audit-logs?action=SIGN_IN_LOCKED_OUT',
    });
  }
  const { rows: failures } = await pool.query(`
    SELECT details::jsonb->>'identifier' AS identifier, COUNT(*)::int AS n FROM audit_logs
    WHERE action='SIGN_IN_FAILED' AND created_at >= $1 GROUP BY 1 HAVING COUNT(*) >= 5 ORDER BY n DESC LIMIT 10`, [dayAgo]);
  if (failures.length) {
    items.push({
      id: 'failed-sign-ins', severity: 'medium', category: 'Security',
      title: 'Repeated failed sign-ins in the last 24 hours',
      detail: failures.map(f => `${f.identifier || 'unknown'} (${f.n})`).join(', '), link: '/platform/audit-logs?action=SIGN_IN_FAILED',
    });
  }
  const { rows: [{ n: adminsWithoutMfa }] } = await pool.query(`
    SELECT COUNT(*)::int AS n FROM platform_admins pa JOIN users u ON u.id=pa.user_id WHERE pa.status='ACTIVE' AND u.mfa_enabled_at IS NULL`);
  if (adminsWithoutMfa) {
    items.push({
      id: 'platform-mfa', severity: 'high', category: 'Security',
      title: `${adminsWithoutMfa} platform administrator(s) haven't set up two-step verification`,
      detail: "They'll be asked to at their next sign-in.", link: '/platform/admins',
    });
  }

  // Drop-off / pickup exceptions.
  const { rows: pickupExceptions } = await pool.query(`
    SELECT a.school_id AS id, s.name, COUNT(*) FILTER (WHERE a.action='PICKUP_CODE_LOCKED_OUT')::int AS lockouts
    FROM audit_logs a JOIN schools s ON s.id=a.school_id
    WHERE a.action='PICKUP_CODE_LOCKED_OUT' AND a.created_at >= $1 GROUP BY a.school_id, s.name ORDER BY lockouts DESC LIMIT 20`, [dayAgo]);
  for (const school of pickupExceptions) {
    items.push({
      id: `pickup-lockout-${school.id}`, severity: 'high', category: 'Pickup exceptions',
      title: `${school.name}: pickups cancelled for too many wrong codes`,
      detail: `${school.lockouts} in the last 24 hours.`, link: `/platform/audit-logs?action=PICKUP_CODE_LOCKED_OUT&schoolId=${school.id}`,
    });
  }
  const { rows: overrides } = await pool.query(`
    SELECT qi.school_id AS id, s.name, COUNT(*)::int AS n FROM queue_items qi JOIN schools s ON s.id=qi.school_id
    WHERE qi.verification_method='ADMIN_OVERRIDE' AND qi.approved_at >= $1 GROUP BY qi.school_id, s.name ORDER BY n DESC LIMIT 20`, [dayAgo]);
  for (const school of overrides) {
    items.push({
      id: `override-${school.id}`, severity: 'medium', category: 'Pickup exceptions',
      title: `${school.name}: children released without the pickup code`,
      detail: `${school.n} administrator override(s) in the last 24 hours.`, link: `/platform/schools/${school.id}`,
    });
  }
  const { rows: waiting } = await pool.query(`
    SELECT qi.school_id AS id, s.name, COUNT(*)::int AS n FROM queue_items qi JOIN schools s ON s.id=qi.school_id AND s.status='ACTIVE'
    WHERE qi.status='PENDING' AND qi.requested_at < $1 GROUP BY qi.school_id, s.name ORDER BY n DESC LIMIT 20`, [halfHourAgo]);
  for (const school of waiting) {
    items.push({
      id: `waiting-${school.id}`, severity: 'medium', category: 'Operations',
      title: `${school.name}: requests waiting over 30 minutes`,
      detail: `${school.n} drop-off/pick-up request(s) haven't been answered.`, link: `/platform/schools/${school.id}`,
    });
  }
  const { rows: approvals } = await pool.query(`
    SELECT gr.school_id AS id, s.name, COUNT(DISTINCT gr.batch_id)::int AS n FROM guardian_requests gr JOIN schools s ON s.id=gr.school_id AND s.status='ACTIVE'
    WHERE gr.status='PENDING' AND gr.requested_at < $1 GROUP BY gr.school_id, s.name ORDER BY n DESC LIMIT 20`, [threeDaysAgo]);
  for (const school of approvals) {
    items.push({
      id: `approvals-${school.id}`, severity: 'low', category: 'Operations',
      title: `${school.name}: guardian approvals waiting over 3 days`,
      detail: `${school.n} request(s) from parents to add another adult.`, link: `/platform/schools/${school.id}`,
    });
  }

  // Emails that failed to send (not ones skipped because email isn't set up — that's its own item above).
  const { rows: [{ n: failedEmails }] } = await pool.query(`SELECT COUNT(*)::int AS n FROM notification_deliveries WHERE status='FAILED' AND created_at >= $1`, [dayAgo]);
  if (failedEmails) {
    items.push({ id: 'failed-emails', severity: 'high', category: 'Notifications', title: `${failedEmails} email(s) failed to send in the last 24 hours`, detail: 'They can be retried from Notifications.', link: '/platform/notifications?status=FAILED' });
  }
  const { rows: [{ n: failedJobs }] } = await pool.query(`SELECT COUNT(*)::int AS n FROM jobs WHERE status='FAILED' AND finished_at >= $1`, [dayAgo]);
  if (failedJobs) {
    items.push({ id: 'failed-jobs', severity: 'medium', category: 'Background jobs', title: `${failedJobs} background job(s) failed in the last 24 hours`, detail: 'Usually a report export that was too large; the person who asked sees the reason.', link: '/platform/reports' });
  }
  for (const school of await billingProblems()) {
    items.push({
      id: `billing-${school.id}`, severity: 'medium', category: 'Billing', title: `${school.name}: ${school.overdueInvoices ? `${school.overdueInvoices} overdue invoice(s)` : 'subscription past due'}`,
      detail: school.overdueCents ? `$${(school.overdueCents / 100).toFixed(2)} overdue.` : 'Marked past due.', link: '/platform/billing/invoices?status=OVERDUE',
    });
  }

  const { rows: [{ n: suspended }] } = await pool.query(`SELECT COUNT(*)::int AS n FROM schools WHERE status='SUSPENDED'`);
  if (suspended) {
    items.push({ id: 'suspended', severity: 'low', category: 'Schools', title: `${suspended} school(s) suspended`, detail: 'Their users cannot sign in.', link: '/platform/schools?tab=suspended' });
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  items.sort((a, b) => order[a.severity] - order[b.severity]);
  return {
    items,
    // Honest about what isn't watched yet, rather than showing "all clear".
    notTracked: ['Text message (SMS) and push notification delivery (not offered yet)'],
  };
}

// ---- per-school detail tabs ------------------------------------------------------------

const page = query => {
  const pageNumber = Math.max(1, Number.parseInt(query.page, 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(query.pageSize, 10) || 25));
  return { pageNumber, pageSize, offset: (pageNumber - 1) * pageSize };
};
const searchText = value => (typeof value === 'string' ? value.trim().slice(0, 100) : '');
async function schoolOr404(req, res) {
  const school = await db.prepare('SELECT id, name FROM schools WHERE id=?').get(req.params.id);
  if (!school) res.status(404).json({ error: 'School not found' });
  return school;
}
// Looking at a school's people or children from the platform is recorded in that school's audit log.
const auditView = (req, school, action, details) => writeAudit({
  schoolId: school.id, actor: req.user, actorRole: req.platformAdmin.role, action, targetType: 'school', targetId: school.id,
  targetLabel: school.name, details, ip: req.ip, requestId: req.requestId,
});

export function registerPlatformInsights(router) {
  router.get('/dashboard', requirePlatformPermission('platform:view'), asyncRoute(async (req, res) => {
    const key = localDate();
    if (!dashboardCache || dashboardCache.key !== key || Date.now() - dashboardCache.at > CACHE_MS || req.query.refresh === '1') {
      dashboardCache = { at: Date.now(), key, value: await buildDashboard() };
    }
    res.json(dashboardCache.value);
  }));

  router.get('/needs-attention', requirePlatformPermission('platform:view'), asyncRoute(async (req, res) => {
    res.json(await buildNeedsAttention());
  }));

  // People in a school: staff (teachers, admins, front desk) or parents. No credentials, ever.
  router.get('/schools/:id/users', requirePlatformPermission('user:view'), asyncRoute(async (req, res) => {
    const school = await schoolOr404(req, res);
    if (!school) return;
    const kind = req.query.kind === 'parents' ? 'parents' : 'staff';
    const roles = kind === 'parents' ? ['parent'] : ['teacher', 'school_admin', 'staff'];
    const search = searchText(req.query.search);
    const { pageNumber, pageSize, offset } = page(req.query);
    const params = [school.id, roles, search || null];
    const where = `m.school_id=$1 AND m.role = ANY($2) AND m.status <> 'ARCHIVED'
      AND ($3::text IS NULL OR u.full_name ILIKE '%' || $3 || '%' OR u.email ILIKE '%' || $3 || '%')`;
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(DISTINCT u.id)::int AS total FROM memberships m JOIN users u ON u.id=m.user_id WHERE ${where}`, params);
    const { rows: users } = await pool.query(`
      SELECT u.id, u.full_name AS "fullName", u.email, u.phone, MIN(m.role) AS role, MIN(m.status) AS status, u.active = 1 AS "accountActive",
        u.mfa_enabled_at IS NOT NULL AS "mfaEnabled", u.needs_password_setup = 1 AS "needsSetup"
      FROM memberships m JOIN users u ON u.id=m.user_id WHERE ${where}
      GROUP BY u.id ORDER BY u.full_name, u.id LIMIT ${pageSize} OFFSET ${offset}`, params);
    // Last sign-in for just this page's people (one grouped query).
    const lastSignIn = new Map((await pool.query(`
      SELECT actor_user_id AS id, MAX(created_at) AS at FROM audit_logs WHERE action='SIGNED_IN' AND actor_user_id = ANY($1) GROUP BY actor_user_id`,
    [users.map(u => u.id)])).rows.map(r => [r.id, r.at]));
    await auditView(req, school, 'PLATFORM_USERS_VIEWED', { kind, page: pageNumber, search: search || undefined });
    res.json({ items: users.map(u => ({ ...u, lastSignIn: lastSignIn.get(u.id) ?? null })), total, page: pageNumber, pageSize });
  }));

  router.get('/schools/:id/students', requirePlatformPermission('student:view'), asyncRoute(async (req, res) => {
    const school = await schoolOr404(req, res);
    if (!school) return;
    const search = searchText(req.query.search);
    const { pageNumber, pageSize, offset } = page(req.query);
    const params = [school.id, search || null];
    const where = `s.school_id=$1 AND s.status <> 'ARCHIVED' AND ($2::text IS NULL OR (s.first_name || ' ' || s.last_name) ILIKE '%' || $2 || '%')`;
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM students s WHERE ${where}`, params);
    // Only what support needs: name, grade/class, status. No birth dates, photos or guardians' details.
    const { rows } = await pool.query(`
      SELECT s.id, s.first_name || ' ' || s.last_name AS "fullName", s.status, s.pickup_status AS "pickupStatus",
        g.name AS "gradeName", c.name AS "className"
      FROM students s
      LEFT JOIN student_enrollments e ON e.student_id=s.id
        AND e.school_year_id=(SELECT id FROM school_years WHERE school_id=s.school_id AND status='ACTIVE' LIMIT 1)
      LEFT JOIN grade_levels g ON g.id=e.grade_level_id LEFT JOIN classes c ON c.id=e.class_id
      WHERE ${where} ORDER BY s.last_name, s.first_name, s.id LIMIT ${pageSize} OFFSET ${offset}`, params);
    await auditView(req, school, 'PLATFORM_STUDENTS_VIEWED', { page: pageNumber, search: search || undefined, count: rows.length });
    res.json({ items: rows, total, page: pageNumber, pageSize });
  }));

  // Today's drop-off/pick-up activity and the latest requests (never pickup codes).
  router.get('/schools/:id/operations', requirePlatformPermission('pickup:view'), asyncRoute(async (req, res) => {
    const school = await schoolOr404(req, res);
    if (!school) return;
    const today = localDate();
    const [todayStart, todayEnd] = await utcBounds(today, daysAgo(today, -1));
    const { rows: [counts] } = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE request_type='DROP_OFF' AND status='APPROVED' AND approved_at >= $2 AND approved_at < $3)::int AS "dropOffs",
        COUNT(*) FILTER (WHERE request_type='PICK_UP' AND status='APPROVED' AND approved_at >= $2 AND approved_at < $3)::int AS "pickUps",
        COUNT(*) FILTER (WHERE status='PENDING')::int AS pending,
        COUNT(*) FILTER (WHERE verification_method='ADMIN_OVERRIDE' AND approved_at >= $2 AND approved_at < $3)::int AS overrides
      FROM queue_items WHERE school_id=$1 AND (status='PENDING' OR approved_at >= $2)`, [school.id, todayStart, todayEnd]);
    const { rows: recent } = await pool.query(`
      SELECT qi.id, qi.request_type AS "requestType", qi.status, qi.requested_at AS "requestedAt", qi.approved_at AS "approvedAt",
        qi.verification_method AS "verificationMethod", st.first_name || ' ' || st.last_name AS "studentName", c.name AS "campusName"
      FROM queue_items qi JOIN students st ON st.id=qi.student_id LEFT JOIN campuses c ON c.id=qi.campus_id
      WHERE qi.school_id=$1 ORDER BY qi.requested_at DESC LIMIT 25`, [school.id]);
    await auditView(req, school, 'PLATFORM_OPERATIONS_VIEWED', null);
    res.json({ timezone: PLATFORM_TZ, today: counts, recent });
  }));

  router.get('/schools/:id/attendance', requirePlatformPermission('attendance:view'), asyncRoute(async (req, res) => {
    const school = await schoolOr404(req, res);
    if (!school) return;
    const today = localDate();
    const from = daysAgo(today, 13);
    const { rows } = await pool.query(`
      SELECT date, COUNT(*) FILTER (WHERE status='PRESENT')::int AS present,
        COUNT(*) FILTER (WHERE status IN ('ABSENT','SICK'))::int AS absent,
        COUNT(*) FILTER (WHERE status NOT IN ('PRESENT','ABSENT','SICK'))::int AS other
      FROM attendance_records WHERE school_id=$1 AND date >= $2 AND date <= $3 GROUP BY date ORDER BY date`, [school.id, from, today]);
    const { rows: [{ students }] } = await pool.query(`SELECT COUNT(*)::int AS students FROM students WHERE school_id=$1 AND status='ACTIVE'`, [school.id]);
    const byDate = Object.fromEntries(rows.map(r => [r.date, r]));
    const days = Array.from({ length: 14 }, (_, i) => daysAgo(today, 13 - i)).map(date => ({
      date, present: byDate[date]?.present ?? 0, absent: byDate[date]?.absent ?? 0, other: byDate[date]?.other ?? 0,
    }));
    res.json({ students, days });
  }));

  router.get('/schools/:id/security', requirePlatformPermission('security:view'), asyncRoute(async (req, res) => {
    const school = await schoolOr404(req, res);
    if (!school) return;
    const weekAgo = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    const { rows: [mfa] } = await pool.query(`
      SELECT COUNT(DISTINCT u.id)::int AS admins, COUNT(DISTINCT u.id) FILTER (WHERE u.mfa_enabled_at IS NOT NULL)::int AS "adminsWithMfa",
        (SELECT COUNT(DISTINCT u2.id)::int FROM memberships m2 JOIN users u2 ON u2.id=m2.user_id
          WHERE m2.school_id=$1 AND m2.status='ACTIVE' AND m2.role='teacher' AND u2.mfa_enabled_at IS NOT NULL) AS "teachersWithMfa"
      FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.school_id=$1 AND m.status='ACTIVE' AND m.role IN ('school_admin','staff')`, [school.id]);
    const { rows: events } = await pool.query(`
      SELECT action, COUNT(*)::int AS n FROM audit_logs
      WHERE school_id=$1 AND created_at >= $2 AND action IN ('SIGN_IN_FAILED','SIGN_IN_LOCKED_OUT','MFA_CODE_FAILED','MFA_RESET','PASSWORD_RESET','PICKUP_CODE_LOCKED_OUT')
      GROUP BY action`, [school.id, weekAgo]);
    const { rows: supportSessions } = await pool.query(`
      SELECT ss.id, u.full_name AS "adminName", ss.reason, ss.allow_changes = 1 AS "allowChanges", ss.started_at AS "startedAt",
        ss.ended_at AS "endedAt", ss.expires_at AS "expiresAt", ss.end_reason AS "endReason"
      FROM support_sessions ss JOIN users u ON u.id=ss.platform_user_id
      WHERE ss.school_id=$1 ORDER BY ss.started_at DESC LIMIT 20`, [school.id]);
    res.json({
      mfa,
      lastSevenDays: Object.fromEntries(events.map(e => [e.action, e.n])),
      supportSessions: supportSessions.map(s => ({ ...s, startedAt: Number(s.startedAt), endedAt: s.endedAt ? Number(s.endedAt) : null, expiresAt: Number(s.expiresAt) })),
    });
  }));

  router.get('/schools/:id/notifications', requirePlatformPermission('school:view'), asyncRoute(async (req, res) => {
    const school = await schoolOr404(req, res);
    if (!school) return;
    const monthAgo = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    // Counts only; message contents stay with the school.
    const { rows } = await pool.query(`
      SELECT target_type AS audience, COUNT(*)::int AS n FROM notices WHERE school_id=$1 AND created_at >= $2 GROUP BY target_type`, [school.id, monthAgo]);
    res.json({ emailConfigured: emailConfigured(), lastThirtyDays: Object.fromEntries(rows.map(r => [r.audience, r.n])) });
  }));
}
