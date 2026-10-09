import { pool } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { enqueueJob, registerJobHandler } from './jobs.js';
import { getPlatformAdmin, requirePlatformPermission } from './permissions.js';
import { PLATFORM_TZ, daysAgo, localDate, utcBounds } from './platformInsights.js';

// Platform reports: usage, drop-offs and pickups, attendance, active
// users, adoption and exceptions (declined requests) — counts only, never individual
// children. Each is one aggregate query over a date range of at most a
// year, optionally for one school. On screen it's paged; "Export CSV"
// runs the full report as a background job (jobs.js).

const MAX_DAYS = 366;
const EXPORT_ROW_CAP = 200_000;
const localDay = column => `to_char((${column}::timestamp AT TIME ZONE 'UTC') AT TIME ZONE $tz, 'YYYY-MM-DD')`;

// Each report: columns, the SQL (named params $fromUtc $toUtc $fromDate $toDate $school $tz), and its sort.
const REPORTS = {
  'school-usage': {
    title: 'School usage',
    description: 'Each school: people, sign-ins, drop-offs, pickups, attendance days and messages in the period.',
    columns: [['school', 'School'], ['students', 'Students'], ['staff', 'Staff'], ['parents', 'Parents'], ['people_signed_in', 'People signed in'],
      ['drop_offs', 'Drop-offs'], ['pick_ups', 'Pickups'], ['declined', 'Requests declined'], ['attendance_days', 'Days with attendance'], ['messages', 'Messages sent']],
    sql: `
      SELECT s.name AS school,
        (SELECT COUNT(*) FROM students st WHERE st.school_id=s.id AND st.status='ACTIVE')::int AS students,
        (SELECT COUNT(DISTINCT m.user_id) FROM memberships m WHERE m.school_id=s.id AND m.status='ACTIVE' AND m.role IN ('teacher','school_admin','staff'))::int AS staff,
        (SELECT COUNT(DISTINCT m.user_id) FROM memberships m WHERE m.school_id=s.id AND m.status='ACTIVE' AND m.role='parent')::int AS parents,
        (SELECT COUNT(DISTINCT a.actor_user_id) FROM audit_logs a WHERE a.school_id=s.id AND a.action='SIGNED_IN' AND a.created_at >= $fromUtc AND a.created_at < $toUtc)::int AS people_signed_in,
        (SELECT COUNT(*) FROM queue_items q WHERE q.school_id=s.id AND q.status='APPROVED' AND q.request_type='DROP_OFF' AND q.approved_at >= $fromUtc AND q.approved_at < $toUtc)::int AS drop_offs,
        (SELECT COUNT(*) FROM queue_items q WHERE q.school_id=s.id AND q.status='APPROVED' AND q.request_type='PICK_UP' AND q.approved_at >= $fromUtc AND q.approved_at < $toUtc)::int AS pick_ups,
        (SELECT COUNT(*) FROM queue_items q WHERE q.school_id=s.id AND q.status='DECLINED' AND q.declined_at >= $fromUtc AND q.declined_at < $toUtc)::int AS declined,
        (SELECT COUNT(DISTINCT ar.date) FROM attendance_records ar WHERE ar.school_id=s.id AND ar.date BETWEEN $fromDate AND $toDate)::int AS attendance_days,
        (SELECT COUNT(*) FROM notices n WHERE n.school_id=s.id AND n.created_at >= $fromUtc AND n.created_at < $toUtc)::int AS messages
      FROM schools s WHERE s.status <> 'ARCHIVED' AND ($school::text IS NULL OR s.id=$school)`,
    orderBy: 'school',
  },
  'drop-offs-pickups': {
    title: 'Drop-offs and pickups',
    description: 'Per day and school: completed drop-offs and pickups, and the average wait.',
    columns: [['date', 'Date'], ['school', 'School'], ['drop_offs', 'Drop-offs'], ['pick_ups', 'Pickups'], ['avg_wait_minutes', 'Average wait (min)']],
    sql: `
      SELECT ${localDay('q.approved_at')} AS date, s.name AS school,
        COUNT(*) FILTER (WHERE q.request_type='DROP_OFF')::int AS drop_offs,
        COUNT(*) FILTER (WHERE q.request_type='PICK_UP')::int AS pick_ups,
        ROUND(AVG(EXTRACT(EPOCH FROM (q.approved_at::timestamp - q.requested_at::timestamp)) / 60)::numeric, 1)::float AS avg_wait_minutes
      FROM queue_items q JOIN schools s ON s.id=q.school_id
      WHERE q.status='APPROVED' AND q.approved_at >= $fromUtc AND q.approved_at < $toUtc AND ($school::text IS NULL OR q.school_id=$school)
      GROUP BY 1, s.id, s.name`,
    orderBy: 'date, school',
  },
  attendance: {
    title: 'Attendance',
    description: 'Per day and school: present (and of those, late), absent or sick, and other marks.',
    columns: [['date', 'Date'], ['school', 'School'], ['present', 'Present'], ['late', 'Late'], ['absent', 'Absent or sick'], ['other', 'Other']],
    sql: `
      SELECT ar.date, s.name AS school,
        COUNT(*) FILTER (WHERE ar.status='PRESENT')::int AS present,
        COUNT(*) FILTER (WHERE ar.status='PRESENT' AND ar.late=1)::int AS late,
        COUNT(*) FILTER (WHERE ar.status IN ('ABSENT','SICK'))::int AS absent,
        COUNT(*) FILTER (WHERE ar.status NOT IN ('PRESENT','ABSENT','SICK'))::int AS other
      FROM attendance_records ar JOIN schools s ON s.id=ar.school_id
      WHERE ar.date BETWEEN $fromDate AND $toDate AND ($school::text IS NULL OR ar.school_id=$school)
      GROUP BY ar.date, s.id, s.name`,
    orderBy: 'date, school',
  },
  'active-users': {
    title: 'Active users',
    description: 'Per day: how many different people signed in, by kind of account.',
    columns: [['date', 'Date'], ['people', 'People signed in'], ['parents', 'Parents'], ['teachers', 'Teachers'], ['admins', 'Admins & staff']],
    sql: `
      SELECT ${localDay('a.created_at')} AS date, COUNT(DISTINCT a.actor_user_id)::int AS people,
        COUNT(DISTINCT a.actor_user_id) FILTER (WHERE u.role='parent')::int AS parents,
        COUNT(DISTINCT a.actor_user_id) FILTER (WHERE u.role='teacher')::int AS teachers,
        COUNT(DISTINCT a.actor_user_id) FILTER (WHERE u.role='admin')::int AS admins
      FROM audit_logs a JOIN users u ON u.id=a.actor_user_id
      WHERE a.action='SIGNED_IN' AND a.created_at >= $fromUtc AND a.created_at < $toUtc AND ($school::text IS NULL OR a.school_id=$school)
      GROUP BY 1`,
    orderBy: 'date',
  },
  adoption: {
    title: 'Adoption',
    description: 'Each school: how many parents and staff have set up their accounts and used SDPMPlus in the period.',
    columns: [['school', 'School'], ['parents', 'Parents'], ['parents_set_up', 'Parents set up'], ['parents_active', 'Parents active'], ['parents_active_pct', 'Parents active %'],
      ['staff', 'Staff'], ['staff_set_up', 'Staff set up'], ['staff_active', 'Staff active']],
    sql: `
      WITH people AS (
        SELECT m.school_id, m.user_id, CASE WHEN m.role='parent' THEN 'parent' ELSE 'staff' END AS kind, u.needs_password_setup = 0 AS set_up,
          EXISTS (SELECT 1 FROM audit_logs a WHERE a.actor_user_id=m.user_id AND a.school_id=m.school_id AND a.action='SIGNED_IN' AND a.created_at >= $fromUtc AND a.created_at < $toUtc)
            OR EXISTS (SELECT 1 FROM queue_items q WHERE q.requested_by_user_id=m.user_id AND q.school_id=m.school_id AND q.requested_at >= $fromUtc AND q.requested_at < $toUtc) AS active
        FROM memberships m JOIN users u ON u.id=m.user_id AND u.active=1
        WHERE m.status='ACTIVE' AND m.role IN ('parent','teacher','school_admin','staff') AND ($school::text IS NULL OR m.school_id=$school)
      )
      SELECT s.name AS school,
        COUNT(DISTINCT p.user_id) FILTER (WHERE p.kind='parent')::int AS parents,
        COUNT(DISTINCT p.user_id) FILTER (WHERE p.kind='parent' AND p.set_up)::int AS parents_set_up,
        COUNT(DISTINCT p.user_id) FILTER (WHERE p.kind='parent' AND p.active)::int AS parents_active,
        COALESCE(ROUND(100.0 * COUNT(DISTINCT p.user_id) FILTER (WHERE p.kind='parent' AND p.active) / NULLIF(COUNT(DISTINCT p.user_id) FILTER (WHERE p.kind='parent'), 0))::int, 0) AS parents_active_pct,
        COUNT(DISTINCT p.user_id) FILTER (WHERE p.kind='staff')::int AS staff,
        COUNT(DISTINCT p.user_id) FILTER (WHERE p.kind='staff' AND p.set_up)::int AS staff_set_up,
        COUNT(DISTINCT p.user_id) FILTER (WHERE p.kind='staff' AND p.active)::int AS staff_active
      FROM schools s LEFT JOIN people p ON p.school_id=s.id
      WHERE s.status='ACTIVE' AND ($school::text IS NULL OR s.id=$school)
      GROUP BY s.id, s.name`,
    orderBy: 'school',
  },
  exceptions: {
    title: 'Exceptions',
    description: 'Per day and school: drop-off and pickup requests the school declined, and requests cancelled before they were answered.',
    columns: [['date', 'Date'], ['school', 'School'], ['declined_drop_offs', 'Drop-offs declined'], ['declined_pick_ups', 'Pickups declined'], ['cancelled', 'Cancelled']],
    sql: `
      SELECT ${localDay('COALESCE(q.declined_at, q.requested_at)')} AS date, s.name AS school,
        COUNT(*) FILTER (WHERE q.status='DECLINED' AND q.request_type='DROP_OFF')::int AS declined_drop_offs,
        COUNT(*) FILTER (WHERE q.status='DECLINED' AND q.request_type='PICK_UP')::int AS declined_pick_ups,
        COUNT(*) FILTER (WHERE q.status='CANCELLED')::int AS cancelled
      FROM queue_items q JOIN schools s ON s.id=q.school_id
      WHERE q.status IN ('DECLINED','CANCELLED') AND COALESCE(q.declined_at, q.requested_at) >= $fromUtc AND COALESCE(q.declined_at, q.requested_at) < $toUtc
        AND ($school::text IS NULL OR q.school_id=$school)
      GROUP BY 1, s.id, s.name`,
    orderBy: 'date, school',
  },
};

/** Turns $name placeholders into $1..$n with only the parameters the query uses. */
function bind(sql, values) {
  const order = [];
  const text = sql.replace(/\$(fromUtc|toUtc|fromDate|toDate|school|tz)\b/g, (_, name) => {
    let index = order.indexOf(name);
    if (index === -1) { order.push(name); index = order.length - 1; }
    return `$${index + 1}`;
  });
  return { text, params: order.map(name => values[name]) };
}

const validDate = value => (/^\d{4}-\d{2}-\d{2}$/.test(value ?? '') ? value : null);

async function reportContext(query) {
  const today = localDate();
  const toDate = validDate(query.to) ?? today;
  const fromDate = validDate(query.from) ?? daysAgo(toDate, 29);
  if (fromDate > toDate) throw Object.assign(new Error('The start date must be on or before the end date.'), { status: 400 });
  const days = (Date.parse(`${toDate}T00:00:00Z`) - Date.parse(`${fromDate}T00:00:00Z`)) / 86400000 + 1;
  if (days > MAX_DAYS) throw Object.assign(new Error('Choose a period of a year or less.'), { status: 400 });
  const [fromUtc] = await utcBounds(fromDate, daysAgo(fromDate, -1));
  const [toUtc] = await utcBounds(daysAgo(toDate, -1), daysAgo(toDate, -2));
  const school = typeof query.schoolId === 'string' && query.schoolId ? query.schoolId : null;
  return { fromDate, toDate, fromUtc, toUtc, school, tz: PLATFORM_TZ };
}

async function runReport(report, ctx, { limit, offset }) {
  const { text, params } = bind(report.sql, ctx);
  const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM (${text}) r`, params);
  const { rows } = await pool.query(`SELECT * FROM (${text}) r ORDER BY ${report.orderBy} LIMIT ${limit} OFFSET ${offset}`, params);
  return { rows, total };
}

// CSV, with spreadsheet formula injection neutralised (a school named "=HYPERLINK(...)" stays text).
function toCsv(columns, rows) {
  const cell = value => {
    let text = value === null || value === undefined ? '' : String(value);
    if (/^[=+\-@\t\r]/.test(text) && !/^-?\d+(\.\d+)?$/.test(text)) text = `'${text}`;
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return [columns.map(([, label]) => cell(label)).join(','), ...rows.map(row => columns.map(([key]) => cell(row[key])).join(','))].join('\r\n');
}

registerJobHandler('REPORT_EXPORT', async ({ reportType, query }) => {
  const report = REPORTS[reportType];
  const ctx = await reportContext(query);
  const { rows, total } = await runReport(report, ctx, { limit: EXPORT_ROW_CAP, offset: 0 });
  if (total > EXPORT_ROW_CAP) throw Object.assign(new Error('That report is too large. Narrow the date range or choose one school.'), { final: true });
  return { name: `sdpmplus-${reportType}-${ctx.fromDate}-to-${ctx.toDate}.csv`, type: 'text/csv', body: `﻿${toCsv(report.columns, rows)}` };
});

export function registerPlatformReports(router) {
  router.get('/reports', requirePlatformPermission('reports:view'), (req, res) => {
    res.json(Object.entries(REPORTS).map(([key, r]) => ({ key, title: r.title, description: r.description, columns: r.columns.map(([k, label]) => ({ key: k, label })) })));
  });

  router.get('/reports/:type', requirePlatformPermission('reports:view'), asyncRoute(async (req, res) => {
    const report = REPORTS[req.params.type];
    if (!report) return res.status(404).json({ error: 'Report not found' });
    let ctx;
    try { ctx = await reportContext(req.query); } catch (error) { return res.status(error.status ?? 400).json({ error: error.message }); }
    const pageNumber = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, Number.parseInt(req.query.pageSize, 10) || 50));
    const { rows, total } = await runReport(report, ctx, { limit: pageSize, offset: (pageNumber - 1) * pageSize });
    res.json({ from: ctx.fromDate, to: ctx.toDate, timezone: ctx.tz, columns: report.columns.map(([key, label]) => ({ key, label })), rows, total, page: pageNumber, pageSize });
  }));

  router.post('/reports/:type/export', requirePlatformPermission('reports:view'), asyncRoute(async (req, res) => {
    const report = REPORTS[req.params.type];
    if (!report) return res.status(404).json({ error: 'Report not found' });
    const query = { from: req.body.from, to: req.body.to, schoolId: req.body.schoolId };
    try { await reportContext(query); } catch (error) { return res.status(error.status ?? 400).json({ error: error.message }); }
    const jobId = await enqueueJob('REPORT_EXPORT', { reportType: req.params.type, query }, req.user.id);
    await writeAudit({
      schoolId: query.schoolId || null, actor: req.user, actorRole: req.platformAdmin.role, action: 'REPORT_EXPORT_REQUESTED',
      targetType: 'job', targetId: jobId, targetLabel: report.title, details: query, ip: req.ip, requestId: req.requestId,
    });
    res.status(202).json({ jobId });
  }));

  // Your own recent exports (super admins see everyone's).
  router.get('/jobs', requirePlatformPermission('reports:view'), asyncRoute(async (req, res) => {
    const all = req.platformAdmin.role === 'SUPER_ADMIN' && req.query.all === '1';
    const { rows } = await pool.query(`
      SELECT j.id, j.type, j.params, j.status, j.error, j.result_name AS "resultName", j.result_size AS "resultSize",
        j.created_at AS "createdAt", j.finished_at AS "finishedAt", u.full_name AS "createdBy"
      FROM jobs j LEFT JOIN users u ON u.id=j.created_by_user_id
      WHERE ($1::boolean OR j.created_by_user_id=$2) ORDER BY j.created_at DESC, j.id LIMIT 25`, [all, req.user.id]);
    res.json(rows.map(r => ({ ...r, params: JSON.parse(r.params) })));
  }));

  router.get('/jobs/:id/download', requirePlatformPermission('reports:view'), asyncRoute(async (req, res) => {
    const { rows: [job] } = await pool.query(`SELECT id, status, result, result_name, result_type, created_by_user_id, params FROM jobs WHERE id=$1`, [req.params.id]);
    const admin = await getPlatformAdmin(req.user.id);
    if (!job || (job.created_by_user_id !== req.user.id && admin.role !== 'SUPER_ADMIN')) return res.status(404).json({ error: 'Export not found' });
    if (job.status !== 'SUCCEEDED') return res.status(409).json({ error: 'This export is not ready.' });
    const params = JSON.parse(job.params);
    await writeAudit({
      schoolId: params.query?.schoolId || null, actor: req.user, actorRole: admin.role, action: 'REPORT_EXPORTED',
      targetType: 'job', targetId: job.id, targetLabel: job.result_name, ip: req.ip, requestId: req.requestId,
    });
    res.setHeader('Content-Type', `${job.result_type}; charset=utf-8`);
    res.setHeader('Content-Disposition', `attachment; filename="${job.result_name.replace(/[^\w.-]/g, '_')}"`);
    res.send(job.result);
  }));
}
