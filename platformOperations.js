import { pool } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { requirePlatformPermission } from './permissions.js';
import { PLATFORM_TZ, daysAgo, localDate, utcBounds } from './platformInsights.js';

// Platform → Operations: live drop-offs and pickups across every school,
// requests still waiting, attendance by school for a day, and incidents
// (pickups released without the code, pickups cancelled for wrong codes)
// that a platform admin can mark as reviewed.
//
// Cross-school lists name a child only as "First L." — enough to talk to
// a school about a specific request, without spreading full names. Every
// query is bounded (today / a date range, and pages of at most 100).

const STUDENT_SHORT_NAME = `st.first_name || ' ' || LEFT(st.last_name, 1) || '.'`;
const WAIT_WARN_MINUTES = 15;
const WAIT_ALERT_MINUTES = 30;

const pageOf = query => {
  const pageNumber = Math.max(1, Number.parseInt(query.page, 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(query.pageSize, 10) || 50));
  return { pageNumber, pageSize, offset: (pageNumber - 1) * pageSize };
};
const validDate = value => (/^\d{4}-\d{2}-\d{2}$/.test(value ?? '') ? value : null);
const optionalId = value => (typeof value === 'string' && value.trim() && value.length <= 100 ? value.trim() : null);

// Seeing cross-school operations is recorded, at most once per person per
// 15 minutes per screen — these screens refresh every few seconds.
const lastViewAudit = new Map();
function auditViewThrottled(req, screen) {
  const key = `${req.user.id}:${screen}`;
  const now = Date.now();
  if ((lastViewAudit.get(key) ?? 0) > now - 15 * 60 * 1000) return;
  lastViewAudit.set(key, now);
  if (lastViewAudit.size > 5000) lastViewAudit.delete(lastViewAudit.keys().next().value);
  writeAudit({ actor: req.user, actorRole: req.platformAdmin.role, action: 'PLATFORM_OPERATIONS_VIEWED', details: { screen }, ip: req.ip, requestId: req.requestId });
}

async function todayBounds() {
  const today = localDate();
  const [start, end] = await utcBounds(today, daysAgo(today, -1));
  return { today, start, end };
}

// ---- incidents ------------------------------------------------------------------
//
// One list built from where each kind of exception already lives:
//   override:<queue item id>  — a pickup released by an admin without the code (queue_items, with the reason given)
//   lockout:<audit entry id>  — a pickup cancelled after too many wrong codes (audit_logs)
const INCIDENT_TYPES = ['ADMIN_OVERRIDE', 'WRONG_CODE_LOCKOUT'];

function incidentsSql() {
  return `
    SELECT incidents.*, r.note AS "reviewNote", r.reviewed_at AS "reviewedAt", ru.full_name AS "reviewedBy" FROM (
      SELECT 'override:' || qi.id AS key, 'ADMIN_OVERRIDE' AS type, qi.school_id AS "schoolId", s.name AS "schoolName",
        qi.approved_at AS "occurredAt", u.full_name AS "actorName", ${STUDENT_SHORT_NAME} AS "studentName",
        qi.override_reason AS reason, qi.request_type AS "requestType"
      FROM queue_items qi JOIN schools s ON s.id=qi.school_id JOIN students st ON st.id=qi.student_id
      LEFT JOIN users u ON u.id=qi.approved_by_user_id
      WHERE qi.verification_method='ADMIN_OVERRIDE' AND qi.approved_at >= $1 AND qi.approved_at < $2
      UNION ALL
      SELECT 'lockout:' || a.id, 'WRONG_CODE_LOCKOUT', a.school_id, s.name, a.created_at, a.actor_name,
        ${STUDENT_SHORT_NAME}, NULL, 'PICK_UP'
      FROM audit_logs a JOIN schools s ON s.id=a.school_id LEFT JOIN students st ON st.id=a.target_id
      WHERE a.action='PICKUP_CODE_LOCKED_OUT' AND a.created_at >= $1 AND a.created_at < $2
    ) incidents
    LEFT JOIN incident_reviews r ON r.incident_key = incidents.key
    LEFT JOIN users ru ON ru.id = r.reviewed_by_user_id
    WHERE ($3::text IS NULL OR incidents."schoolId" = $3)
      AND ($4::text IS NULL OR incidents.type = $4)
      AND ($5::text = 'all' OR ($5 = 'open' AND r.incident_key IS NULL) OR ($5 = 'reviewed' AND r.incident_key IS NOT NULL))`;
}

export function registerPlatformOperations(router) {
  // Per-school summary of today: what's done, what's waiting, how long.
  router.get('/operations/schools', requirePlatformPermission('pickup:view'), asyncRoute(async (req, res) => {
    const { start, end } = await todayBounds();
    const { pageNumber, pageSize, offset } = pageOf(req.query);
    const search = typeof req.query.search === 'string' ? req.query.search.trim().slice(0, 100) : '';
    const params = [start, end, search || null];
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM schools s WHERE s.status='ACTIVE' AND ($3::text IS NULL OR s.name ILIKE '%' || $3 || '%') AND $1::text IS NOT NULL AND $2::text IS NOT NULL`, params);
    const { rows } = await pool.query(`
      WITH q AS (
        SELECT school_id,
          COUNT(*) FILTER (WHERE request_type='DROP_OFF' AND status='APPROVED' AND approved_at >= $1 AND approved_at < $2)::int AS "dropOffs",
          COUNT(*) FILTER (WHERE request_type='PICK_UP' AND status='APPROVED' AND approved_at >= $1 AND approved_at < $2)::int AS "pickUps",
          COUNT(*) FILTER (WHERE status='PENDING' AND request_type='DROP_OFF')::int AS "pendingDropOffs",
          COUNT(*) FILTER (WHERE status='PENDING' AND request_type='PICK_UP')::int AS "pendingPickUps",
          MIN(requested_at) FILTER (WHERE status='PENDING') AS "oldestPendingAt",
          COUNT(*) FILTER (WHERE verification_method='ADMIN_OVERRIDE' AND approved_at >= $1 AND approved_at < $2)::int AS overrides
        FROM queue_items WHERE status='PENDING' OR approved_at >= $1 GROUP BY school_id
      )
      SELECT s.id, s.name, COALESCE(q."dropOffs",0) AS "dropOffs", COALESCE(q."pickUps",0) AS "pickUps",
        COALESCE(q."pendingDropOffs",0) AS "pendingDropOffs", COALESCE(q."pendingPickUps",0) AS "pendingPickUps",
        q."oldestPendingAt", COALESCE(q.overrides,0) AS overrides
      FROM schools s LEFT JOIN q ON q.school_id=s.id
      WHERE s.status='ACTIVE' AND ($3::text IS NULL OR s.name ILIKE '%' || $3 || '%')
      -- Longest-waiting request first: that's the school most likely to need a nudge.
      ORDER BY q."oldestPendingAt" ASC NULLS LAST, COALESCE(q."pendingDropOffs",0) + COALESCE(q."pendingPickUps",0) DESC, s.name, s.id
      LIMIT ${pageSize} OFFSET ${offset}`, params);
    const now = Date.now();
    res.json({
      items: rows.map(r => ({ ...r, oldestWaitMinutes: r.oldestPendingAt ? Math.floor((now - Date.parse(`${r.oldestPendingAt.replace(' ', 'T')}Z`)) / 60000) : null })),
      total, page: pageNumber, pageSize, timezone: PLATFORM_TZ,
    });
  }));

  // Individual requests: waiting (any day, oldest first) or done today (newest first).
  router.get('/operations/requests', requirePlatformPermission('pickup:view'), asyncRoute(async (req, res) => {
    const { start } = await todayBounds();
    const { pageNumber, pageSize, offset } = pageOf(req.query);
    const state = ['waiting', 'done'].includes(req.query.state) ? req.query.state : 'waiting';
    const type = ['DROP_OFF', 'PICK_UP'].includes(req.query.type) ? req.query.type : null;
    const params = [start, type, optionalId(req.query.schoolId)];
    const where = `${state === 'waiting' ? `qi.status='PENDING'` : `qi.status IN ('APPROVED','CANCELLED') AND COALESCE(qi.approved_at, qi.declined_at) >= $1`}
      AND ($2::text IS NULL OR qi.request_type = $2) AND ($3::text IS NULL OR qi.school_id = $3) AND $1::text IS NOT NULL`;
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM queue_items qi WHERE ${where}`, params);
    const { rows } = await pool.query(`
      SELECT qi.id, qi.school_id AS "schoolId", s.name AS "schoolName", c.name AS "campusName", qi.request_type AS "requestType",
        qi.status, qi.requested_at AS "requestedAt", COALESCE(qi.approved_at, qi.declined_at) AS "closedAt",
        qi.verification_method AS "verificationMethod", ${STUDENT_SHORT_NAME} AS "studentName", t.full_name AS "teacherName"
      FROM queue_items qi JOIN schools s ON s.id=qi.school_id JOIN students st ON st.id=qi.student_id
      LEFT JOIN campuses c ON c.id=qi.campus_id LEFT JOIN users t ON t.id=qi.teacher_user_id
      WHERE ${where}
      ORDER BY ${state === 'waiting' ? 'qi.requested_at ASC' : 'COALESCE(qi.approved_at, qi.declined_at) DESC'}, qi.id
      LIMIT ${pageSize} OFFSET ${offset}`, params);
    auditViewThrottled(req, `requests:${state}`);
    const now = Date.now();
    res.json({
      items: rows.map(r => ({ ...r, waitMinutes: r.status === 'PENDING' ? Math.floor((now - Date.parse(`${r.requestedAt.replace(' ', 'T')}Z`)) / 60000) : null })),
      total, page: pageNumber, pageSize, thresholds: { warn: WAIT_WARN_MINUTES, alert: WAIT_ALERT_MINUTES },
    });
  }));

  // Attendance for one day, per school.
  router.get('/operations/attendance', requirePlatformPermission('attendance:view'), asyncRoute(async (req, res) => {
    const date = validDate(req.query.date) ?? localDate();
    const { pageNumber, pageSize, offset } = pageOf(req.query);
    const params = [date];
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM schools WHERE status='ACTIVE' AND $1::text IS NOT NULL`, params);
    const { rows } = await pool.query(`
      WITH a AS (
        SELECT school_id, COUNT(*) FILTER (WHERE status='PRESENT')::int AS present, COUNT(*) FILTER (WHERE status='PRESENT' AND late=1)::int AS late,
          COUNT(*) FILTER (WHERE status IN ('ABSENT','SICK'))::int AS absent, COUNT(*) FILTER (WHERE status NOT IN ('PRESENT','ABSENT','SICK'))::int AS other
        FROM attendance_records WHERE date=$1 GROUP BY school_id
      ), st AS (
        SELECT school_id, COUNT(*)::int AS students FROM students WHERE status='ACTIVE' GROUP BY school_id
      )
      SELECT s.id, s.name, COALESCE(st.students,0) AS students, COALESCE(a.present,0) AS present, COALESCE(a.late,0) AS late,
        COALESCE(a.absent,0) AS absent, COALESCE(a.other,0) AS other
      FROM schools s LEFT JOIN a ON a.school_id=s.id LEFT JOIN st ON st.school_id=s.id
      WHERE s.status='ACTIVE' ORDER BY s.name, s.id LIMIT ${pageSize} OFFSET ${offset}`, params);
    const { rows: [totals] } = await pool.query(`
      SELECT COUNT(*) FILTER (WHERE a.status='PRESENT')::int AS present, COUNT(*) FILTER (WHERE a.status IN ('ABSENT','SICK'))::int AS absent,
        COUNT(*) FILTER (WHERE a.status='PRESENT' AND a.late=1)::int AS late
      FROM attendance_records a JOIN schools s ON s.id=a.school_id AND s.status='ACTIVE' WHERE a.date=$1`, params);
    res.json({
      date, totals,
      items: rows.map(r => ({ ...r, unmarked: Math.max(0, r.students - r.present - r.absent - r.other) })),
      total, page: pageNumber, pageSize,
    });
  }));

  router.get('/operations/incidents', requirePlatformPermission('pickup:view'), asyncRoute(async (req, res) => {
    const today = localDate();
    const to = validDate(req.query.to) ?? today;
    const from = validDate(req.query.from) ?? daysAgo(today, 6);
    if (from > to) return res.status(400).json({ error: 'The start date must be on or before the end date.' });
    const [start] = await utcBounds(from, daysAgo(to, -1));
    const [, end] = await utcBounds(to, daysAgo(to, -1));
    const type = INCIDENT_TYPES.includes(req.query.type) ? req.query.type : null;
    const state = ['open', 'reviewed', 'all'].includes(req.query.state) ? req.query.state : 'open';
    const { pageNumber, pageSize, offset } = pageOf(req.query);
    const params = [start, end, optionalId(req.query.schoolId), type, state];
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM (${incidentsSql()}) x`, params);
    const { rows } = await pool.query(`${incidentsSql()} ORDER BY incidents."occurredAt" DESC, incidents.key LIMIT ${pageSize} OFFSET ${offset}`, params);
    auditViewThrottled(req, 'incidents');
    res.json({
      from, to,
      items: rows,
      total, page: pageNumber, pageSize,
    });
  }));

  // Marking an incident reviewed needs a note; it's audited under the incident's school.
  router.post('/operations/incidents/review', requirePlatformPermission('incident:review'), asyncRoute(async (req, res) => {
    const key = typeof req.body.key === 'string' ? req.body.key : '';
    const note = typeof req.body.note === 'string' ? req.body.note.trim().slice(0, 500) : '';
    if (note.length < 5) return res.status(400).json({ error: 'Add a note about what was checked (at least 5 characters).' });
    const [kind, id] = key.split(':');
    const source = kind === 'override'
      ? await pool.query(`SELECT school_id AS "schoolId" FROM queue_items WHERE id=$1 AND verification_method='ADMIN_OVERRIDE'`, [id])
      : kind === 'lockout'
        ? await pool.query(`SELECT school_id AS "schoolId" FROM audit_logs WHERE id=$1 AND action='PICKUP_CODE_LOCKED_OUT'`, [id])
        : { rows: [] };
    const incident = source.rows[0];
    if (!incident) return res.status(404).json({ error: 'Incident not found' });
    const saved = await pool.query(`INSERT INTO incident_reviews (incident_key,school_id,note,reviewed_by_user_id) VALUES ($1,$2,$3,$4) ON CONFLICT (incident_key) DO NOTHING`,
      [key, incident.schoolId, note, req.user.id]);
    if (saved.rowCount === 0) return res.status(409).json({ error: 'This incident was already reviewed.' });
    await writeAudit({
      schoolId: incident.schoolId, actor: req.user, actorRole: req.platformAdmin.role, action: 'INCIDENT_REVIEWED',
      targetType: kind === 'override' ? 'queue_item' : 'audit_entry', targetId: id, reason: note, ip: req.ip, requestId: req.requestId,
    });
    res.status(204).end();
  }));
}
