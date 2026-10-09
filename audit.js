import { pool, id } from './db.js';

// Audit trail for sensitive actions — who viewed student data, changed
// pickup authorization, requested/accepted/declined a drop-off or
// pickup, changed a student/staff/parent record, or changed school
// settings. Rows live in audit_logs (migration 17), which the database
// itself keeps append-only.
//
// Writes go straight to the pool, never through db.prepare: an entry is
// written after the response has finished, by which point any
// withTransaction() client the route used may already be released.

// Request-body keys never copied into an entry's details — secrets
// (including pickup PINs: pin, currentPin, newPin), and photos (a base64
// data URL can be megabytes).
// Also the emailed confirmation code (emailCode) and any uploaded image.
const OMITTED_KEYS = /password|token|secret|photo|dataurl|emailcode|(^|[a-z])pin$/i;
const MAX_STRING = 200;

export function sanitizeDetails(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  if (typeof value !== 'object' || depth > 2) return typeof value === 'object' ? '[…]' : value;
  if (Array.isArray(value)) return value.slice(0, 20).map(item => sanitizeDetails(item, depth + 1));
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !OMITTED_KEYS.test(key))
    .map(([key, item]) => [key, sanitizeDetails(item, depth + 1)]));
}

/**
 * Writes one entry. Never throws — a failed audit write is logged to
 * the console instead of failing (or un-doing) the action it describes.
 */
export async function writeAudit({
  schoolId = null, actor = null, actorRole = null, action, targetType = null, targetId = null, targetLabel = null, details = null, ip = null,
  reason = null, requestId = null, supportSessionId = null,
}) {
  try {
    const cleanDetails = details && Object.keys(details).length ? JSON.stringify(sanitizeDetails(details)) : null;
    await pool.query(
      `INSERT INTO audit_logs (id,school_id,actor_user_id,actor_name,actor_role,action,target_type,target_id,target_label,details,ip_address,reason,request_id,support_session_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [id('audit'), schoolId, actor?.id ?? null, actor?.full_name ?? actor?.fullName ?? null, actorRole ?? actor?.role ?? null,
        action, targetType, targetId, targetLabel, cleanDetails, ip, typeof reason === 'string' ? reason.slice(0, 500) : null,
        requestId, supportSessionId],
    );
  } catch (error) {
    console.error('Audit log write failed', action, error);
  }
}

// Display names, copied into the entry so it stays readable after the
// record it points at is renamed or removed.
const lookups = {
  student: `SELECT first_name || ' ' || last_name AS label FROM students WHERE id=$1`,
  user: `SELECT full_name AS label FROM users WHERE id=$1`,
  guardian: `SELECT u.full_name AS label FROM guardians gu JOIN users u ON u.id=gu.user_id WHERE gu.id=$1`,
  campus: `SELECT name AS label FROM campuses WHERE id=$1`,
  class: `SELECT name AS label FROM classes WHERE id=$1`,
  school_year: `SELECT name AS label FROM school_years WHERE id=$1`,
  school: `SELECT name AS label FROM schools WHERE id=$1`,
};
async function labelFor(targetType, targetId) {
  const sql = lookups[targetType];
  if (!sql || !targetId) return null;
  try { return (await pool.query(sql, [targetId])).rows[0]?.label ?? null; } catch { return null; }
}

// For routes with no school in the request (a teacher's own roster, a
// password change): the actor's first active school. Teachers and staff
// belong to one school in practice.
async function defaultSchoolFor(user) {
  if (!user?.id) return null;
  try {
    return (await pool.query(`SELECT school_id FROM memberships WHERE user_id=$1 AND status='ACTIVE' ORDER BY school_id LIMIT 1`, [user.id])).rows[0]?.school_id ?? null;
  } catch { return null; }
}

/**
 * Route middleware: records `action` once the response finishes
 * successfully (any 2xx/3xx). Put it after requireAuth/requireSchoolAccess.
 *
 * `describe(req, responseBody)` returns any of { schoolId, targetType,
 * targetId, details, actor } for this entry; by default details are the
 * (sanitized) request body and schoolId is req.school.id. A handler can
 * also set `res.locals.audit` to the same shape (plus `action`) when only
 * it knows the school or the exact outcome — e.g. whether a queue item
 * it just approved was a drop-off or a pickup.
 */
export const audited = (action, describe = () => ({})) => (req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = body => { res.locals.auditResponseBody = body; return originalJson(body); };
  res.on('finish', async () => {
    if (res.statusCode >= 400) return;
    try {
      const entry = { ...(await describe(req, res.locals.auditResponseBody)), ...res.locals.audit };
      await writeAudit({
        schoolId: entry.schoolId ?? req.school?.id ?? await defaultSchoolFor(entry.actor ?? req.user),
        actor: entry.actor ?? req.user,
        // In a support session the actor is the platform admin, not a school admin.
        actorRole: entry.actorRole ?? req.supportSession?.platformRole ?? req.membership?.role ?? req.user?.role,
        action: entry.action ?? action,
        targetType: entry.targetType ?? null,
        targetId: entry.targetId ?? null,
        targetLabel: entry.targetLabel ?? await labelFor(entry.targetType, entry.targetId),
        details: entry.details !== undefined ? entry.details : req.body,
        ip: req.ip,
        reason: entry.reason ?? null,
        requestId: req.requestId ?? null,
        supportSessionId: req.supportSession?.id ?? null,
      });
    } catch (error) {
      console.error('Audit log write failed', action, error);
    }
  });
  next();
};
