import { db } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { activeSupportSession } from './supportSessions.js';

/** Roles with full administrative rights in a school. (Platform admins act in a school only through a support session.) */
export const SCHOOL_ADMIN_ROLES = ['school_admin', 'district_admin'];

// A person's active per-school roles. A district admin's district
// membership is expanded here into one 'district_admin' row per ACTIVE
// school in their district — so every per-school permission check
// (requireSchoolAccess, the queue/attendance checks, ...) handles them
// without knowing districts exist, and a school outside the district
// never appears. districtId/districtName are set on those rows.
export function getMemberships(userId) {
  return db.prepare(`
    SELECT m.id,m.school_id AS "schoolId",m.campus_id AS "campusId",m.role,
      s.name AS "schoolName",s.code AS "schoolCode",c.name AS "campusName",
      NULL AS "districtId", NULL AS "districtName"
    FROM memberships m JOIN schools s ON s.id=m.school_id
    LEFT JOIN campuses c ON c.id=m.campus_id
    WHERE m.user_id=? AND m.status='ACTIVE' AND s.status='ACTIVE'
    UNION ALL
    SELECT dm.id,s.id AS "schoolId",NULL AS "campusId",'district_admin' AS role,
      s.name AS "schoolName",s.code AS "schoolCode",NULL AS "campusName",
      o.id AS "districtId", o.name AS "districtName"
    FROM district_memberships dm JOIN organizations o ON o.id=dm.organization_id AND o.status='ACTIVE'
    JOIN schools s ON s.organization_id=o.id AND s.status='ACTIVE'
    WHERE dm.user_id=? AND dm.status='ACTIVE'
    ORDER BY "schoolName","campusName"
  `).all(userId, userId);
}

export async function canAccessSchool(userId, schoolId, allowedRoles = []) {
  const memberships = await getMemberships(userId);
  return memberships.find(m => m.schoolId === schoolId && (allowedRoles.length === 0 || allowedRoles.includes(m.role))) || null;
}

const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Route guard: the signed-in person must hold one of `allowedRoles` in the
 * school this request is about (X-School-ID, or their only/first school).
 * Sets req.school ({ id, name }) and req.membership.
 *
 * A platform admin gets nothing from their platform role here. They reach
 * a school only through an open support session (supportSessions.js):
 * limited to that one school, read-only unless changes were allowed, and
 * every request made through it is audited.
 */
export function requireSchoolAccess(...allowedRoles) {
  return asyncRoute(async (req, res, next) => {
    const requestedSchoolId = req.headers['x-school-id'] || req.query.schoolId || req.body?.schoolId;

    const support = await activeSupportSession(req);
    if (support) {
      if (requestedSchoolId && requestedSchoolId !== support.schoolId) {
        return res.status(403).json({ error: 'Your support session is for a different school' });
      }
      if (!support.allowChanges && !READ_METHODS.has(req.method)) {
        return res.status(403).json({ error: 'This support session is read-only. Start one that allows changes to do this.' });
      }
      req.school = { id: support.schoolId, name: support.schoolName };
      req.membership = { role: 'school_admin', schoolId: support.schoolId, schoolName: support.schoolName, support: true };
      auditSupportRequest(req, res, support);
      return next();
    }

    const memberships = await getMemberships(req.user.id);
    const candidates = requestedSchoolId ? memberships.filter(m => m.schoolId === requestedSchoolId) : memberships;
    // A district admin counts as a school admin in each district school.
    const membership = candidates.find(m => allowedRoles.length === 0 || allowedRoles.includes(m.role)
      || (m.role === 'district_admin' && allowedRoles.includes('school_admin')));
    if (!membership) return res.status(403).json({ error: 'You do not have access to the requested school' });
    req.school = { id: membership.schoolId, name: membership.schoolName };
    req.membership = membership;
    next();
  });
}

// Every change made through a support session is recorded, and the first
// view of each page — the screens poll every few seconds, and one entry
// per refresh would bury everything else in the school's audit log.
const viewedInSupport = new Map(); // support session id -> Set of paths
function auditSupportRequest(req, res, support) {
  const path = req.originalUrl.split('?')[0];
  if (READ_METHODS.has(req.method)) {
    const seen = viewedInSupport.get(support.id) ?? new Set();
    if (seen.has(path)) return;
    seen.add(path);
    viewedInSupport.set(support.id, seen);
    if (viewedInSupport.size > 1000) viewedInSupport.delete(viewedInSupport.keys().next().value);
  }
  res.on('finish', () => {
    writeAudit({
      schoolId: support.schoolId, actor: req.user, actorRole: support.platformRole,
      action: READ_METHODS.has(req.method) ? 'SUPPORT_VIEWED' : 'SUPPORT_CHANGE',
      details: { method: req.method, path, status: res.statusCode },
      ip: req.ip, requestId: req.requestId, supportSessionId: support.id,
    });
  });
}
