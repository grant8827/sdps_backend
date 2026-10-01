import { db } from './db.js';
import { asyncRoute } from './asyncRoute.js';

/** Roles with full administrative rights in a school. */
export const SCHOOL_ADMIN_ROLES = ['school_admin', 'district_admin', 'platform_super_admin'];

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
  const superAdmin = memberships.some(m => m.role === 'platform_super_admin');
  if (superAdmin) return (await db.prepare(`SELECT id AS "schoolId",name AS "schoolName",code AS "schoolCode" FROM schools WHERE id=? AND status='ACTIVE'`).get(schoolId)) || null;
  return memberships.find(m => m.schoolId === schoolId && (allowedRoles.length === 0 || allowedRoles.includes(m.role))) || null;
}

export function requireSchoolAccess(...allowedRoles) {
  return asyncRoute(async (req, res, next) => {
    const memberships = await getMemberships(req.user.id);
    const requestedSchoolId = req.headers['x-school-id'] || req.query.schoolId || req.body?.schoolId;
    const superAdmin = memberships.find(m => m.role === 'platform_super_admin');
    if (superAdmin && requestedSchoolId) {
      const school = await db.prepare(`SELECT id FROM schools WHERE id=? AND status='ACTIVE'`).get(requestedSchoolId);
      if (!school) return res.status(404).json({ error: 'School not found' });
      req.school = { id: requestedSchoolId };
      req.membership = superAdmin;
      return next();
    }
    const candidates = requestedSchoolId ? memberships.filter(m => m.schoolId === requestedSchoolId) : memberships;
    // A district admin counts as a school admin in each district school.
    const membership = candidates.find(m => m.role === 'platform_super_admin' || allowedRoles.length === 0 || allowedRoles.includes(m.role)
      || (m.role === 'district_admin' && allowedRoles.includes('school_admin')));
    if (!membership) return res.status(403).json({ error: 'You do not have access to the requested school' });
    req.school = { id: requestedSchoolId || membership.schoolId };
    req.membership = membership;
    next();
  });
}
