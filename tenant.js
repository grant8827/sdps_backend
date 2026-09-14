import { db } from './database.js';

export function getMemberships(userId) {
  return db.prepare(`
    SELECT m.id,m.school_id AS schoolId,m.campus_id AS campusId,m.role,
      s.name AS schoolName,s.code AS schoolCode,c.name AS campusName
    FROM memberships m JOIN schools s ON s.id=m.school_id
    LEFT JOIN campuses c ON c.id=m.campus_id
    WHERE m.user_id=? AND m.status='ACTIVE' AND s.status='ACTIVE'
    ORDER BY s.name,c.name
  `).all(userId);
}

export function canAccessSchool(userId, schoolId, allowedRoles = []) {
  const memberships = getMemberships(userId);
  const superAdmin = memberships.some(m => m.role === 'platform_super_admin');
  if (superAdmin) return db.prepare(`SELECT id AS schoolId,name AS schoolName,code AS schoolCode FROM schools WHERE id=? AND status='ACTIVE'`).get(schoolId) || null;
  return memberships.find(m => m.schoolId === schoolId && (allowedRoles.length === 0 || allowedRoles.includes(m.role))) || null;
}

export function requireSchoolAccess(...allowedRoles) {
  return (req, res, next) => {
    const memberships = getMemberships(req.user.id);
    const requestedSchoolId = req.headers['x-school-id'] || req.query.schoolId || req.body?.schoolId;
    const superAdmin = memberships.find(m => m.role === 'platform_super_admin');
    if (superAdmin && requestedSchoolId) {
      const school = db.prepare(`SELECT id FROM schools WHERE id=? AND status='ACTIVE'`).get(requestedSchoolId);
      if (!school) return res.status(404).json({ error: 'School not found' });
      req.school = { id: requestedSchoolId };
      req.membership = superAdmin;
      return next();
    }
    const candidates = requestedSchoolId ? memberships.filter(m => m.schoolId === requestedSchoolId) : memberships;
    const membership = candidates.find(m => m.role === 'platform_super_admin' || allowedRoles.length === 0 || allowedRoles.includes(m.role));
    if (!membership) return res.status(403).json({ error: 'You do not have access to the requested school' });
    req.school = { id: requestedSchoolId || membership.schoolId };
    req.membership = membership;
    next();
  };
}
