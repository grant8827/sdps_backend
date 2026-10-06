import { db } from './db.js';
import { asyncRoute } from './asyncRoute.js';

// Platform-level roles and what each may do. Kept in code, not in the
// database, so every change is reviewed and tested. School-level roles
// (school_admin, staff, teacher, parent) are separate and live in
// memberships; a platform role never grants school data by itself —
// that needs a support session (supportSessions.js).

export const PLATFORM_ROLES = ['SUPER_ADMIN', 'PLATFORM_ADMIN', 'SUPPORT_ADMIN', 'BILLING_ADMIN'];

export const PERMISSIONS = [
  'platform:view',          // see the platform dashboard at all
  'school:view',
  'school:create',
  'school:update',
  'school:suspend',         // suspend and reactivate
  'school:archive',
  'user:view',
  'user:create',
  'user:disable',
  'platform_admin:manage',  // add/disable platform admins and change their roles
  'audit:view',
  'support:start',          // open a read-only support session into a school
  'support:write',          // ...and one that may also make changes
  'student:view',
  'pickup:view',
  'pickup:override',
  'incident:review',        // mark a drop-off/pickup exception as reviewed
  'attendance:view',
  'security:view',
  'compliance:view',
  'data_request:manage',    // log, review and carry out export/deletion requests
  'legal_hold:manage',      // put a school's records on legal hold, or release it
  'billing:view',
  'billing:update',
  'reports:view',
  'platform:settings',
  'system:view',            // System Health
];

const ROLE_PERMISSIONS = {
  SUPER_ADMIN: PERMISSIONS,
  PLATFORM_ADMIN: [
    'platform:view', 'school:view', 'school:create', 'school:update', 'school:suspend', 'user:view', 'user:create', 'user:disable',
    'audit:view', 'support:start', 'student:view', 'pickup:view', 'incident:review', 'attendance:view', 'security:view', 'compliance:view', 'data_request:manage', 'reports:view', 'system:view',
  ],
  SUPPORT_ADMIN: ['platform:view', 'school:view', 'user:view', 'audit:view', 'support:start', 'pickup:view', 'incident:review', 'attendance:view', 'system:view'],
  BILLING_ADMIN: ['platform:view', 'school:view', 'billing:view', 'billing:update', 'reports:view'],
};

export const permissionsFor = role => ROLE_PERMISSIONS[role] ?? [];

/** The person's ACTIVE platform role and permissions, or null. */
export async function getPlatformAdmin(userId) {
  if (!userId) return null;
  const row = await db.prepare(`SELECT role FROM platform_admins WHERE user_id=? AND status='ACTIVE'`).get(userId);
  return row ? { role: row.role, permissions: permissionsFor(row.role) } : null;
}

/**
 * Route guard (after requireAuth): the signed-in person must be an active
 * platform admin whose role includes every listed permission. Sets
 * req.platformAdmin. School admins, teachers and parents always get 403.
 */
export function requirePlatformPermission(...required) {
  return asyncRoute(async (req, res, next) => {
    const admin = await getPlatformAdmin(req.user?.id);
    if (!admin) return res.status(403).json({ error: 'Platform administrator access required' });
    if (!required.every(permission => admin.permissions.includes(permission))) {
      return res.status(403).json({ error: "Your platform role doesn't allow this" });
    }
    req.platformAdmin = admin;
    next();
  });
}
