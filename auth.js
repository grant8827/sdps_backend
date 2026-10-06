import { createHash, randomBytes } from 'node:crypto';
import { db, passwordHash, verifyPassword } from './db.js';
import { getMemberships } from './tenant.js';
import { getPlatformAdmin } from './permissions.js';
import { endSupportSession } from './supportSessions.js';
import { asyncRoute } from './asyncRoute.js';

const ONE_DAY = 24 * 60 * 60 * 1000;

// Sessions live in the `sessions` table (migration 7), not an in-memory
// Map — this process restarts constantly during development (nodemon
// restarts on every backend file save), and an in-memory store used to
// force-log-out every user on each restart.
const insertSession = db.prepare('INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)');
const findSession = db.prepare('SELECT user_id AS "userId", expires_at AS "expiresAt" FROM sessions WHERE token=?');
const deleteExpired = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
const deleteSession = db.prepare('DELETE FROM sessions WHERE token=?');

// An account is only usable while it holds at least one ACTIVE
// membership in an ACTIVE school — or is an active platform admin.
// Suspending or removing someone from Faculty/Families only changes their
// membership row (users.active stays 1), so without this a suspended
// teacher or parent could keep signing in and calling the API —
// including requesting a pickup.
export async function canSignIn(userId) {
  return (await getMemberships(userId)).length > 0 || Boolean(await getPlatformAdmin(userId));
}
const hasActiveMembership = { get: canSignIn };

// Two-step verification is mandatory for anyone on the admin dashboard
// (school admins and front desk staff — users.role 'admin') and for
// platform admins; optional for teachers and parents, who can turn it
// on themselves. REQUIRE_ADMIN_MFA=false switches the requirement off
// (local development/tests only); it never turns off MFA for someone
// who has already enabled it.
export async function mfaRequiredFor(user) {
  if (process.env.REQUIRE_ADMIN_MFA === 'false') return false;
  if (user.role === 'admin') return true;
  return Boolean(await getPlatformAdmin(user.id));
}

const CHALLENGE_TTL_MS = 10 * 60 * 1000;
export const MAX_CHALLENGE_ATTEMPTS = 5;
const hashToken = token => createHash('sha256').update(token).digest('hex');

async function startChallenge(user, purpose) {
  const token = randomBytes(32).toString('hex');
  await db.prepare('DELETE FROM mfa_challenges WHERE expires_at <= ?').run(Date.now());
  await db.prepare('INSERT INTO mfa_challenges (token_hash,user_id,purpose,expires_at) VALUES (?,?,?,?)').run(hashToken(token), user.id, purpose, Date.now() + CHALLENGE_TTL_MS);
  return purpose === 'VERIFY'
    ? { mfaRequired: true, mfaToken: token }
    : { mfaSetupRequired: true, mfaToken: token };
}

/** The user behind an unexpired challenge of this purpose, or null. */
export async function findChallenge(token, purpose) {
  if (!token) return null;
  const row = await db.prepare(`
    SELECT c.token_hash AS "tokenHash", c.attempts, u.* FROM mfa_challenges c JOIN users u ON u.id=c.user_id
    WHERE c.token_hash=? AND c.purpose=? AND c.expires_at > ? AND u.active=1`).get(hashToken(String(token)), purpose, Date.now());
  return row || null;
}

/** Counts a wrong code; returns how many tries are left (0 = challenge discarded, password needed again). */
export async function failChallenge(challenge) {
  const attempts = challenge.attempts + 1;
  if (attempts >= MAX_CHALLENGE_ATTEMPTS) {
    await db.prepare('DELETE FROM mfa_challenges WHERE token_hash=?').run(challenge.tokenHash);
    return 0;
  }
  await db.prepare('UPDATE mfa_challenges SET attempts=? WHERE token_hash=?').run(attempts, challenge.tokenHash);
  return MAX_CHALLENGE_ATTEMPTS - attempts;
}

export async function endChallenge(challenge) {
  await db.prepare('DELETE FROM mfa_challenges WHERE token_hash=?').run(challenge.tokenHash);
}

export async function createSession(user) {
  const token = randomBytes(32).toString('hex');
  const expiresAt = Date.now() + ONE_DAY;
  await deleteExpired.run(Date.now()); // opportunistic cleanup, no separate cron needed
  await insertSession.run(token, user.id, expiresAt);
  const memberships = await getMemberships(user.id);
  // Platform role and permissions, so the website can show the platform area; the API re-checks them on every call.
  const platform = await getPlatformAdmin(user.id);
  return { token, expiresAt, user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role, memberships, platform } };
}

/**
 * Password step of sign-in. Returns null (wrong/blocked), a session, or —
 * when two-step verification applies — a challenge instead of a session:
 * { mfaRequired, mfaToken } to enter a code, or { mfaSetupRequired,
 * mfaToken } when the account must enroll before it can sign in at all.
 */
export async function login(identifier, password) {
  const user = await db.prepare('SELECT * FROM users WHERE (LOWER(email)=LOWER(?) OR phone=?) AND active=1').get(identifier, identifier);
  if (!user) return null;
  const { ok, needsRehash } = verifyPassword(password, user.password_hash);
  if (!ok) return null;
  if (!(await hasActiveMembership.get(user.id))) return null;
  if (needsRehash) await db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(passwordHash(password), user.id);
  if (user.mfa_enabled_at) return startChallenge(user, 'VERIFY');
  if (await mfaRequiredFor(user)) return startChallenge(user, 'SETUP');
  return createSession(user);
}

export async function logout(token) {
  await endSupportSession(token, 'SIGNED_OUT');
  await deleteSession.run(token);
}

/** Signs someone out everywhere — e.g. after an admin resets their two-step verification. */
export async function endAllSessions(userId) {
  await db.prepare('DELETE FROM sessions WHERE user_id=?').run(userId);
}

export const requireAuth = asyncRoute(async (req, res, next) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const session = token && (await findSession.get(token));
  if (!session || session.expiresAt <= Date.now()) return res.status(401).json({ error: 'Authentication required' });
  req.user = await db.prepare('SELECT id,full_name,email,role FROM users WHERE id=? AND active=1').get(session.userId);
  if (!req.user || !(await hasActiveMembership.get(req.user.id))) return res.status(401).json({ error: 'Account is inactive' });
  req.sessionToken = token; // support sessions belong to one sign-in session (supportSessions.js)
  next();
});

export const requireRole = role => (req, res, next) => req.user?.role === role ? next() : res.status(403).json({ error: `${role} access required` });
