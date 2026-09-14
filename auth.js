import { randomBytes, timingSafeEqual } from 'node:crypto';
import { db, passwordHash } from './database.js';
import { getMemberships } from './tenant.js';

const ONE_DAY = 24 * 60 * 60 * 1000;

// Sessions live in the `sessions` table (migration 7), not an in-memory
// Map — this process restarts constantly during development (nodemon
// restarts on every backend file save), and an in-memory store used to
// force-log-out every user on each restart.
const insertSession = db.prepare('INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)');
const findSession = db.prepare('SELECT user_id AS userId, expires_at AS expiresAt FROM sessions WHERE token=?');
const deleteExpired = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
const deleteSession = db.prepare('DELETE FROM sessions WHERE token=?');

export function login(identifier, password) {
  const user = db.prepare('SELECT * FROM users WHERE (email=? COLLATE NOCASE OR phone=?) AND active=1').get(identifier, identifier);
  if (!user) return null;
  const actual = Buffer.from(user.password_hash, 'hex');
  const supplied = Buffer.from(passwordHash(password), 'hex');
  if (actual.length !== supplied.length || !timingSafeEqual(actual, supplied)) return null;
  const token = randomBytes(32).toString('hex');
  const expiresAt = Date.now() + ONE_DAY;
  deleteExpired.run(Date.now()); // opportunistic cleanup, no separate cron needed
  insertSession.run(token, user.id, expiresAt);
  const memberships = getMemberships(user.id);
  return { token, expiresAt, user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role, memberships } };
}

export function logout(token) {
  deleteSession.run(token);
}

export function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const session = token && findSession.get(token);
  if (!session || session.expiresAt <= Date.now()) return res.status(401).json({ error: 'Authentication required' });
  req.user = db.prepare('SELECT id,full_name,email,role FROM users WHERE id=? AND active=1').get(session.userId);
  if (!req.user) return res.status(401).json({ error: 'Account is inactive' });
  next();
}

export const requireRole = role => (req, res, next) => req.user?.role === role ? next() : res.status(403).json({ error: `${role} access required` });
