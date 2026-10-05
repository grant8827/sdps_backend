import { createHash, randomBytes } from 'node:crypto';
import { db, passwordHash } from './db.js';
import { appBaseUrl } from './mailer.js';

// One-time links emailed to people (see account_links, migration 23):
//   INVITE — a new account choosing its first password. Nobody else ever
//            knows that password, so it never travels by email.
//   RESET  — "Forgot password?", or an admin sending someone a fresh link.
// The token is only in the link; the table keeps its SHA-256. Using a link
// sets the password, burns every other open link for that person and
// signs them out everywhere (the caller does the sign-out).
const TTL_MS = { INVITE: 7 * 24 * 60 * 60 * 1000, RESET: 60 * 60 * 1000 };
const hashToken = token => createHash('sha256').update(String(token)).digest('hex');

/** A password nobody knows, for an account that will choose its own via an INVITE link. */
export const unusablePasswordHash = () => passwordHash(randomBytes(32).toString('hex'));

export const ADMIN_RESET_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Creates a link and returns its full URL. Older open links of the same
 * purpose stop working. `ttlMs` overrides the default lifetime (an
 * admin-sent reset link lasts a day, not an hour).
 */
export async function createAccountLink(userId, purpose, ttlMs = TTL_MS[purpose]) {
  const token = randomBytes(32).toString('base64url');
  const now = Date.now();
  await db.prepare('DELETE FROM account_links WHERE expires_at <= ? OR (used_at IS NOT NULL AND used_at <= ?)').run(now, now - TTL_MS.INVITE);
  await db.prepare('UPDATE account_links SET used_at=? WHERE user_id=? AND purpose=? AND used_at IS NULL').run(now, userId, purpose);
  await db.prepare('INSERT INTO account_links (token_hash,user_id,purpose,expires_at,created_at) VALUES (?,?,?,?,?)')
    .run(hashToken(token), userId, purpose, now + ttlMs, now);
  return `${appBaseUrl()}/set-password?token=${token}`;
}

/** The open link's purpose and account, or null when it's unknown, used or expired. */
export async function findAccountLink(token) {
  if (!token || String(token).length > 200) return null;
  return await db.prepare(`
    SELECT l.token_hash AS "tokenHash", l.purpose, u.id AS "userId", u.full_name AS "fullName", u.email
    FROM account_links l JOIN users u ON u.id=l.user_id
    WHERE l.token_hash=? AND l.used_at IS NULL AND l.expires_at > ? AND u.active=1`).get(hashToken(token), Date.now()) || null;
}

/** Sets the password from an open link. Returns the link row, or null if it can't be used. */
export async function useAccountLink(token, newPassword) {
  const link = await findAccountLink(token);
  if (!link) return null;
  const claimed = await db.prepare('UPDATE account_links SET used_at=? WHERE token_hash=? AND used_at IS NULL').run(Date.now(), link.tokenHash);
  if (claimed.changes === 0) return null; // used twice at once — only the first wins
  await db.prepare('UPDATE users SET password_hash=?, needs_password_setup=0 WHERE id=?').run(passwordHash(newPassword), link.userId);
  await db.prepare('UPDATE account_links SET used_at=? WHERE user_id=? AND used_at IS NULL').run(Date.now(), link.userId);
  return link;
}
