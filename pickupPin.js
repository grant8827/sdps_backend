import { db, passwordHash, verifyPassword } from './db.js';
import { clear, hit, peek } from './rateLimit.js';

// Pickup PIN: a private 6-digit PIN each parent enters every time they
// request a pickup, so a pickup can't be requested from a phone that was
// left unlocked or an account someone else is signed in to. Stored only
// as a salted scrypt hash, like a password; never logged, exported or
// returned by the API.
//
// Five wrong PINs lock PIN use for that account for 15 minutes (counted
// in the database, so every server enforces it).

export const PIN_WINDOW_MS = 15 * 60 * 1000;
export const MAX_PIN_FAILURES = 5;
const limitKey = userId => `pin:${userId}`;

// PINs people pick first and attackers try first.
const TOO_EASY = new Set(['123456', '654321', '012345', '123123', '112233', '121212', '123321']);

/** Why a PIN isn't acceptable, or null if it is. */
export function pinProblem(pin) {
  if (typeof pin !== 'string' || !/^\d{6}$/.test(pin)) return 'The PIN must be exactly 6 digits.';
  if (/^(\d)\1{5}$/.test(pin) || TOO_EASY.has(pin)) return 'That PIN is too easy to guess. Choose a different one.';
  return null;
}

export const hasPin = async userId =>
  Boolean((await db.prepare('SELECT pickup_pin_hash FROM users WHERE id=?').get(userId))?.pickup_pin_hash);

export async function setPin(userId, pin) {
  await db.prepare(`UPDATE users SET pickup_pin_hash=?, pickup_pin_set_at=to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS') WHERE id=?`)
    .run(passwordHash(pin), userId);
  await clear(limitKey(userId));
}

/**
 * Checks a PIN. Returns one of:
 *   { ok: true }
 *   { ok: false, reason: 'NOT_SET' }
 *   { ok: false, reason: 'LOCKED' }                — too many wrong tries; nothing was checked
 *   { ok: false, reason: 'WRONG', triesLeft, lockedNow }
 */
export async function checkPin(userId, pin) {
  const row = await db.prepare('SELECT pickup_pin_hash AS hash FROM users WHERE id=?').get(userId);
  if (!row?.hash) return { ok: false, reason: 'NOT_SET' };
  if ((await peek(limitKey(userId))) >= MAX_PIN_FAILURES) return { ok: false, reason: 'LOCKED' };
  if (typeof pin === 'string' && /^\d{6}$/.test(pin) && verifyPassword(pin, row.hash).ok) {
    await clear(limitKey(userId));
    return { ok: true };
  }
  const failures = await hit(limitKey(userId), PIN_WINDOW_MS);
  const triesLeft = Math.max(0, MAX_PIN_FAILURES - failures);
  return { ok: false, reason: 'WRONG', triesLeft, lockedNow: triesLeft === 0 };
}
