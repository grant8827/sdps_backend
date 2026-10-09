import { randomInt } from 'node:crypto';
import { db, passwordHash, verifyPassword } from './db.js';

// Email confirmation codes: a 6-digit code emailed to an address to
// prove the person can read mail sent there. Used when a school
// registers, before any account exists (so it is keyed by email, not by
// user). One code per address at a time; a new one replaces the old.
//
// The code is stored only as a salted hash, works for 10 minutes, and
// is thrown away after 5 wrong tries (the person asks for a new one).
//
// REQUIRE_EMAIL_CONFIRMATION=false switches the check off, for local
// development and tests where no email can be sent.

export const CODE_MINUTES = 10;
export const MAX_CODE_TRIES = 5;

export const emailConfirmationRequired = () => process.env.REQUIRE_EMAIL_CONFIRMATION !== 'false';
const normalize = email => String(email ?? '').trim().toLowerCase();

/** Makes (and stores) a new code for this address, replacing any earlier one. Returns the code to email. */
export async function createEmailCode(email, purpose = 'REGISTER_SCHOOL') {
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  await db.prepare(`
    INSERT INTO email_codes (email, purpose, code_hash, expires_at, attempts) VALUES (?,?,?,?,0)
    ON CONFLICT (email, purpose) DO UPDATE SET code_hash=EXCLUDED.code_hash, expires_at=EXCLUDED.expires_at, attempts=0`)
    .run(normalize(email), purpose, passwordHash(code), Date.now() + CODE_MINUTES * 60 * 1000);
  return code;
}

/**
 * Checks a code without using it up.
 * → { ok: true } | { ok: false, reason: 'MISSING' | 'WRONG' | 'LOCKED', triesLeft }
 * MISSING covers "never sent", "expired" and "already used".
 */
export async function checkEmailCode(email, code, purpose = 'REGISTER_SCHOOL') {
  const key = normalize(email);
  const row = await db.prepare('SELECT code_hash, expires_at, attempts FROM email_codes WHERE email=? AND purpose=?').get(key, purpose);
  if (!row || Number(row.expires_at) <= Date.now()) return { ok: false, reason: 'MISSING' };
  if (typeof code === 'string' && /^\d{6}$/.test(code) && verifyPassword(code, row.code_hash).ok) return { ok: true };
  const { attempts } = await db.prepare('UPDATE email_codes SET attempts=attempts+1 WHERE email=? AND purpose=? RETURNING attempts').get(key, purpose) ?? { attempts: MAX_CODE_TRIES };
  if (attempts >= MAX_CODE_TRIES) {
    await discardEmailCode(key, purpose);
    return { ok: false, reason: 'LOCKED', triesLeft: 0 };
  }
  return { ok: false, reason: 'WRONG', triesLeft: MAX_CODE_TRIES - attempts };
}

/** Throws the code away: after it was used, or when its email could not be sent. */
export async function discardEmailCode(email, purpose = 'REGISTER_SCHOOL') {
  await db.prepare('DELETE FROM email_codes WHERE email=? AND purpose=?').run(normalize(email), purpose);
}

export async function sweepEmailCodes() {
  await db.prepare('DELETE FROM email_codes WHERE expires_at <= ?').run(Date.now());
}
