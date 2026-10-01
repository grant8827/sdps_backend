import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

// Two-step verification with an authenticator app (Google/Microsoft
// Authenticator, 1Password, Authy, ...): standard TOTP (RFC 6238 — 30s
// steps, 6 digits, HMAC-SHA1), so it works with any of them, plus
// one-time recovery codes for a lost phone. No third-party service is
// involved; codes are generated on the user's phone and checked here.

const STEP_SECONDS = 30;
const DIGITS = 6;
const ISSUER = 'School Drop-off & Pick-up';

// ---- Secret storage -------------------------------------------------
// The per-user TOTP secret is stored encrypted (AES-256-GCM) with a key
// from MFA_ENCRYPTION_KEY (64 hex chars = 32 bytes), so a copy of the
// database alone isn't enough to generate someone's codes. Without the
// env var a fixed development key is used — fine locally, and loudly
// flagged, but production must set it (and keep it: changing it makes
// every enrolled user's secret unreadable, so they'd have to re-enroll).
const DEV_KEY = createHash('sha256').update('school-dropoff-dev-mfa-key').digest();
function encryptionKey() {
  const configured = process.env.MFA_ENCRYPTION_KEY;
  if (configured && /^[0-9a-f]{64}$/i.test(configured)) return Buffer.from(configured, 'hex');
  if (process.env.NODE_ENV === 'production' && !encryptionKey.warned) {
    console.warn('MFA_ENCRYPTION_KEY is not set (or not 64 hex characters) — two-step verification secrets are using the development key. Set it before going live.');
    encryptionKey.warned = true;
  }
  return DEV_KEY;
}

export function encryptSecret(secret) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const data = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('hex'), cipher.getAuthTag().toString('hex'), data.toString('hex')].join(':');
}

export function decryptSecret(stored) {
  const [version, iv, tag, data] = String(stored).split(':');
  if (version !== 'v1') throw new Error('Unknown MFA secret format');
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'hex')), decipher.final()]).toString('utf8');
}

// ---- TOTP -----------------------------------------------------------
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0; let value = 0; let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(text) {
  let bits = 0; let value = 0; const bytes = [];
  for (const char of text.toUpperCase().replace(/[^A-Z2-7]/g, '')) {
    value = (value << 5) | BASE32.indexOf(char); bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(bytes);
}

/** A new random secret, base32 as authenticator apps expect it (160 bits, per RFC 4226). */
export const newTotpSecret = () => base32Encode(randomBytes(20));

function codeAt(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hmac = createHmac('sha1', base32Decode(secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary = hmac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

export const currentStep = (now = Date.now()) => Math.floor(now / 1000 / STEP_SECONDS);

/**
 * Checks a 6-digit code against the current step and one step either
 * side (allows ~30s of clock drift). Returns the matching step, or null.
 * The caller must refuse a step at or before the last one this user
 * already used, so an observed code can't be replayed.
 */
export function verifyTotp(secret, code, now = Date.now()) {
  const supplied = Buffer.from(String(code ?? '').replace(/\s/g, ''));
  if (supplied.length !== DIGITS) return null;
  const step = currentStep(now);
  for (const candidate of [step - 1, step, step + 1]) {
    const expected = Buffer.from(codeAt(secret, candidate));
    if (timingSafeEqual(expected, supplied)) return candidate;
  }
  return null;
}

/** Test helper / reference: the code an authenticator would show right now. */
export const totpNow = (secret, now = Date.now()) => codeAt(secret, currentStep(now));

/** otpauth:// URI an authenticator app imports (from a QR code, or tapped on the same phone). */
export function otpauthUri(secret, accountName) {
  const label = encodeURIComponent(`${ISSUER}:${accountName}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}

// ---- Recovery codes -------------------------------------------------
// Ten single-use codes shown once at enrollment, stored only as hashes.
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O, 1/I
export function newRecoveryCodes(count = 10) {
  return Array.from({ length: count }, () => {
    const chars = Array.from({ length: 10 }, () => RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)]).join('');
    return `${chars.slice(0, 5)}-${chars.slice(5)}`;
  });
}
export const hashRecoveryCode = code => createHash('sha256').update(String(code).toUpperCase().replace(/[^A-Z0-9]/g, '')).digest('hex');
export const looksLikeRecoveryCode = code => String(code ?? '').replace(/[^A-Za-z0-9]/g, '').length === 10;
