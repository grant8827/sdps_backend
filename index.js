import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { db, id, passwordHash, verifyPassword, isUniqueViolation, withTransaction } from './db.js';
import { createSession, endAllSessions, endChallenge, failChallenge, findChallenge, login, logout, mfaRequiredFor, requireAuth, requireRole } from './auth.js';
import { decryptSecret, encryptSecret, hashRecoveryCode, looksLikeRecoveryCode, newRecoveryCodes, newTotpSecret, otpauthUri, verifyTotp } from './mfa.js';
import { SCHOOL_ADMIN_ROLES, getMemberships, requireSchoolAccess } from './tenant.js';
import { asyncRoute } from './asyncRoute.js';
import { audited, writeAudit } from './audit.js';
import { MIN_RETENTION_DAYS, applyRetention, applyRetentionEverywhere, buildSchoolExport, buildStudentExport, deletedStudentLabel, permanentlyDeleteStudent, previewRetention, retentionSettings } from './dataRights.js';
import { ADMIN_RESET_TTL_MS, createAccountLink, findAccountLink, unusablePasswordHash, useAccountLink } from './accountLinks.js';
import {
  deliverLater, sendAddedToSchoolEmail, sendGuardianApprovedEmail, sendGuardianDecisionEmail, sendInviteEmail, sendMfaResetEmail,
  sendNoticeEmail, sendPasswordChangedEmail, sendPasswordResetEmail, sendSchoolWelcomeEmail, verifyEmailConnection,
} from './mailer.js';
import { randomInt, timingSafeEqual } from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDist = path.join(__dirname, '..', 'frontend', 'dist');

const app = express();
const port = process.env.PORT || 3000;

// Behind Railway's (or any) TLS-terminating proxy, the original scheme
// and client IP arrive in X-Forwarded-Proto/-For. Only trust them when
// actually deployed behind one — otherwise any client could spoof its
// IP (dodging the login rate limit) or claim to be on HTTPS.
const behindProxy = Boolean(process.env.TRUST_PROXY || process.env.RAILWAY_ENVIRONMENT);
if (behindProxy) app.set('trust proxy', 1);

// Security headers on every response, plus HTTPS-only when deployed:
// a plain-HTTP page request is redirected, and a plain-HTTP API call is
// refused outright rather than redirected (a redirect would already
// have sent the password/token in the clear). HSTS then tells browsers
// to never try plain HTTP for this site again.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(self), camera=(), microphone=()');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'", "img-src 'self' data: blob:",
    "connect-src 'self'", "font-src 'self' data:", "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'none'",
  ].join('; '));
  // /api/health stays reachable over plain HTTP — the platform's own
  // health check calls the container directly, not through the proxy.
  if (behindProxy && req.path !== '/api/health') {
    if (!req.secure) {
      if (req.path.startsWith('/api/')) return res.status(400).json({ error: 'HTTPS is required.' });
      return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
    }
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// The website and API can be deployed as separate services. In that setup the
// browser needs an explicit CORS grant from this API. Accept a comma-separated
// list so preview and production frontends can both be configured without
// allowing arbitrary origins.
const PRODUCTION_FRONTEND_URL = 'https://sdpsfrontend-production.up.railway.app';
const allowedOrigins = new Set(
  [PRODUCTION_FRONTEND_URL, ...String(process.env.FRONTEND_URL || '').split(',')]
    .map(origin => origin.trim().replace(/\/$/, ''))
    .filter(Boolean),
);
app.use((req, res, next) => {
  const origin = req.headers.origin?.replace(/\/$/, '');
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.status(allowedOrigins.has(origin) ? 204 : 403).end();
  next();
});

// Same shape as the CURRENT_TIMESTAMP column defaults in db.js/migrations.js
// — used wherever a row needs an explicit "now" written from a query, so
// every timestamp in the app keeps the same sortable UTC string shape
// instead of Postgres's own now()/CURRENT_TIMESTAMP format (which is
// timezone-offset-suffixed and in the server's local zone, not UTC).
const NOW_UTC = `to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')`;

// The school's own local wall-clock time as 'HH:MM' (24-hour) — used to
// compare against schools.start_time, which is entered by the admin as
// a local clock time, not UTC. Using Intl instead of raw Date methods
// means this stays correct across DST without a date library.
function localClockTime(timeZone) {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone, hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(new Date());
  const hour = parts.find(p => p.type === 'hour')?.value ?? '00';
  const minute = parts.find(p => p.type === 'minute')?.value ?? '00';
  return `${hour}:${minute}`;
}

// Turns a campus's typed address into the lat/long that drives its
// drop-off/pick-up geofence (see DropoffPickupScreen.tsx in the mobile
// app). OpenStreetMap's Nominatim is free and needs no API key/billing —
// a descriptive User-Agent is required by their usage policy. Isolated
// in one function so swapping to a paid provider later is a one-place change.
const NOMINATIM_USER_AGENT = 'school-dropoff-pickup/1.0 (admin-configured campus geocoding)';

function parseAddressFields(address) {
  const fields = { addressLine1: '', addressLine2: '', city: '', state: '', postalCode: '', country: '' };
  const parts = String(address || '').split(',').map(part => part.trim()).filter(Boolean);
  if (parts.length >= 5) {
    fields.country = parts.pop() || '';
    fields.postalCode = parts.pop() || '';
    fields.state = parts.pop() || '';
    fields.city = parts.pop() || '';
    fields.addressLine1 = parts.shift() || '';
    fields.addressLine2 = parts.join(', ');
  } else {
    fields.addressLine1 = parts.shift() || '';
    fields.city = parts.shift() || '';
    fields.state = parts.shift() || '';
    fields.country = parts.join(', ');
  }
  return fields;
}

function addressFieldsFromInput(input, fallback = {}) {
  const hasStructuredFields = ['addressLine1', 'addressLine2', 'city', 'state', 'postalCode', 'country']
    .some(key => input[key] !== undefined);
  if (!hasStructuredFields && input.address !== undefined) return parseAddressFields(input.address);
  return Object.fromEntries(['addressLine1', 'addressLine2', 'city', 'state', 'postalCode', 'country']
    .map(key => [key, input[key] !== undefined ? String(input[key]).trim() : (fallback[key] || '')]));
}

function formatAddressFields(fields) {
  const street = [fields.addressLine1, fields.addressLine2].filter(Boolean).join(', ');
  return [street, fields.city, fields.state, fields.postalCode, fields.country].filter(Boolean).join(', ');
}

// Nominatim frequently can't resolve a street address with a unit/suite
// marker in it — even one entered as part of a single address line (e.g.
// legacy data saved before address fields were split out), not just one
// living in a separate line 2. Requiring a digit after the designator
// keeps this from misfiring on an ordinary word that merely starts with
// one, like "Unit" inside "United States".
function stripUnitMarker(address) {
  return address
    .replace(/[,]?\s*(?:#\s*[\w-]*\d[\w-]*|\b(?:suite|ste|unit|apt|apartment|bldg|building|rm|room)\b\.?\s*[\w-]*\d[\w-]*)/gi, '')
    .replace(/\s{2,}/g, ' ')
    .replace(/,\s*,/g, ',')
    .trim();
}

async function geocodeAddress(address) {
  const parts = address.split(',').map(part => part.trim()).filter(Boolean);
  const candidates = [address];
  // The clients store line 2 as the second comma-delimited component.
  // Geocoders frequently fail on suite/building/room text even though the
  // street address is valid. Keep line 2 in storage, but retry the lookup
  // without it so it cannot prevent a campus from being mapped.
  if (parts.length >= 6) candidates.push([parts[0], ...parts.slice(2)].join(', '));
  // Catches a unit marker embedded directly in address line 1 (common in
  // addresses saved before line 2 existed as its own field), which the
  // line-2-drop candidate above can't reach since there's nothing to drop.
  const destuited = stripUnitMarker(address);
  if (destuited && destuited !== address) candidates.push(destuited);

  for (const candidate of [...new Set(candidates)]) {
    const url = `https://nominatim.openstreetmap.org/search?format=json&addressdetails=1&limit=1&q=${encodeURIComponent(candidate)}`;
    let response;
    try {
      response = await fetch(url, {
        headers: { 'User-Agent': NOMINATIM_USER_AGENT, Accept: 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
    } catch {
      continue;
    }
    if (!response.ok) continue;
    const [result] = await response.json();
    if (result && Number.isFinite(Number(result.lat)) && Number.isFinite(Number(result.lon))) {
      return { latitude: Number(result.lat), longitude: Number(result.lon) };
    }
  }

  // Nominatim occasionally has no match for a valid U.S. street address.
  // The U.S. Census geocoder is an independent, key-free authoritative
  // fallback, so a temporary coverage gap in one provider does not prevent
  // an administrator from saving the school's geofence location.
  const censusAddress = stripUnitMarker(candidates.at(-1)).slice(0, 100);
  try {
    const params = new URLSearchParams({
      address: censusAddress,
      benchmark: 'Public_AR_Current',
      format: 'json',
    });
    const response = await fetch(`https://geocoding.geo.census.gov/geocoder/locations/onelineaddress?${params}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
    if (response.ok) {
      const result = await response.json();
      const coordinates = result?.result?.addressMatches?.[0]?.coordinates;
      const latitude = Number(coordinates?.y);
      const longitude = Number(coordinates?.x);
      if (Number.isFinite(latitude) && Number.isFinite(longitude)) return { latitude, longitude };
    }
  } catch {
    // The actionable validation error below is shared by both providers.
  }
  throw new Error('That address could not be mapped. Confirm the street, city, state, ZIP/postal code, and country, then try again.');
}

// Higher than Express's 100kb default so a student photo (sent as a
// base64 data URL in the JSON body — no file-upload middleware in this
// app) actually fits.
app.use(express.json({ limit: '6mb' }));

const MAX_PHOTO_DATA_URL_LENGTH = 4_000_000; // ~3MB of image, base64-inflated
function normalizePhotoDataUrl(value) {
  if (!value) return null;
  if (typeof value !== 'string' || !/^data:image\/(png|jpe?g|webp|gif);base64,/.test(value)) {
    throw new Error('Photo must be a PNG, JPEG, WEBP, or GIF image');
  }
  if (value.length > MAX_PHOTO_DATA_URL_LENGTH) throw new Error('Photo is too large — please use a smaller image');
  return value;
}

/**
 * One Node/Express server backs both clients: the React Native mobile
 * app and the React website talk to the same API under /api. Routes
 * here are stand-ins until the real domain endpoints (auth, children,
 * queue, notices, ...) land — see mobile_app/src and frontend/src for
 * the mock services/shapes they should match.
 */
app.get('/api/health', (req, res) => {
  res.json({ message: 'Backend running' });
});

// Brute-force guard on sign-in: too many failed attempts within the
// window locks that account name (from any IP) and that IP (across any
// account names) until the window passes. A successful sign-in clears
// the account's counter. In-memory, so it resets on restart and isn't
// shared between server instances — fine for one instance; move it to
// the database (or Redis) before running several.
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES_PER_ACCOUNT = 5;
const MAX_FAILURES_PER_IP = 20;
const loginFailures = new Map(); // key -> { count, resetAt }
function failureCount(key) {
  const entry = loginFailures.get(key);
  if (!entry || entry.resetAt <= Date.now()) { loginFailures.delete(key); return 0; }
  return entry.count;
}
function recordFailure(key) {
  const count = failureCount(key) + 1;
  loginFailures.set(key, { count, resetAt: loginFailures.get(key)?.resetAt ?? Date.now() + LOGIN_WINDOW_MS });
}
setInterval(() => { for (const key of loginFailures.keys()) failureCount(key); }, LOGIN_WINDOW_MS).unref();

// A failed or locked-out sign-in for a real account is filed under each
// school that account belongs to, so that school's admins can see
// someone trying to get into it. One for an unknown email/phone is
// filed with no school (visible to platform staff only).
async function auditSignIn(action, identifier, ip) {
  const user = identifier && await db.prepare('SELECT id, full_name, role FROM users WHERE LOWER(email)=LOWER(?) OR phone=?').get(identifier, identifier);
  // Every school the account is (or was) in — including suspended
  // memberships, and each school of a district admin's district.
  const schoolIds = user ? [...new Set([
    ...(await db.prepare('SELECT school_id AS "schoolId" FROM memberships WHERE user_id=?').all(user.id)).map(r => r.schoolId),
    ...(await getMemberships(user.id)).map(m => m.schoolId),
  ])] : [];
  for (const schoolId of schoolIds.length ? schoolIds : [null]) {
    await writeAudit({ schoolId, action, targetType: 'user', targetId: user?.id ?? null, targetLabel: user?.full_name ?? null, details: { identifier }, ip });
  }
}

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const identifier = String(req.body.identifier || '').trim();
  const accountKey = `account:${identifier.toLowerCase()}`;
  const ipKey = `ip:${req.ip}`;
  if (failureCount(accountKey) >= MAX_FAILURES_PER_ACCOUNT || failureCount(ipKey) >= MAX_FAILURES_PER_IP) {
    await auditSignIn('SIGN_IN_LOCKED_OUT', identifier, req.ip);
    return res.status(429).json({ error: 'Too many failed sign-in attempts. Please wait 15 minutes and try again.' });
  }
  const session = await login(identifier, String(req.body.password || ''));
  if (!session) {
    recordFailure(accountKey);
    recordFailure(ipKey);
    await auditSignIn('SIGN_IN_FAILED', identifier, req.ip);
    return res.status(401).json({ error: 'Invalid email/phone or password' });
  }
  loginFailures.delete(accountKey);
  // Right password but a second step is still owed: no session yet.
  if (!session.token) return res.json(session);
  await auditSignedIn(session, req.ip);
  res.json(session);
}));

async function auditSignedIn(session, ip, details = null) {
  for (const schoolId of new Set(session.user.memberships.map(m => m.schoolId))) {
    await writeAudit({ schoolId, actor: session.user, action: 'SIGNED_IN', targetType: 'user', targetId: session.user.id, details, ip });
  }
}
async function auditForUser(user, action, ip, details = null, actor = user) {
  const schoolIds = [...new Set((await getMemberships(user.id)).map(m => m.schoolId))];
  for (const schoolId of schoolIds.length ? schoolIds : [null]) {
    await writeAudit({ schoolId, actor, action, targetType: 'user', targetId: user.id, targetLabel: user.full_name, details, ip });
  }
}

// ---- Two-step verification (see mfa.js / auth.js) ----------------------

// Checks an authenticator code — or, if it's shaped like one, a
// recovery code (each works once). An authenticator code is refused if
// its time step was already used, so a code read over someone's
// shoulder can't be replayed within its 30-second window.
async function checkSecondFactor(user, code) {
  if (looksLikeRecoveryCode(code)) {
    const used = await db.prepare(`UPDATE mfa_recovery_codes SET used_at=${NOW_UTC} WHERE id=(SELECT id FROM mfa_recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL LIMIT 1) RETURNING id`)
      .get(user.id, hashRecoveryCode(code));
    return used ? 'RECOVERY_CODE' : null;
  }
  if (!user.mfa_secret) return null;
  const step = verifyTotp(decryptSecret(user.mfa_secret), code);
  if (step === null) return null;
  const claimed = await db.prepare('UPDATE users SET mfa_last_step=? WHERE id=? AND (mfa_last_step IS NULL OR mfa_last_step < ?)').run(step, user.id, step);
  return claimed.changes ? 'AUTHENTICATOR' : null;
}

async function beginEnrollment(user) {
  const secret = newTotpSecret();
  await db.prepare('UPDATE users SET mfa_pending_secret=? WHERE id=?').run(encryptSecret(secret), user.id);
  return { secret, otpauthUri: otpauthUri(secret, user.email || user.full_name) };
}

// Turns MFA on once the user proves their app works; returns the new
// recovery codes (shown once, stored hashed), or null for a wrong code.
async function finishEnrollment(user, code) {
  if (!user.mfa_pending_secret) return null;
  const secret = decryptSecret(user.mfa_pending_secret);
  const step = verifyTotp(secret, code);
  if (step === null) return null;
  const recoveryCodes = newRecoveryCodes();
  await withTransaction(async () => {
    await db.prepare(`UPDATE users SET mfa_secret=?, mfa_pending_secret=NULL, mfa_enabled_at=${NOW_UTC}, mfa_last_step=? WHERE id=?`).run(encryptSecret(secret), step, user.id);
    await replaceRecoveryCodes(user.id, recoveryCodes);
  });
  return recoveryCodes;
}

async function replaceRecoveryCodes(userId, codes) {
  await db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id=?').run(userId);
  const insert = db.prepare('INSERT INTO mfa_recovery_codes (id,user_id,code_hash) VALUES (?,?,?)');
  for (const code of codes) await insert.run(id('recovery'), userId, hashRecoveryCode(code));
}

const wrongCodeResponse = (res, left) => res.status(left ? 401 : 410).json({
  error: left ? `That code didn't work. ${left} ${left === 1 ? 'try' : 'tries'} left.` : 'Too many wrong codes. Please sign in again.',
  restart: !left,
});

// Second step of sign-in for an account with MFA on.
app.post('/api/auth/mfa/verify', asyncRoute(async (req, res) => {
  const challenge = await findChallenge(req.body.mfaToken, 'VERIFY');
  if (!challenge) return res.status(410).json({ error: 'This sign-in has expired. Please sign in again.', restart: true });
  const method = await checkSecondFactor(challenge, req.body.code);
  if (!method) {
    await auditForUser(challenge, 'MFA_CODE_FAILED', req.ip);
    return wrongCodeResponse(res, await failChallenge(challenge));
  }
  await endChallenge(challenge);
  const session = await createSession(challenge);
  await auditSignedIn(session, req.ip, { secondFactor: method });
  const left = (await db.prepare('SELECT COUNT(*) AS c FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').get(challenge.id)).c;
  res.json({ ...session, ...(method === 'RECOVERY_CODE' ? { recoveryCodesLeft: left } : {}) });
}));

// An account that must have MFA but hasn't set it up: enrolls as part of
// signing in (the password was already checked to get this challenge).
app.post('/api/auth/mfa/setup', asyncRoute(async (req, res) => {
  const challenge = await findChallenge(req.body.mfaToken, 'SETUP');
  if (!challenge) return res.status(410).json({ error: 'This sign-in has expired. Please sign in again.', restart: true });
  res.json(await beginEnrollment(challenge));
}));

app.post('/api/auth/mfa/setup/confirm', asyncRoute(async (req, res) => {
  const challenge = await findChallenge(req.body.mfaToken, 'SETUP');
  if (!challenge) return res.status(410).json({ error: 'This sign-in has expired. Please sign in again.', restart: true });
  const recoveryCodes = await finishEnrollment(challenge, req.body.code);
  if (!recoveryCodes) return wrongCodeResponse(res, await failChallenge(challenge));
  await endChallenge(challenge);
  await auditForUser(challenge, 'MFA_ENABLED', req.ip);
  const session = await createSession(challenge);
  await auditSignedIn(session, req.ip, { secondFactor: 'AUTHENTICATOR' });
  res.json({ ...session, recoveryCodes });
}));

// Managing your own two-step verification while signed in (teachers and
// parents can opt in here; required accounts can't turn it off).
const userWithMfa = userId => db.prepare('SELECT * FROM users WHERE id=?').get(userId);

app.get('/api/me/mfa', requireAuth, asyncRoute(async (req, res) => {
  const user = await userWithMfa(req.user.id);
  const left = (await db.prepare('SELECT COUNT(*) AS c FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').get(user.id)).c;
  res.json({ enabled: Boolean(user.mfa_enabled_at), enabledAt: user.mfa_enabled_at, required: await mfaRequiredFor(user), recoveryCodesLeft: left });
}));

app.post('/api/me/mfa/setup', requireAuth, asyncRoute(async (req, res) => {
  const user = await userWithMfa(req.user.id);
  if (user.mfa_enabled_at) return res.status(409).json({ error: 'Two-step verification is already on.' });
  res.json(await beginEnrollment(user));
}));

app.post('/api/me/mfa/confirm', requireAuth, asyncRoute(async (req, res) => {
  const user = await userWithMfa(req.user.id);
  if (user.mfa_enabled_at) return res.status(409).json({ error: 'Two-step verification is already on.' });
  const recoveryCodes = await finishEnrollment(user, req.body.code);
  if (!recoveryCodes) return res.status(401).json({ error: "That code didn't work. Check the time on your phone and try the newest code." });
  await auditForUser(user, 'MFA_ENABLED', req.ip);
  res.json({ recoveryCodes });
}));

app.post('/api/me/mfa/recovery-codes', requireAuth, asyncRoute(async (req, res) => {
  const user = await userWithMfa(req.user.id);
  if (!user.mfa_enabled_at) return res.status(409).json({ error: 'Two-step verification is off.' });
  if (await checkSecondFactor(user, req.body.code) !== 'AUTHENTICATOR') return res.status(401).json({ error: 'Enter the current code from your authenticator app.' });
  const recoveryCodes = newRecoveryCodes();
  await replaceRecoveryCodes(user.id, recoveryCodes);
  await auditForUser(user, 'MFA_RECOVERY_CODES_REPLACED', req.ip);
  res.json({ recoveryCodes });
}));

app.post('/api/me/mfa/disable', requireAuth, asyncRoute(async (req, res) => {
  const user = await userWithMfa(req.user.id);
  if (await mfaRequiredFor(user)) return res.status(403).json({ error: 'Two-step verification is required for your account and cannot be turned off.' });
  if (!verifyPassword(String(req.body.password || ''), user.password_hash).ok) return res.status(401).json({ error: 'Password is incorrect.' });
  await withTransaction(async () => {
    await db.prepare('UPDATE users SET mfa_secret=NULL, mfa_pending_secret=NULL, mfa_enabled_at=NULL, mfa_last_step=NULL WHERE id=?').run(user.id);
    await db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id=?').run(user.id);
  });
  await auditForUser(user, 'MFA_DISABLED', req.ip);
  res.status(204).end();
}));

app.post('/api/auth/logout', requireAuth, asyncRoute(async (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  await logout(token);
  res.status(204).end();
}));

app.get('/api/me/schools', requireAuth, asyncRoute(async (req, res) => {
  res.json(await getMemberships(req.user.id));
}));

// ---- Account emails (accountLinks.js, mailer.js) -----------------------------
//
// New accounts never get a password by email: they get an INVITE link to
// choose their own. If email isn't set up, or delivery fails, the link
// comes back in the response (`setupLink`) so whoever created the account
// can pass it on another way; they're already trusted to create it.
async function inviteNewAccount({ userId, to, fullName, schoolName, roleLabel, invitedBy, pendingApproval }) {
  const link = await createAccountLink(userId, 'INVITE');
  const { sent } = await sendInviteEmail({ to, fullName, schoolName, roleLabel, link, invitedBy, pendingApproval });
  return sent ? { emailSent: true } : { emailSent: false, setupLink: link };
}

// The password for a new account: the one an older app version still
// sends, or one nobody knows (the person chooses theirs via the invite).
function initialPassword(password) {
  if (password !== undefined && password !== null && password !== '') {
    if (String(password).length < 8) throw new Error('Password must be at least 8 characters');
    return { hash: passwordHash(String(password)), needsSetup: 0 };
  }
  return { hash: unusablePasswordHash(), needsSetup: 1 };
}

// "Forgot password?" — always the same answer whether or not the email
// has an account (so it can't be used to find out who's registered), and
// the email is sent after responding so timing doesn't tell either.
// Rate-limited per address and per IP.
const RESET_WINDOW_MS = 60 * 60 * 1000;
const resetRequests = new Map(); // key -> { count, resetAt }
function overResetLimit(key, max) {
  const now = Date.now();
  const entry = resetRequests.get(key);
  if (!entry || entry.resetAt <= now) { resetRequests.set(key, { count: 1, resetAt: now + RESET_WINDOW_MS }); return false; }
  entry.count += 1;
  return entry.count > max;
}
setInterval(() => { const now = Date.now(); for (const [key, entry] of resetRequests) if (entry.resetAt <= now) resetRequests.delete(key); }, RESET_WINDOW_MS).unref();

app.post('/api/auth/forgot-password', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!email.includes('@') || email.length > 254) return res.status(400).json({ error: 'Enter the email address you sign in with.' });
  res.json({ message: "If that email has an SDPMPlus account, we've sent a link to reset the password. Check your inbox (and spam folder)." });
  const emailLimited = overResetLimit(`email:${email}`, 3);
  const ipLimited = overResetLimit(`ip:${req.ip}`, 10);
  if (emailLimited || ipLimited) return;
  deliverLater(async () => {
    const user = await db.prepare('SELECT id, full_name, email FROM users WHERE LOWER(email)=? AND active=1').get(email);
    if (!user || !(await getMemberships(user.id)).length) return;
    const link = await createAccountLink(user.id, 'RESET');
    await sendPasswordResetEmail({ to: user.email, fullName: user.full_name, link });
    await auditForUser(user, 'PASSWORD_RESET_REQUESTED', req.ip, null);
  });
}));

// The set-password page checks its link first, to greet the person and
// show "expired" instead of a form that can't work.
app.post('/api/auth/account-link', asyncRoute(async (req, res) => {
  const link = await findAccountLink(req.body.token);
  if (!link) return res.status(404).json({ error: 'This link has expired or was already used.' });
  res.json({ purpose: link.purpose, fullName: link.fullName, email: link.email });
}));

app.post('/api/auth/set-password', asyncRoute(async (req, res) => {
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (password.length > 200) return res.status(400).json({ error: 'That password is too long.' });
  const link = await useAccountLink(req.body.token, password);
  if (!link) return res.status(404).json({ error: 'This link has expired or was already used. Ask for a new one.' });
  await endAllSessions(link.userId);
  const user = { id: link.userId, full_name: link.fullName };
  await auditForUser(user, link.purpose === 'INVITE' ? 'ACCOUNT_SET_UP' : 'PASSWORD_RESET', req.ip, null);
  if (link.purpose === 'RESET') deliverLater(() => sendPasswordChangedEmail({ to: link.email, fullName: link.fullName }));
  res.json({ email: link.email });
}));

// An admin emails someone at their school a fresh link: an invite if
// they never chose a password, otherwise a reset link that lasts a day.
app.post('/api/admin/members/:userId/send-link', requireAuth, requireSchoolAccess('school_admin'), audited('ACCOUNT_LINK_SENT', req => ({ targetType: 'user', targetId: req.params.userId })), asyncRoute(async (req, res) => {
  const member = await db.prepare(`
    SELECT u.id, u.full_name, u.email, u.needs_password_setup AS "needsSetup", m.role FROM users u
    JOIN memberships m ON m.user_id=u.id AND m.school_id=? AND m.status='ACTIVE' AND m.role IN ('teacher','school_admin','staff','parent')
    WHERE u.id=? AND u.active=1`).get(req.school.id, req.params.userId);
  if (!member) return res.status(404).json({ error: 'That person is not an active member of this school.' });
  if (member.id === req.user.id) return res.status(400).json({ error: 'Use "Forgot password?" on the sign-in page for your own account.' });
  if (member.needsSetup) {
    const roleLabel = { teacher: 'a teacher', school_admin: 'an administrator', staff: 'front desk staff', parent: 'a parent or guardian' }[member.role];
    res.locals.audit = { details: { kind: 'INVITE' } };
    return res.json(await inviteNewAccount({ userId: member.id, to: member.email, fullName: member.full_name, schoolName: req.school.name, roleLabel }));
  }
  const link = await createAccountLink(member.id, 'RESET', ADMIN_RESET_TTL_MS);
  const { sent } = await sendPasswordResetEmail({ to: member.email, fullName: member.full_name, link, requestedByAdmin: `${req.user.full_name} at ${req.school.name}`, expiresIn: '24 hours' });
  res.locals.audit = { details: { kind: 'RESET' } };
  res.json(sent ? { emailSent: true } : { emailSent: false, setupLink: link });
}));

app.post('/api/me/change-password', requireAuth, audited('PASSWORD_CHANGED', req => ({ targetType: 'user', targetId: req.user.id, details: null })), asyncRoute(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  const user = await db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.user.id);
  if (!verifyPassword(currentPassword, user.password_hash).ok) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  await db.prepare('UPDATE users SET password_hash=?, needs_password_setup=0 WHERE id=?').run(passwordHash(newPassword), req.user.id);
  deliverLater(() => sendPasswordChangedEmail({ to: req.user.email, fullName: req.user.full_name }));
  res.status(204).end();
}));

const codeFromSchoolName = name => name.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8) || 'SCHOOL';

// Public self-service signup: a brand-new school registers its first
// campus and admin account in one step, then signs straight in (same
// response shape as /api/auth/login) so they land in the admin
// dashboard immediately. Also creates one ACTIVE school year so
// Faculty/Families/Students are usable right away — creating
// additional classes/school years still needs an admin UI that
// doesn't exist yet (see CUSTOMER_OPERATIONS_GUIDE.md's production
// readiness list).
app.post('/api/auth/register-school', audited('SCHOOL_REGISTERED'), asyncRoute(async (req, res) => {
  const { schoolName, campusName, campusAddress, adminFullName, email, password } = req.body;
  if (!schoolName?.trim() || !campusName?.trim() || !adminFullName?.trim() || !email?.trim() || !password) {
    return res.status(400).json({ error: 'School name, campus name, your name, email, and password are all required.' });
  }
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  try {
    const result = await withTransaction(async () => {
      if (await db.prepare('SELECT 1 FROM users WHERE LOWER(email)=LOWER(?)').get(email.trim())) {
        throw new Error('An account with this email already exists.');
      }

      let code = codeFromSchoolName(schoolName);
      for (let attempt = 0; await db.prepare('SELECT 1 FROM schools WHERE code=?').get(code); attempt++) {
        if (attempt > 20) throw new Error('Could not allocate a school code — try a slightly different school name.');
        code = `${codeFromSchoolName(schoolName).slice(0, 6)}${Math.floor(100 + Math.random() * 900)}`;
      }

      const organizationId = id('org');
      await db.prepare('INSERT INTO organizations (id,name) VALUES (?,?)').run(organizationId, schoolName.trim());

      const schoolId = id('school');
      await db.prepare('INSERT INTO schools (id,organization_id,name,code) VALUES (?,?,?,?)').run(schoolId, organizationId, schoolName.trim(), code);

      const campusId = id('campus');
      const campusAddressFields = parseAddressFields(campusAddress);
      await db.prepare('INSERT INTO campuses (id,school_id,name,address,address_line1,address_line2,city,state,postal_code,country) VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(campusId, schoolId, campusName.trim(), campusAddress?.trim() || null, campusAddressFields.addressLine1 || null, campusAddressFields.addressLine2 || null, campusAddressFields.city || null, campusAddressFields.state || null, campusAddressFields.postalCode || null, campusAddressFields.country || null);

      const userId = id('admin');
      await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES (?,?,?,?,'admin')`).run(userId, adminFullName.trim(), email.trim(), passwordHash(password));
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,NULL,'school_admin')`).run(id('membership'), userId, schoolId);

      // School year starting ~August, so the label reads right whether
      // they sign up mid-summer (next year) or mid-year (current year).
      const now = new Date();
      const startYear = now.getMonth() >= 6 ? now.getFullYear() : now.getFullYear() - 1;
      await db.prepare(`INSERT INTO school_years (id,school_id,name,starts_on,ends_on,status) VALUES (?,?,?,?,?,'ACTIVE')`)
        .run(id('year'), schoolId, `${startYear}-${startYear + 1}`, `${startYear}-08-01`, `${startYear + 1}-06-30`);

      // Admins must use two-step verification, so this is normally a
      // { mfaSetupRequired, mfaToken } challenge rather than a session —
      // the new admin sets up their authenticator before landing in the dashboard.
      return { schoolId, userId, code, session: await login(email.trim(), password) };
    });
    deliverLater(() => sendSchoolWelcomeEmail({ to: email.trim(), fullName: adminFullName.trim(), schoolName: schoolName.trim(), schoolCode: result.code }));
    res.locals.audit = {
      schoolId: result.schoolId, actor: { id: result.userId, full_name: adminFullName.trim() }, actorRole: 'school_admin',
      targetType: 'school', targetId: result.schoolId,
    };
    res.status(201).json(result.session);
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'That email is already in use.' : error.message });
  }
}));

const studentSelect = `
  SELECT s.id, s.first_name || ' ' || s.last_name AS "fullName", s.first_name AS "firstName",
    s.last_name AS "lastName", s.date_of_birth AS "dateOfBirth", s.student_number AS "studentNumber",
    s.photo_url AS "photoUrl", s.daycare AS daycare,
    s.status, s.pickup_status AS "pickupStatus", e.school_year_id AS "schoolYearId",
    e.grade_level_id AS "gradeLevelId", g.name AS "gradeName", e.class_id AS "classId",
    c.name AS "className", c.teacher_user_id AS "teacherId", tu.full_name AS "teacherName", s.school_id AS "schoolId",
    s.campus_id AS "campusId", sc.name AS "schoolName", cp.name AS "campusName",
    cp.latitude, cp.longitude, cp.geofence_radius AS "geofenceRadius"
  FROM students s LEFT JOIN student_enrollments e ON e.student_id=s.id
  LEFT JOIN school_years y ON y.id=e.school_year_id LEFT JOIN grade_levels g ON g.id=e.grade_level_id
  LEFT JOIN classes c ON c.id=e.class_id LEFT JOIN users tu ON tu.id=c.teacher_user_id
  LEFT JOIN schools sc ON sc.id=s.school_id
  LEFT JOIN campuses cp ON cp.id=s.campus_id`;

app.get('/api/me/students', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  const rows = await db.prepare(`${studentSelect} JOIN student_guardians sg ON sg.student_id=s.id JOIN guardians gu ON gu.id=sg.guardian_id JOIN memberships m ON m.user_id=gu.user_id AND m.school_id=s.school_id AND m.role='parent' AND m.status='ACTIVE' WHERE gu.user_id=? AND y.status='ACTIVE' AND s.status='ACTIVE' GROUP BY s.id,e.id,g.name,c.name,c.teacher_user_id,tu.full_name,sc.name,cp.name,cp.latitude,cp.longitude,cp.geofence_radius ORDER BY sc.name,s.last_name,s.first_name`).all(req.user.id);
  // The pickup code for a child's pending pickup — only to the adult who
  // requested it, never to other guardians of the same child.
  const codes = new Map((await db.prepare(`SELECT student_id AS "studentId", pickup_code AS "pickupCode" FROM queue_items WHERE requested_by_user_id=? AND status='PENDING' AND request_type='PICK_UP' AND pickup_code IS NOT NULL`)
    .all(req.user.id)).map(row => [row.studentId, row.pickupCode]));
  res.json(rows.map(row => ({ ...row, status: row.pickupStatus, daycare: Boolean(row.daycare), pickupCode: codes.get(row.id) ?? null })));
}));

// Read-only attendance history for a parent's own children — every
// record on file, grouped per child; the client renders whatever
// window it needs (e.g. the current Mon-Fri) from the full list.
app.get('/api/me/attendance', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  const rows = await db.prepare(`
    SELECT s.id AS "studentId", s.first_name || ' ' || s.last_name AS "fullName", c.name AS "className", u.full_name AS "teacherName",
      ar.date, ar.status, ar.late
    FROM students s
    JOIN student_guardians sg ON sg.student_id=s.id
    JOIN guardians gu ON gu.id=sg.guardian_id
    JOIN memberships pm ON pm.user_id=gu.user_id AND pm.school_id=s.school_id AND pm.role='parent' AND pm.status='ACTIVE'
    JOIN student_enrollments e ON e.student_id=s.id
    JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
    LEFT JOIN classes c ON c.id=e.class_id
    LEFT JOIN users u ON u.id=c.teacher_user_id
    LEFT JOIN attendance_records ar ON ar.student_id=s.id
    WHERE gu.user_id=? AND s.status='ACTIVE'
    ORDER BY s.last_name, s.first_name, ar.date`).all(req.user.id);

  const byStudent = new Map();
  for (const row of rows) {
    if (!byStudent.has(row.studentId)) {
      byStudent.set(row.studentId, { id: row.studentId, fullName: row.fullName, className: row.className, teacherName: row.teacherName, records: [] });
    }
    if (row.date) byStudent.get(row.studentId).records.push({ date: row.date, status: row.status, late: Boolean(row.late) });
  }
  res.json([...byStudent.values()]);
}));

// The parent Class tab's "My Class" view — one entry per child (siblings
// in the same class still get a card each), with their grade, room and
// teacher.
app.get('/api/me/classes', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  const children = await db.prepare(`
    SELECT s.id, s.first_name || ' ' || s.last_name AS "fullName", s.photo_url AS "photoUrl", g.name AS "gradeName",
      c.id AS "classId", c.name AS "className", c.room_name AS "roomName", u.full_name AS "teacherName"
    FROM students s
    JOIN student_guardians sg ON sg.student_id=s.id
    JOIN guardians gu ON gu.id=sg.guardian_id
    JOIN memberships pm ON pm.user_id=gu.user_id AND pm.school_id=s.school_id AND pm.role='parent' AND pm.status='ACTIVE'
    JOIN student_enrollments e ON e.student_id=s.id
    JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
    LEFT JOIN grade_levels g ON g.id=e.grade_level_id
    LEFT JOIN classes c ON c.id=e.class_id
    LEFT JOIN users u ON u.id=c.teacher_user_id
    WHERE gu.user_id=? AND s.status='ACTIVE'
    GROUP BY s.id, g.name, c.id, c.name, c.room_name, u.full_name
    ORDER BY s.last_name, s.first_name`).all(req.user.id);

  res.json(children.map(({ classId, ...child }) => child));
}));

// Real drop-off/pick-up queue, shared by every client (mobile + web,
// any role) via the database — replaces the old in-memory mock that
// only ever synced within one running app process.
// Requires the parent's membership in *this student's* school to be
// ACTIVE — a parent suspended at one school can't act on children there
// even if they're still active at another.
const guardianLinkQuery = db.prepare(`
  SELECT sg.can_pick_up AS "canPickUp" FROM student_guardians sg
  JOIN guardians gu ON gu.id=sg.guardian_id
  JOIN students s ON s.id=sg.student_id
  JOIN memberships pm ON pm.user_id=gu.user_id AND pm.school_id=s.school_id AND pm.role='parent' AND pm.status='ACTIVE'
  WHERE sg.student_id=? AND gu.user_id=?`);
const studentContextQuery = db.prepare(`
  SELECT s.school_id AS "schoolId", s.campus_id AS "campusId", c.teacher_user_id AS "teacherId", e.class_id AS "classId", s.pickup_status AS "pickupStatus",
    cp.latitude, cp.longitude, cp.geofence_radius AS "geofenceRadius", cp.status AS "campusStatus"
  FROM students s
  LEFT JOIN student_enrollments e ON e.student_id=s.id
  LEFT JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
  LEFT JOIN classes c ON c.id=e.class_id
  LEFT JOIN campuses cp ON cp.id=s.campus_id
  WHERE s.id=? AND s.status='ACTIVE'`);

function distanceMeters(a, b) {
  const radians = degrees => degrees * Math.PI / 180;
  const dLat = radians(b.latitude - a.latitude);
  const dLon = radians(b.longitude - a.longitude);
  const lat1 = radians(a.latitude); const lat2 = radians(b.latitude);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 6371000 * 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
}

// Pickup verification: every pickup request gets its own random 6-digit
// code, shown only on the requesting adult's phone. The teacher (or an
// admin) has to type it in to release the child — so a pickup can't be
// accepted just because someone is signed in to a parent's account
// somewhere; the person at the door has to hold the phone that asked.
// The code is single-use (cleared once the request is decided) and
// MAX_PICKUP_CODE_ATTEMPTS wrong entries cancel the request.
const MAX_PICKUP_CODE_ATTEMPTS = 5;
const newPickupCode = () => String(randomInt(0, 1_000_000)).padStart(6, '0');
function pickupCodeMatches(expected, supplied) {
  const a = Buffer.from(String(expected)); const b = Buffer.from(String(supplied ?? '').replace(/\s/g, ''));
  return a.length === b.length && timingSafeEqual(a, b);
}

async function createQueueRequest(req, res, requestType, requiredStatus, nextStatus) {
  const link = await guardianLinkQuery.get(req.params.studentId, req.user.id);
  if (!link) return res.status(403).json({ error: 'You are not linked to this student.' });
  if (requestType === 'PICK_UP' && !link.canPickUp) {
    return res.status(403).json({ error: 'You are not authorized to pick up this student.' });
  }
  const context = await studentContextQuery.get(req.params.studentId);
  if (!context) return res.status(404).json({ error: 'Student not found.' });
  if (context.pickupStatus !== requiredStatus) {
    return res.status(409).json({ error: `This student isn't currently ${requiredStatus === 'AT_HOME' ? 'at home' : 'present'}.` });
  }
  if (context.campusStatus === 'SUSPENDED') {
    return res.status(409).json({ error: 'Drop-off and pick-up are paused at this school location right now. Please contact the school.' });
  }
  if (context.latitude == null || context.longitude == null) {
    return res.status(409).json({ error: 'School location is not configured. Ask the administrator to save the campus address in School Setup.' });
  }
  {
    if (req.body.latitude == null || req.body.longitude == null) {
      return res.status(400).json({ error: 'A valid device location is required for drop-off and pick-up.' });
    }
    const latitude = Number(req.body.latitude); const longitude = Number(req.body.longitude);
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude) || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
      return res.status(400).json({ error: 'A valid device location is required for drop-off and pick-up.' });
    }
    const distance = distanceMeters({ latitude, longitude }, { latitude: context.latitude, longitude: context.longitude });
    if (distance > (context.geofenceRadius || DEFAULT_GEOFENCE_RADIUS_METERS)) {
      return res.status(403).json({ error: `You must be at the school location to ${requestType === 'DROP_OFF' ? 'drop off' : 'pick up'} this student.` });
    }
  }
  try {
    const itemId = id('queue');
    const pickupCode = requestType === 'PICK_UP' ? newPickupCode() : null;
    await withTransaction(async () => {
      await db.prepare(`INSERT INTO queue_items (id,school_id,campus_id,student_id,teacher_user_id,request_type,requested_by_user_id,pickup_code) VALUES (?,?,?,?,?,?,?,?)`)
        .run(itemId, context.schoolId, context.campusId, req.params.studentId, context.teacherId, requestType, req.user.id, pickupCode);
      await db.prepare('UPDATE students SET pickup_status=? WHERE id=?').run(nextStatus, req.params.studentId);
    });
    res.locals.audit = { schoolId: context.schoolId, details: { queueItemId: itemId } };
    res.status(201).json({ id: itemId, ...(pickupCode ? { pickupCode } : {}) });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
}

app.post('/api/me/students/:studentId/drop-off', requireAuth, requireRole('parent'), audited('DROPOFF_REQUESTED', req => ({ targetType: 'student', targetId: req.params.studentId, details: null })), asyncRoute(async (req, res) => {
  await createQueueRequest(req, res, 'DROP_OFF', 'AT_HOME', 'DROPOFF_REQUESTED');
}));

app.post('/api/me/students/:studentId/pick-up', requireAuth, requireRole('parent'), audited('PICKUP_REQUESTED', req => ({ targetType: 'student', targetId: req.params.studentId, details: null })), asyncRoute(async (req, res) => {
  await createQueueRequest(req, res, 'PICK_UP', 'PRESENT', 'PICKUP_REQUESTED');
}));

const queueSelect = `
  SELECT qi.id, qi.student_id AS "childId", s.first_name || ' ' || s.last_name AS "childName",
    s.photo_url AS "childPhotoUrl", c.name AS "className",
    qi.teacher_user_id AS "teacherId", qi.request_type AS "requestType", qi.requested_at AS "requestedAt",
    u.full_name AS "parentName", (qi.pickup_code IS NOT NULL) AS "requiresCode"
  FROM queue_items qi
  JOIN students s ON s.id=qi.student_id
  JOIN users u ON u.id=qi.requested_by_user_id
  LEFT JOIN student_enrollments e ON e.student_id=s.id
  LEFT JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
  LEFT JOIN classes c ON c.id=e.class_id`;

app.get('/api/teacher/queue', requireAuth, requireRole('teacher'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`${queueSelect} WHERE qi.status='PENDING' AND qi.teacher_user_id=? ORDER BY qi.requested_at ASC`).all(req.user.id));
}));

// Front desk / office staff (membership role 'staff') get read access
// to the admin console — queue, attendance, students, families,
// messages — but every /api/admin route that changes data is
// school_admin-only (platform_super_admin always passes too): staff
// can't create or suspend accounts, edit students or guardians, change
// pickup authorization, run promotions or change school settings.
app.get('/api/admin/queue', requireAuth, requireSchoolAccess('school_admin', 'staff'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`${queueSelect} WHERE qi.status='PENDING' AND qi.school_id=? ORDER BY qi.requested_at ASC`).all(req.school.id));
}));

// A teacher may approve only their own class's requests; an admin may
// approve anything in a school they belong to (mirrors the Live Queue
// screens: admin sees and can act on every class, teacher only theirs).
app.post('/api/queue/:id/approve', requireAuth, audited('QUEUE_REQUEST_ACCEPTED'), asyncRoute(async (req, res) => {
  const item = await db.prepare(`SELECT * FROM queue_items WHERE id=? AND status='PENDING'`).get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Request not found or already handled.' });
  const memberships = await getMemberships(req.user.id);
  const isOwningTeacher = req.user.role === 'teacher' && item.teacher_user_id === req.user.id && memberships.some(m => m.schoolId === item.school_id && m.role === 'teacher');
  const isSchoolAdmin = memberships.some(m => m.schoolId === item.school_id && SCHOOL_ADMIN_ROLES.includes(m.role));
  if (!isOwningTeacher && !isSchoolAdmin) return res.status(403).json({ error: 'You do not have permission to approve this request.' });
  res.locals.audit = {
    schoolId: item.school_id, action: item.request_type === 'DROP_OFF' ? 'DROPOFF_ACCEPTED' : 'PICKUP_ACCEPTED',
    targetType: 'student', targetId: item.student_id, details: { queueItemId: item.id, requestedByUserId: item.requested_by_user_id },
  };

  // Pickup verification (see newPickupCode). A request from before codes
  // existed has no pickup_code and goes through as before.
  let verificationMethod = null; let overrideReason = null;
  if (item.request_type === 'PICK_UP' && item.pickup_code) {
    const reason = typeof req.body?.overrideReason === 'string' ? req.body.overrideReason.trim() : '';
    if (reason) {
      if (!isSchoolAdmin) return res.status(403).json({ error: 'Only an administrator can release a child without the pickup code.' });
      verificationMethod = 'ADMIN_OVERRIDE'; overrideReason = reason.slice(0, 500);
    } else if (pickupCodeMatches(item.pickup_code, req.body?.code)) {
      verificationMethod = 'CODE';
    } else {
      const audit = { schoolId: item.school_id, actor: req.user, targetType: 'student', targetId: item.student_id, ip: req.ip };
      const { attempts } = await db.prepare(`UPDATE queue_items SET pickup_code_attempts=pickup_code_attempts+1 WHERE id=? RETURNING pickup_code_attempts AS attempts`).get(item.id);
      if (attempts >= MAX_PICKUP_CODE_ATTEMPTS) {
        const lockoutNoticeId = id('notice');
        await withTransaction(async () => {
          await db.prepare(`UPDATE queue_items SET status='CANCELLED', pickup_code=NULL, declined_at=${NOW_UTC}, declined_by_user_id=? WHERE id=? AND status='PENDING'`).run(req.user.id, item.id);
          await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id=?`).run(item.student_id);
          await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_parent_user_id) VALUES (?,?,?,?,?,?,?,?,?,?)`)
            .run(lockoutNoticeId, item.school_id, item.campus_id, req.user.id, req.user.full_name, req.user.role === 'teacher' ? 'teacher' : 'admin',
              'Pickup cancelled', 'Your pickup request was cancelled because the wrong pickup code was entered too many times. Please request the pickup again from your phone.', 'PARENT', item.requested_by_user_id);
        });
        await writeAudit({ ...audit, action: 'PICKUP_CODE_LOCKED_OUT', details: { queueItemId: item.id, attempts } });
        emailNoticeLater(lockoutNoticeId);
        return res.status(409).json({ error: 'Too many wrong codes. This pickup request has been cancelled; the parent needs to request it again.' });
      }
      await writeAudit({ ...audit, action: 'PICKUP_CODE_REJECTED', details: { queueItemId: item.id, attempts } });
      const left = MAX_PICKUP_CODE_ATTEMPTS - attempts;
      return res.status(422).json({ error: `Wrong pickup code. ${left} ${left === 1 ? 'try' : 'tries'} left.` });
    }
    res.locals.audit.details = { ...res.locals.audit.details, verificationMethod, overrideReason };
  }

  try {
    await withTransaction(async () => {
      const claimed = await db.prepare(`UPDATE queue_items SET status='APPROVED', approved_at=${NOW_UTC}, approved_by_user_id=?, pickup_code=NULL, verification_method=?, override_reason=? WHERE id=? AND status='PENDING'`)
        .run(req.user.id, verificationMethod, overrideReason, item.id);
      if (claimed.changes === 0) throw new Error('This request was already handled.');
      await db.prepare('UPDATE students SET pickup_status=? WHERE id=?').run(item.request_type === 'DROP_OFF' ? 'PRESENT' : 'PICKED_UP', item.student_id);
      // Accepting a drop-off also marks today's attendance PRESENT, so
      // the teacher doesn't have to separately mark it by hand on the
      // Class Roster — a checked-in student is a present student. If
      // this student's location has a start time configured (falling
      // back to the school-wide one if that location doesn't set its
      // own) and this lands after it, flag the record late so parents
      // see it (an "L" alongside Present).
      if (item.request_type === 'DROP_OFF') {
        const context = await studentContextQuery.get(item.student_id);
        const school = await db.prepare('SELECT timezone, start_time AS "startTime" FROM schools WHERE id=?').get(item.school_id);
        const campus = item.campus_id ? await db.prepare('SELECT timezone, start_time AS "startTime" FROM campuses WHERE id=?').get(item.campus_id) : null;
        const startTime = campus?.startTime || school?.startTime;
        const timezone = (campus?.startTime ? campus.timezone : school?.timezone) || 'America/New_York';
        const late = startTime && localClockTime(timezone) > startTime ? 1 : 0;
        await db.prepare(`
          INSERT INTO attendance_records (id,school_id,campus_id,student_id,class_id,date,status,marked_by_user_id,late) VALUES (?,?,?,?,?,?,?,?,?)
          ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status, marked_by_user_id=excluded.marked_by_user_id, marked_at=${NOW_UTC}, late=excluded.late`)
          .run(id('attendance'), item.school_id, item.campus_id, item.student_id, context?.classId ?? null, todayIso(), 'PRESENT', req.user.id, late);
      }
    });
    res.status(204).end();
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
}));

// Same permission split as approve. Declining puts the student back to
// where they were before the request (AT_HOME for a declined drop-off,
// PRESENT for a declined pick-up) so the parent isn't stuck showing a
// pending request that will never clear, and can try again.
app.post('/api/queue/:id/decline', requireAuth, audited('QUEUE_REQUEST_DECLINED'), asyncRoute(async (req, res) => {
  const item = await db.prepare(`SELECT * FROM queue_items WHERE id=? AND status='PENDING'`).get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Request not found or already handled.' });
  const memberships = await getMemberships(req.user.id);
  const isOwningTeacher = req.user.role === 'teacher' && item.teacher_user_id === req.user.id && memberships.some(m => m.schoolId === item.school_id && m.role === 'teacher');
  const isSchoolAdmin = memberships.some(m => m.schoolId === item.school_id && SCHOOL_ADMIN_ROLES.includes(m.role));
  if (!isOwningTeacher && !isSchoolAdmin) return res.status(403).json({ error: 'You do not have permission to decline this request.' });
  res.locals.audit = {
    schoolId: item.school_id, action: item.request_type === 'DROP_OFF' ? 'DROPOFF_DECLINED' : 'PICKUP_DECLINED',
    targetType: 'student', targetId: item.student_id, details: { queueItemId: item.id, requestedByUserId: item.requested_by_user_id },
  };
  try {
    await withTransaction(async () => {
      await db.prepare(`UPDATE queue_items SET status='DECLINED', declined_at=${NOW_UTC}, declined_by_user_id=?, pickup_code=NULL WHERE id=?`).run(req.user.id, item.id);
      await db.prepare('UPDATE students SET pickup_status=? WHERE id=?').run(item.request_type === 'DROP_OFF' ? 'AT_HOME' : 'PRESENT', item.student_id);
    });
    res.status(204).end();
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
}));

const todayIso = () => new Date().toISOString().slice(0, 10);

// Daily present/absent attendance, independent of the drop-off/pick-up
// queue — a teacher (or admin, standing in for one) checks a class off
// each morning rather than waiting on individual parent requests.
// A day with no explicit record defaults to WEEKEND on Sat/Sun
// (Postgres's EXTRACT(DOW FROM date), like SQLite's strftime('%w',
// date), is 0=Sun..6=Sat) and UNMARKED otherwise — the teacher can
// still override either default by marking that date explicitly, same
// as any other status.
const attendanceSelect = `
  SELECT s.id AS "studentId", s.first_name || ' ' || s.last_name AS "fullName", s.photo_url AS "photoUrl",
    e.class_id AS "classId", c.name AS "className",
    COALESCE(ar.status, CASE WHEN EXTRACT(DOW FROM ?::date) IN (0,6) THEN 'WEEKEND' ELSE 'UNMARKED' END) AS status,
    COALESCE(ar.late, 0) AS late
  FROM students s
  JOIN student_enrollments e ON e.student_id=s.id
  JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
  JOIN classes c ON c.id=e.class_id
  LEFT JOIN attendance_records ar ON ar.student_id=s.id AND ar.date=?
  WHERE s.status='ACTIVE'`;

app.get('/api/teacher/attendance', requireAuth, requireRole('teacher'), asyncRoute(async (req, res) => {
  const date = req.query.date || todayIso();
  const rows = await db.prepare(`${attendanceSelect} AND c.teacher_user_id=? ORDER BY s.last_name,s.first_name`).all(date, date, req.user.id);
  res.json(rows.map(row => ({ ...row, late: Boolean(row.late) })));
}));

// The classroom a teacher was assigned to (admin sets this from the
// Faculty tab's classroom dropdown) — null if not assigned to one yet,
// so the Class tab can say so rather than just show an empty roster.
app.get('/api/teacher/class', requireAuth, requireRole('teacher'), asyncRoute(async (req, res) => {
  const myClass = await db.prepare(`
    SELECT c.id, c.name, c.room_name AS "roomName", g.name AS "gradeName"
    FROM classes c
    JOIN grade_levels g ON g.id=c.grade_level_id
    JOIN school_years y ON y.id=c.school_year_id AND y.status='ACTIVE'
    WHERE c.teacher_user_id=?`).get(req.user.id);
  res.json(myClass || null);
}));

// Read-only roster for the Class tab — a teacher can see whether a
// student is active or suspended (an admin-only action, set from
// Students), but can't change it here. A removed (ARCHIVED) student is
// filtered out entirely rather than shown with a status, since there's
// nothing left for a teacher to do about them.
app.get('/api/teacher/students', requireAuth, requireRole('teacher'), audited('CLASS_ROSTER_VIEWED', (req, body) => ({ details: { studentCount: body?.length ?? 0 } })), asyncRoute(async (req, res) => {
  const rows = await db.prepare(`
    SELECT s.id, s.first_name || ' ' || s.last_name AS "fullName", s.photo_url AS "photoUrl", s.status
    FROM students s
    JOIN student_enrollments e ON e.student_id=s.id
    JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
    JOIN classes c ON c.id=e.class_id
    WHERE c.teacher_user_id=? AND s.status!='ARCHIVED'
    ORDER BY s.last_name,s.first_name`).all(req.user.id);
  res.json(rows);
}));

// Every attendance record on file for the teacher's own class — mirrors
// /api/me/attendance's shape (per-student record list) so the same kind
// of month-by-month history view can be built for a teacher's whole
// class instead of just a parent's own children.
app.get('/api/teacher/attendance-history', requireAuth, requireRole('teacher'), audited('ATTENDANCE_HISTORY_VIEWED', (req, body) => ({ details: { studentCount: body?.length ?? 0 } })), asyncRoute(async (req, res) => {
  const rows = await db.prepare(`
    SELECT s.id AS "studentId", s.first_name || ' ' || s.last_name AS "fullName",
      ar.date, ar.status, ar.late
    FROM students s
    JOIN student_enrollments e ON e.student_id=s.id
    JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
    JOIN classes c ON c.id=e.class_id
    LEFT JOIN attendance_records ar ON ar.student_id=s.id
    WHERE c.teacher_user_id=? AND s.status!='ARCHIVED'
    ORDER BY s.last_name, s.first_name, ar.date`).all(req.user.id);

  const byStudent = new Map();
  for (const row of rows) {
    if (!byStudent.has(row.studentId)) {
      byStudent.set(row.studentId, { id: row.studentId, fullName: row.fullName, records: [] });
    }
    if (row.date) byStudent.get(row.studentId).records.push({ date: row.date, status: row.status, late: Boolean(row.late) });
  }
  res.json([...byStudent.values()]);
}));

app.get('/api/admin/attendance', requireAuth, requireSchoolAccess('school_admin', 'staff'), audited('ATTENDANCE_VIEWED', (req, body) => ({ details: { date: req.query.date || null, studentCount: body?.length ?? 0 } })), asyncRoute(async (req, res) => {
  if (!req.query.classId) return res.status(400).json({ error: 'classId is required' });
  const date = req.query.date || todayIso();
  const rows = await db.prepare(`${attendanceSelect} AND s.school_id=? AND e.class_id=? ORDER BY s.last_name,s.first_name`).all(date, date, req.school.id, req.query.classId);
  res.json(rows.map(row => ({ ...row, late: Boolean(row.late) })));
}));

// School-wide counts for the Students > Attendance analytics strip —
// every active student's status for the day, across every classroom,
// not just whichever one classroom happens to be selected below it.
// "Late" is its own tile even though it's a subset of Present (a
// PRESENT record whose drop-off landed after the school's start time,
// see the late computation on the queue-approval insert above) — that
// overlap is intentional, same as most attendance dashboards.
app.get('/api/admin/attendance/summary', requireAuth, requireSchoolAccess('school_admin', 'staff'), asyncRoute(async (req, res) => {
  const date = req.query.date || todayIso();
  const rows = await db.prepare(`${attendanceSelect} AND s.school_id=?`).all(date, date, req.school.id);
  const summary = { present: 0, absent: 0, sick: 0, late: 0, unmarked: 0, total: rows.length };
  for (const row of rows) {
    if (row.status === 'PRESENT') summary.present++;
    else if (row.status === 'ABSENT') summary.absent++;
    else if (row.status === 'SICK') summary.sick++;
    else if (row.status === 'UNMARKED') summary.unmarked++;
    if (row.late) summary.late++;
  }
  res.json(summary);
}));

// A teacher may mark attendance only for their own class; an admin may
// mark it for anything in a school they belong to — same split as the
// live queue's approve permission.
const ATTENDANCE_STATUSES = ['PRESENT', 'ABSENT', 'SICK', 'SUSPENDED', 'HOLIDAY', 'WEEKEND'];
app.post('/api/attendance', requireAuth, audited('ATTENDANCE_MARKED', req => ({ targetType: 'student', targetId: req.body.studentId, details: { date: req.body.date, status: req.body.status } })), asyncRoute(async (req, res) => {
  const { studentId, date, status } = req.body;
  if (!studentId || !date || !ATTENDANCE_STATUSES.includes(status)) {
    return res.status(400).json({ error: `studentId, date, and a status of ${ATTENDANCE_STATUSES.join('/')} are required` });
  }
  const context = await db.prepare(`
    SELECT s.school_id AS "schoolId", s.campus_id AS "campusId", e.class_id AS "classId", c.teacher_user_id AS "teacherId"
    FROM students s
    LEFT JOIN student_enrollments e ON e.student_id=s.id
    LEFT JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
    LEFT JOIN classes c ON c.id=e.class_id
    WHERE s.id=? AND s.status='ACTIVE'`).get(studentId);
  if (!context) return res.status(404).json({ error: 'Student not found' });
  const memberships = await getMemberships(req.user.id);
  const isOwningTeacher = req.user.role === 'teacher' && context.teacherId === req.user.id && memberships.some(m => m.schoolId === context.schoolId && m.role === 'teacher');
  const isSchoolAdmin = memberships.some(m => m.schoolId === context.schoolId && SCHOOL_ADMIN_ROLES.includes(m.role));
  if (!isOwningTeacher && !isSchoolAdmin) return res.status(403).json({ error: 'You do not have permission to mark attendance for this student.' });
  res.locals.audit = { schoolId: context.schoolId };
  await db.prepare(`
    INSERT INTO attendance_records (id,school_id,campus_id,student_id,class_id,date,status,marked_by_user_id) VALUES (?,?,?,?,?,?,?,?)
    ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status, marked_by_user_id=excluded.marked_by_user_id, marked_at=${NOW_UTC}`)
    .run(id('attendance'), context.schoolId, context.campusId, studentId, context.classId, date, status, req.user.id);
  res.status(204).end();
}));

app.get('/api/admin/overview', requireAuth, requireSchoolAccess('school_admin', 'staff'), asyncRoute(async (req, res) => {
  const totalStudents = (await db.prepare(`SELECT COUNT(*) AS c FROM students WHERE school_id=? AND status='ACTIVE'`).get(req.school.id)).c;
  const activeTeachers = (await db.prepare(`SELECT COUNT(*) AS c FROM memberships WHERE school_id=? AND role='teacher' AND status='ACTIVE'`).get(req.school.id)).c;
  const presentToday = (await db.prepare(`SELECT COUNT(*) AS c FROM students WHERE school_id=? AND status='ACTIVE' AND pickup_status='PRESENT'`).get(req.school.id)).c;
  const pendingRequests = (await db.prepare(`SELECT COUNT(*) AS c FROM queue_items WHERE school_id=? AND status='PENDING'`).get(req.school.id)).c;
  res.json({ totalStudents, activeTeachers, presentToday, pendingRequests });
}));

app.get('/api/admin/setup', requireAuth, requireSchoolAccess('school_admin', 'staff'), asyncRoute(async (req, res) => {
  res.json({
    school: await db.prepare('SELECT id,name,code,address,address_line1 AS "addressLine1",address_line2 AS "addressLine2",city,state,postal_code AS "postalCode",country,timezone,status,start_time AS "startTime",dismissal_time AS "dismissalTime",extended_time AS "extendedTime" FROM schools WHERE id=?').get(req.school.id),
    campuses: await db.prepare('SELECT id,name,address,address_line1 AS "addressLine1",address_line2 AS "addressLine2",city,state,postal_code AS "postalCode",country,latitude,longitude,geofence_radius AS "geofenceRadius",timezone,status,start_time AS "startTime",dismissal_time AS "dismissalTime",extended_time AS "extendedTime",created_at AS "createdAt" FROM campuses WHERE school_id=? AND status<>\'ARCHIVED\' ORDER BY created_at, id').all(req.school.id)
      .then(rows => rows.map((row, index) => ({ ...row, isPrimary: index === 0 }))),
    schoolYears: await db.prepare('SELECT * FROM school_years WHERE school_id=? ORDER BY starts_on DESC').all(req.school.id),
    gradeLevels: await db.prepare('SELECT id,name,sort_order AS "sortOrder",next_grade_level_id AS "nextGradeLevelId" FROM grade_levels ORDER BY sort_order').all(),
    classes: await db.prepare('SELECT id,name,room_name AS "roomName",school_year_id AS "schoolYearId",grade_level_id AS "gradeLevelId",teacher_user_id AS "teacherId",campus_id AS "campusId" FROM classes WHERE school_id=? ORDER BY name').all(req.school.id),
    guardians: await db.prepare(`SELECT DISTINCT gu.id,u.full_name AS "fullName",u.email,u.phone FROM guardians gu JOIN users u ON u.id=gu.user_id JOIN memberships m ON m.user_id=u.id WHERE m.school_id=? AND m.status='ACTIVE' ORDER BY u.full_name`).all(req.school.id),
  });
}));

// 'HH:MM', 24-hour — validated so bad input can't silently break the
// lexicographic time comparison the late-arrival check below relies on.
const isValidClockTime = value => /^([01]\d|2[0-3]):[0-5]\d$/.test(value);

app.patch('/api/admin/school', requireAuth, requireSchoolAccess('school_admin'), audited('SCHOOL_SETTINGS_UPDATED', req => ({ targetType: 'school', targetId: req.school.id })), asyncRoute(async (req, res) => {
  const { name, address, startTime, dismissalTime, extendedTime } = req.body;
  for (const [label, value] of [['startTime', startTime], ['dismissalTime', dismissalTime], ['extendedTime', extendedTime]]) {
    if (value !== undefined && value !== null && value !== '' && !isValidClockTime(value)) {
      return res.status(400).json({ error: `${label} must be a HH:MM time` });
    }
  }
  const current = await db.prepare('SELECT name,address,address_line1 AS "addressLine1",address_line2 AS "addressLine2",city,state,postal_code AS "postalCode",country,start_time AS "startTime",dismissal_time AS "dismissalTime",extended_time AS "extendedTime" FROM schools WHERE id=?').get(req.school.id);
  if (!current) return res.status(404).json({ error: 'School not found' });
  const addressFields = addressFieldsFromInput(req.body, current);
  // undefined (field omitted) keeps the existing value; '' explicitly clears it.
  const next = {
    name: name !== undefined && name.trim() ? name.trim() : current.name,
    address: address !== undefined || req.body.addressLine1 !== undefined ? (formatAddressFields(addressFields) || null) : current.address,
    startTime: startTime !== undefined ? (startTime || null) : current.startTime,
    dismissalTime: dismissalTime !== undefined ? (dismissalTime || null) : current.dismissalTime,
    extendedTime: extendedTime !== undefined ? (extendedTime || null) : current.extendedTime,
  };
  await db.prepare('UPDATE schools SET name=?, address=?, address_line1=?, address_line2=?, city=?, state=?, postal_code=?, country=?, start_time=?, dismissal_time=?, extended_time=? WHERE id=?')
    .run(next.name, next.address, addressFields.addressLine1 || null, addressFields.addressLine2 || null, addressFields.city || null, addressFields.state || null, addressFields.postalCode || null, addressFields.country || null, next.startTime, next.dismissalTime, next.extendedTime, req.school.id);
  res.status(204).end();
}));

// A "location" is a campus — some schools run more than one site with
// its own bell schedule (e.g. an early-childhood building vs the main
// campus), so each gets its own start/dismissal/extended time, same
// shape as the school-wide profile above.
// Default radius (meters) for a newly created location's drop-off/pick-up
// geofence — wide enough to cover a parking lot/curb without requiring the
// admin to pick a number up front; editable afterward in School Setup.
const DEFAULT_GEOFENCE_RADIUS_METERS = 150;

app.post('/api/admin/campuses', requireAuth, requireSchoolAccess('school_admin'), audited('LOCATION_CREATED', (req, body) => ({ targetType: 'campus', targetId: body?.id })), asyncRoute(async (req, res) => {
  const { name, address, startTime, dismissalTime, extendedTime, geofenceRadius } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Location name is required' });
  const addressFields = addressFieldsFromInput(req.body);
  const formattedAddress = formatAddressFields(addressFields);
  if (!formattedAddress) return res.status(400).json({ error: 'Address is required — it sets up the drop-off/pick-up geofence for this location' });
  if (!addressFields.addressLine1 || !addressFields.city || !addressFields.state || !addressFields.postalCode || !addressFields.country) {
    return res.status(400).json({ error: 'Street address, city, state, ZIP/postal code, and country are required' });
  }
  for (const [label, value] of [['startTime', startTime], ['dismissalTime', dismissalTime], ['extendedTime', extendedTime]]) {
    if (value !== undefined && value !== null && value !== '' && !isValidClockTime(value)) {
      return res.status(400).json({ error: `${label} must be a HH:MM time` });
    }
  }
  const radius = geofenceRadius === undefined || geofenceRadius === null || geofenceRadius === '' ? DEFAULT_GEOFENCE_RADIUS_METERS : Number(geofenceRadius);
  if (!Number.isFinite(radius) || radius <= 0) return res.status(400).json({ error: 'geofenceRadius must be a positive number of meters' });

  let coordinates;
  try {
    coordinates = await geocodeAddress(formattedAddress);
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }

  const campusId = id('campus');
  try {
    await db.prepare('INSERT INTO campuses (id,school_id,name,address,address_line1,address_line2,city,state,postal_code,country,latitude,longitude,geofence_radius,start_time,dismissal_time,extended_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(campusId, req.school.id, name.trim(), formattedAddress, addressFields.addressLine1 || null, addressFields.addressLine2 || null, addressFields.city || null, addressFields.state || null, addressFields.postalCode || null, addressFields.country || null, coordinates.latitude, coordinates.longitude, radius, startTime || null, dismissalTime || null, extendedTime || null);
    res.status(201).json({ id: campusId, latitude: coordinates.latitude, longitude: coordinates.longitude });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'A location with that name already exists' : error.message });
  }
}));

// The school's primary location: the first one it created (normally the
// one made at registration). It can't be removed, and is where students
// and classes move when another location is removed.
const primaryCampusId = async schoolId =>
  (await db.prepare(`SELECT id FROM campuses WHERE school_id=? AND status<>'ARCHIVED' ORDER BY created_at, id LIMIT 1`).get(schoolId))?.id ?? null;

// Remove an added location. Its students, classes and staff assignments
// move to the primary location (so every child still has a pickup area),
// and the location is archived rather than erased so past drop-off/pickup
// and attendance records keep pointing at it. Its name is freed for reuse.
app.delete('/api/admin/campuses/:id', requireAuth, requireSchoolAccess('school_admin'), audited('LOCATION_REMOVED', (req, body) => ({ targetType: 'campus', targetId: req.params.id, details: body?.moved ?? null })), asyncRoute(async (req, res) => {
  const campus = await db.prepare(`SELECT id, name FROM campuses WHERE id=? AND school_id=? AND status<>'ARCHIVED'`).get(req.params.id, req.school.id);
  if (!campus) return res.status(404).json({ error: 'Location not found' });
  const primaryId = await primaryCampusId(req.school.id);
  if (campus.id === primaryId) return res.status(400).json({ error: "The primary location can't be removed." });
  const moved = await withTransaction(async () => {
    const move = table => db.prepare(`UPDATE ${table} SET campus_id=? WHERE campus_id=? AND school_id=?`).run(primaryId, campus.id, req.school.id).then(r => r.changes);
    const counts = { students: await move('students'), classes: await move('classes'), enrollments: await move('student_enrollments'), staffAssignments: await move('memberships') };
    await db.prepare(`UPDATE campuses SET status='ARCHIVED', name=name || ' (removed ' || id || ')' WHERE id=?`).run(campus.id);
    return counts;
  });
  res.json({ moved });
}));

// Suspend a location (drop-off/pick-up requests there are refused until
// it's reactivated — e.g. a site closed for repairs) or reactivate it.
// Nothing is moved or deleted.
app.post('/api/admin/campuses/:id/status', requireAuth, requireSchoolAccess('school_admin'), audited('LOCATION_STATUS_CHANGED', req => ({ targetType: 'campus', targetId: req.params.id, details: { status: req.body.active ? 'ACTIVE' : 'SUSPENDED' } })), asyncRoute(async (req, res) => {
  const result = await db.prepare(`UPDATE campuses SET status=? WHERE id=? AND school_id=? AND status<>'ARCHIVED'`)
    .run(req.body.active ? 'ACTIVE' : 'SUSPENDED', req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Location not found' });
  res.status(204).end();
}));

app.patch('/api/admin/campuses/:id', requireAuth, requireSchoolAccess('school_admin'), audited('LOCATION_UPDATED', req => ({ targetType: 'campus', targetId: req.params.id })), asyncRoute(async (req, res) => {
  const { name, address, startTime, dismissalTime, extendedTime, geofenceRadius } = req.body;
  if (address !== undefined && !address.trim()) return res.status(400).json({ error: 'Address is required — it sets up the drop-off/pick-up geofence for this location' });
  for (const [label, value] of [['startTime', startTime], ['dismissalTime', dismissalTime], ['extendedTime', extendedTime]]) {
    if (value !== undefined && value !== null && value !== '' && !isValidClockTime(value)) {
      return res.status(400).json({ error: `${label} must be a HH:MM time` });
    }
  }
  if (geofenceRadius !== undefined && geofenceRadius !== null && geofenceRadius !== '' && !(Number(geofenceRadius) > 0)) {
    return res.status(400).json({ error: 'geofenceRadius must be a positive number of meters' });
  }
  const current = await db.prepare('SELECT name,address,address_line1 AS "addressLine1",address_line2 AS "addressLine2",city,state,postal_code AS "postalCode",country,latitude,longitude,geofence_radius AS "geofenceRadius",start_time AS "startTime",dismissal_time AS "dismissalTime",extended_time AS "extendedTime" FROM campuses WHERE id=? AND school_id=? AND status<>\'ARCHIVED\'').get(req.params.id, req.school.id);
  if (!current) return res.status(404).json({ error: 'Location not found' });

  // Re-geocode when the address actually changed, or when it hasn't but
  // still has no coordinates — a location saved before geofencing existed
  // has an address with no lat/long yet, and would otherwise never get
  // one until someone happened to edit the address text itself.
  const addressFields = addressFieldsFromInput(req.body, current);
  const addressWasProvided = address !== undefined || req.body.addressLine1 !== undefined;
  const nextAddress = addressWasProvided ? formatAddressFields(addressFields) : current.address;
  if (addressWasProvided && (!addressFields.addressLine1 || !addressFields.city || !addressFields.state || !addressFields.postalCode || !addressFields.country)) {
    return res.status(400).json({ error: 'Street address, city, state, ZIP/postal code, and country are required' });
  }
  let coordinates = { latitude: current.latitude, longitude: current.longitude };
  if (addressWasProvided && (nextAddress !== current.address || current.latitude == null || current.longitude == null)) {
    try {
      coordinates = await geocodeAddress(nextAddress);
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  }

  // undefined (field omitted) keeps the existing value; '' explicitly clears it (time fields only — address is required, so it can't be cleared this way).
  const next = {
    name: name !== undefined && name.trim() ? name.trim() : current.name,
    address: nextAddress,
    latitude: coordinates.latitude,
    longitude: coordinates.longitude,
    geofenceRadius: geofenceRadius !== undefined && geofenceRadius !== null && geofenceRadius !== '' ? Number(geofenceRadius) : current.geofenceRadius,
    startTime: startTime !== undefined ? (startTime || null) : current.startTime,
    dismissalTime: dismissalTime !== undefined ? (dismissalTime || null) : current.dismissalTime,
    extendedTime: extendedTime !== undefined ? (extendedTime || null) : current.extendedTime,
  };
  try {
    await db.prepare('UPDATE campuses SET name=?, address=?, address_line1=?, address_line2=?, city=?, state=?, postal_code=?, country=?, latitude=?, longitude=?, geofence_radius=?, start_time=?, dismissal_time=?, extended_time=? WHERE id=?')
      .run(next.name, next.address, addressFields.addressLine1 || null, addressFields.addressLine2 || null, addressFields.city || null, addressFields.state || null, addressFields.postalCode || null, addressFields.country || null, next.latitude, next.longitude, next.geofenceRadius, next.startTime, next.dismissalTime, next.extendedTime, req.params.id);
    res.status(204).end();
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'A location with that name already exists' : error.message });
  }
}));

app.get('/api/admin/classes', requireAuth, requireSchoolAccess('school_admin', 'staff'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`
    SELECT c.id, c.name, c.room_name AS "roomName", c.school_year_id AS "schoolYearId", y.name AS "schoolYearName",
      c.grade_level_id AS "gradeLevelId", g.name AS "gradeName", c.campus_id AS "campusId",
      c.teacher_user_id AS "teacherId", u.full_name AS "teacherName",
      (SELECT COUNT(*) FROM student_enrollments e WHERE e.class_id=c.id AND e.status='ENROLLED') AS "studentCount"
    FROM classes c
    JOIN grade_levels g ON g.id=c.grade_level_id
    JOIN school_years y ON y.id=c.school_year_id
    LEFT JOIN users u ON u.id=c.teacher_user_id
    WHERE c.school_id=?
    ORDER BY y.starts_on DESC, g.sort_order, c.name`).all(req.school.id));
}));

app.post('/api/admin/classes', requireAuth, requireSchoolAccess('school_admin'), audited('CLASS_CREATED', (req, body) => ({ targetType: 'class', targetId: body?.id })), asyncRoute(async (req, res) => {
  const { name, gradeLevelId, roomName, schoolYearId, campusId } = req.body;
  if (!name?.trim() || !gradeLevelId || !schoolYearId) return res.status(400).json({ error: 'Class name, grade, and school year are required' });
  const year = await db.prepare('SELECT id FROM school_years WHERE id=? AND school_id=?').get(schoolYearId, req.school.id);
  if (!year) return res.status(400).json({ error: 'That school year does not belong to this school' });
  let resolvedCampusId = campusId || null;
  if (!resolvedCampusId) {
    resolvedCampusId = await primaryCampusId(req.school.id);
  }
  try {
    const classId = id('class');
    await db.prepare(`INSERT INTO classes (id,name,room_name,school_year_id,grade_level_id,campus_id,school_id) VALUES (?,?,?,?,?,?,?)`)
      .run(classId, name.trim(), roomName?.trim() || null, schoolYearId, gradeLevelId, resolvedCampusId, req.school.id);
    res.status(201).json({ id: classId });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'A class with this name already exists for that school year' : error.message });
  }
}));

app.get('/api/admin/teachers', requireAuth, requireSchoolAccess('school_admin', 'staff'), asyncRoute(async (req, res) => {
  const rows = await db.prepare(`
    SELECT u.id, u.full_name AS "fullName", u.email, u.photo_url AS "photoUrl", m.status,
      c.id AS "classId", c.name AS "className"
    FROM memberships m
    JOIN users u ON u.id=m.user_id
    LEFT JOIN classes c ON c.teacher_user_id=u.id AND c.school_id=?
    WHERE m.school_id=? AND m.role='teacher'
    ORDER BY u.full_name`).all(req.school.id, req.school.id);
  res.json(rows.map(r => ({ ...r, active: r.status === 'ACTIVE' })));
}));

app.post('/api/admin/teachers', requireAuth, requireSchoolAccess('school_admin'), audited('STAFF_CREATED', (req, body) => ({ targetType: 'user', targetId: body?.id, details: { role: 'teacher', email: req.body.email, classId: req.body.classId } })), asyncRoute(async (req, res) => {
  const { fullName, email, password, photoDataUrl, classId } = req.body;
  if (!fullName?.trim() || !email?.trim()) return res.status(400).json({ error: 'Name and email are required' });
  let photoUrl, initial;
  try {
    initial = initialPassword(password);
    photoUrl = normalizePhotoDataUrl(photoDataUrl); // optional — photo is never required
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
  let assignedClass = null;
  if (classId) {
    assignedClass = await db.prepare('SELECT id, campus_id AS "campusId" FROM classes WHERE id=? AND school_id=?').get(classId, req.school.id);
    if (!assignedClass) return res.status(400).json({ error: 'That classroom does not belong to this school' });
  }
  try {
    const userId = await withTransaction(async () => {
      if (await db.prepare('SELECT 1 FROM users WHERE LOWER(email)=LOWER(?)').get(email.trim())) {
        throw new Error('An account with this email already exists.');
      }
      const userId = id('teacher');
      await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,needs_password_setup,photo_url,role) VALUES (?,?,?,?,?,?,'teacher')`)
        .run(userId, fullName.trim(), email.trim(), initial.hash, initial.needsSetup, photoUrl);
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'teacher')`)
        .run(id('membership'), userId, req.school.id, assignedClass?.campusId || null);
      if (assignedClass) await db.prepare('UPDATE classes SET teacher_user_id=? WHERE id=?').run(userId, assignedClass.id);
      return userId;
    });
    const invite = await inviteNewAccount({ userId, to: email.trim(), fullName: fullName.trim(), schoolName: req.school.name, roleLabel: 'a teacher' });
    res.status(201).json({ id: userId, ...invite });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'That email is already in use.' : error.message });
  }
}));

// Edit an existing teacher: name, photo, and/or which classroom they're
// assigned to (passing classId: null unassigns them; omitting it leaves
// the assignment as-is). No password reset here — out of scope for now.
app.patch('/api/admin/teachers/:id', requireAuth, requireSchoolAccess('school_admin'), audited('STAFF_UPDATED', req => ({ targetType: 'user', targetId: req.params.id, details: { fullName: req.body.fullName, classId: req.body.classId, photoChanged: req.body.photoDataUrl !== undefined } })), asyncRoute(async (req, res) => {
  const membership = await db.prepare(`SELECT 1 FROM memberships WHERE user_id=? AND school_id=? AND role='teacher'`).get(req.params.id, req.school.id);
  if (!membership) return res.status(404).json({ error: 'Teacher not found in this school' });
  const { fullName, photoDataUrl, classId } = req.body;
  let photoUrl;
  try {
    photoUrl = photoDataUrl !== undefined ? normalizePhotoDataUrl(photoDataUrl) : undefined;
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
  if (fullName?.trim()) await db.prepare('UPDATE users SET full_name=? WHERE id=?').run(fullName.trim(), req.params.id);
  if (photoUrl !== undefined) await db.prepare('UPDATE users SET photo_url=? WHERE id=?').run(photoUrl, req.params.id);
  if (classId !== undefined) {
    await db.prepare(`UPDATE classes SET teacher_user_id=NULL WHERE teacher_user_id=? AND school_id=?`).run(req.params.id, req.school.id);
    if (classId) {
      const cls = await db.prepare('SELECT id FROM classes WHERE id=? AND school_id=?').get(classId, req.school.id);
      if (!cls) return res.status(400).json({ error: 'That classroom does not belong to this school' });
      await db.prepare('UPDATE classes SET teacher_user_id=? WHERE id=?').run(req.params.id, classId);
    }
  }
  res.status(204).end();
}));

// General staff directory — teachers, admins, and front-desk/office
// staff together (unlike /api/admin/teachers above, which stays
// teacher-only since it also backs the classroom-teacher pickers
// elsewhere). 'admin' and 'front_desk' both get a users.role='admin'
// login (routed to the admin dashboard by the frontend); 'front_desk'
// is tagged with the 'staff' membership role so it's a distinct entry
// in the Staff list — and, unlike school_admin, it only gets read access
// to the admin routes (see the note above /api/admin/queue).
const STAFF_ROLES = {
  teacher: { userRole: 'teacher', membershipRole: 'teacher' },
  admin: { userRole: 'admin', membershipRole: 'school_admin' },
  front_desk: { userRole: 'admin', membershipRole: 'staff' },
};

app.get('/api/admin/staff', requireAuth, requireSchoolAccess('school_admin', 'staff'), asyncRoute(async (req, res) => {
  const rows = await db.prepare(`
    SELECT u.id, u.full_name AS "fullName", u.email, u.photo_url AS "photoUrl", m.status, m.role,
      (u.mfa_enabled_at IS NOT NULL) AS "mfaEnabled", (u.needs_password_setup=1) AS "needsSetup", c.id AS "classId", c.name AS "className"
    FROM memberships m
    JOIN users u ON u.id=m.user_id
    LEFT JOIN classes c ON c.teacher_user_id=u.id AND c.school_id=?
    WHERE m.school_id=? AND m.role IN ('teacher','school_admin','staff') AND m.status != 'ARCHIVED'
    ORDER BY u.full_name`).all(req.school.id, req.school.id);
  res.json(rows.map(r => ({ ...r, active: r.status === 'ACTIVE' })));
}));

// Adding someone whose email already has an account. Allowed only for a
// former staff member of THIS school who isn't active anywhere else
// (not a parent, not at another school, not a district admin) — so an
// admin can never take over someone else's account by typing its email.
// They come back with the role and photo the admin just entered (and the
// password, if one was given — otherwise they keep their old one and get
// an email link to choose a new one); two-step verification is cleared
// so they set it up again, and any old sessions are ended.
async function restoreFormerStaff(userId, schoolId, { fullName, password, photoUrl, roleConfig, campusId }) {
  const staffRoles = ['teacher', 'school_admin', 'staff'];
  const here = await db.prepare(`SELECT id, status FROM memberships WHERE user_id=? AND school_id=? AND role = ANY(?) ORDER BY status='ACTIVE' DESC`).all(userId, schoolId, staffRoles);
  if (here.length === 0) {
    throw new Error('That email already belongs to another account (for example a parent, or staff at another school). Use a different email address.');
  }
  if (here.some(m => m.status === 'ACTIVE')) throw new Error('This person is already on your staff list. Use Reactivate or edit them there.');
  const activeElsewhere = await db.prepare(`
    SELECT 1 FROM memberships WHERE user_id=? AND status='ACTIVE' AND NOT (school_id=? AND role = ANY(?))
    UNION ALL SELECT 1 FROM district_memberships WHERE user_id=? AND status='ACTIVE' LIMIT 1`).get(userId, schoolId, staffRoles, userId);
  if (activeElsewhere) throw new Error('That email already belongs to an active account elsewhere. Use a different email address.');

  const [keep, ...others] = here;
  for (const other of others) await db.prepare('DELETE FROM memberships WHERE id=?').run(other.id);
  await db.prepare(`UPDATE memberships SET status='ACTIVE', role=?, campus_id=? WHERE id=?`).run(roleConfig.membershipRole, campusId, keep.id);
  await db.prepare(`
    UPDATE users SET full_name=?, password_hash=COALESCE(?, password_hash), role=?, active=1, photo_url=COALESCE(?, photo_url),
      mfa_secret=NULL, mfa_pending_secret=NULL, mfa_enabled_at=NULL, mfa_last_step=NULL
    WHERE id=?`).run(fullName.trim(), password ? passwordHash(String(password)) : null, roleConfig.userRole, photoUrl, userId);
  await db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id=?').run(userId);
}

app.post('/api/admin/staff', requireAuth, requireSchoolAccess('school_admin'), audited('STAFF_CREATED', (req, body) => ({ targetType: 'user', targetId: body?.id })), asyncRoute(async (req, res) => {
  const { fullName, email, password, photoDataUrl, classId, role } = req.body;
  const roleConfig = STAFF_ROLES[role];
  if (!roleConfig) return res.status(400).json({ error: 'role must be one of teacher, admin, front_desk' });
  if (!fullName?.trim() || !email?.trim()) return res.status(400).json({ error: 'Name and email are required' });
  let photoUrl, initial;
  try {
    initial = initialPassword(password);
    photoUrl = normalizePhotoDataUrl(photoDataUrl); // optional — photo is never required
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
  let assignedClass = null;
  if (role === 'teacher' && classId) {
    assignedClass = await db.prepare('SELECT id, campus_id AS "campusId" FROM classes WHERE id=? AND school_id=?').get(classId, req.school.id);
    if (!assignedClass) return res.status(400).json({ error: 'That classroom does not belong to this school' });
  }
  try {
    const { userId, restored } = await withTransaction(async () => {
      const existing = await db.prepare('SELECT id FROM users WHERE LOWER(email)=LOWER(?)').get(email.trim());
      if (existing) {
        await restoreFormerStaff(existing.id, req.school.id, { fullName, password, photoUrl, roleConfig, campusId: assignedClass?.campusId || null });
        if (assignedClass) await db.prepare('UPDATE classes SET teacher_user_id=? WHERE id=?').run(existing.id, assignedClass.id);
        return { userId: existing.id, restored: true };
      }
      const userId = id('staff');
      await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,needs_password_setup,photo_url,role) VALUES (?,?,?,?,?,?,?)`)
        .run(userId, fullName.trim(), email.trim(), initial.hash, initial.needsSetup, photoUrl, roleConfig.userRole);
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?,?)`)
        .run(id('membership'), userId, req.school.id, assignedClass?.campusId || null, roleConfig.membershipRole);
      if (assignedClass) await db.prepare('UPDATE classes SET teacher_user_id=? WHERE id=?').run(userId, assignedClass.id);
      return { userId, restored: false };
    });
    if (restored) {
      await endAllSessions(userId);
      res.locals.audit = { details: { role, email: email.trim(), classId: assignedClass?.id ?? null, returningStaff: true } };
    }
    const roleLabel = role === 'front_desk' ? 'front desk staff' : role === 'admin' ? 'an administrator' : 'a teacher';
    let invite;
    if (restored) {
      // A returning person keeps their old password unless one was given;
      // either way they get a link to choose a new one.
      const link = await createAccountLink(userId, 'RESET', ADMIN_RESET_TTL_MS);
      const { sent } = await sendPasswordResetEmail({ to: email.trim(), fullName: fullName.trim(), link, requestedByAdmin: `${req.user.full_name} at ${req.school.name}`, expiresIn: '24 hours' });
      invite = sent ? { emailSent: true } : { emailSent: false, setupLink: link };
    } else {
      invite = await inviteNewAccount({ userId, to: email.trim(), fullName: fullName.trim(), schoolName: req.school.name, roleLabel });
    }
    res.status(201).json({ id: userId, restored, ...invite });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'That email is already in use.' : error.message });
  }
}));

// Suspend blocks admin-route access (requireSchoolAccess only honors an
// ACTIVE membership) without touching their login itself; delete
// archives the membership and, for a teacher, frees up their classroom.
// Either way, an admin can't take either action on their own account —
// that would risk locking every admin out of the school at once.
app.patch('/api/admin/staff/:id', requireAuth, requireSchoolAccess('school_admin'), audited('STAFF_STATUS_CHANGED', req => ({ targetType: 'user', targetId: req.params.id, details: { status: req.body.active ? 'ACTIVE' : 'SUSPENDED' } })), asyncRoute(async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot change your own status' });
  const status = req.body.active ? 'ACTIVE' : 'SUSPENDED';
  const result = await db.prepare(`UPDATE memberships SET status=? WHERE user_id=? AND school_id=? AND role IN ('teacher','school_admin','staff')`).run(status, req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Staff member not found in this school' });
  res.status(204).end();
}));

// Lost phone and recovery codes: another admin clears the person's
// two-step verification and signs them out everywhere. They set it up
// again at their next sign-in (or may, if it's optional for them).
// Not for your own account — that needs a second admin.
app.post('/api/admin/staff/:id/reset-mfa', requireAuth, requireSchoolAccess('school_admin'), audited('MFA_RESET', req => ({ targetType: 'user', targetId: req.params.id, details: null })), asyncRoute(async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Ask another administrator to reset your two-step verification.' });
  const member = await db.prepare(`SELECT 1 FROM memberships WHERE user_id=? AND school_id=? AND role IN ('teacher','school_admin','staff')`).get(req.params.id, req.school.id);
  if (!member) return res.status(404).json({ error: 'Staff member not found in this school' });
  await withTransaction(async () => {
    await db.prepare('UPDATE users SET mfa_secret=NULL, mfa_pending_secret=NULL, mfa_enabled_at=NULL, mfa_last_step=NULL WHERE id=?').run(req.params.id);
    await db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id=?').run(req.params.id);
  });
  await endAllSessions(req.params.id);
  const person = await db.prepare('SELECT full_name, email FROM users WHERE id=?').get(req.params.id);
  if (person) deliverLater(() => sendMfaResetEmail({ to: person.email, fullName: person.full_name, schoolName: req.school.name, resetBy: req.user.full_name }));
  res.status(204).end();
}));

app.delete('/api/admin/staff/:id', requireAuth, requireSchoolAccess('school_admin'), audited('STAFF_REMOVED', req => ({ targetType: 'user', targetId: req.params.id })), asyncRoute(async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account' });
  const result = await db.prepare(`UPDATE memberships SET status='ARCHIVED' WHERE user_id=? AND school_id=? AND role IN ('teacher','school_admin','staff')`).run(req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Staff member not found in this school' });
  await db.prepare(`UPDATE classes SET teacher_user_id=NULL WHERE teacher_user_id=? AND school_id=?`).run(req.params.id, req.school.id);
  res.status(204).end();
}));

app.get('/api/admin/students', requireAuth, requireSchoolAccess('school_admin', 'staff'), audited('STUDENT_LIST_VIEWED', (req, body) => ({ details: { studentCount: body?.length ?? 0 } })), asyncRoute(async (req, res) => {
  // Removed (ARCHIVED) students are listed separately, under Data & Privacy.
  const active = await db.prepare(`${studentSelect} WHERE s.school_id=? AND y.status='ACTIVE' AND s.status<>'ARCHIVED' ORDER BY s.last_name,s.first_name`).all(req.school.id);
  const guardianQuery = db.prepare(`SELECT gu.id,u.full_name AS "fullName",u.email,sg.relationship,sg.can_pick_up AS "canPickUp",sg.is_primary AS "isPrimary" FROM student_guardians sg JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id WHERE sg.student_id=?`);
  // `status` mirrors pickupStatus everywhere else this shape is used (the
  // Child type); the real enrollment status (ACTIVE/SUSPENDED) that admin
  // actions toggle gets its own field so it doesn't collide with that.
  const students = await Promise.all(active.map(async student => ({ ...student, status: student.pickupStatus, enrollmentStatus: student.status, daycare: Boolean(student.daycare), guardians: await guardianQuery.all(student.id) })));
  res.json(students);
}));

app.post('/api/admin/students', requireAuth, requireSchoolAccess('school_admin'), audited('STUDENT_CREATED', (req, body) => ({ targetType: 'student', targetId: body?.id })), asyncRoute(async (req, res) => {
  const { firstName, lastName, dateOfBirth, studentNumber, photoDataUrl, schoolYearId, gradeLevelId, classId, daycare, guardian } = req.body;
  if (!firstName?.trim() || !lastName?.trim() || !schoolYearId || !gradeLevelId) return res.status(400).json({ error: 'Name, school year, and grade are required' });
  if (!classId) return res.status(400).json({ error: 'Select a class so pickup requests reach a teacher' });
  const selectedClass = await db.prepare('SELECT campus_id FROM classes WHERE id=? AND school_id=? AND school_year_id=? AND grade_level_id=?').get(classId, req.school.id, schoolYearId, gradeLevelId);
  if (!selectedClass) return res.status(400).json({ error: 'The selected class, grade, or school year does not belong to this school' });
  let guardianId = guardian?.id;
  let createdGuardianAccount = false;
  let addedExistingGuardian = null;
  let photoUrl;
  try {
    photoUrl = normalizePhotoDataUrl(photoDataUrl);
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
  try {
    const studentId = await withTransaction(async () => {
      if (!guardianId && guardian?.email) {
        const existing = await db.prepare(`SELECT gu.id,u.id AS user_id FROM guardians gu JOIN users u ON u.id=gu.user_id WHERE LOWER(u.email)=LOWER(?)`).get(guardian.email.trim());
        if (existing) {
          guardianId = existing.id;
          const added = await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'parent') ON CONFLICT (user_id, school_id, COALESCE(campus_id, ''), role) DO NOTHING`).run(id('membership'), existing.user_id, req.school.id, null);
          if (added.changes > 0) addedExistingGuardian = existing.user_id;
        }
        else {
          if (!guardian.fullName?.trim()) throw new Error("New guardian's name is required");
          const initial = initialPassword(guardian.temporaryPassword);
          const userId = id('parent'); guardianId = id('guardian');
          createdGuardianAccount = userId;
          await db.prepare(`INSERT INTO users (id,full_name,email,phone,password_hash,needs_password_setup,role) VALUES (?,?,?,?,?,?,'parent')`).run(userId, guardian.fullName.trim(), guardian.email.trim(), guardian.phone || null, initial.hash, initial.needsSetup);
          await db.prepare('INSERT INTO guardians (id,user_id) VALUES (?,?)').run(guardianId, userId);
          await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'parent')`).run(id('membership'), userId, req.school.id, null);
        }
      }
      if (guardianId) {
        const permittedGuardian = await db.prepare(`SELECT 1 FROM guardians gu JOIN memberships m ON m.user_id=gu.user_id WHERE gu.id=? AND m.school_id=? AND m.status='ACTIVE'`).get(guardianId, req.school.id);
        if (!permittedGuardian) throw new Error('The selected parent does not belong to this school');
      }
      const studentId = id('student');
      await db.prepare(`INSERT INTO students (id,first_name,last_name,date_of_birth,student_number,photo_url,daycare,school_id,campus_id) VALUES (?,?,?,?,?,?,?,?,?)`).run(studentId, firstName.trim(), lastName.trim(), dateOfBirth || null, studentNumber?.trim() || null, photoUrl, daycare ? 1 : 0, req.school.id, selectedClass.campus_id);
      await db.prepare(`INSERT INTO student_enrollments (id,student_id,school_year_id,grade_level_id,class_id,school_id,campus_id) VALUES (?,?,?,?,?,?,?)`).run(id('enrollment'), studentId, schoolYearId, gradeLevelId, classId, req.school.id, selectedClass.campus_id);
      if (guardianId) await db.prepare(`INSERT INTO student_guardians (student_id,guardian_id,relationship,is_primary,can_pick_up,can_manage) VALUES (?,?,?,1,?,1)`).run(studentId, guardianId, guardian.relationship || 'Guardian', guardian.canPickUp === false ? 0 : 1);
      return studentId;
    });
    let invite = {};
    if (createdGuardianAccount) {
      invite = await inviteNewAccount({ userId: createdGuardianAccount, to: guardian.email.trim(), fullName: guardian.fullName.trim(), schoolName: req.school.name, roleLabel: 'a parent or guardian' });
    } else if (addedExistingGuardian) {
      const person = await db.prepare('SELECT full_name, email FROM users WHERE id=?').get(addedExistingGuardian);
      deliverLater(() => sendAddedToSchoolEmail({ to: person.email, fullName: person.full_name, schoolName: req.school.name, roleLabel: 'a parent or guardian' }));
    }
    res.status(201).json({ id: studentId, ...invite });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'Student number or guardian email already exists' : error.message });
  }
}));

app.post('/api/admin/students/:studentId/guardians', requireAuth, requireSchoolAccess('school_admin'), audited('PICKUP_AUTHORIZATION_CHANGED', req => ({ targetType: 'student', targetId: req.params.studentId })), asyncRoute(async (req, res) => {
  const { guardianId, relationship = 'Guardian', canPickUp = true, canManage = true } = req.body;
  try {
    const allowed = await db.prepare(`SELECT 1 FROM students s JOIN guardians gu ON gu.id=? JOIN memberships m ON m.user_id=gu.user_id AND m.school_id=s.school_id AND m.status='ACTIVE' WHERE s.id=? AND s.school_id=?`).get(guardianId, req.params.studentId, req.school.id);
    if (!allowed) return res.status(404).json({ error: 'Student or guardian not found in this school' });
    await db.prepare(`INSERT INTO student_guardians (student_id,guardian_id,relationship,can_pick_up,can_manage) VALUES (?,?,?,?,?) ON CONFLICT(student_id,guardian_id) DO UPDATE SET relationship=excluded.relationship,can_pick_up=excluded.can_pick_up,can_manage=excluded.can_manage`).run(req.params.studentId, guardianId, relationship, canPickUp ? 1 : 0, canManage ? 1 : 0);
    res.status(204).end();
  } catch { res.status(400).json({ error: 'Invalid student or guardian' }); }
}));

// Suspend blocks login (auth.js's login query requires active=1); delete
// removes the user outright and cascades to their guardian row and any
// student_guardians links (both declared ON DELETE CASCADE).
app.patch('/api/admin/students/:id', requireAuth, requireSchoolAccess('school_admin'), audited('STUDENT_STATUS_CHANGED', req => ({ targetType: 'student', targetId: req.params.id, details: { status: req.body.status === 'SUSPENDED' ? 'SUSPENDED' : 'ACTIVE' } })), asyncRoute(async (req, res) => {
  const status = req.body.status === 'SUSPENDED' ? 'SUSPENDED' : 'ACTIVE';
  const result = await db.prepare('UPDATE students SET status=? WHERE id=? AND school_id=?').run(status, req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Student not found' });
  res.status(204).end();
}));

app.delete('/api/admin/students/:id', requireAuth, requireSchoolAccess('school_admin'), audited('STUDENT_REMOVED', req => ({ targetType: 'student', targetId: req.params.id })), asyncRoute(async (req, res) => {
  const result = await db.prepare(`UPDATE students SET status='ARCHIVED', archived_at=${NOW_UTC} WHERE id=? AND school_id=? AND status<>'ARCHIVED'`).run(req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Student not found' });
  res.status(204).end();
}));

app.get('/api/admin/guardians', requireAuth, requireSchoolAccess('school_admin', 'staff'), audited('PARENT_LIST_VIEWED', (req, body) => ({ details: { parentCount: body?.length ?? 0 } })), asyncRoute(async (req, res) => {
  const guardians = await db.prepare(`SELECT DISTINCT gu.id, u.id AS "userId", u.full_name AS "fullName", u.email, u.phone, (u.needs_password_setup=1) AS "needsSetup", m.status FROM guardians gu JOIN users u ON u.id=gu.user_id JOIN memberships m ON m.user_id=u.id WHERE m.school_id=? AND m.role='parent' ORDER BY u.full_name`).all(req.school.id);
  const children = db.prepare(`SELECT s.id, s.first_name || ' ' || s.last_name AS "fullName" FROM student_guardians sg JOIN students s ON s.id=sg.student_id WHERE sg.guardian_id=? AND s.school_id=?`);
  const result = await Promise.all(guardians.map(async g => ({ ...g, active: g.status === 'ACTIVE', children: await children.all(g.id, req.school.id) })));
  res.json(result);
}));

app.post('/api/admin/guardians', requireAuth, requireSchoolAccess('school_admin'), audited('PARENT_CREATED', (req, body) => ({ targetType: 'guardian', targetId: body?.id })), asyncRoute(async (req, res) => {
  const { fullName, email, phone, temporaryPassword } = req.body;
  if (!fullName?.trim() || !email?.trim()) return res.status(400).json({ error: 'Name and email are required' });
  try {
    const { guardianId, created, userId, existingName } = await withTransaction(async () => {
      let user = await db.prepare('SELECT id, full_name FROM users WHERE LOWER(email)=LOWER(?)').get(email.trim());
      let guardianId;
      let created = false;
      if (user) {
        const guardian = await db.prepare('SELECT id FROM guardians WHERE user_id=?').get(user.id);
        if (!guardian) throw new Error('This email belongs to a non-parent account');
        guardianId = guardian.id;
      } else {
        created = true;
        const initial = initialPassword(temporaryPassword);
        user = { id: id('parent') }; guardianId = id('guardian');
        await db.prepare(`INSERT INTO users (id,full_name,email,phone,password_hash,needs_password_setup,role) VALUES (?,?,?,?,?,?,'parent')`).run(user.id, fullName.trim(), email.trim(), phone?.trim() || null, initial.hash, initial.needsSetup);
        await db.prepare('INSERT INTO guardians (id,user_id) VALUES (?,?)').run(guardianId, user.id);
      }
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'parent')`).run(id('membership'), user.id, req.school.id, null);
      return { guardianId, created, userId: user.id, existingName: user.full_name };
    });
    const invite = created
      ? await inviteNewAccount({ userId, to: email.trim(), fullName: fullName.trim(), schoolName: req.school.name, roleLabel: 'a parent or guardian' })
      : (deliverLater(() => sendAddedToSchoolEmail({ to: email.trim(), fullName: existingName, schoolName: req.school.name, roleLabel: 'a parent or guardian' })), {});
    res.status(201).json({ id: guardianId, ...invite });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'Parent already belongs to this school' : error.message });
  }
}));

app.patch('/api/admin/guardians/:id', requireAuth, requireSchoolAccess('school_admin'), audited('PARENT_STATUS_CHANGED', req => ({ targetType: 'guardian', targetId: req.params.id, details: { status: req.body.active ? 'ACTIVE' : 'SUSPENDED' } })), asyncRoute(async (req, res) => {
  const guardian = await db.prepare('SELECT user_id FROM guardians WHERE id=?').get(req.params.id);
  if (!guardian) return res.status(404).json({ error: 'Guardian not found' });
  const result = await db.prepare(`UPDATE memberships SET status=? WHERE user_id=? AND school_id=? AND role='parent'`).run(req.body.active ? 'ACTIVE' : 'SUSPENDED', guardian.user_id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Parent membership not found in this school' });
  res.status(204).end();
}));

app.delete('/api/admin/guardians/:id', requireAuth, requireSchoolAccess('school_admin'), audited('PARENT_REMOVED', req => ({ targetType: 'guardian', targetId: req.params.id, details: { pickupAuthorizationRemoved: true } })), asyncRoute(async (req, res) => {
  const guardian = await db.prepare('SELECT user_id FROM guardians WHERE id=?').get(req.params.id);
  if (!guardian) return res.status(404).json({ error: 'Guardian not found' });
  const result = await db.prepare(`UPDATE memberships SET status='ARCHIVED' WHERE user_id=? AND school_id=? AND role='parent'`).run(guardian.user_id, req.school.id);
  await db.prepare(`DELETE FROM student_guardians WHERE guardian_id=? AND student_id IN (SELECT id FROM students WHERE school_id=?)`).run(req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Parent membership not found in this school' });
  res.status(204).end();
}));

app.get('/api/admin/promotions/preview', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const from = req.query.from; const to = req.query.to;
  const rows = await db.prepare(`${studentSelect} WHERE e.school_year_id=? AND s.school_id=? AND e.status='ENROLLED' ORDER BY s.last_name,s.first_name`).all(from, req.school.id);
  const next = db.prepare('SELECT id,name FROM grade_levels WHERE id=(SELECT next_grade_level_id FROM grade_levels WHERE id=?)');
  const exists = db.prepare('SELECT 1 FROM student_enrollments WHERE student_id=? AND school_year_id=?');
  const result = await Promise.all(rows.map(async row => ({ studentId: row.id, fullName: row.fullName, fromGrade: row.gradeName, proposedGrade: (await next.get(row.gradeLevelId)) || null, alreadyEnrolled: Boolean(await exists.get(row.id, to)) })));
  res.json(result);
}));

app.post('/api/admin/promotions', requireAuth, requireSchoolAccess('school_admin'), audited('PROMOTION_RUN', (req, body) => ({ details: { type: 'whole-school', fromSchoolYearId: req.body.fromSchoolYearId, toSchoolYearId: req.body.toSchoolYearId, promoted: body?.promoted } })), asyncRoute(async (req, res) => {
  const { fromSchoolYearId, toSchoolYearId, overrides = {} } = req.body;
  try {
    const promoted = await withTransaction(async () => {
      const validYears = await db.prepare(`SELECT count(*) AS count FROM school_years WHERE id IN (?,?) AND school_id=?`).get(fromSchoolYearId, toSchoolYearId, req.school.id);
      if (validYears.count !== 2) throw new Error('School years do not belong to this school');
      await db.prepare('INSERT INTO promotion_runs (id,from_school_year_id,to_school_year_id,created_by,school_id) VALUES (?,?,?,?,?)').run(id('promotion'), fromSchoolYearId, toSchoolYearId, req.user.id, req.school.id);
      const enrollments = await db.prepare(`SELECT e.*,g.next_grade_level_id FROM student_enrollments e JOIN grade_levels g ON g.id=e.grade_level_id WHERE e.school_year_id=? AND e.school_id=? AND e.status='ENROLLED'`).all(fromSchoolYearId, req.school.id);
      const insert = db.prepare(`INSERT INTO student_enrollments (id,student_id,school_year_id,grade_level_id,class_id,status,promoted_from_id,school_id,campus_id) VALUES (?,?,?,?,NULL,?,?,?,?)`);
      let promoted = 0;
      for (const enrollment of enrollments) {
        const choice = overrides[enrollment.student_id] || {};
        if (choice.status === 'WITHDRAWN' || choice.status === 'GRADUATED') continue;
        const gradeId = choice.gradeLevelId || enrollment.next_grade_level_id;
        if (!gradeId) continue;
        await insert.run(id('enrollment'), enrollment.student_id, toSchoolYearId, gradeId, choice.status || 'ENROLLED', enrollment.id, req.school.id, enrollment.campus_id); promoted++;
      }
      return promoted;
    });
    res.status(201).json({ promoted });
  } catch (error) { res.status(409).json({ error: 'This promotion has already run, or next-year enrollments already exist.' }); }
}));

// A targeted alternative to the whole-cohort promotion above: move just
// one grade's students into another grade (usually the next one up) for
// the new school year, and — since the bulk promotion above always
// leaves class_id NULL — optionally hand them straight to a teacher's
// classroom in the same step. Can be run once per grade (each student
// still only gets one enrollment per school year, same as any other
// enrollment path), unlike the whole-cohort run above which is a
// one-shot per (fromYear,toYear) pair.
app.post('/api/admin/promotions/by-grade', requireAuth, requireSchoolAccess('school_admin'), audited('PROMOTION_RUN', (req, body) => ({ details: { type: 'by-grade', ...req.body, promoted: body?.promoted, skipped: body?.skipped } })), asyncRoute(async (req, res) => {
  const { fromSchoolYearId, toSchoolYearId, fromGradeLevelId, toGradeLevelId, teacherUserId } = req.body;
  if (!fromSchoolYearId || !toSchoolYearId || !fromGradeLevelId || !toGradeLevelId) {
    return res.status(400).json({ error: 'From/To school year and From/To grade are required' });
  }
  const validYears = await db.prepare(`SELECT count(*) AS count FROM school_years WHERE id IN (?,?) AND school_id=?`).get(fromSchoolYearId, toSchoolYearId, req.school.id);
  if (validYears.count !== 2) return res.status(400).json({ error: 'School years do not belong to this school' });
  let classId = null;
  if (teacherUserId) {
    const teacherClass = await db.prepare(`SELECT id FROM classes WHERE teacher_user_id=? AND school_id=?`).get(teacherUserId, req.school.id);
    if (!teacherClass) return res.status(400).json({ error: 'That teacher is not assigned to a classroom yet' });
    classId = teacherClass.id;
  }
  try {
    const { promoted, skipped } = await withTransaction(async () => {
      const enrollments = await db.prepare(`
        SELECT e.id, e.student_id, e.campus_id FROM student_enrollments e
        JOIN students s ON s.id=e.student_id
        WHERE e.school_year_id=? AND e.school_id=? AND e.grade_level_id=? AND e.status='ENROLLED' AND s.status='ACTIVE'`)
        .all(fromSchoolYearId, req.school.id, fromGradeLevelId);
      const already = db.prepare(`SELECT 1 FROM student_enrollments WHERE student_id=? AND school_year_id=?`);
      const insert = db.prepare(`INSERT INTO student_enrollments (id,student_id,school_year_id,grade_level_id,class_id,status,promoted_from_id,school_id,campus_id) VALUES (?,?,?,?,?,'ENROLLED',?,?,?)`);
      let promoted = 0, skipped = 0;
      for (const enrollment of enrollments) {
        if (await already.get(enrollment.student_id, toSchoolYearId)) { skipped++; continue; }
        await insert.run(id('enrollment'), enrollment.student_id, toSchoolYearId, toGradeLevelId, classId, enrollment.id, req.school.id, enrollment.campus_id);
        promoted++;
      }
      return { promoted, skipped };
    });
    res.json({ promoted, skipped });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
}));

// Class-to-class promotion: pick an actual classroom (by name) to move
// students out of and another actual classroom to land them in — the
// grade and teacher aren't separate inputs, they're just whatever the
// destination class already is, so there's no way to pick a grade that
// doesn't match the teacher you picked.
app.post('/api/admin/promotions/by-class', requireAuth, requireSchoolAccess('school_admin'), audited('PROMOTION_RUN', (req, body) => ({ details: { type: 'by-class', ...req.body, promoted: body?.promoted, skipped: body?.skipped } })), asyncRoute(async (req, res) => {
  const { fromClassId, toClassId, teacherUserId } = req.body;
  if (!fromClassId || !toClassId) return res.status(400).json({ error: 'fromClassId and toClassId are required' });
  const fromClass = await db.prepare('SELECT id, school_year_id AS "schoolYearId" FROM classes WHERE id=? AND school_id=?').get(fromClassId, req.school.id);
  const toClass = await db.prepare('SELECT id, school_year_id AS "schoolYearId", grade_level_id AS "gradeLevelId" FROM classes WHERE id=? AND school_id=?').get(toClassId, req.school.id);
  if (!fromClass || !toClass) return res.status(400).json({ error: 'Invalid class selection' });
  if (teacherUserId) {
    const validTeacher = await db.prepare(`SELECT 1 FROM memberships WHERE user_id=? AND school_id=? AND role='teacher'`).get(teacherUserId, req.school.id);
    if (!validTeacher) return res.status(400).json({ error: 'Invalid teacher selection' });
  }
  try {
    const { promoted, skipped } = await withTransaction(async () => {
      if (teacherUserId) {
        // Same reassignment pattern as PATCH /api/admin/teachers/:id — a
        // teacher owns at most one classroom, so picking a teacher here
        // (e.g. because the destination class has none yet) moves them
        // off whatever class they had onto this one.
        await db.prepare(`UPDATE classes SET teacher_user_id=NULL WHERE teacher_user_id=? AND school_id=?`).run(teacherUserId, req.school.id);
        await db.prepare(`UPDATE classes SET teacher_user_id=? WHERE id=?`).run(teacherUserId, toClassId);
      }
      const enrollments = await db.prepare(`
        SELECT e.id, e.student_id, e.campus_id FROM student_enrollments e
        JOIN students s ON s.id=e.student_id
        WHERE e.class_id=? AND e.school_year_id=? AND e.school_id=? AND e.status='ENROLLED' AND s.status='ACTIVE'`)
        .all(fromClassId, fromClass.schoolYearId, req.school.id);
      const already = db.prepare(`SELECT 1 FROM student_enrollments WHERE student_id=? AND school_year_id=?`);
      const insert = db.prepare(`INSERT INTO student_enrollments (id,student_id,school_year_id,grade_level_id,class_id,status,promoted_from_id,school_id,campus_id) VALUES (?,?,?,?,?,'ENROLLED',?,?,?)`);
      let promoted = 0, skipped = 0;
      for (const enrollment of enrollments) {
        if (await already.get(enrollment.student_id, toClass.schoolYearId)) { skipped++; continue; }
        await insert.run(id('enrollment'), enrollment.student_id, toClass.schoolYearId, toClass.gradeLevelId, toClassId, enrollment.id, req.school.id, enrollment.campus_id);
        promoted++;
      }
      return { promoted, skipped };
    });
    res.json({ promoted, skipped });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
}));

// Flips a PLANNING year to ACTIVE (and closes whatever year was ACTIVE
// before it) — the step that actually makes a finished round of
// promotions visible to parents and teachers, who only ever see data
// tied to the ACTIVE year. Kept as its own explicit action, separate
// from promoting individual classes, so an admin can promote classes
// one grade at a time without the school's current year flipping out
// from under the classes not promoted yet.
app.post('/api/admin/school-years/:id/activate', requireAuth, requireSchoolAccess('school_admin'), audited('SCHOOL_YEAR_ACTIVATED', req => ({ targetType: 'school_year', targetId: req.params.id })), asyncRoute(async (req, res) => {
  const year = await db.prepare('SELECT id, status FROM school_years WHERE id=? AND school_id=?').get(req.params.id, req.school.id);
  if (!year) return res.status(404).json({ error: 'School year not found' });
  if (year.status !== 'PLANNING') return res.status(400).json({ error: 'Only a year that is still in planning can be activated' });
  await withTransaction(async () => {
    await db.prepare(`UPDATE school_years SET status='CLOSED' WHERE school_id=? AND status='ACTIVE'`).run(req.school.id);
    await db.prepare(`UPDATE school_years SET status='ACTIVE' WHERE id=?`).run(req.params.id);
  });
  res.status(204).end();
}));

// Real notices — a teacher can message their whole class or one
// specific parent (real name, from the actual guardians on file), an
// admin can broadcast to the whole school. Replaces the old in-memory
// mock state that never synced across devices or survived a restart —
// the same problem the queue and attendance used to have.
app.get('/api/teacher/parents', requireAuth, requireRole('teacher'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`
    SELECT DISTINCT u.id, u.full_name AS "fullName"
    FROM classes c
    JOIN student_enrollments e ON e.class_id=c.id
    JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
    JOIN students s ON s.id=e.student_id AND s.status='ACTIVE'
    JOIN student_guardians sg ON sg.student_id=s.id
    JOIN guardians gu ON gu.id=sg.guardian_id
    JOIN users u ON u.id=gu.user_id
    WHERE c.teacher_user_id=?
    ORDER BY u.full_name`).all(req.user.id));
}));

// "You have a new message" emails. Recipients mirror who sees the notice
// in the app (/api/me/notices, /api/staff/notices, /api/admin/notices),
// limited to active accounts with an active membership in that school,
// never the sender. The email carries the title only; the message stays
// in the app behind sign-in.
async function noticeRecipients(notice) {
  const parentInSchool = `JOIN memberships pm ON pm.user_id=u.id AND pm.school_id=? AND pm.role='parent' AND pm.status='ACTIVE'`;
  switch (notice.target_type) {
    case 'PARENT':
      return db.prepare(`SELECT u.full_name, u.email FROM users u ${parentInSchool} WHERE u.id=? AND u.active=1`).all(notice.school_id, notice.target_parent_user_id);
    case 'CLASS':
      return db.prepare(`
        SELECT DISTINCT u.full_name, u.email FROM classes c
        JOIN student_enrollments e ON e.class_id=c.id
        JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
        JOIN students s ON s.id=e.student_id AND s.status='ACTIVE'
        JOIN student_guardians sg ON sg.student_id=s.id
        JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id
        ${parentInSchool}
        WHERE c.teacher_user_id=? AND c.school_id=? AND u.active=1`).all(notice.school_id, notice.target_teacher_id, notice.school_id);
    case 'SCHOOL':
      return db.prepare(`
        SELECT DISTINCT u.full_name, u.email FROM students s
        JOIN student_guardians sg ON sg.student_id=s.id
        JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id
        ${parentInSchool}
        WHERE s.school_id=? AND s.status='ACTIVE' AND u.active=1`).all(notice.school_id, notice.school_id);
    case 'STAFF':
      return db.prepare(`
        SELECT DISTINCT u.full_name, u.email FROM memberships m JOIN users u ON u.id=m.user_id
        WHERE m.school_id=? AND m.role IN ('teacher','school_admin','staff') AND m.status='ACTIVE' AND u.active=1
          AND (?::text IS NULL OR u.id=?)`).all(notice.school_id, notice.target_staff_user_id, notice.target_staff_user_id);
    case 'ADMIN':
      return db.prepare(`
        SELECT DISTINCT u.full_name, u.email FROM memberships m JOIN users u ON u.id=m.user_id
        WHERE m.school_id=? AND m.role IN ('school_admin','staff') AND m.status='ACTIVE' AND u.active=1`).all(notice.school_id);
    default:
      return [];
  }
}

function emailNoticeLater(noticeId) {
  deliverLater(async () => {
    const notice = await db.prepare('SELECT n.*, s.name AS school_name, u.email AS sender_email FROM notices n JOIN schools s ON s.id=n.school_id LEFT JOIN users u ON u.id=n.sender_user_id WHERE n.id=?').get(noticeId);
    if (!notice) return;
    const recipients = (await noticeRecipients(notice)).filter(r => r.email.toLowerCase() !== notice.sender_email?.toLowerCase());
    for (const person of recipients) {
      await sendNoticeEmail({ to: person.email, fullName: person.full_name, schoolName: notice.school_name, senderName: notice.sender_name, title: notice.title });
    }
  });
}

app.post('/api/notices', requireAuth, asyncRoute(async (req, res) => {
  const { title, body, targetType, targetParentUserId, targetStaffUserId } = req.body;
  // Exactly one notice is created per request; its recipients get an email once it's saved.
  const noticeId = id('notice');
  res.on('finish', () => { if (res.statusCode === 204) emailNoticeLater(noticeId); });
  if (!title?.trim() || !body?.trim()) return res.status(400).json({ error: 'title and body are required' });

  if (req.user.role === 'teacher') {
    const membership = (await getMemberships(req.user.id)).find(m => m.role === 'teacher');
    if (!membership) return res.status(403).json({ error: 'No active teacher membership' });
    if (targetType === 'PARENT') {
      if (!targetParentUserId) return res.status(400).json({ error: 'targetParentUserId is required' });
      const isMyClassParent = await db.prepare(`
        SELECT 1 FROM classes c
        JOIN student_enrollments e ON e.class_id=c.id
        JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
        JOIN students s ON s.id=e.student_id AND s.status='ACTIVE'
        JOIN student_guardians sg ON sg.student_id=s.id
        JOIN guardians gu ON gu.id=sg.guardian_id
        WHERE c.teacher_user_id=? AND gu.user_id=?`).get(req.user.id, targetParentUserId);
      if (!isMyClassParent) return res.status(403).json({ error: 'That parent is not linked to a student in your class.' });
      await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_parent_user_id) VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(noticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'teacher', title.trim(), body.trim(), 'PARENT', targetParentUserId);
    } else if (targetType === 'ADMIN') {
      await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type) VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(noticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'teacher', title.trim(), body.trim(), 'ADMIN');
    } else {
      await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_teacher_id) VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(noticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'teacher', title.trim(), body.trim(), 'CLASS', req.user.id);
    }
    return res.status(204).end();
  }

  if (req.user.role === 'parent') {
    const membership = (await getMemberships(req.user.id)).find(m => m.role === 'parent');
    if (!membership) return res.status(403).json({ error: 'No active parent membership' });
    if (targetType === 'TEACHER') {
      if (!targetStaffUserId) return res.status(400).json({ error: 'targetStaffUserId is required' });
      const isMyChildsTeacher = await db.prepare(`
        SELECT 1 FROM classes c
        JOIN student_enrollments e ON e.class_id=c.id
        JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
        JOIN students s ON s.id=e.student_id AND s.status='ACTIVE'
        JOIN student_guardians sg ON sg.student_id=s.id
        JOIN guardians gu ON gu.id=sg.guardian_id
        WHERE gu.user_id=? AND c.teacher_user_id=?`).get(req.user.id, targetStaffUserId);
      if (!isMyChildsTeacher) return res.status(403).json({ error: "That teacher doesn't teach one of your children." });
      // Lands in the same STAFF inbox a teacher already checks — no
      // separate parent-to-teacher mailbox needed, and 'staff' here
      // means "this one teacher", never "all staff", since a parent
      // never gets to broadcast.
      await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_staff_user_id) VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(noticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'parent', title.trim(), body.trim(), 'STAFF', targetStaffUserId);
    } else if (targetType === 'ADMIN') {
      await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type) VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(noticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'parent', title.trim(), body.trim(), 'ADMIN');
    } else {
      // Do not silently reinterpret a forged/unknown audience as an admin
      // message. In particular, a parent-supplied PARENT target must never
      // create a parent-to-parent message.
      return res.status(400).json({ error: 'Parents can only message one of their children\'s teachers or the school admin.' });
    }
    return res.status(204).end();
  }

  // Admins/staff send from the school they're working in (X-School-ID —
  // a district admin may cover several), else their first school.
  const requestedSchoolId = req.headers['x-school-id'];
  const adminMemberships = (await getMemberships(req.user.id)).filter(m => [...SCHOOL_ADMIN_ROLES, 'staff'].includes(m.role));
  const membership = adminMemberships.find(m => !requestedSchoolId || m.schoolId === requestedSchoolId);
  if (!membership) return res.status(403).json({ error: 'Only a teacher, admin, or staff member can send notices.' });

  if (targetType === 'PARENT') {
    if (!targetParentUserId) return res.status(400).json({ error: 'targetParentUserId is required' });
    const isSchoolParent = await db.prepare(`
      SELECT 1 FROM guardians gu JOIN memberships m ON m.user_id=gu.user_id
      WHERE gu.user_id=? AND m.school_id=? AND m.role='parent' AND m.status='ACTIVE'`).get(targetParentUserId, membership.schoolId);
    if (!isSchoolParent) return res.status(400).json({ error: 'That parent does not belong to this school' });
    await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_parent_user_id) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(noticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'admin', title.trim(), body.trim(), 'PARENT', targetParentUserId);
  } else if (targetType === 'STAFF') {
    let staffUserId = null;
    if (targetStaffUserId) {
      const isSchoolStaff = await db.prepare(`
        SELECT 1 FROM memberships WHERE user_id=? AND school_id=? AND role IN ('teacher','school_admin','staff') AND status='ACTIVE'`).get(targetStaffUserId, membership.schoolId);
      if (!isSchoolStaff) return res.status(400).json({ error: 'That staff member does not belong to this school' });
      staffUserId = targetStaffUserId;
    }
    await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_staff_user_id) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(noticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'admin', title.trim(), body.trim(), 'STAFF', staffUserId);
  } else {
    await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type) VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(noticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'admin', title.trim(), body.trim(), 'SCHOOL');
  }
  res.status(204).end();
}));

// Staff inbox — every teacher/admin/front-desk membership can see
// notices addressed to "All Staff" (target_staff_user_id IS NULL) or to
// them specifically. Shared by the admin dashboard's Notices tab and
// the teacher app's Notices tab, same as /me/notices is shared by every
// parent screen. Admin-side viewers (school_admin/staff) additionally
// see ADMIN-targeted notices here — messages a parent or teacher sent
// to the school office, plus the existing co-guardian-invite alerts —
// so a teacher's own inbox isn't cluttered with messages meant for the
// office, but the office sees everything addressed to it in one place.
app.get('/api/staff/notices', requireAuth, requireSchoolAccess('school_admin', 'staff', 'teacher'), asyncRoute(async (req, res) => {
  const isAdminSide = ['school_admin', 'staff', 'platform_super_admin'].includes(req.membership.role);
  res.json(await db.prepare(`
    SELECT n.id, n.title, n.body, n.sender_name AS "senderName", n.sender_role AS "senderRole", n.created_at AS "createdAt",
      CASE WHEN nr.user_id IS NULL THEN 0 ELSE 1 END AS read
    FROM notices n
    LEFT JOIN notice_reads nr ON nr.notice_id=n.id AND nr.user_id=?
    WHERE n.school_id=? AND (
      (n.target_type='STAFF' AND (n.target_staff_user_id IS NULL OR n.target_staff_user_id=?))
      OR (n.target_type='ADMIN' AND ?)
    )
    ORDER BY n.created_at DESC`).all(req.user.id, req.school.id, req.user.id, isAdminSide));
}));

app.get('/api/me/notices', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`
    SELECT n.id, n.title, n.body, n.sender_name AS "senderName", n.sender_role AS "senderRole", n.created_at AS "createdAt",
      CASE WHEN nr.user_id IS NULL THEN 0 ELSE 1 END AS read
    FROM notices n
    LEFT JOIN notice_reads nr ON nr.notice_id=n.id AND nr.user_id=?
    WHERE (n.target_type='SCHOOL' AND n.school_id IN (
        SELECT DISTINCT s.school_id FROM students s JOIN student_guardians sg ON sg.student_id=s.id JOIN guardians gu ON gu.id=sg.guardian_id WHERE gu.user_id=?
      ))
      OR (n.target_type='PARENT' AND n.target_parent_user_id=?)
      OR (n.target_type='CLASS' AND n.target_teacher_id IN (
        SELECT DISTINCT c.teacher_user_id FROM classes c
        JOIN student_enrollments e ON e.class_id=c.id
        JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
        JOIN students s ON s.id=e.student_id AND s.status='ACTIVE'
        JOIN student_guardians sg ON sg.student_id=s.id
        JOIN guardians gu ON gu.id=sg.guardian_id
        WHERE gu.user_id=?
      ))
    ORDER BY n.created_at DESC`).all(req.user.id, req.user.id, req.user.id, req.user.id));
}));

// Any signed-in role can mark a notice read — read state is scoped to
// req.user.id regardless of role, so a parent marking their own feed
// and an admin marking theirs both just work here.
app.post('/api/notices/:id/read', requireAuth, asyncRoute(async (req, res) => {
  const notice = await db.prepare('SELECT id FROM notices WHERE id=?').get(req.params.id);
  if (!notice) return res.status(404).json({ error: 'Notice not found' });
  await db.prepare('INSERT INTO notice_reads (notice_id,user_id) VALUES (?,?) ON CONFLICT (notice_id, user_id) DO NOTHING').run(req.params.id, req.user.id);
  res.status(204).end();
}));

// A parent-invited co-guardian shows up here so the admin isn't
// surprised by a new adult with pickup access they never approved —
// nothing blocks the invite (this app has no in-app approval flow
// yet), but it's not silent either.
app.get('/api/admin/notices', requireAuth, requireSchoolAccess('school_admin', 'staff'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`
    SELECT n.id, n.title, n.body, n.sender_name AS "senderName", n.sender_role AS "senderRole", n.created_at AS "createdAt",
      CASE WHEN nr.user_id IS NULL THEN 0 ELSE 1 END AS read
    FROM notices n
    LEFT JOIN notice_reads nr ON nr.notice_id=n.id AND nr.user_id=?
    WHERE n.target_type='ADMIN' AND n.school_id=?
    ORDER BY n.created_at DESC`).all(req.user.id, req.school.id));
}));

// A parent invites a co-guardian (e.g. a grandparent or the other
// parent) onto the SAME account — the new guardian is linked to every
// student the inviting parent already has access to, with the same
// pickup/manage permissions the inviter has for each, so they can drop
// off/pick up and see everything the inviter can. The admin is
// notified (see /api/admin/notices) since this grants real pickup
// access without any admin approval step existing yet.
// A parent asks for another adult (the other parent, a grandparent, a
// sitter) to be authorized for their children. Nothing is granted here:
// this only files a PENDING request per child — for children this parent
// is allowed to manage (can_manage) — and an admin approves or rejects
// it from Families → Pending Approvals. Until then the adult has no
// student_guardians link, so they can't see the children or request a
// drop-off/pickup. An account is created for them now (if they don't
// already have one) so the parent can hand over the sign-in details.
// Approved adults get pickup rights only; the admin decides at approval
// time whether they may also add other adults.
app.post('/api/me/guardians', requireAuth, requireRole('parent'), audited('PICKUP_AUTHORIZATION_REQUESTED'), asyncRoute(async (req, res) => {
  const { fullName, email, phone, relationship, temporaryPassword } = req.body;
  if (!fullName?.trim() || !email?.trim() || !relationship?.trim()) {
    return res.status(400).json({ error: 'Name, email, and relationship are required' });
  }
  let initial;
  try { initial = initialPassword(temporaryPassword); } catch (error) { return res.status(400).json({ error: error.message }); }
  const myGuardian = await db.prepare('SELECT id FROM guardians WHERE user_id=?').get(req.user.id);
  if (!myGuardian) return res.status(403).json({ error: 'No guardian profile found for this account' });
  const membership = (await getMemberships(req.user.id)).find(m => m.role === 'parent');
  if (!membership) return res.status(403).json({ error: 'No active parent membership' });
  const myLinks = await db.prepare(`
    SELECT sg.student_id AS "studentId", s.first_name || ' ' || s.last_name AS "fullName"
    FROM student_guardians sg JOIN students s ON s.id=sg.student_id
    WHERE sg.guardian_id=? AND sg.can_manage=1 AND s.school_id=? AND s.status='ACTIVE'`).all(myGuardian.id, membership.schoolId);
  if (myLinks.length === 0) return res.status(403).json({ error: "You aren't allowed to add adults for any children on this account. Please contact the school." });

  const adminNoticeId = id('notice');
  try {
    const result = await withTransaction(async () => {
      let user = await db.prepare('SELECT id FROM users WHERE LOWER(email)=LOWER(?)').get(email.trim());
      let guardianId;
      let created = false;
      if (user) {
        const guardian = await db.prepare('SELECT id FROM guardians WHERE user_id=?').get(user.id);
        if (!guardian) throw new Error('This email belongs to a non-parent account');
        guardianId = guardian.id;
      } else {
        created = true;
        user = { id: id('parent') }; guardianId = id('guardian');
        await db.prepare(`INSERT INTO users (id,full_name,email,phone,password_hash,needs_password_setup,role) VALUES (?,?,?,?,?,?,'parent')`)
          .run(user.id, fullName.trim(), email.trim(), phone?.trim() || null, initial.hash, initial.needsSetup);
        await db.prepare('INSERT INTO guardians (id,user_id) VALUES (?,?)').run(guardianId, user.id);
      }
      if (guardianId === myGuardian.id) throw new Error("That's your own account.");
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'parent') ON CONFLICT (user_id, school_id, COALESCE(campus_id, ''), role) DO NOTHING`)
        .run(id('membership'), user.id, membership.schoolId, membership.campusId);

      // Children this adult isn't already authorized for — re-asking for
      // a child they're already linked to is a no-op, and a second ask
      // while one is pending supersedes it (the old one is closed as
      // replaced, kept for history).
      const alreadyLinked = db.prepare('SELECT 1 FROM student_guardians WHERE student_id=? AND guardian_id=?');
      const toRequest = [];
      for (const child of myLinks) if (!(await alreadyLinked.get(child.studentId, guardianId))) toRequest.push(child);
      if (toRequest.length === 0) throw new Error(`${fullName.trim()} is already authorized for your children.`);

      const batchId = id('guardianrequest');
      await db.prepare(`UPDATE guardian_requests SET status='REJECTED', decided_by_user_id=?, decided_at=${NOW_UTC}, decision_note='Replaced by a newer request' WHERE guardian_id=? AND status='PENDING' AND student_id = ANY(?)`)
        .run(req.user.id, guardianId, toRequest.map(c => c.studentId));
      const insert = db.prepare(`INSERT INTO guardian_requests (id,batch_id,school_id,student_id,guardian_id,relationship,can_pick_up,can_manage,requested_by_user_id) VALUES (?,?,?,?,?,?,1,0,?)`);
      for (const child of toRequest) await insert.run(id('guardianrequestitem'), batchId, membership.schoolId, child.studentId, guardianId, relationship.trim(), req.user.id);

      const childNames = toRequest.map(c => c.fullName).join(', ');
      await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type) VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(adminNoticeId, membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'parent',
          'Guardian awaiting approval', `${req.user.full_name} asked for ${fullName.trim()} (${relationship.trim()}) to be authorized to pick up ${childNames}. Review it in Families → Pending Approvals.`, 'ADMIN');
      return { guardianId, batchId, toRequest, created, userId: user.id };
    });
    res.locals.audit = {
      schoolId: membership.schoolId, targetType: 'guardian', targetId: result.guardianId,
      details: { batchId: result.batchId, relationship: relationship.trim(), email: email.trim(), students: result.toRequest.map(s => ({ id: s.studentId, name: s.fullName })) },
    };
    const invite = result.created
      ? await inviteNewAccount({
        userId: result.userId, to: email.trim(), fullName: fullName.trim(), schoolName: membership.schoolName,
        roleLabel: `a trusted adult (${relationship.trim()})`, invitedBy: req.user.full_name, pendingApproval: true,
      })
      : {};
    emailNoticeLater(adminNoticeId);
    res.status(201).json({ id: result.guardianId, status: 'PENDING', ...invite });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'That email is already registered' : error.message });
  }
}));

// The adults on this parent's children — already authorized ones, and
// every request filed for them (pending, approved or rejected), so the
// parent can see where their request stands.
app.get('/api/me/guardians', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  const authorized = await db.prepare(`
    SELECT gu.id AS "guardianId", u.full_name AS "fullName", sg.relationship, sg.can_pick_up AS "canPickUp",
      s.id AS "studentId", s.first_name || ' ' || s.last_name AS "studentName"
    FROM student_guardians mine
    JOIN guardians me ON me.id=mine.guardian_id AND me.user_id=?
    JOIN students s ON s.id=mine.student_id AND s.status='ACTIVE'
    JOIN memberships pm ON pm.user_id=me.user_id AND pm.school_id=s.school_id AND pm.role='parent' AND pm.status='ACTIVE'
    JOIN student_guardians sg ON sg.student_id=s.id AND sg.guardian_id<>me.id
    JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id
    ORDER BY u.full_name, s.first_name`).all(req.user.id);
  const requests = await db.prepare(`
    SELECT gr.batch_id AS "batchId", u.full_name AS "fullName", gr.relationship, gr.status, gr.requested_at AS "requestedAt",
      gr.decided_at AS "decidedAt", gr.decision_note AS "decisionNote", s.first_name || ' ' || s.last_name AS "studentName"
    FROM guardian_requests gr
    JOIN guardians gu ON gu.id=gr.guardian_id JOIN users u ON u.id=gu.user_id
    JOIN students s ON s.id=gr.student_id
    WHERE gr.student_id IN (
      SELECT sg.student_id FROM student_guardians sg JOIN guardians me ON me.id=sg.guardian_id WHERE me.user_id=?)
    ORDER BY gr.requested_at DESC`).all(req.user.id);
  res.json({ authorized: groupAdults(authorized, 'guardianId'), requests: groupAdults(requests, 'batchId') });
}));

// Folds one-row-per-child into one entry per adult (or per request
// batch) with the list of children it covers.
function groupAdults(rows, key) {
  const byKey = new Map();
  for (const { studentId, studentName, ...row } of rows) {
    if (!byKey.has(row[key])) byKey.set(row[key], { ...row, students: [] });
    byKey.get(row[key]).students.push(studentName);
  }
  return [...byKey.values()];
}

// Admin side of the approval flow: the school's guardian requests,
// pending first, one entry per batch.
app.get('/api/admin/guardian-requests', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const rows = await db.prepare(`
    SELECT gr.batch_id AS "batchId", gr.status, gr.relationship, gr.requested_at AS "requestedAt",
      gr.decided_at AS "decidedAt", gr.decision_note AS "decisionNote",
      u.full_name AS "fullName", u.email, u.phone, ru.full_name AS "requestedByName", du.full_name AS "decidedByName",
      s.first_name || ' ' || s.last_name AS "studentName"
    FROM guardian_requests gr
    JOIN guardians gu ON gu.id=gr.guardian_id JOIN users u ON u.id=gu.user_id
    JOIN users ru ON ru.id=gr.requested_by_user_id
    LEFT JOIN users du ON du.id=gr.decided_by_user_id
    JOIN students s ON s.id=gr.student_id
    WHERE gr.school_id=?
    ORDER BY CASE gr.status WHEN 'PENDING' THEN 0 ELSE 1 END, gr.requested_at DESC
    LIMIT 500`).all(req.school.id);
  res.json(groupAdults(rows, 'batchId'));
}));

// Approve or reject a whole pending batch. Approving creates the real
// student_guardians links (pickup rights; `canManage` lets the adult add
// other adults too) — re-checked here that each child is still an
// ACTIVE student of this school. Either way the requesting parent gets
// a message with the outcome.
async function decideGuardianRequest(req, res, approve) {
  const pending = await db.prepare(`
    SELECT gr.*, u.full_name AS "guardianName" FROM guardian_requests gr
    JOIN guardians gu ON gu.id=gr.guardian_id JOIN users u ON u.id=gu.user_id
    JOIN students s ON s.id=gr.student_id AND s.school_id=gr.school_id AND s.status='ACTIVE'
    WHERE gr.batch_id=? AND gr.school_id=? AND gr.status='PENDING'`).all(req.params.batchId, req.school.id);
  if (pending.length === 0) return res.status(404).json({ error: 'Request not found or already decided.' });
  const canManage = approve && req.body.canManage ? 1 : 0;
  const note = typeof req.body.note === 'string' && req.body.note.trim() ? req.body.note.trim().slice(0, 500) : null;
  const first = pending[0];
  await withTransaction(async () => {
    for (const item of pending) {
      if (approve) {
        await db.prepare(`
          INSERT INTO student_guardians (student_id,guardian_id,relationship,can_pick_up,can_manage) VALUES (?,?,?,?,?)
          ON CONFLICT(student_id,guardian_id) DO UPDATE SET relationship=excluded.relationship, can_pick_up=excluded.can_pick_up, can_manage=excluded.can_manage`)
          .run(item.student_id, item.guardian_id, item.relationship, item.can_pick_up, canManage);
      }
      await db.prepare(`UPDATE guardian_requests SET status=?, can_manage=?, decided_by_user_id=?, decided_at=${NOW_UTC}, decision_note=? WHERE id=?`)
        .run(approve ? 'APPROVED' : 'REJECTED', canManage, req.user.id, note, item.id);
    }
    const outcome = approve
      ? `${first.guardianName} has been approved and can now drop off and pick up.`
      : `The school did not approve ${first.guardianName}.${note ? ` Note: ${note}` : ''}`;
    await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_parent_user_id) VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(id('notice'), req.school.id, null, req.user.id, req.user.full_name, 'admin',
        approve ? 'Guardian approved' : 'Guardian not approved', outcome, 'PARENT', first.requested_by_user_id);
  });
  res.locals.audit = {
    targetType: 'guardian', targetId: first.guardian_id,
    details: { batchId: req.params.batchId, studentIds: pending.map(item => item.student_id), canManage: Boolean(canManage), note },
  };
  res.status(204).end();

  // Emails after responding: the parent who asked hears the outcome, and
  // an approved adult hears they're good to go (with a set-up link if
  // they never chose a password).
  deliverLater(async () => {
    const people = db.prepare('SELECT u.id, u.full_name, u.email, u.needs_password_setup AS "needsSetup" FROM users u WHERE u.id=? AND u.active=1');
    const requester = await people.get(first.requested_by_user_id);
    if (requester) {
      await sendGuardianDecisionEmail({ to: requester.email, fullName: requester.full_name, schoolName: req.school.name, adultName: first.guardianName, approved: approve, note });
    }
    if (!approve) return;
    const adultUser = await db.prepare('SELECT user_id FROM guardians WHERE id=?').get(first.guardian_id);
    const adult = adultUser && await people.get(adultUser.user_id);
    if (!adult) return;
    const link = adult.needsSetup ? await createAccountLink(adult.id, 'INVITE') : null;
    await sendGuardianApprovedEmail({ to: adult.email, fullName: adult.full_name, schoolName: req.school.name, link });
  });
}

app.post('/api/admin/guardian-requests/:batchId/approve', requireAuth, requireSchoolAccess('school_admin'), audited('PICKUP_AUTHORIZATION_APPROVED'), asyncRoute(async (req, res) => {
  await decideGuardianRequest(req, res, true);
}));

app.post('/api/admin/guardian-requests/:batchId/reject', requireAuth, requireSchoolAccess('school_admin'), audited('PICKUP_AUTHORIZATION_REJECTED'), asyncRoute(async (req, res) => {
  await decideGuardianRequest(req, res, false);
}));

// ---- District (see district_memberships, tenant.js) ----------------------

// A district admin's at-a-glance view of every school in their district.
// They act inside one school at a time by picking it in the website's
// school switcher (sent as X-School-ID).
app.get('/api/district/overview', requireAuth, asyncRoute(async (req, res) => {
  const schools = (await getMemberships(req.user.id)).filter(m => m.role === 'district_admin');
  if (schools.length === 0) return res.status(403).json({ error: 'District administrator access required' });
  const count = (sql, schoolId) => db.prepare(sql).get(schoolId).then(row => row.c);
  const rows = await Promise.all(schools.map(async m => ({
    schoolId: m.schoolId, schoolName: m.schoolName, schoolCode: m.schoolCode, districtName: m.districtName,
    students: await count(`SELECT COUNT(*) AS c FROM students WHERE school_id=? AND status='ACTIVE'`, m.schoolId),
    teachers: await count(`SELECT COUNT(*) AS c FROM memberships WHERE school_id=? AND role='teacher' AND status='ACTIVE'`, m.schoolId),
    presentToday: await count(`SELECT COUNT(*) AS c FROM students WHERE school_id=? AND status='ACTIVE' AND pickup_status='PRESENT'`, m.schoolId),
    pendingRequests: await count(`SELECT COUNT(*) AS c FROM queue_items WHERE school_id=? AND status='PENDING'`, m.schoolId),
    pendingGuardianApprovals: await count(`SELECT COUNT(DISTINCT batch_id) AS c FROM guardian_requests WHERE school_id=? AND status='PENDING'`, m.schoolId),
  })));
  res.json(rows);
}));

// ---- Data export, deletion and retention (see dataRights.js) -------------
// School admins only. Every export and erasure is audited.

const sendJsonDownload = (res, filename, data) => {
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.json(data);
};
const fileSafe = text => String(text).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'export';

app.get('/api/admin/students/:id/export', requireAuth, requireSchoolAccess('school_admin'), audited('STUDENT_RECORD_EXPORTED', req => ({ targetType: 'student', targetId: req.params.id, details: null })), asyncRoute(async (req, res) => {
  const data = await buildStudentExport(req.params.id, req.school.id);
  if (!data) return res.status(404).json({ error: 'Student not found' });
  sendJsonDownload(res, `student-${fileSafe(`${data.student.firstName}-${data.student.lastName}`)}-${new Date().toISOString().slice(0, 10)}.json`, data);
}));

app.get('/api/admin/export', requireAuth, requireSchoolAccess('school_admin'), audited('SCHOOL_DATA_EXPORTED', () => ({ details: null })), asyncRoute(async (req, res) => {
  const data = await buildSchoolExport(req.school.id);
  sendJsonDownload(res, `school-${fileSafe(data.school?.name)}-${new Date().toISOString().slice(0, 10)}.json`, data);
}));

// Removed students: still on file until restored, erased by hand, or
// erased by the retention setting (purgeAfter says when).
app.get('/api/admin/students/removed', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { removedStudentRetentionDays: days } = await retentionSettings(req.school.id);
  const rows = await db.prepare(`
    SELECT id, first_name || ' ' || last_name AS "fullName", student_number AS "studentNumber", archived_at AS "removedAt",
      CASE WHEN ?::int IS NULL THEN NULL ELSE to_char((archived_at::timestamp + make_interval(days => ?::int)), 'YYYY-MM-DD HH24:MI:SS') END AS "purgeAfter"
    FROM students WHERE school_id=? AND status='ARCHIVED' ORDER BY archived_at DESC`).all(days, days, req.school.id);
  res.json(rows);
}));

app.post('/api/admin/students/:id/restore', requireAuth, requireSchoolAccess('school_admin'), audited('STUDENT_RESTORED', req => ({ targetType: 'student', targetId: req.params.id, details: null })), asyncRoute(async (req, res) => {
  const result = await db.prepare(`UPDATE students SET status='ACTIVE', archived_at=NULL WHERE id=? AND school_id=? AND status='ARCHIVED'`).run(req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Removed student not found' });
  res.status(204).end();
}));

// Erase a removed student now. The admin must type the student's full
// name to confirm — this cannot be undone.
app.delete('/api/admin/students/:id/permanent', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const student = await db.prepare(`SELECT first_name AS "firstName", last_name AS "lastName", student_number AS "studentNumber" FROM students WHERE id=? AND school_id=? AND status='ARCHIVED'`).get(req.params.id, req.school.id);
  if (!student) return res.status(404).json({ error: 'Only a removed student can be permanently deleted. Remove them from Students first.' });
  const typed = String(req.body?.confirmName ?? '').trim().replace(/\s+/g, ' ').toLowerCase();
  if (typed !== `${student.firstName} ${student.lastName}`.toLowerCase()) return res.status(400).json({ error: "Type the student's full name exactly to confirm." });
  const counts = await permanentlyDeleteStudent(req.params.id, req.school.id);
  if (!counts) return res.status(404).json({ error: 'Removed student not found' });
  await writeAudit({
    schoolId: req.school.id, actor: req.user, actorRole: req.membership?.role, action: 'STUDENT_PERMANENTLY_DELETED',
    targetType: 'student', targetId: req.params.id, targetLabel: deletedStudentLabel(student),
    details: { reason: typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 500) || null : null, ...counts }, ip: req.ip,
  });
  res.json({ deleted: counts });
}));

app.get('/api/admin/retention', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { removedStudentRetentionDays, queueHistoryRetentionDays } = await retentionSettings(req.school.id);
  res.json({ removedStudentRetentionDays, queueHistoryRetentionDays, minimumDays: MIN_RETENTION_DAYS, wouldDeleteNow: await previewRetention(req.school.id) });
}));

app.patch('/api/admin/retention', requireAuth, requireSchoolAccess('school_admin'), audited('RETENTION_SETTINGS_CHANGED'), asyncRoute(async (req, res) => {
  const parse = value => (value === null || value === '' || value === undefined ? null : Number(value));
  const removed = parse(req.body.removedStudentRetentionDays);
  const queue = parse(req.body.queueHistoryRetentionDays);
  for (const value of [removed, queue]) {
    if (value !== null && (!Number.isInteger(value) || value < MIN_RETENTION_DAYS || value > 36500)) {
      return res.status(400).json({ error: `Retention must be a whole number of days, at least ${MIN_RETENTION_DAYS}, or empty to keep records.` });
    }
  }
  await db.prepare('UPDATE schools SET removed_student_retention_days=?, queue_history_retention_days=? WHERE id=?').run(removed, queue, req.school.id);
  res.status(204).end();
}));

app.post('/api/admin/retention/run', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  res.json(await applyRetention(req.school.id, { actor: req.user, ip: req.ip }));
}));

// The school's audit trail, newest first, for school admins only (front
// desk staff can't see it). Keyset-paged by `before` (an entry's
// createdAt + id) so new entries arriving mid-browse don't shift pages.
// Optional filters: action, targetType + targetId (one student's or one
// person's history).
app.get('/api/admin/audit-log', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
  const where = ['school_id=?']; const params = [req.school.id];
  if (req.query.action) { where.push('action=?'); params.push(String(req.query.action)); }
  if (req.query.targetType && req.query.targetId) { where.push('target_type=? AND target_id=?'); params.push(String(req.query.targetType), String(req.query.targetId)); }
  if (req.query.beforeCreatedAt && req.query.beforeId) {
    where.push('(created_at, id) < (?, ?)'); params.push(String(req.query.beforeCreatedAt), String(req.query.beforeId));
  }
  const rows = await db.prepare(`
    SELECT id, created_at AS "createdAt", actor_user_id AS "actorUserId", actor_name AS "actorName", actor_role AS "actorRole",
      action, target_type AS "targetType", target_id AS "targetId", target_label AS "targetLabel", details, ip_address AS "ipAddress"
    FROM audit_logs WHERE ${where.join(' AND ')}
    ORDER BY created_at DESC, id DESC LIMIT ?`).all(...params, limit + 1);
  const entries = rows.slice(0, limit).map(row => ({ ...row, details: row.details ? JSON.parse(row.details) : null }));
  const actions = (await db.prepare('SELECT DISTINCT action FROM audit_logs WHERE school_id=? ORDER BY action').all(req.school.id)).map(r => r.action);
  res.json({ entries, hasMore: rows.length > limit, actions });
}));

// Serve the built React website (run `npm run build` in frontend/
// first) so the same server hosts the site alongside the API.
app.use(express.static(frontendDist));

// SPA fallback: let the client-side router (react-router) handle any
// non-API route that isn't a static file.
app.get(/^(?!\/api\/).*/, (req, res, next) => {
  res.sendFile(path.join(frontendDist, 'index.html'), err => {
    if (err) next();
  });
});

// Last, after every route: catches whatever an asyncRoute-wrapped
// handler/middleware rejected with, so a thrown/rejected error returns
// a clean 500 instead of hanging the request (Express 4 doesn't catch
// async rejections on its own).
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Internal server error' });
});

export { app };

if (process.env.NODE_ENV !== 'test') {
  app.listen(port, () => {
    console.log(`Server listening on ${port}`);
    verifyEmailConnection()
      .then(() => console.log(`SMTP connection verified (${process.env.SMTP_HOST}:${process.env.SMTP_PORT}).`))
      .catch(error => console.error(`SMTP connection failed: ${error?.message || error}`));
  });
  // Retention: once shortly after startup, then daily.
  const DAY_MS = 24 * 60 * 60 * 1000;
  setTimeout(() => applyRetentionEverywhere(), 60 * 1000).unref();
  setInterval(() => applyRetentionEverywhere(), DAY_MS).unref();
}
