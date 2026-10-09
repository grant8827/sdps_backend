import nodemailer from 'nodemailer';
import { randomUUID } from 'node:crypto';
import { pool } from './db.js';

const requiredSettings = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM'];

export function emailConfigured() {
  return requiredSettings.every(name => Boolean(process.env[name]?.trim()));
}

let transporter;

function getTransporter() {
  if (!emailConfigured()) return null;
  if (!transporter) {
    const port = Number(process.env.SMTP_PORT);
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465,
      requireTLS: port !== 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },
    });
  }
  return transporter;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

export async function sendEmail({ to, subject, text, html }) {
  const smtp = getTransporter();
  if (!smtp) {
    console.warn(`Email not sent: missing SMTP settings (${requiredSettings.filter(name => !process.env[name]?.trim()).join(', ')}).`);
    return { sent: false, reason: 'not-configured' };
  }
  const info = await smtp.sendMail({
    from: process.env.SMTP_FROM,
    replyTo: process.env.SMTP_REPLY_TO || undefined,
    to,
    subject,
    text,
    html,
  });
  return { sent: true, messageId: info.messageId };
}

// ---- Branded messages -------------------------------------------------------
//
// Every email shares one simple layout: navy header, a heading, a few
// short paragraphs, at most one blue button (with the link also written
// out for mail clients that hide buttons), and a footer saying who sent
// it. Inline styles only — most mail clients ignore <style> blocks.
// Emails never contain a password or a student's details;
// links lead into the app, which checks who's signed in.

const BRAND = { navy: '#123B6D', blue: '#1976D2', slate: '#374151', bg: '#F4F8FC', muted: '#6B7280' };

function layout({ preheader = '', heading, paragraphs = [], button, footnote, schoolName }) {
  const html = `<!doctype html><html><body style="margin:0;padding:0;background:${BRAND.bg};">
<span style="display:none;max-height:0;overflow:hidden;opacity:0;">${escapeHtml(preheader)}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${BRAND.bg};padding:24px 12px;"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:12px;overflow:hidden;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:${BRAND.slate};">
<tr><td style="background:${BRAND.navy};padding:18px 28px;color:#ffffff;font-size:20px;font-weight:700;letter-spacing:.2px;">SDPM<span style="color:#72C936;">Plus</span></td></tr>
<tr><td style="padding:28px;">
<h1 style="margin:0 0 16px;font-size:22px;line-height:1.3;color:${BRAND.navy};">${escapeHtml(heading)}</h1>
${paragraphs.map(p => `<p style="margin:0 0 14px;font-size:16px;line-height:1.55;">${escapeHtml(p)}</p>`).join('\n')}
${button ? `<p style="margin:24px 0;"><a href="${escapeHtml(button.url)}" style="display:inline-block;background:${BRAND.blue};color:#ffffff;text-decoration:none;font-weight:600;font-size:16px;padding:12px 22px;border-radius:8px;">${escapeHtml(button.label)}</a></p>
<p style="margin:0 0 14px;font-size:13px;line-height:1.5;color:${BRAND.muted};">Or copy this link into your browser:<br><a href="${escapeHtml(button.url)}" style="color:${BRAND.blue};word-break:break-all;">${escapeHtml(button.url)}</a></p>` : ''}
${footnote ? `<p style="margin:18px 0 0;font-size:13px;line-height:1.5;color:${BRAND.muted};">${escapeHtml(footnote)}</p>` : ''}
</td></tr>
<tr><td style="padding:16px 28px;border-top:1px solid #E5E7EB;font-size:12px;line-height:1.5;color:${BRAND.muted};">
Sent by SDPMPlus${schoolName ? ` on behalf of ${escapeHtml(schoolName)}` : ''} · School drop-off, pick-up and attendance.<br>SDPMPlus is a service of GGHighTech LLC.
</td></tr></table></td></tr></table></body></html>`;
  const text = [
    heading, '', ...paragraphs.flatMap(p => [p, '']),
    ...(button ? [`${button.label}: ${button.url}`, ''] : []),
    ...(footnote ? [footnote, ''] : []),
    `Sent by SDPMPlus${schoolName ? ` on behalf of ${schoolName}` : ''}. SDPMPlus is a service of GGHighTech LLC.`,
  ].join('\n');
  return { html, text };
}

// Sending must never break the action that triggered it (creating an
// account, approving a guardian...): a failure is logged — without the
// link — and reported as { sent: false } so the caller can fall back.
//
// Every attempt is written to notification_deliveries (template + the
// details needed to send it again, never a sign-in link) so the platform
// can see failures and retry them (notifications.js).
async function deliver(to, subject, message, log) {
  const deliveryId = await recordDelivery(to, subject, log);
  try {
    const result = await sendEmail({ to, subject, ...layout(message) });
    await finishDelivery(deliveryId, result.sent ? 'SENT' : 'SKIPPED', result.sent ? null : 'Email sending is not set up');
    return { ...result, deliveryId };
  } catch (error) {
    console.error(`Could not send "${subject}" email:`, error?.message || error);
    await finishDelivery(deliveryId, 'FAILED', String(error?.message || error).slice(0, 300));
    return { sent: false, reason: 'delivery-failed', deliveryId };
  }
}

async function recordDelivery(to, subject, log) {
  if (!log) return null;
  try {
    const deliveryId = `delivery-${randomUUID()}`;
    await pool.query(
      `INSERT INTO notification_deliveries (id,template,recipient,subject,school_name,args,status,retry_of) VALUES ($1,$2,$3,$4,$5,$6,'SENDING',$7)`,
      [deliveryId, log.template, to, subject, log.args?.schoolName ?? null, JSON.stringify(log.args ?? {}), log.retryOf ?? null],
    );
    return deliveryId;
  } catch (error) {
    console.error('Could not record email delivery:', error?.message || error);
    return null;
  }
}
async function finishDelivery(deliveryId, status, error) {
  if (!deliveryId) return;
  try { await pool.query('UPDATE notification_deliveries SET status=$1, error=$2 WHERE id=$3', [status, error, deliveryId]); } catch { /* logged on insert */ }
}

/** Fire-and-forget for emails nobody waits on (message notifications). */
export function deliverLater(send) {
  Promise.resolve().then(send).catch(error => console.error('Background email failed:', error?.message || error));
}

/** A new account: choose a password through the link (valid 7 days). */
export function sendInviteEmail({ to, fullName, schoolName, roleLabel, link, invitedBy, pendingApproval, retryOf }) {
  const log = { template: 'invite', retryOf, args: { fullName, schoolName, roleLabel, invitedBy, pendingApproval } };
  return deliver(to, `You're invited to ${schoolName} on SDPMPlus`, {
    schoolName,
    preheader: 'Set up your account to get started.',
    heading: `Welcome to ${schoolName}`,
    paragraphs: [
      `Hello ${fullName},`,
      invitedBy
        ? `${invitedBy} asked ${schoolName} to add you as ${roleLabel} on SDPMPlus, the school's drop-off and pick-up app.`
        : `${schoolName} has created an SDPMPlus account for you as ${roleLabel}. SDPMPlus is the school's drop-off, pick-up and attendance app.`,
      ...(pendingApproval ? ['You can set up your account now. The school still has to approve the request before you can drop off or pick up; we will email you when it does.'] : []),
      `Choose your password with the button below, then sign in on the web or in the SDPMPlus app with ${to}.`,
    ],
    button: { label: 'Set up my account', url: link },
    footnote: "This link works once and expires in 7 days. If it has expired, ask the school to send a new one. If you weren't expecting this email, you can ignore it.",
  }, log);
}

/** An existing account was added to another school (no new password needed). */
export function sendAddedToSchoolEmail({ to, fullName, schoolName, roleLabel, retryOf }) {
  const log = { template: 'addedToSchool', retryOf, args: { fullName, schoolName, roleLabel } };
  return deliver(to, `You've been added to ${schoolName} on SDPMPlus`, {
    schoolName,
    heading: `You've been added to ${schoolName}`,
    paragraphs: [`Hello ${fullName},`, `${schoolName} added you as ${roleLabel}. Sign in with your existing SDPMPlus email and password to see it.`],
    button: { label: 'Sign in', url: `${appBaseUrl()}/login` },
  }, log);
}

/** "Forgot password?" or an admin-sent link (valid 1 hour). */
export function sendPasswordResetEmail({ to, fullName, link, requestedByAdmin, expiresIn = '1 hour', retryOf }) {
  const log = { template: 'passwordReset', retryOf, args: { fullName, requestedByAdmin, expiresIn } };
  return deliver(to, 'Reset your SDPMPlus password', {
    preheader: `Choose a new password. This link expires in ${expiresIn}.`,
    heading: 'Reset your password',
    paragraphs: [
      `Hello ${fullName},`,
      requestedByAdmin
        ? `${requestedByAdmin} sent you a link to choose a new SDPMPlus password.`
        : 'Someone (hopefully you) asked to reset the password for your SDPMPlus account.',
      'Choose a new password with the button below. Signing in still needs your two-step verification code if you have it turned on.',
    ],
    button: { label: 'Choose a new password', url: link },
    footnote: `This link works once and expires in ${expiresIn}. If you didn't ask for it, ignore this email; your password stays the same.`,
  }, log);
}

/** Security notice after any password change. */
export function sendPasswordChangedEmail({ to, fullName, retryOf }) {
  const log = { template: 'passwordChanged', retryOf, args: { fullName } };
  return deliver(to, 'Your SDPMPlus password was changed', {
    heading: 'Your password was changed',
    paragraphs: [
      `Hello ${fullName},`,
      'The password for your SDPMPlus account was just changed.',
      "If this was you, there's nothing else to do.",
      "If it wasn't, reset your password right away and tell your school office.",
    ],
    button: { label: 'Reset my password', url: `${appBaseUrl()}/forgot-password` },
  }, log);
}

/** "Forgot PIN?" — a link to choose a new pickup PIN (valid 1 hour). The link is never logged. */
export function sendPinResetEmail({ to, fullName, link, retryOf }) {
  const log = { template: 'pinReset', retryOf, args: { fullName } };
  return deliver(to, 'Reset your SDPMPlus pickup PIN', {
    preheader: 'Choose a new pickup PIN. This link expires in 1 hour.',
    heading: 'Reset your pickup PIN',
    paragraphs: [
      `Hello ${fullName},`,
      'Someone (hopefully you) asked to reset the 6-digit PIN you enter to request a pickup.',
      'Choose a new PIN with the button below. Your password stays the same.',
    ],
    button: { label: 'Choose a new PIN', url: link },
    footnote: "This link works once and expires in 1 hour. If you didn't ask for it, ignore this email; your PIN stays the same.",
  }, log);
}

/** Security notice after the pickup PIN is created, changed or reset. */
export function sendPinChangedEmail({ to, fullName, retryOf }) {
  const log = { template: 'pinChanged', retryOf, args: { fullName } };
  return deliver(to, 'Your SDPMPlus pickup PIN was changed', {
    heading: 'Your pickup PIN was changed',
    paragraphs: [
      `Hello ${fullName},`,
      'The PIN you enter to request a pickup was just set or changed.',
      "If this was you, there's nothing else to do.",
      "If it wasn't, change your password right away and tell your school office.",
    ],
    button: { label: 'Reset my password', url: `${appBaseUrl()}/forgot-password` },
  }, log);
}

/** Security notice when an administrator cleared someone's two-step verification. */
export function sendMfaResetEmail({ to, fullName, schoolName, resetBy, retryOf }) {
  const log = { template: 'mfaReset', retryOf, args: { fullName, schoolName, resetBy } };
  return deliver(to, 'Your two-step verification was reset', {
    schoolName,
    heading: 'Two-step verification was reset',
    paragraphs: [
      `Hello ${fullName},`,
      `${resetBy} at ${schoolName} turned off two-step verification on your account and signed you out everywhere. You'll set it up again the next time you sign in.`,
      "If you didn't ask for this, contact your school office right away.",
    ],
    button: { label: 'Sign in', url: `${appBaseUrl()}/login` },
  }, log);
}

/** Sent to the person who registered a new school. */
export function sendSchoolWelcomeEmail({ to, fullName, schoolName, schoolCode, retryOf }) {
  const log = { template: 'schoolWelcome', retryOf, args: { fullName, schoolName, schoolCode } };
  return deliver(to, `${schoolName} is set up on SDPMPlus`, {
    schoolName,
    heading: `${schoolName} is ready`,
    paragraphs: [
      `Hello ${fullName},`,
      `Your school is registered on SDPMPlus${schoolCode ? ` (school code ${schoolCode})` : ''}, and you're its first administrator.`,
      'Next steps: add your locations and classrooms in School Setup, invite your staff in Faculty, then add students and their families. Each person gets an email to set up their own account.',
      'Administrator accounts use two-step verification. Keep your recovery codes somewhere safe.',
    ],
    button: { label: 'Open the dashboard', url: `${appBaseUrl()}/login` },
  }, log);
}

/** To the parent who asked for another adult to be authorized. */
export function sendGuardianDecisionEmail({ to, fullName, schoolName, adultName, approved, note, retryOf }) {
  const log = { template: 'guardianDecision', retryOf, args: { fullName, schoolName, adultName, approved, note } };
  return deliver(to, approved ? `${adultName} was approved for pickup` : `${adultName} was not approved`, {
    schoolName,
    heading: approved ? `${adultName} was approved` : `${adultName} was not approved`,
    paragraphs: [
      `Hello ${fullName},`,
      approved
        ? `${schoolName} approved ${adultName}. They can now drop off and pick up your children using their own SDPMPlus account.`
        : `${schoolName} did not approve your request for ${adultName}.`,
      ...(note ? [`Note from the school: ${note}`] : []),
    ],
    button: { label: 'Open SDPMPlus', url: `${appBaseUrl()}/login` },
  }, log);
}

/** To the adult who was just approved. */
export function sendGuardianApprovedEmail({ to, fullName, schoolName, link, retryOf }) {
  const log = { template: 'guardianApproved', retryOf, args: { fullName, schoolName, hadLink: Boolean(link) } };
  return deliver(to, `You're approved at ${schoolName}`, {
    schoolName,
    heading: "You're approved for drop-off and pick-up",
    paragraphs: [
      `Hello ${fullName},`,
      `${schoolName} approved you. You can now request drop-off and pick-up in the SDPMPlus app when you're at the school.`,
      ...(link ? ["You haven't set up your account yet. Use the button below to choose a password."] : []),
    ],
    button: link ? { label: 'Set up my account', url: link } : { label: 'Sign in', url: `${appBaseUrl()}/login` },
    ...(link ? { footnote: 'This link works once and expires in 7 days.' } : {}),
  }, log);
}

/** "You have a new message" — the message itself stays in the app. */
export function sendNoticeEmail({ to, fullName, schoolName, senderName, title, retryOf }) {
  const log = { template: 'notice', retryOf, args: { fullName, schoolName, senderName, title } };
  return deliver(to, `New message from ${schoolName}: ${title}`, {
    schoolName,
    preheader: `${senderName} sent you a message.`,
    heading: 'You have a new message',
    paragraphs: [`Hello ${fullName},`, `${senderName} sent a message: "${title}".`, 'Open SDPMPlus to read it.'],
    button: { label: 'Read the message', url: `${appBaseUrl()}/login` },
  }, log);
}

export function appBaseUrl() {
  return (process.env.PUBLIC_APP_URL || process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
}

export async function verifyEmailConnection() {
  const smtp = getTransporter();
  if (!smtp) throw new Error(`Missing email settings: ${requiredSettings.filter(name => !process.env[name]?.trim()).join(', ')}`);
  await smtp.verify();
}
