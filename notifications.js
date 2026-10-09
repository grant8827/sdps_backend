import { createAccountLink, ADMIN_RESET_TTL_MS } from './accountLinks.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { db, id, pool, withTransaction } from './db.js';
import {
  deliverLater, emailConfigured, sendAddedToSchoolEmail, sendGuardianApprovedEmail, sendGuardianDecisionEmail, sendInviteEmail,
  sendMfaResetEmail, sendNoticeEmail, sendPasswordChangedEmail, sendPasswordResetEmail, sendPinChangedEmail, sendPinResetEmail,
  sendSchoolWelcomeEmail,
} from './mailer.js';
import { requirePlatformPermission } from './permissions.js';

// Notifications: the "new message" emails for notices, the platform's
// email delivery log (with retry), and announcements from SDPMPlus to
// schools.

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

export function emailNoticeLater(noticeId) {
  deliverLater(async () => {
    const notice = await db.prepare('SELECT n.*, s.name AS school_name, u.email AS sender_email FROM notices n JOIN schools s ON s.id=n.school_id LEFT JOIN users u ON u.id=n.sender_user_id WHERE n.id=?').get(noticeId);
    if (!notice) return;
    const recipients = (await noticeRecipients(notice)).filter(r => r.email.toLowerCase() !== notice.sender_email?.toLowerCase());
    for (const person of recipients) {
      await sendNoticeEmail({ to: person.email, fullName: person.full_name, schoolName: notice.school_name, senderName: notice.sender_name, title: notice.title });
    }
  });
}


// ---- retrying a failed or skipped email -------------------------------------------
//
// The log keeps what's needed to send each email again, but never a
// sign-in link. Emails that carried one get a fresh link: an invite only
// if the person still hasn't set up their account.
async function resend(delivery) {
  const args = JSON.parse(delivery.args || '{}');
  const base = { to: delivery.recipient, retryOf: delivery.id, ...args };
  const user = await db.prepare('SELECT id, needs_password_setup AS "needsSetup" FROM users WHERE LOWER(email)=LOWER(?) AND active=1').get(delivery.recipient);
  switch (delivery.template) {
    case 'invite':
      if (!user) throw Object.assign(new Error('That account no longer exists or is disabled.'), { status: 409 });
      if (!user.needsSetup) throw Object.assign(new Error('They have already set up their account, so the invite is no longer needed.'), { status: 409 });
      return sendInviteEmail({ ...base, link: await createAccountLink(user.id, 'INVITE') });
    case 'passwordReset':
      if (!user) throw Object.assign(new Error('That account no longer exists or is disabled.'), { status: 409 });
      return sendPasswordResetEmail({ ...base, expiresIn: '24 hours', link: await createAccountLink(user.id, 'RESET', ADMIN_RESET_TTL_MS) });
    case 'guardianApproved':
      return sendGuardianApprovedEmail({ ...base, link: user?.needsSetup ? await createAccountLink(user.id, 'INVITE') : null });
    case 'pinReset':
      if (!user) throw Object.assign(new Error('That account no longer exists or is disabled.'), { status: 409 });
      return sendPinResetEmail({ ...base, link: await createAccountLink(user.id, 'PIN_RESET') });
    case 'pinChanged': return sendPinChangedEmail(base);
    case 'addedToSchool': return sendAddedToSchoolEmail(base);
    case 'passwordChanged': return sendPasswordChangedEmail(base);
    case 'mfaReset': return sendMfaResetEmail(base);
    case 'schoolWelcome': return sendSchoolWelcomeEmail(base);
    case 'guardianDecision': return sendGuardianDecisionEmail(base);
    case 'notice': return sendNoticeEmail(base);
    default: throw Object.assign(new Error('This kind of email cannot be resent.'), { status: 409 });
  }
}

const TEMPLATE_NAMES = ['invite', 'addedToSchool', 'passwordReset', 'passwordChanged', 'pinReset', 'pinChanged', 'mfaReset', 'schoolWelcome', 'guardianDecision', 'guardianApproved', 'notice'];

export function registerPlatformNotifications(router) {
  router.get('/notifications/summary', requirePlatformPermission('platform:view'), asyncRoute(async (req, res) => {
    const day = new Date(Date.now() - 86400000).toISOString().replace('T', ' ').slice(0, 19);
    const week = new Date(Date.now() - 7 * 86400000).toISOString().replace('T', ' ').slice(0, 19);
    const { rows } = await pool.query(`
      SELECT status, COUNT(*) FILTER (WHERE created_at >= $1)::int AS day, COUNT(*)::int AS week
      FROM notification_deliveries WHERE created_at >= $2 GROUP BY status`, [day, week]);
    res.json({ emailConfigured: emailConfigured(), counts: rows });
  }));

  // The delivery log. Recipients are shown (support needs them); message bodies and links never are.
  router.get('/notifications/deliveries', requirePlatformPermission('platform:view'), asyncRoute(async (req, res) => {
    const pageNumber = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, Number.parseInt(req.query.pageSize, 10) || 50));
    const status = ['SENT', 'FAILED', 'SKIPPED', 'RETRIED', 'SENDING'].includes(req.query.status) ? req.query.status : null;
    const template = TEMPLATE_NAMES.includes(req.query.template) ? req.query.template : null;
    const search = typeof req.query.search === 'string' ? req.query.search.trim().slice(0, 100) : '';
    const params = [status, template, search || null];
    const where = `($1::text IS NULL OR status=$1) AND ($2::text IS NULL OR template=$2)
      AND ($3::text IS NULL OR recipient ILIKE '%' || $3 || '%' OR school_name ILIKE '%' || $3 || '%')`;
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM notification_deliveries WHERE ${where}`, params);
    const { rows } = await pool.query(`
      SELECT id, channel, template, recipient, subject, school_name AS "schoolName", status, error, retry_of AS "retryOf", created_at AS "createdAt"
      FROM notification_deliveries WHERE ${where} ORDER BY created_at DESC, id LIMIT ${pageSize} OFFSET ${(pageNumber - 1) * pageSize}`, params);
    res.json({ items: rows, total, page: pageNumber, pageSize });
  }));

  router.post('/notifications/deliveries/:id/retry', requirePlatformPermission('platform:settings'), asyncRoute(async (req, res) => {
    const delivery = await db.prepare(`SELECT * FROM notification_deliveries WHERE id=?`).get(req.params.id);
    if (!delivery) return res.status(404).json({ error: 'Delivery not found' });
    if (!['FAILED', 'SKIPPED'].includes(delivery.status)) return res.status(409).json({ error: 'Only a failed or skipped email can be retried.' });
    if (!emailConfigured()) return res.status(409).json({ error: "Email sending isn't set up on the server yet, so a retry would be skipped too." });
    let result;
    try {
      result = await resend(delivery);
    } catch (error) {
      if (error.status) return res.status(error.status).json({ error: error.message });
      throw error;
    }
    await db.prepare(`UPDATE notification_deliveries SET status='RETRIED' WHERE id=? AND status IN ('FAILED','SKIPPED')`).run(delivery.id);
    await writeAudit({
      actor: req.user, actorRole: req.platformAdmin.role, action: 'EMAIL_RETRIED', targetType: 'notification_delivery', targetId: delivery.id,
      targetLabel: delivery.subject, details: { template: delivery.template, sent: result.sent }, ip: req.ip, requestId: req.requestId,
    });
    res.json({ sent: result.sent, deliveryId: result.deliveryId });
  }));

  // ---- announcements ----------------------------------------------------------------

  router.get('/announcements', requirePlatformPermission('platform:view'), asyncRoute(async (req, res) => {
    res.json(await db.prepare(`
      SELECT a.id, a.title, a.body, a.audience, a.school_count AS "schoolCount", a.created_at AS "createdAt", u.full_name AS "sentBy"
      FROM announcements a JOIN users u ON u.id=a.created_by_user_id ORDER BY a.created_at DESC LIMIT 50`).all());
  }));

  // Sent as a notice in each chosen school — to its admins (and front
  // desk) or to all its staff — and emailed like any other message.
  router.post('/announcements', requirePlatformPermission('platform:settings'), asyncRoute(async (req, res) => {
    const title = typeof req.body.title === 'string' ? req.body.title.trim().slice(0, 150) : '';
    const body = typeof req.body.body === 'string' ? req.body.body.trim().slice(0, 4000) : '';
    const audience = req.body.audience === 'ALL_STAFF' ? 'ALL_STAFF' : 'SCHOOL_ADMINS';
    if (!title || !body) return res.status(400).json({ error: 'A title and a message are required.' });
    const chosen = Array.isArray(req.body.schoolIds) ? req.body.schoolIds.filter(v => typeof v === 'string').slice(0, 5000) : null;
    const schools = chosen && chosen.length
      ? await db.prepare(`SELECT id FROM schools WHERE status='ACTIVE' AND id = ANY(?)`).all(chosen)
      : await db.prepare(`SELECT id FROM schools WHERE status='ACTIVE'`).all();
    if (schools.length === 0) return res.status(400).json({ error: 'No active schools to send to.' });
    const announcementId = id('announcement');
    const noticeIds = [];
    await withTransaction(async () => {
      await db.prepare('INSERT INTO announcements (id,title,body,audience,school_count,created_by_user_id) VALUES (?,?,?,?,?,?)')
        .run(announcementId, title, body, audience, schools.length, req.user.id);
      for (const school of schools) {
        const noticeId = id('notice');
        noticeIds.push(noticeId);
        await db.prepare(`
          INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,announcement_id)
          VALUES (?,?,NULL,?,'SDPMPlus','platform',?,?,?,?)`)
          .run(noticeId, school.id, req.user.id, title, body, audience === 'ALL_STAFF' ? 'STAFF' : 'ADMIN', announcementId);
      }
    });
    for (const noticeId of noticeIds) emailNoticeLater(noticeId);
    await writeAudit({
      actor: req.user, actorRole: req.platformAdmin.role, action: 'ANNOUNCEMENT_SENT', targetType: 'announcement', targetId: announcementId,
      targetLabel: title, details: { audience, schools: schools.length }, ip: req.ip, requestId: req.requestId,
    });
    res.status(201).json({ id: announcementId, schoolCount: schools.length });
  }));
}
