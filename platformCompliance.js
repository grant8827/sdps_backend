import { db, id, pool, withTransaction } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { emailConfigured } from './mailer.js';
import { requirePlatformPermission } from './permissions.js';
import { buildSchoolExport, buildStudentExport, deletedStudentLabel, legalHold, permanentlyDeleteStudent } from './dataRights.js';
import { mfaCoverage } from './platformSecurity.js';

// Platform → Compliance Center: the operational side of student-data
// privacy — export and deletion requests worked through a reviewed
// workflow, retention and legal holds per school, and the security
// controls that can be checked from inside the app. It reports facts; it
// never claims a certification.
//
// Data request workflow:
//   REQUESTED → UNDER_REVIEW → APPROVED → PROCESSING → COMPLETED
//   (REQUESTED or UNDER_REVIEW → REJECTED)
// A deletion is approved by someone other than the person who logged it,
// runs only on a school without a legal hold, and leaves the audit log
// (the record that it happened) in place.

const DUE_DAYS = 30;
const TRANSITIONS = {
  REQUESTED: ['UNDER_REVIEW', 'REJECTED'],
  UNDER_REVIEW: ['APPROVED', 'REJECTED'],
  APPROVED: ['PROCESSING'],
  PROCESSING: ['COMPLETED'],
  COMPLETED: [],
  REJECTED: [],
};
const NOTE_REQUIRED = new Set(['APPROVED', 'REJECTED', 'COMPLETED']);
const text = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');
const utcNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const utcInDays = days => new Date(Date.now() + days * 86400000).toISOString().replace('T', ' ').slice(0, 19);

const REQUEST_SELECT = `
  SELECT r.id, r.school_id AS "schoolId", s.name AS "schoolName", r.kind, r.subject_type AS "subjectType", r.subject_id AS "subjectId",
    r.subject_label AS "subjectLabel", r.requester_name AS "requesterName", r.requester_relationship AS "requesterRelationship",
    r.received_via AS "receivedVia", r.details, r.status, r.status_note AS "statusNote", r.due_at AS "dueAt",
    r.created_at AS "createdAt", r.updated_at AS "updatedAt", r.completed_at AS "completedAt", r.outcome,
    cu.full_name AS "createdBy", r.created_by_user_id AS "createdById", au.full_name AS "approvedBy",
    s.legal_hold_reason AS "legalHold"
  FROM data_requests r JOIN schools s ON s.id=r.school_id
  JOIN users cu ON cu.id=r.created_by_user_id LEFT JOIN users au ON au.id=r.approved_by_user_id`;

const shape = row => row && ({ ...row, outcome: row.outcome ? JSON.parse(row.outcome) : null, overdue: !['COMPLETED', 'REJECTED'].includes(row.status) && row.dueAt < utcNow() });

const auditRequest = (req, request, action, extra = {}) => writeAudit({
  schoolId: request.schoolId ?? request.school_id, actor: req.user, actorRole: req.platformAdmin.role, action,
  targetType: 'data_request', targetId: request.id, targetLabel: `${request.kind} · ${request.subjectLabel ?? request.subject_label}`,
  ip: req.ip, requestId: req.requestId, ...extra,
});

/** Who/what the request is about, checked to belong to that school. */
async function resolveSubject(schoolId, subjectType, subjectId) {
  if (subjectType === 'SCHOOL') {
    const school = await db.prepare('SELECT name FROM schools WHERE id=?').get(schoolId);
    return school ? { id: schoolId, label: `Whole school: ${school.name}` } : null;
  }
  if (subjectType === 'STUDENT') {
    const student = await db.prepare(`SELECT first_name || ' ' || last_name AS label FROM students WHERE id=? AND school_id=?`).get(subjectId, schoolId);
    return student ? { id: subjectId, label: student.label } : null;
  }
  const parent = await db.prepare(`
    SELECT u.full_name AS label FROM users u JOIN memberships m ON m.user_id=u.id AND m.school_id=? AND m.role='parent' WHERE u.id=?`).get(schoolId, subjectId);
  return parent ? { id: subjectId, label: parent.label } : null;
}

async function loadRequest(requestId) {
  return shape(await db.prepare(`${REQUEST_SELECT} WHERE r.id=?`).get(requestId));
}

export function registerPlatformCompliance(router) {
  router.get('/compliance/overview', requirePlatformPermission('compliance:view'), asyncRoute(async (req, res) => {
    const { rows: requestCounts } = await pool.query(`
      SELECT status, kind, COUNT(*)::int AS n, COUNT(*) FILTER (WHERE due_at < $1 AND status NOT IN ('COMPLETED','REJECTED'))::int AS overdue
      FROM data_requests GROUP BY status, kind`, [utcNow()]);
    const { rows: [retention] } = await pool.query(`
      SELECT COUNT(*) FILTER (WHERE removed_student_retention_days IS NOT NULL OR queue_history_retention_days IS NOT NULL)::int AS "schoolsWithRetention",
        COUNT(*)::int AS "activeSchools",
        (SELECT COUNT(*)::int FROM students st JOIN schools sc ON sc.id=st.school_id AND sc.status <> 'ARCHIVED' WHERE st.status='ARCHIVED') AS "removedStudentsKept"
      FROM schools WHERE status='ACTIVE'`);
    const { rows: holds } = await pool.query(`
      SELECT s.id, s.name, s.legal_hold_reason AS reason, s.legal_hold_at AS "since", u.full_name AS "setBy"
      FROM schools s LEFT JOIN users u ON u.id=s.legal_hold_by_user_id WHERE s.legal_hold_reason IS NOT NULL ORDER BY s.legal_hold_at DESC`);
    const { rows: [audit] } = await pool.query(`
      SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='audit_logs_no_change' AND NOT tgisinternal) AS "appendOnly",
        (SELECT COUNT(*)::int FROM audit_logs WHERE created_at >= $1) AS "entriesLast30Days"`, [new Date(Date.now() - 30 * 86400000).toISOString().replace('T', ' ').slice(0, 19)]);
    const databaseUrl = process.env.DATABASE_URL ?? '';
    res.json({
      requests: requestCounts,
      retention,
      legalHolds: holds,
      // Only facts the server can check about itself — no secrets or settings values.
      controls: {
        passwordHashing: 'scrypt with a unique salt per password',
        mfaSecretsEncrypted: Boolean(process.env.MFA_ENCRYPTION_KEY),
        mfaRequiredForAdmins: process.env.REQUIRE_ADMIN_MFA !== 'false',
        httpsEnforced: Boolean(process.env.TRUST_PROXY || process.env.RAILWAY_ENVIRONMENT),
        databaseTls: process.env.PGSSL !== 'false' && !/sslmode=disable/.test(databaseUrl),
        auditLogAppendOnly: audit.appendOnly,
        auditEntriesLast30Days: audit.entriesLast30Days,
        tenantIsolation: 'Enforced by the API on every school-scoped request; covered by automated tests.',
        emailConfigured: emailConfigured(),
      },
      mfa: await mfaCoverage(),
    });
  }));

  // ---- data requests -------------------------------------------------------------

  router.get('/compliance/data-requests', requirePlatformPermission('compliance:view'), asyncRoute(async (req, res) => {
    const pageNumber = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, Number.parseInt(req.query.pageSize, 10) || 25));
    const status = Object.keys(TRANSITIONS).includes(req.query.status) ? req.query.status : null;
    const open = req.query.status === 'OPEN';
    const kind = ['EXPORT', 'DELETION'].includes(req.query.kind) ? req.query.kind : null;
    const schoolId = typeof req.query.schoolId === 'string' && req.query.schoolId ? req.query.schoolId : null;
    const params = [status, kind, schoolId, open];
    const where = `($1::text IS NULL OR r.status=$1) AND ($2::text IS NULL OR r.kind=$2) AND ($3::text IS NULL OR r.school_id=$3)
      AND (NOT $4::boolean OR r.status NOT IN ('COMPLETED','REJECTED'))`;
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM data_requests r WHERE ${where}`, params);
    const { rows } = await pool.query(`${REQUEST_SELECT} WHERE ${where} ORDER BY r.status IN ('COMPLETED','REJECTED'), r.due_at, r.id LIMIT ${pageSize} OFFSET ${(pageNumber - 1) * pageSize}`, params);
    res.json({ items: rows.map(shape), total, page: pageNumber, pageSize });
  }));

  router.get('/compliance/data-requests/:id', requirePlatformPermission('compliance:view'), asyncRoute(async (req, res) => {
    const request = await loadRequest(req.params.id);
    if (!request) return res.status(404).json({ error: 'Request not found' });
    const { rows: history } = await pool.query(`
      SELECT id, created_at AS "createdAt", action, actor_name AS "actorName", actor_role AS "actorRole", reason, details
      FROM audit_logs WHERE target_type='data_request' AND target_id=$1 ORDER BY seq`, [request.id]);
    res.json({ ...request, history: history.map(h => ({ ...h, details: h.details ? JSON.parse(h.details) : null })) });
  }));

  router.post('/compliance/data-requests', requirePlatformPermission('data_request:manage'), asyncRoute(async (req, res) => {
    const kind = req.body.kind;
    const subjectType = req.body.subjectType;
    const schoolId = text(req.body.schoolId, 100);
    const requesterName = text(req.body.requesterName, 120);
    if (!['EXPORT', 'DELETION'].includes(kind) || !['STUDENT', 'PARENT', 'SCHOOL'].includes(subjectType) || !schoolId || !requesterName) {
      return res.status(400).json({ error: 'School, kind, subject and the requester\'s name are required.' });
    }
    const subject = await resolveSubject(schoolId, subjectType, text(req.body.subjectId, 100));
    if (!subject) return res.status(400).json({ error: 'That student or parent was not found in this school.' });
    const request = {
      id: id('datarequest'), schoolId, kind, subjectType, subjectLabel: subject.label,
    };
    await db.prepare(`
      INSERT INTO data_requests (id,school_id,kind,subject_type,subject_id,subject_label,requester_name,requester_relationship,received_via,details,due_at,created_by_user_id)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(request.id, schoolId, kind, subjectType, subject.id, subject.label, requesterName, text(req.body.requesterRelationship, 80) || null,
        text(req.body.receivedVia, 120) || null, text(req.body.details, 2000) || null, utcInDays(DUE_DAYS), req.user.id);
    await auditRequest(req, request, kind === 'EXPORT' ? 'DATA_EXPORT_REQUESTED' : 'DATA_DELETION_REQUESTED', {
      details: { subjectType, requester: requesterName, receivedVia: text(req.body.receivedVia, 120) || null },
    });
    res.status(201).json(await loadRequest(request.id));
  }));

  router.post('/compliance/data-requests/:id/status', requirePlatformPermission('data_request:manage'), asyncRoute(async (req, res) => {
    const request = await loadRequest(req.params.id);
    if (!request) return res.status(404).json({ error: 'Request not found' });
    const to = req.body.status;
    const note = text(req.body.note, 1000);
    if (!TRANSITIONS[request.status]?.includes(to)) return res.status(409).json({ error: `A ${request.status.toLowerCase().replace('_', ' ')} request can't move to ${String(to).toLowerCase().replace('_', ' ')}.` });
    if (NOTE_REQUIRED.has(to) && note.length < 5) return res.status(400).json({ error: 'Add a note (at least 5 characters) explaining the decision.' });
    // Four eyes on deletions: the person who logged it can't approve it.
    if (to === 'APPROVED' && request.kind === 'DELETION' && request.createdById === req.user.id) {
      return res.status(403).json({ error: 'A deletion must be approved by someone other than the person who logged it.' });
    }
    if (to === 'APPROVED' && request.kind === 'DELETION' && request.legalHold) {
      return res.status(409).json({ error: `This school is on legal hold (${request.legalHold}). Deletions can't be approved until it's released.` });
    }
    // Automated requests finish through their own action (export download / run deletion).
    if (to === 'COMPLETED' && request.kind === 'DELETION' && request.subjectType === 'STUDENT') {
      return res.status(409).json({ error: 'Use "Run deletion" to carry out this request; it completes automatically.' });
    }
    await db.prepare(`
      UPDATE data_requests SET status=?, status_note=COALESCE(?, status_note), updated_at=?,
        approved_by_user_id=CASE WHEN ?='APPROVED' THEN ? ELSE approved_by_user_id END,
        completed_at=CASE WHEN ? IN ('COMPLETED','REJECTED') THEN ? ELSE completed_at END
      WHERE id=? AND status=?`)
      .run(to, note || null, utcNow(), to, req.user.id, to, utcNow(), request.id, request.status);
    await auditRequest(req, request, `DATA_REQUEST_${to}`, { reason: note || null, details: { from: request.status, to } });
    res.json(await loadRequest(request.id));
  }));

  // Export: the file itself, for an approved export request (student or whole school).
  router.get('/compliance/data-requests/:id/export', requirePlatformPermission('data_request:manage'), asyncRoute(async (req, res) => {
    const request = await loadRequest(req.params.id);
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.kind !== 'EXPORT' || !['APPROVED', 'PROCESSING'].includes(request.status)) {
      return res.status(409).json({ error: 'Only an approved export request can be downloaded.' });
    }
    if (request.subjectType === 'PARENT') return res.status(409).json({ error: 'Parent exports are prepared by hand for now: record what was sent, then mark the request completed.' });
    const data = request.subjectType === 'SCHOOL'
      ? await buildSchoolExport(request.schoolId)
      : await buildStudentExport(request.subjectId, request.schoolId);
    if (!data) return res.status(404).json({ error: 'The student no longer exists in this school.' });
    if (request.status === 'APPROVED') {
      await db.prepare(`UPDATE data_requests SET status='PROCESSING', updated_at=? WHERE id=? AND status='APPROVED'`).run(utcNow(), request.id);
    }
    await auditRequest(req, request, 'DATA_EXPORTED', { details: { subjectType: request.subjectType } });
    res.setHeader('Content-Disposition', `attachment; filename="sdpmplus-${request.subjectType.toLowerCase()}-export-${request.id.slice(-8)}.json"`);
    res.json(data);
  }));

  // Deletion: runs an approved student deletion. Confirm by typing the student's full name.
  router.post('/compliance/data-requests/:id/run-deletion', requirePlatformPermission('data_request:manage'), asyncRoute(async (req, res) => {
    const request = await loadRequest(req.params.id);
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.kind !== 'DELETION' || request.subjectType !== 'STUDENT' || request.status !== 'APPROVED') {
      return res.status(409).json({ error: 'Only an approved student deletion request can be run.' });
    }
    const hold = await legalHold(request.schoolId);
    if (hold) return res.status(409).json({ error: `This school is on legal hold (${hold}). Nothing can be deleted until it's released.` });
    const student = await db.prepare(`SELECT first_name AS "firstName", last_name AS "lastName", student_number AS "studentNumber", status FROM students WHERE id=? AND school_id=?`)
      .get(request.subjectId, request.schoolId);
    if (!student) return res.status(404).json({ error: 'The student no longer exists in this school.' });
    const typed = text(req.body?.confirmName, 200).replace(/\s+/g, ' ').toLowerCase();
    if (typed !== `${student.firstName} ${student.lastName}`.toLowerCase()) return res.status(400).json({ error: "Type the student's full name exactly to confirm." });

    await db.prepare(`UPDATE data_requests SET status='PROCESSING', updated_at=? WHERE id=? AND status='APPROVED'`).run(utcNow(), request.id);
    // A student still enrolled is removed first (as the school would), then erased.
    if (student.status !== 'ARCHIVED') {
      await withTransaction(async () => {
        await db.prepare(`UPDATE students SET status='ARCHIVED', archived_at=? WHERE id=?`).run(utcNow(), request.subjectId);
        await db.prepare(`UPDATE queue_items SET status='CANCELLED' WHERE student_id=? AND status='PENDING'`).run(request.subjectId);
      });
    }
    const counts = await permanentlyDeleteStudent(request.subjectId, request.schoolId);
    const label = deletedStudentLabel(student);
    const outcome = { erased: counts, kept: ['Audit log entries (the record that this deletion happened)'] };
    // The request itself stops naming the child once they're erased.
    await db.prepare(`UPDATE data_requests SET status='COMPLETED', subject_label=?, outcome=?, completed_at=?, updated_at=? WHERE id=?`)
      .run(`Student ${label}`, JSON.stringify(outcome), utcNow(), utcNow(), request.id);
    await writeAudit({
      schoolId: request.schoolId, actor: req.user, actorRole: req.platformAdmin.role, action: 'STUDENT_PERMANENTLY_DELETED',
      targetType: 'student', targetId: request.subjectId, targetLabel: label, details: { dataRequestId: request.id, ...counts },
      ip: req.ip, requestId: req.requestId,
    });
    await auditRequest(req, { ...request, subjectLabel: `Student ${label}` }, 'DATA_REQUEST_COMPLETED', { details: counts });
    res.json(await loadRequest(request.id));
  }));

  // ---- legal holds -------------------------------------------------------------------

  router.post('/compliance/schools/:id/legal-hold', requirePlatformPermission('legal_hold:manage'), asyncRoute(async (req, res) => {
    const reason = text(req.body?.reason, 500);
    if (reason.length < 5) return res.status(400).json({ error: 'Please give a reason (at least 5 characters).' });
    const hold = req.body?.hold !== false;
    const school = await db.prepare(hold
      ? `UPDATE schools SET legal_hold_reason=?, legal_hold_at=?, legal_hold_by_user_id=? WHERE id=? AND legal_hold_reason IS NULL RETURNING id, name`
      : `UPDATE schools SET legal_hold_reason=NULL, legal_hold_at=NULL, legal_hold_by_user_id=NULL WHERE id=? AND legal_hold_reason IS NOT NULL RETURNING id, name`)
      .get(...(hold ? [reason, utcNow(), req.user.id, req.params.id] : [req.params.id]));
    if (!school) return res.status(409).json({ error: hold ? 'This school is already on legal hold (or does not exist).' : 'This school is not on legal hold.' });
    await writeAudit({
      schoolId: school.id, actor: req.user, actorRole: req.platformAdmin.role, action: hold ? 'LEGAL_HOLD_SET' : 'LEGAL_HOLD_RELEASED',
      targetType: 'school', targetId: school.id, targetLabel: school.name, reason, ip: req.ip, requestId: req.requestId,
    });
    res.status(204).end();
  }));
}
