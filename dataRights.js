import { db, withTransaction } from './db.js';
import { writeAudit } from './audit.js';

// Data export, permanent deletion and retention — the tools a school
// needs to answer a records request, honor a deletion request, or meet
// its own retention policy / contract.
//
// Never exported: password hashes, two-step verification secrets,
// recovery codes, sessions, or pickup codes.

const utcDaysAgo = days => `to_char((now() - interval '${Number(days)} days') AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')`;

/** Everything held about one student in this school, or null if not found. */
export async function buildStudentExport(studentId, schoolId) {
  const student = await db.prepare(`
    SELECT s.id, s.first_name AS "firstName", s.last_name AS "lastName", s.date_of_birth AS "dateOfBirth",
      s.student_number AS "studentNumber", s.status, s.pickup_status AS "pickupStatus", s.daycare,
      s.photo_url AS "photoUrl", s.created_at AS "createdAt", s.archived_at AS "removedAt", cp.name AS "campus"
    FROM students s LEFT JOIN campuses cp ON cp.id=s.campus_id
    WHERE s.id=? AND s.school_id=?`).get(studentId, schoolId);
  if (!student) return null;
  const [enrollments, guardians, guardianRequests, attendance, pickupHistory, auditTrail] = await Promise.all([
    db.prepare(`
      SELECT y.name AS "schoolYear", g.name AS grade, c.name AS class, c.room_name AS room, t.full_name AS teacher, e.status
      FROM student_enrollments e JOIN school_years y ON y.id=e.school_year_id JOIN grade_levels g ON g.id=e.grade_level_id
      LEFT JOIN classes c ON c.id=e.class_id LEFT JOIN users t ON t.id=c.teacher_user_id
      WHERE e.student_id=? ORDER BY y.starts_on`).all(studentId),
    db.prepare(`
      SELECT u.full_name AS "fullName", u.email, u.phone, sg.relationship, sg.is_primary AS "isPrimary",
        sg.can_pick_up AS "canPickUp", sg.can_manage AS "canManage"
      FROM student_guardians sg JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id
      WHERE sg.student_id=? ORDER BY u.full_name`).all(studentId),
    db.prepare(`
      SELECT u.full_name AS "adult", gr.relationship, gr.status, ru.full_name AS "requestedBy", gr.requested_at AS "requestedAt",
        du.full_name AS "decidedBy", gr.decided_at AS "decidedAt", gr.decision_note AS "note"
      FROM guardian_requests gr JOIN guardians gu ON gu.id=gr.guardian_id JOIN users u ON u.id=gu.user_id
      JOIN users ru ON ru.id=gr.requested_by_user_id LEFT JOIN users du ON du.id=gr.decided_by_user_id
      WHERE gr.student_id=? ORDER BY gr.requested_at`).all(studentId),
    db.prepare(`
      SELECT ar.date, ar.status, ar.late, u.full_name AS "markedBy", ar.marked_at AS "markedAt"
      FROM attendance_records ar LEFT JOIN users u ON u.id=ar.marked_by_user_id
      WHERE ar.student_id=? ORDER BY ar.date`).all(studentId),
    db.prepare(`
      SELECT qi.request_type AS type, qi.status, ru.full_name AS "requestedBy", qi.requested_at AS "requestedAt",
        au.full_name AS "acceptedBy", qi.approved_at AS "acceptedAt", du.full_name AS "declinedBy", qi.declined_at AS "declinedAt",
        qi.verification_method AS "verification", qi.override_reason AS "overrideReason"
      FROM queue_items qi JOIN users ru ON ru.id=qi.requested_by_user_id
      LEFT JOIN users au ON au.id=qi.approved_by_user_id LEFT JOIN users du ON du.id=qi.declined_by_user_id
      WHERE qi.student_id=? ORDER BY qi.requested_at`).all(studentId),
    db.prepare(`
      SELECT created_at AS "at", actor_name AS "by", actor_role AS "role", action, details
      FROM audit_logs WHERE school_id=? AND target_type='student' AND target_id=? ORDER BY created_at`).all(schoolId, studentId),
  ]);
  return {
    exportedAt: new Date().toISOString(),
    student: { ...student, daycare: Boolean(student.daycare) },
    enrollments,
    guardians: guardians.map(g => ({ ...g, isPrimary: Boolean(g.isPrimary), canPickUp: Boolean(g.canPickUp), canManage: Boolean(g.canManage) })),
    guardianRequests,
    attendance: attendance.map(a => ({ ...a, late: Boolean(a.late) })),
    pickupHistory,
    auditTrail: auditTrail.map(entry => ({ ...entry, details: entry.details ? JSON.parse(entry.details) : null })),
  };
}

/**
 * The whole school's data (e.g. for an end-of-contract data return).
 * Photos are left out to keep the file manageable — the per-student
 * export includes them.
 */
export async function buildSchoolExport(schoolId) {
  const school = await db.prepare('SELECT id, name, code, address, timezone, start_time AS "startTime", dismissal_time AS "dismissalTime" FROM schools WHERE id=?').get(schoolId);
  const [campuses, schoolYears, classes, staff, parents, students, studentGuardians, enrollments, attendance, pickupHistory, guardianRequests] = await Promise.all([
    db.prepare('SELECT id, name, address, latitude, longitude, geofence_radius AS "geofenceRadius" FROM campuses WHERE school_id=? ORDER BY name').all(schoolId),
    db.prepare('SELECT id, name, starts_on AS "startsOn", ends_on AS "endsOn", status FROM school_years WHERE school_id=? ORDER BY starts_on').all(schoolId),
    db.prepare(`SELECT c.id, c.name, c.room_name AS room, g.name AS grade, y.name AS "schoolYear", c.teacher_user_id AS "teacherId"
      FROM classes c JOIN grade_levels g ON g.id=c.grade_level_id JOIN school_years y ON y.id=c.school_year_id WHERE c.school_id=? ORDER BY y.starts_on, c.name`).all(schoolId),
    db.prepare(`SELECT u.id, u.full_name AS "fullName", u.email, m.role, m.status FROM memberships m JOIN users u ON u.id=m.user_id
      WHERE m.school_id=? AND m.role IN ('teacher','school_admin','staff') ORDER BY u.full_name`).all(schoolId),
    db.prepare(`SELECT gu.id, u.full_name AS "fullName", u.email, u.phone, m.status FROM memberships m JOIN users u ON u.id=m.user_id
      JOIN guardians gu ON gu.user_id=u.id WHERE m.school_id=? AND m.role='parent' ORDER BY u.full_name`).all(schoolId),
    db.prepare(`SELECT id, first_name AS "firstName", last_name AS "lastName", date_of_birth AS "dateOfBirth", student_number AS "studentNumber",
      status, daycare, created_at AS "createdAt", archived_at AS "removedAt" FROM students WHERE school_id=? ORDER BY last_name, first_name`).all(schoolId),
    db.prepare(`SELECT sg.student_id AS "studentId", sg.guardian_id AS "guardianId", sg.relationship, sg.can_pick_up AS "canPickUp", sg.can_manage AS "canManage"
      FROM student_guardians sg JOIN students s ON s.id=sg.student_id WHERE s.school_id=?`).all(schoolId),
    db.prepare(`SELECT student_id AS "studentId", school_year_id AS "schoolYearId", grade_level_id AS "gradeLevelId", class_id AS "classId", status
      FROM student_enrollments WHERE school_id=?`).all(schoolId),
    db.prepare(`SELECT student_id AS "studentId", date, status, late, marked_by_user_id AS "markedBy" FROM attendance_records WHERE school_id=? ORDER BY date`).all(schoolId),
    db.prepare(`SELECT student_id AS "studentId", request_type AS type, status, requested_by_user_id AS "requestedBy", requested_at AS "requestedAt",
      approved_by_user_id AS "acceptedBy", approved_at AS "acceptedAt", declined_by_user_id AS "declinedBy", declined_at AS "declinedAt",
      verification_method AS verification, override_reason AS "overrideReason" FROM queue_items WHERE school_id=? ORDER BY requested_at`).all(schoolId),
    db.prepare(`SELECT student_id AS "studentId", guardian_id AS "guardianId", relationship, status, requested_by_user_id AS "requestedBy",
      requested_at AS "requestedAt", decided_by_user_id AS "decidedBy", decided_at AS "decidedAt", decision_note AS note FROM guardian_requests WHERE school_id=?`).all(schoolId),
  ]);
  return {
    exportedAt: new Date().toISOString(),
    school, campuses, schoolYears, classes, staff, parents,
    students: students.map(s => ({ ...s, daycare: Boolean(s.daycare) })),
    studentGuardians: studentGuardians.map(l => ({ ...l, canPickUp: Boolean(l.canPickUp), canManage: Boolean(l.canManage) })),
    enrollments,
    attendance: attendance.map(a => ({ ...a, late: Boolean(a.late) })),
    pickupHistory, guardianRequests,
    notes: 'Student photos are not included here; export a single student to get their photo. Audit log entries are available from the Audit Log page.',
  };
}

/**
 * Permanently erases a removed (ARCHIVED) student and everything tied to
 * them: attendance, drop-off/pickup history, guardian links and
 * requests, enrollments, photo. Cannot be undone. Audit log entries that
 * mention the student are kept — the audit log is append-only and is the
 * school's record that the deletion happened.
 */
export async function permanentlyDeleteStudent(studentId, schoolId) {
  return withTransaction(async () => {
    const student = await db.prepare(`SELECT id FROM students WHERE id=? AND school_id=? AND status='ARCHIVED' FOR UPDATE`).get(studentId, schoolId);
    if (!student) return null;
    const counts = {};
    counts.guardianRequests = (await db.prepare('DELETE FROM guardian_requests WHERE student_id=?').run(studentId)).changes;
    counts.attendanceRecords = (await db.prepare('DELETE FROM attendance_records WHERE student_id=?').run(studentId)).changes;
    counts.pickupHistory = (await db.prepare('DELETE FROM queue_items WHERE student_id=?').run(studentId)).changes;
    counts.guardianLinks = (await db.prepare('DELETE FROM student_guardians WHERE student_id=?').run(studentId)).changes;
    // Enrollments point at each other (promoted_from_id) — unlink first.
    await db.prepare('UPDATE student_enrollments SET promoted_from_id=NULL WHERE promoted_from_id IN (SELECT id FROM student_enrollments WHERE student_id=?)').run(studentId);
    counts.enrollments = (await db.prepare('DELETE FROM student_enrollments WHERE student_id=?').run(studentId)).changes;
    await db.prepare('DELETE FROM students WHERE id=?').run(studentId);
    return counts;
  });
}

// ---- Retention -------------------------------------------------------
// Per school: removed students are erased N days after removal, and
// finished drop-off/pickup requests older than N days are erased. Either
// setting left empty means "keep". Attendance of current students and
// the audit log are not touched by retention.

export const MIN_RETENTION_DAYS = 30;

async function retentionCandidates(school) {
  const removedStudents = school.removedStudentRetentionDays
    ? await db.prepare(`SELECT id, first_name AS "firstName", last_name AS "lastName", student_number AS "studentNumber" FROM students
        WHERE school_id=? AND status='ARCHIVED' AND archived_at < ${utcDaysAgo(school.removedStudentRetentionDays)}`).all(school.id)
    : [];
  const oldQueueItems = school.queueHistoryRetentionDays
    ? (await db.prepare(`SELECT COUNT(*) AS c FROM queue_items WHERE school_id=? AND status<>'PENDING' AND requested_at < ${utcDaysAgo(school.queueHistoryRetentionDays)}`).get(school.id)).c
    : 0;
  return { removedStudents, oldQueueItems };
}

export const retentionSettings = schoolId => db.prepare(`
  SELECT id, removed_student_retention_days AS "removedStudentRetentionDays", queue_history_retention_days AS "queueHistoryRetentionDays"
  FROM schools WHERE id=?`).get(schoolId);

/** What the next retention run would erase in this school (nothing is changed). */
export async function previewRetention(schoolId) {
  const { removedStudents, oldQueueItems } = await retentionCandidates(await retentionSettings(schoolId));
  return { removedStudents: removedStudents.length, pickupHistory: oldQueueItems };
}

/** Applies one school's retention settings now; each erasure is audited. */
export async function applyRetention(schoolId, { actor = null, ip = null } = {}) {
  const school = await retentionSettings(schoolId);
  const { removedStudents } = await retentionCandidates(school);
  const runBy = actor ?? { id: null, full_name: 'Automatic retention' };
  let studentsDeleted = 0;
  for (const student of removedStudents) {
    const counts = await permanentlyDeleteStudent(student.id, schoolId);
    if (!counts) continue;
    studentsDeleted++;
    await writeAudit({
      schoolId, actor: runBy, actorRole: actor ? undefined : 'system', action: 'STUDENT_PERMANENTLY_DELETED',
      targetType: 'student', targetId: student.id, targetLabel: deletedStudentLabel(student),
      details: { reason: `Retention: removed more than ${school.removedStudentRetentionDays} days ago`, ...counts }, ip,
    });
  }
  let pickupHistoryDeleted = 0;
  if (school.queueHistoryRetentionDays) {
    pickupHistoryDeleted = (await db.prepare(`DELETE FROM queue_items WHERE school_id=? AND status<>'PENDING' AND requested_at < ${utcDaysAgo(school.queueHistoryRetentionDays)}`).run(schoolId)).changes;
    if (pickupHistoryDeleted) {
      await writeAudit({
        schoolId, actor: runBy, actorRole: actor ? undefined : 'system', action: 'PICKUP_HISTORY_PURGED',
        details: { count: pickupHistoryDeleted, olderThanDays: school.queueHistoryRetentionDays }, ip,
      });
    }
  }
  return { studentsDeleted, pickupHistoryDeleted };
}

/** Every school with a retention setting — run daily by the server. */
export async function applyRetentionEverywhere() {
  const schools = await db.prepare(`SELECT id FROM schools WHERE removed_student_retention_days IS NOT NULL OR queue_history_retention_days IS NOT NULL`).all();
  for (const { id } of schools) {
    try { await applyRetention(id); } catch (error) { console.error('Retention run failed for school', id, error); }
  }
}

/**
 * What the audit log keeps about an erased student: initials and student
 * number — enough for the school to show the deletion happened without
 * keeping their full name.
 */
export const deletedStudentLabel = student =>
  `${student.firstName?.[0] ?? ''}.${student.lastName?.[0] ?? ''}. (deleted${student.studentNumber ? `, #${student.studentNumber}` : ''})`;

