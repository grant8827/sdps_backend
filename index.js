import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { timingSafeEqual } from 'node:crypto';
import { db, id, passwordHash, isUniqueViolation, withTransaction } from './db.js';
import { login, logout, requireAuth, requireRole } from './auth.js';
import { getMemberships, requireSchoolAccess } from './tenant.js';
import { asyncRoute } from './asyncRoute.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDist = path.join(__dirname, '..', 'frontend', 'dist');

const app = express();
const port = process.env.PORT || 3000;

// The website and API can be deployed as separate services. In that setup the
// browser needs an explicit CORS grant from this API. Accept a comma-separated
// list so preview and production frontends can both be configured without
// allowing arbitrary origins.
const allowedOrigins = new Set(
  String(process.env.FRONTEND_URL || '')
    .split(',')
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

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const session = await login(String(req.body.identifier || '').trim(), String(req.body.password || ''));
  if (!session) return res.status(401).json({ error: 'Invalid email/phone or password' });
  res.json(session);
}));

app.post('/api/auth/logout', requireAuth, asyncRoute(async (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  await logout(token);
  res.status(204).end();
}));

app.get('/api/me/schools', requireAuth, asyncRoute(async (req, res) => {
  res.json(await getMemberships(req.user.id));
}));

app.post('/api/me/change-password', requireAuth, asyncRoute(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  const user = await db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.user.id);
  const actual = Buffer.from(user.password_hash, 'hex');
  const supplied = Buffer.from(passwordHash(currentPassword), 'hex');
  if (actual.length !== supplied.length || !timingSafeEqual(actual, supplied)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  await db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(passwordHash(newPassword), req.user.id);
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
app.post('/api/auth/register-school', asyncRoute(async (req, res) => {
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
      await db.prepare('INSERT INTO campuses (id,school_id,name,address) VALUES (?,?,?,?)').run(campusId, schoolId, campusName.trim(), campusAddress?.trim() || null);

      const userId = id('admin');
      await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES (?,?,?,?,'admin')`).run(userId, adminFullName.trim(), email.trim(), passwordHash(password));
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,NULL,'school_admin')`).run(id('membership'), userId, schoolId);

      // School year starting ~August, so the label reads right whether
      // they sign up mid-summer (next year) or mid-year (current year).
      const now = new Date();
      const startYear = now.getMonth() >= 6 ? now.getFullYear() : now.getFullYear() - 1;
      await db.prepare(`INSERT INTO school_years (id,school_id,name,starts_on,ends_on,status) VALUES (?,?,?,?,?,'ACTIVE')`)
        .run(id('year'), schoolId, `${startYear}-${startYear + 1}`, `${startYear}-08-01`, `${startYear + 1}-06-30`);

      return login(email.trim(), password);
    });
    res.status(201).json(result);
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
    c.name AS "className", c.teacher_user_id AS "teacherId", s.school_id AS "schoolId",
    s.campus_id AS "campusId", sc.name AS "schoolName", cp.name AS "campusName"
  FROM students s LEFT JOIN student_enrollments e ON e.student_id=s.id
  LEFT JOIN school_years y ON y.id=e.school_year_id LEFT JOIN grade_levels g ON g.id=e.grade_level_id
  LEFT JOIN classes c ON c.id=e.class_id LEFT JOIN schools sc ON sc.id=s.school_id
  LEFT JOIN campuses cp ON cp.id=s.campus_id`;

app.get('/api/me/students', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  const rows = await db.prepare(`${studentSelect} JOIN student_guardians sg ON sg.student_id=s.id JOIN guardians gu ON gu.id=sg.guardian_id JOIN memberships m ON m.user_id=gu.user_id AND m.school_id=s.school_id AND m.role='parent' AND m.status='ACTIVE' WHERE gu.user_id=? AND y.status='ACTIVE' AND s.status='ACTIVE' GROUP BY s.id,e.id,g.name,c.name,c.teacher_user_id,sc.name,cp.name ORDER BY sc.name,s.last_name,s.first_name`).all(req.user.id);
  res.json(rows.map(row => ({ ...row, status: row.pickupStatus, daycare: Boolean(row.daycare) })));
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

// Real drop-off/pick-up queue, shared by every client (mobile + web,
// any role) via the database — replaces the old in-memory mock that
// only ever synced within one running app process.
const guardianLinkQuery = db.prepare(`
  SELECT sg.can_pick_up AS "canPickUp" FROM student_guardians sg
  JOIN guardians gu ON gu.id=sg.guardian_id WHERE sg.student_id=? AND gu.user_id=?`);
const studentContextQuery = db.prepare(`
  SELECT s.school_id AS "schoolId", s.campus_id AS "campusId", c.teacher_user_id AS "teacherId", e.class_id AS "classId", s.pickup_status AS "pickupStatus"
  FROM students s
  LEFT JOIN student_enrollments e ON e.student_id=s.id
  LEFT JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
  LEFT JOIN classes c ON c.id=e.class_id
  WHERE s.id=? AND s.status='ACTIVE'`);

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
  try {
    const itemId = id('queue');
    await withTransaction(async () => {
      await db.prepare(`INSERT INTO queue_items (id,school_id,campus_id,student_id,teacher_user_id,request_type,requested_by_user_id) VALUES (?,?,?,?,?,?,?)`)
        .run(itemId, context.schoolId, context.campusId, req.params.studentId, context.teacherId, requestType, req.user.id);
      await db.prepare('UPDATE students SET pickup_status=? WHERE id=?').run(nextStatus, req.params.studentId);
    });
    res.status(201).json({ id: itemId });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
}

app.post('/api/me/students/:studentId/drop-off', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  await createQueueRequest(req, res, 'DROP_OFF', 'AT_HOME', 'DROPOFF_REQUESTED');
}));

app.post('/api/me/students/:studentId/pick-up', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  await createQueueRequest(req, res, 'PICK_UP', 'PRESENT', 'PICKUP_REQUESTED');
}));

const queueSelect = `
  SELECT qi.id, qi.student_id AS "childId", s.first_name || ' ' || s.last_name AS "childName",
    s.photo_url AS "childPhotoUrl", c.name AS "className",
    qi.teacher_user_id AS "teacherId", qi.request_type AS "requestType", qi.requested_at AS "requestedAt",
    u.full_name AS "parentName"
  FROM queue_items qi
  JOIN students s ON s.id=qi.student_id
  JOIN users u ON u.id=qi.requested_by_user_id
  LEFT JOIN student_enrollments e ON e.student_id=s.id
  LEFT JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
  LEFT JOIN classes c ON c.id=e.class_id`;

app.get('/api/teacher/queue', requireAuth, requireRole('teacher'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`${queueSelect} WHERE qi.status='PENDING' AND qi.teacher_user_id=? ORDER BY qi.requested_at ASC`).all(req.user.id));
}));

app.get('/api/admin/queue', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  res.json(await db.prepare(`${queueSelect} WHERE qi.status='PENDING' AND qi.school_id=? ORDER BY qi.requested_at ASC`).all(req.school.id));
}));

// A teacher may approve only their own class's requests; an admin may
// approve anything in a school they belong to (mirrors the Live Queue
// screens: admin sees and can act on every class, teacher only theirs).
app.post('/api/queue/:id/approve', requireAuth, asyncRoute(async (req, res) => {
  const item = await db.prepare(`SELECT * FROM queue_items WHERE id=? AND status='PENDING'`).get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Request not found or already handled.' });
  const isOwningTeacher = req.user.role === 'teacher' && item.teacher_user_id === req.user.id;
  const isSchoolAdmin = (await getMemberships(req.user.id)).some(m => m.schoolId === item.school_id && ['school_admin', 'platform_super_admin'].includes(m.role));
  if (!isOwningTeacher && !isSchoolAdmin) return res.status(403).json({ error: 'You do not have permission to approve this request.' });
  try {
    await withTransaction(async () => {
      await db.prepare(`UPDATE queue_items SET status='APPROVED', approved_at=${NOW_UTC}, approved_by_user_id=? WHERE id=?`).run(req.user.id, item.id);
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
app.post('/api/queue/:id/decline', requireAuth, asyncRoute(async (req, res) => {
  const item = await db.prepare(`SELECT * FROM queue_items WHERE id=? AND status='PENDING'`).get(req.params.id);
  if (!item) return res.status(404).json({ error: 'Request not found or already handled.' });
  const isOwningTeacher = req.user.role === 'teacher' && item.teacher_user_id === req.user.id;
  const isSchoolAdmin = (await getMemberships(req.user.id)).some(m => m.schoolId === item.school_id && ['school_admin', 'platform_super_admin'].includes(m.role));
  if (!isOwningTeacher && !isSchoolAdmin) return res.status(403).json({ error: 'You do not have permission to decline this request.' });
  try {
    await withTransaction(async () => {
      await db.prepare(`UPDATE queue_items SET status='DECLINED', declined_at=${NOW_UTC}, declined_by_user_id=? WHERE id=?`).run(req.user.id, item.id);
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
    COALESCE(ar.status, CASE WHEN EXTRACT(DOW FROM ?::date) IN (0,6) THEN 'WEEKEND' ELSE 'UNMARKED' END) AS status
  FROM students s
  JOIN student_enrollments e ON e.student_id=s.id
  JOIN school_years y ON y.id=e.school_year_id AND y.status='ACTIVE'
  JOIN classes c ON c.id=e.class_id
  LEFT JOIN attendance_records ar ON ar.student_id=s.id AND ar.date=?
  WHERE s.status='ACTIVE'`;

app.get('/api/teacher/attendance', requireAuth, requireRole('teacher'), asyncRoute(async (req, res) => {
  const date = req.query.date || todayIso();
  res.json(await db.prepare(`${attendanceSelect} AND c.teacher_user_id=? ORDER BY s.last_name,s.first_name`).all(date, date, req.user.id));
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

app.get('/api/admin/attendance', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  if (!req.query.classId) return res.status(400).json({ error: 'classId is required' });
  const date = req.query.date || todayIso();
  res.json(await db.prepare(`${attendanceSelect} AND s.school_id=? AND e.class_id=? ORDER BY s.last_name,s.first_name`).all(date, date, req.school.id, req.query.classId));
}));

// A teacher may mark attendance only for their own class; an admin may
// mark it for anything in a school they belong to — same split as the
// live queue's approve permission.
const ATTENDANCE_STATUSES = ['PRESENT', 'ABSENT', 'SICK', 'SUSPENDED', 'HOLIDAY', 'WEEKEND'];
app.post('/api/attendance', requireAuth, asyncRoute(async (req, res) => {
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
  const isOwningTeacher = req.user.role === 'teacher' && context.teacherId === req.user.id;
  const isSchoolAdmin = (await getMemberships(req.user.id)).some(m => m.schoolId === context.schoolId && ['school_admin', 'platform_super_admin'].includes(m.role));
  if (!isOwningTeacher && !isSchoolAdmin) return res.status(403).json({ error: 'You do not have permission to mark attendance for this student.' });
  await db.prepare(`
    INSERT INTO attendance_records (id,school_id,campus_id,student_id,class_id,date,status,marked_by_user_id) VALUES (?,?,?,?,?,?,?,?)
    ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status, marked_by_user_id=excluded.marked_by_user_id, marked_at=${NOW_UTC}`)
    .run(id('attendance'), context.schoolId, context.campusId, studentId, context.classId, date, status, req.user.id);
  res.status(204).end();
}));

app.get('/api/admin/overview', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const totalStudents = (await db.prepare(`SELECT COUNT(*) AS c FROM students WHERE school_id=? AND status='ACTIVE'`).get(req.school.id)).c;
  const activeTeachers = (await db.prepare(`SELECT COUNT(*) AS c FROM memberships WHERE school_id=? AND role='teacher' AND status='ACTIVE'`).get(req.school.id)).c;
  const presentToday = (await db.prepare(`SELECT COUNT(*) AS c FROM students WHERE school_id=? AND status='ACTIVE' AND pickup_status='PRESENT'`).get(req.school.id)).c;
  const pendingRequests = (await db.prepare(`SELECT COUNT(*) AS c FROM queue_items WHERE school_id=? AND status='PENDING'`).get(req.school.id)).c;
  res.json({ totalStudents, activeTeachers, presentToday, pendingRequests });
}));

app.get('/api/admin/setup', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  res.json({
    school: await db.prepare('SELECT id,name,code,timezone,status,start_time AS "startTime",dismissal_time AS "dismissalTime",extended_time AS "extendedTime" FROM schools WHERE id=?').get(req.school.id),
    campuses: await db.prepare('SELECT id,name,address,latitude,longitude,geofence_radius AS "geofenceRadius",timezone,status,start_time AS "startTime",dismissal_time AS "dismissalTime",extended_time AS "extendedTime" FROM campuses WHERE school_id=? ORDER BY name').all(req.school.id),
    schoolYears: await db.prepare('SELECT * FROM school_years WHERE school_id=? ORDER BY starts_on DESC').all(req.school.id),
    gradeLevels: await db.prepare('SELECT id,name,sort_order AS "sortOrder",next_grade_level_id AS "nextGradeLevelId" FROM grade_levels ORDER BY sort_order').all(),
    classes: await db.prepare('SELECT id,name,room_name AS "roomName",school_year_id AS "schoolYearId",grade_level_id AS "gradeLevelId",teacher_user_id AS "teacherId",campus_id AS "campusId" FROM classes WHERE school_id=? ORDER BY name').all(req.school.id),
    guardians: await db.prepare(`SELECT DISTINCT gu.id,u.full_name AS "fullName",u.email,u.phone FROM guardians gu JOIN users u ON u.id=gu.user_id JOIN memberships m ON m.user_id=u.id WHERE m.school_id=? AND m.status='ACTIVE' ORDER BY u.full_name`).all(req.school.id),
  });
}));

// 'HH:MM', 24-hour — validated so bad input can't silently break the
// lexicographic time comparison the late-arrival check below relies on.
const isValidClockTime = value => /^([01]\d|2[0-3]):[0-5]\d$/.test(value);

app.patch('/api/admin/school', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { name, startTime, dismissalTime, extendedTime } = req.body;
  for (const [label, value] of [['startTime', startTime], ['dismissalTime', dismissalTime], ['extendedTime', extendedTime]]) {
    if (value !== undefined && value !== null && value !== '' && !isValidClockTime(value)) {
      return res.status(400).json({ error: `${label} must be a HH:MM time` });
    }
  }
  const current = await db.prepare('SELECT name,start_time AS "startTime",dismissal_time AS "dismissalTime",extended_time AS "extendedTime" FROM schools WHERE id=?').get(req.school.id);
  if (!current) return res.status(404).json({ error: 'School not found' });
  // undefined (field omitted) keeps the existing value; '' explicitly clears it.
  const next = {
    name: name !== undefined && name.trim() ? name.trim() : current.name,
    startTime: startTime !== undefined ? (startTime || null) : current.startTime,
    dismissalTime: dismissalTime !== undefined ? (dismissalTime || null) : current.dismissalTime,
    extendedTime: extendedTime !== undefined ? (extendedTime || null) : current.extendedTime,
  };
  await db.prepare('UPDATE schools SET name=?, start_time=?, dismissal_time=?, extended_time=? WHERE id=?')
    .run(next.name, next.startTime, next.dismissalTime, next.extendedTime, req.school.id);
  res.status(204).end();
}));

// A "location" is a campus — some schools run more than one site with
// its own bell schedule (e.g. an early-childhood building vs the main
// campus), so each gets its own start/dismissal/extended time, same
// shape as the school-wide profile above.
app.post('/api/admin/campuses', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { name, address, startTime, dismissalTime, extendedTime } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Location name is required' });
  for (const [label, value] of [['startTime', startTime], ['dismissalTime', dismissalTime], ['extendedTime', extendedTime]]) {
    if (value !== undefined && value !== null && value !== '' && !isValidClockTime(value)) {
      return res.status(400).json({ error: `${label} must be a HH:MM time` });
    }
  }
  const campusId = id('campus');
  try {
    await db.prepare('INSERT INTO campuses (id,school_id,name,address,start_time,dismissal_time,extended_time) VALUES (?,?,?,?,?,?,?)')
      .run(campusId, req.school.id, name.trim(), address?.trim() || null, startTime || null, dismissalTime || null, extendedTime || null);
    res.status(201).json({ id: campusId });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'A location with that name already exists' : error.message });
  }
}));

app.patch('/api/admin/campuses/:id', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { name, address, startTime, dismissalTime, extendedTime } = req.body;
  for (const [label, value] of [['startTime', startTime], ['dismissalTime', dismissalTime], ['extendedTime', extendedTime]]) {
    if (value !== undefined && value !== null && value !== '' && !isValidClockTime(value)) {
      return res.status(400).json({ error: `${label} must be a HH:MM time` });
    }
  }
  const current = await db.prepare('SELECT name,address,start_time AS "startTime",dismissal_time AS "dismissalTime",extended_time AS "extendedTime" FROM campuses WHERE id=? AND school_id=?').get(req.params.id, req.school.id);
  if (!current) return res.status(404).json({ error: 'Location not found' });
  // undefined (field omitted) keeps the existing value; '' explicitly clears it.
  const next = {
    name: name !== undefined && name.trim() ? name.trim() : current.name,
    address: address !== undefined ? (address.trim() || null) : current.address,
    startTime: startTime !== undefined ? (startTime || null) : current.startTime,
    dismissalTime: dismissalTime !== undefined ? (dismissalTime || null) : current.dismissalTime,
    extendedTime: extendedTime !== undefined ? (extendedTime || null) : current.extendedTime,
  };
  try {
    await db.prepare('UPDATE campuses SET name=?, address=?, start_time=?, dismissal_time=?, extended_time=? WHERE id=?')
      .run(next.name, next.address, next.startTime, next.dismissalTime, next.extendedTime, req.params.id);
    res.status(204).end();
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'A location with that name already exists' : error.message });
  }
}));

app.get('/api/admin/classes', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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

app.post('/api/admin/classes', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { name, gradeLevelId, roomName, schoolYearId, campusId } = req.body;
  if (!name?.trim() || !gradeLevelId || !schoolYearId) return res.status(400).json({ error: 'Class name, grade, and school year are required' });
  const year = await db.prepare('SELECT id FROM school_years WHERE id=? AND school_id=?').get(schoolYearId, req.school.id);
  if (!year) return res.status(400).json({ error: 'That school year does not belong to this school' });
  let resolvedCampusId = campusId || null;
  if (!resolvedCampusId) {
    resolvedCampusId = (await db.prepare('SELECT id FROM campuses WHERE school_id=? ORDER BY name LIMIT 1').get(req.school.id))?.id || null;
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

app.get('/api/admin/teachers', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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

app.post('/api/admin/teachers', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { fullName, email, password, photoDataUrl, classId } = req.body;
  if (!fullName?.trim() || !email?.trim() || !password) return res.status(400).json({ error: 'Name, email, and password are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  let photoUrl;
  try {
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
      await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,photo_url,role) VALUES (?,?,?,?,?,'teacher')`)
        .run(userId, fullName.trim(), email.trim(), passwordHash(password), photoUrl);
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'teacher')`)
        .run(id('membership'), userId, req.school.id, assignedClass?.campusId || null);
      if (assignedClass) await db.prepare('UPDATE classes SET teacher_user_id=? WHERE id=?').run(userId, assignedClass.id);
      return userId;
    });
    res.status(201).json({ id: userId });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'That email is already in use.' : error.message });
  }
}));

// Edit an existing teacher: name, photo, and/or which classroom they're
// assigned to (passing classId: null unassigns them; omitting it leaves
// the assignment as-is). No password reset here — out of scope for now.
app.patch('/api/admin/teachers/:id', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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

app.get('/api/admin/students', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const active = await db.prepare(`${studentSelect} WHERE s.school_id=? AND y.status='ACTIVE' ORDER BY s.last_name,s.first_name`).all(req.school.id);
  const guardianQuery = db.prepare(`SELECT gu.id,u.full_name AS "fullName",u.email,sg.relationship,sg.can_pick_up AS "canPickUp",sg.is_primary AS "isPrimary" FROM student_guardians sg JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id WHERE sg.student_id=?`);
  // `status` mirrors pickupStatus everywhere else this shape is used (the
  // Child type); the real enrollment status (ACTIVE/SUSPENDED) that admin
  // actions toggle gets its own field so it doesn't collide with that.
  const students = await Promise.all(active.map(async student => ({ ...student, status: student.pickupStatus, enrollmentStatus: student.status, daycare: Boolean(student.daycare), guardians: await guardianQuery.all(student.id) })));
  res.json(students);
}));

app.post('/api/admin/students', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { firstName, lastName, dateOfBirth, studentNumber, photoDataUrl, schoolYearId, gradeLevelId, classId, daycare, guardian } = req.body;
  if (!firstName?.trim() || !lastName?.trim() || !schoolYearId || !gradeLevelId) return res.status(400).json({ error: 'Name, school year, and grade are required' });
  if (!classId) return res.status(400).json({ error: 'Select a class so pickup requests reach a teacher' });
  const selectedClass = await db.prepare('SELECT campus_id FROM classes WHERE id=? AND school_id=? AND school_year_id=? AND grade_level_id=?').get(classId, req.school.id, schoolYearId, gradeLevelId);
  if (!selectedClass) return res.status(400).json({ error: 'The selected class, grade, or school year does not belong to this school' });
  let guardianId = guardian?.id;
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
          await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'parent') ON CONFLICT (user_id, school_id, COALESCE(campus_id, ''), role) DO NOTHING`).run(id('membership'), existing.user_id, req.school.id, null);
        }
        else {
          if (!guardian.fullName?.trim() || !guardian.temporaryPassword) throw new Error('New guardian name and temporary password are required');
          const userId = id('parent'); guardianId = id('guardian');
          await db.prepare(`INSERT INTO users (id,full_name,email,phone,password_hash,role) VALUES (?,?,?,?,?,'parent')`).run(userId, guardian.fullName.trim(), guardian.email.trim(), guardian.phone || null, passwordHash(guardian.temporaryPassword));
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
    res.status(201).json({ id: studentId });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'Student number or guardian email already exists' : error.message });
  }
}));

app.post('/api/admin/students/:studentId/guardians', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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
app.patch('/api/admin/students/:id', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const status = req.body.status === 'SUSPENDED' ? 'SUSPENDED' : 'ACTIVE';
  const result = await db.prepare('UPDATE students SET status=? WHERE id=? AND school_id=?').run(status, req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Student not found' });
  res.status(204).end();
}));

app.delete('/api/admin/students/:id', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const result = await db.prepare(`UPDATE students SET status='ARCHIVED' WHERE id=? AND school_id=?`).run(req.params.id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Student not found' });
  res.status(204).end();
}));

app.get('/api/admin/guardians', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const guardians = await db.prepare(`SELECT DISTINCT gu.id, u.full_name AS "fullName", u.email, u.phone, m.status FROM guardians gu JOIN users u ON u.id=gu.user_id JOIN memberships m ON m.user_id=u.id WHERE m.school_id=? AND m.role='parent' ORDER BY u.full_name`).all(req.school.id);
  const children = db.prepare(`SELECT s.id, s.first_name || ' ' || s.last_name AS "fullName" FROM student_guardians sg JOIN students s ON s.id=sg.student_id WHERE sg.guardian_id=? AND s.school_id=?`);
  const result = await Promise.all(guardians.map(async g => ({ ...g, active: g.status === 'ACTIVE', children: await children.all(g.id, req.school.id) })));
  res.json(result);
}));

app.post('/api/admin/guardians', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const { fullName, email, phone, temporaryPassword } = req.body;
  if (!fullName?.trim() || !email?.trim() || !temporaryPassword) return res.status(400).json({ error: 'Name, email, and temporary password are required' });
  try {
    const guardianId = await withTransaction(async () => {
      let user = await db.prepare('SELECT id FROM users WHERE LOWER(email)=LOWER(?)').get(email.trim());
      let guardianId;
      if (user) {
        const guardian = await db.prepare('SELECT id FROM guardians WHERE user_id=?').get(user.id);
        if (!guardian) throw new Error('This email belongs to a non-parent account');
        guardianId = guardian.id;
      } else {
        user = { id: id('parent') }; guardianId = id('guardian');
        await db.prepare(`INSERT INTO users (id,full_name,email,phone,password_hash,role) VALUES (?,?,?,?,?,'parent')`).run(user.id, fullName.trim(), email.trim(), phone?.trim() || null, passwordHash(temporaryPassword));
        await db.prepare('INSERT INTO guardians (id,user_id) VALUES (?,?)').run(guardianId, user.id);
      }
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'parent')`).run(id('membership'), user.id, req.school.id, null);
      return guardianId;
    });
    res.status(201).json({ id: guardianId });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'Parent already belongs to this school' : error.message });
  }
}));

app.patch('/api/admin/guardians/:id', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
  const guardian = await db.prepare('SELECT user_id FROM guardians WHERE id=?').get(req.params.id);
  if (!guardian) return res.status(404).json({ error: 'Guardian not found' });
  const result = await db.prepare(`UPDATE memberships SET status=? WHERE user_id=? AND school_id=? AND role='parent'`).run(req.body.active ? 'ACTIVE' : 'SUSPENDED', guardian.user_id, req.school.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Parent membership not found in this school' });
  res.status(204).end();
}));

app.delete('/api/admin/guardians/:id', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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

app.post('/api/admin/promotions', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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
app.post('/api/admin/promotions/by-grade', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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
app.post('/api/admin/promotions/by-class', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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

app.post('/api/notices', requireAuth, asyncRoute(async (req, res) => {
  const { title, body, targetType, targetParentUserId } = req.body;
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
        .run(id('notice'), membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'teacher', title.trim(), body.trim(), 'PARENT', targetParentUserId);
    } else {
      await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_teacher_id) VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(id('notice'), membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'teacher', title.trim(), body.trim(), 'CLASS', req.user.id);
    }
    return res.status(204).end();
  }

  const isSchoolAdmin = (await getMemberships(req.user.id)).some(m => ['school_admin', 'platform_super_admin'].includes(m.role));
  if (!isSchoolAdmin) return res.status(403).json({ error: 'Only a teacher or school admin can send notices.' });
  const membership = (await getMemberships(req.user.id)).find(m => ['school_admin', 'platform_super_admin'].includes(m.role));
  await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type) VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(id('notice'), membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'admin', title.trim(), body.trim(), 'SCHOOL');
  res.status(204).end();
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
app.get('/api/admin/notices', requireAuth, requireSchoolAccess('school_admin'), asyncRoute(async (req, res) => {
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
app.post('/api/me/guardians', requireAuth, requireRole('parent'), asyncRoute(async (req, res) => {
  const { fullName, email, phone, relationship, temporaryPassword } = req.body;
  if (!fullName?.trim() || !email?.trim() || !relationship?.trim() || !temporaryPassword) {
    return res.status(400).json({ error: 'Name, email, relationship, and a temporary password are required' });
  }
  const myGuardian = await db.prepare('SELECT id FROM guardians WHERE user_id=?').get(req.user.id);
  if (!myGuardian) return res.status(403).json({ error: 'No guardian profile found for this account' });
  const membership = (await getMemberships(req.user.id)).find(m => m.role === 'parent');
  if (!membership) return res.status(403).json({ error: 'No active parent membership' });
  const myLinks = await db.prepare(`
    SELECT sg.student_id AS "studentId", sg.can_pick_up AS "canPickUp", sg.can_manage AS "canManage",
      s.first_name || ' ' || s.last_name AS "fullName"
    FROM student_guardians sg JOIN students s ON s.id=sg.student_id
    WHERE sg.guardian_id=? AND s.school_id=? AND s.status='ACTIVE'`).all(myGuardian.id, membership.schoolId);
  if (myLinks.length === 0) return res.status(400).json({ error: "You don't have any children linked to this account yet." });

  try {
    const guardianId = await withTransaction(async () => {
      let user = await db.prepare('SELECT id FROM users WHERE LOWER(email)=LOWER(?)').get(email.trim());
      let guardianId;
      if (user) {
        const guardian = await db.prepare('SELECT id FROM guardians WHERE user_id=?').get(user.id);
        if (!guardian) throw new Error('This email belongs to a non-parent account');
        guardianId = guardian.id;
      } else {
        user = { id: id('parent') }; guardianId = id('guardian');
        await db.prepare(`INSERT INTO users (id,full_name,email,phone,password_hash,role) VALUES (?,?,?,?,?,'parent')`)
          .run(user.id, fullName.trim(), email.trim(), phone?.trim() || null, passwordHash(temporaryPassword));
        await db.prepare('INSERT INTO guardians (id,user_id) VALUES (?,?)').run(guardianId, user.id);
      }
      await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?, 'parent') ON CONFLICT (user_id, school_id, COALESCE(campus_id, ''), role) DO NOTHING`)
        .run(id('membership'), user.id, membership.schoolId, membership.campusId);
      const link = db.prepare(`
        INSERT INTO student_guardians (student_id,guardian_id,relationship,can_pick_up,can_manage) VALUES (?,?,?,?,?)
        ON CONFLICT(student_id,guardian_id) DO UPDATE SET relationship=excluded.relationship, can_pick_up=excluded.can_pick_up, can_manage=excluded.can_manage`);
      for (const student of myLinks) await link.run(student.studentId, guardianId, relationship.trim(), student.canPickUp, student.canManage);

      const childNames = myLinks.map(s => s.fullName).join(', ');
      await db.prepare(`INSERT INTO notices (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type) VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(id('notice'), membership.schoolId, membership.campusId, req.user.id, req.user.full_name, 'parent',
          'New guardian added', `${req.user.full_name} added ${fullName.trim()} (${relationship.trim()}) as a guardian for ${childNames}.`, 'ADMIN');

      return guardianId;
    });
    res.status(201).json({ id: guardianId });
  } catch (error) {
    res.status(400).json({ error: isUniqueViolation(error) ? 'That email is already registered' : error.message });
  }
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

app.listen(port, () => {
  console.log(`Server listening on ${port}`);
});
