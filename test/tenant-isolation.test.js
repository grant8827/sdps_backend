import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import pg from 'pg';

const { Client } = pg;

// Postgres has no equivalent of "just create a throwaway SQLite file" —
// instead, create a disposable database on whatever Postgres server
// DATABASE_URL already points at (local dev or CI), run the app's own
// schema/migrations/seed against it via db.js, and drop it afterward.
const baseUrl = new URL(process.env.DATABASE_URL || 'postgres://localhost:5432/postgres');
const testDbName = `school_test_${randomUUID().replace(/-/g, '')}`;
const adminUrl = new URL(baseUrl);
adminUrl.pathname = '/postgres';

const admin = new Client({ connectionString: adminUrl.toString() });
await admin.connect();
await admin.query(`CREATE DATABASE "${testDbName}"`);
await admin.end();

const testUrl = new URL(baseUrl);
testUrl.pathname = `/${testDbName}`;
process.env.DATABASE_URL = testUrl.toString();
process.env.SEED_DEMO_DATA = 'true'; // the tests use the demo school's accounts

const { db, passwordHash } = await import('../db.js');
const { login } = await import('../auth.js');
const { canAccessSchool, getMemberships, requireSchoolAccess } = await import('../tenant.js');

process.env.NODE_ENV = 'test';
// Most tests sign admins in with just a password; the two-step
// verification tests at the end switch the requirement back on.
process.env.REQUIRE_ADMIN_MFA = 'false';
const { app } = await import('../index.js');
const server = app.listen(0);
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  server.once('error', reject);
});
const apiBaseUrl = `http://127.0.0.1:${server.address().port}`;

await db.prepare(`INSERT INTO organizations (id,name) VALUES ('organization-b','Organization B')`).run();
await db.prepare(`INSERT INTO schools (id,organization_id,name,code) VALUES ('school-b','organization-b','School B','SCHOOLB')`).run();
await db.prepare(`INSERT INTO campuses (id,school_id,name) VALUES ('campus-b','school-b','School B Main')`).run();
await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES ('admin-b','School B Admin','admin-b@test.local',?,'admin')`).run(passwordHash('password'));
await db.prepare(`INSERT INTO memberships (id,user_id,school_id,role) VALUES ('membership-admin-b','admin-b','school-b','school_admin')`).run();
await db.prepare(`INSERT INTO students (id,first_name,last_name,student_number,school_id,campus_id) VALUES ('student-b','Private','Student','B-1','school-b','campus-b')`).run();

after(async () => {
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  await db.close();
  const cleanup = new Client({ connectionString: adminUrl.toString() });
  await cleanup.connect();
  await cleanup.query(`DROP DATABASE IF EXISTS "${testDbName}"`);
  await cleanup.end();
});

async function sendParentNotice(token, input) {
  return fetch(`${apiBaseUrl}/api/notices`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
}

test('parent messaging is limited to their children\'s teachers and the admin', async () => {
  const session = await login('parent@school.test', 'password');
  assert.ok(session?.token);

  const parentAttemptTitle = `forged-parent-target-${randomUUID()}`;
  const parentAttempt = await sendParentNotice(session.token, {
    title: parentAttemptTitle,
    body: 'This must not reach another parent.',
    targetType: 'PARENT',
    targetParentUserId: 'parent-2',
  });
  assert.equal(parentAttempt.status, 400);
  assert.match((await parentAttempt.json()).error, /only message/i);
  assert.equal(await db.prepare('SELECT id FROM notices WHERE title=?').get(parentAttemptTitle), undefined);

  const unrelatedTeacher = await sendParentNotice(session.token, {
    title: `unrelated-teacher-${randomUUID()}`,
    body: 'This must be rejected.',
    targetType: 'TEACHER',
    targetStaffUserId: 'teacher-2',
  });
  assert.equal(unrelatedTeacher.status, 403);

  const teacherTitle = `child-teacher-${randomUUID()}`;
  const validTeacher = await sendParentNotice(session.token, {
    title: teacherTitle,
    body: 'Valid teacher message.',
    targetType: 'TEACHER',
    targetStaffUserId: 'teacher-1',
  });
  assert.equal(validTeacher.status, 204);
  const teacherNotice = await db.prepare('SELECT target_type, target_staff_user_id FROM notices WHERE title=?').get(teacherTitle);
  assert.deepEqual(teacherNotice, { target_type: 'STAFF', target_staff_user_id: 'teacher-1' });

  const adminTitle = `school-admin-${randomUUID()}`;
  const validAdmin = await sendParentNotice(session.token, {
    title: adminTitle,
    body: 'Valid admin message.',
    targetType: 'ADMIN',
  });
  assert.equal(validAdmin.status, 204);
  const adminNotice = await db.prepare('SELECT target_type FROM notices WHERE title=?').get(adminTitle);
  assert.deepEqual(adminNotice, { target_type: 'ADMIN' });
});

test('existing users are backfilled into the default school', async () => {
  const memberships = await getMemberships('admin-1');
  assert.equal(memberships.length, 1);
  assert.equal(memberships[0].schoolId, 'school-default');
  assert.equal(memberships[0].role, 'school_admin');
});

test('School A admin cannot access School B', async () => {
  assert.equal(await canAccessSchool('admin-1', 'school-b', ['school_admin']), null);
  assert.equal((await canAccessSchool('admin-b', 'school-b', ['school_admin'])).schoolId, 'school-b');
});

test('forging X-School-ID is rejected by middleware', async () => {
  const req = { user: { id: 'admin-1' }, headers: { 'x-school-id': 'school-b' }, query: {}, body: {} };
  let statusCode; let responseBody; let nextCalled = false;
  const res = { status(code) { statusCode = code; return this; }, json(body) { responseBody = body; return this; } };
  await requireSchoolAccess('school_admin')(req, res, () => { nextCalled = true; });
  assert.equal(statusCode, 403);
  assert.equal(nextCalled, false);
  assert.match(responseBody.error, /do not have access/i);
});

test('school-scoped student query cannot return another school student', async () => {
  const schoolAStudents = await db.prepare('SELECT id FROM students WHERE school_id=?').all('school-default');
  const schoolBStudents = await db.prepare('SELECT id FROM students WHERE school_id=?').all('school-b');
  assert.equal(schoolAStudents.some(student => student.id === 'student-b'), false);
  assert.deepEqual(schoolBStudents.map(student => student.id), ['student-b']);
});

async function apiCall(method, path, token, body) {
  return fetch(`${apiBaseUrl}/api${path}`, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function addSchoolUser(userId, role, membershipRole, passwordHashValue = passwordHash('password')) {
  await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES (?,?,?,?,?)`).run(userId, userId, `${userId}@test.local`, passwordHashValue, role);
  await db.prepare(`INSERT INTO memberships (id,user_id,school_id,role) VALUES (?,?,'school-default',?)`).run(`membership-${userId}`, userId, membershipRole);
}

test('passwords get a per-user salt, and legacy hashes are upgraded on login', async () => {
  assert.notEqual(passwordHash('same-password'), passwordHash('same-password'));
  const { scryptSync } = await import('node:crypto');
  await addSchoolUser('legacy-user', 'teacher', 'teacher', scryptSync('password', 'school-dropoff-local-v1', 64).toString('hex'));
  assert.ok((await login('legacy-user@test.local', 'password'))?.token);
  const { password_hash: upgraded } = await db.prepare('SELECT password_hash FROM users WHERE id=?').get('legacy-user');
  assert.match(upgraded, /^scrypt\$/);
  assert.ok((await login('legacy-user@test.local', 'password'))?.token);
  assert.equal(await login('legacy-user@test.local', 'wrong'), null);
});

test('a suspended teacher is signed out and cannot sign back in', async () => {
  await addSchoolUser('teacher-suspend', 'teacher', 'teacher');
  const { token } = await login('teacher-suspend@test.local', 'password');
  assert.equal((await apiCall('GET', '/teacher/class', token)).status, 200);
  await db.prepare(`UPDATE memberships SET status='SUSPENDED' WHERE user_id='teacher-suspend'`).run();
  assert.equal((await apiCall('GET', '/teacher/class', token)).status, 401);
  assert.equal(await login('teacher-suspend@test.local', 'password'), null);
});

test('a suspended parent can no longer reach their children or request a pickup', async () => {
  await addSchoolUser('parent-suspend', 'parent', 'parent');
  await db.prepare(`INSERT INTO guardians (id,user_id) VALUES ('guardian-suspend','parent-suspend')`).run();
  await db.prepare(`INSERT INTO student_guardians (student_id,guardian_id) VALUES ('child-3','guardian-suspend')`).run();
  const { token } = await login('parent-suspend@test.local', 'password');
  assert.equal((await apiCall('GET', '/me/classes', token)).status, 200);
  await db.prepare(`UPDATE memberships SET status='SUSPENDED' WHERE user_id='parent-suspend'`).run();
  assert.equal((await apiCall('POST', '/me/students/child-3/pick-up', token, { latitude: 0, longitude: 0 })).status, 401);
});

test('front desk staff can read the admin console but not change data', async () => {
  await addSchoolUser('front-desk', 'admin', 'staff');
  const { token } = await login('front-desk@test.local', 'password');
  assert.equal((await apiCall('GET', '/admin/students', token)).status, 200);
  assert.equal((await apiCall('GET', '/admin/guardians', token)).status, 200);
  assert.equal((await apiCall('POST', '/admin/staff', token, { fullName: 'Sneaky Admin', email: 'sneaky@test.local', password: 'password', role: 'admin' })).status, 403);
  assert.equal((await apiCall('DELETE', '/admin/students/child-1', token)).status, 403);
  assert.equal((await apiCall('POST', '/admin/students/child-1/guardians', token, { guardianId: 'guardian-2' })).status, 403);
  assert.equal((await apiCall('PATCH', '/admin/school', token, { name: 'Renamed' })).status, 403);
  assert.equal((await db.prepare(`SELECT status FROM students WHERE id='child-1'`).get()).status, 'ACTIVE');
});

test('repeated failed sign-ins lock the account name for a while', async () => {
  const identifier = `nobody-${randomUUID()}@test.local`;
  for (let attempt = 0; attempt < 5; attempt++) {
    assert.equal((await apiCall('POST', '/auth/login', null, { identifier, password: 'wrong' })).status, 401);
  }
  assert.equal((await apiCall('POST', '/auth/login', null, { identifier, password: 'wrong' })).status, 429);
});

test('responses carry security headers', async () => {
  const response = await apiCall('GET', '/health');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/);
});

// Audit entries are written once the response has finished, so give
// the write a moment to land before asserting on it.
async function waitForAudit(where, params) {
  for (let attempt = 0; attempt < 40; attempt++) {
    const row = await db.prepare(`SELECT * FROM audit_logs WHERE ${where} ORDER BY created_at DESC, id DESC LIMIT 1`).get(...params);
    if (row) return row;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  return undefined;
}

test('changing a student record is audited with who did it and to whom', async () => {
  await db.prepare(`INSERT INTO students (id,first_name,last_name,school_id) VALUES ('student-audit','Audit','Kid','school-default')`).run();
  const { token } = await login('admin@school.test', 'password');
  assert.equal((await apiCall('DELETE', '/admin/students/student-audit', token)).status, 204);
  const entry = await waitForAudit(`action='STUDENT_REMOVED' AND target_id=?`, ['student-audit']);
  assert.ok(entry);
  assert.equal(entry.school_id, 'school-default');
  assert.equal(entry.actor_user_id, 'admin-1');
  assert.equal(entry.actor_name, 'Alex Admin');
  assert.equal(entry.actor_role, 'school_admin');
  assert.equal(entry.target_label, 'Audit Kid');
});

test('accepting a pickup is audited as PICKUP_ACCEPTED', async () => {
  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,teacher_user_id,request_type,requested_by_user_id) VALUES ('queue-audit','school-default','child-1','teacher-1','PICK_UP','parent-1')`).run();
  const { token } = await login('teacher@school.test', 'password');
  assert.equal((await apiCall('POST', '/queue/queue-audit/approve', token)).status, 204);
  const entry = await waitForAudit(`action='PICKUP_ACCEPTED' AND details LIKE ?`, ['%queue-audit%']);
  assert.ok(entry);
  assert.equal(entry.target_id, 'child-1');
  assert.equal(entry.actor_user_id, 'teacher-1');
  assert.equal(entry.school_id, 'school-default');
});

test('audit entries never store passwords', async () => {
  const { token } = await login('admin@school.test', 'password');
  const email = `audited-parent-${randomUUID()}@test.local`;
  assert.equal((await apiCall('POST', '/admin/guardians', token, { fullName: 'Audited Parent', email, temporaryPassword: 'super-secret-123' })).status, 201);
  const entry = await waitForAudit(`action='PARENT_CREATED' AND details LIKE ?`, [`%${email}%`]);
  assert.ok(entry);
  assert.doesNotMatch(entry.details, /super-secret-123|temporaryPassword/);
});

test('failed sign-ins are audited under the account\'s school', async () => {
  assert.equal((await apiCall('POST', '/auth/login', null, { identifier: 'morgan@school.test', password: 'wrong' })).status, 401);
  const entry = await waitForAudit(`action='SIGN_IN_FAILED' AND target_id=?`, ['parent-2']);
  assert.ok(entry);
  assert.equal(entry.school_id, 'school-default');
});

test('the audit log cannot be edited or deleted', async () => {
  await assert.rejects(db.prepare(`UPDATE audit_logs SET action='HIDDEN'`).run(), /append-only/);
  await assert.rejects(db.prepare(`DELETE FROM audit_logs`).run(), /append-only/);
});

test('only that school\'s admins can read its audit log', async () => {
  const admin = await login('admin@school.test', 'password');
  const response = await apiCall('GET', '/admin/audit-log', admin.token);
  assert.equal(response.status, 200);
  const { entries, actions } = await response.json();
  assert.ok(entries.length > 0);
  assert.ok(actions.includes('STUDENT_REMOVED'));
  assert.ok(entries.every(entry => entry.actorUserId !== 'admin-b'));

  const frontDesk = await login('front-desk@test.local', 'password');
  assert.equal((await apiCall('GET', '/admin/audit-log', frontDesk.token)).status, 403);

  const otherSchool = await login('admin-b@test.local', 'password');
  const otherEntries = (await (await apiCall('GET', '/admin/audit-log', otherSchool.token)).json()).entries;
  assert.ok(otherEntries.every(entry => entry.action === 'SIGNED_IN' && entry.actorUserId === 'admin-b'));
});

test('an adult added by a parent gets no access until an admin approves', async () => {
  const parent = await login('morgan@school.test', 'password');
  const email = `grandma-${randomUUID()}@test.local`;
  const requested = await apiCall('POST', '/me/guardians', parent.token, { fullName: 'Grandma Kid', email, relationship: 'Grandmother', temporaryPassword: 'temporary-123' });
  assert.equal(requested.status, 201);
  assert.equal((await requested.json()).status, 'PENDING');

  // Pending: can sign in, but sees no children and can't request a pickup.
  const grandma = await login(email, 'temporary-123');
  assert.ok(grandma?.token);
  assert.deepEqual(await (await apiCall('GET', '/me/students', grandma.token)).json(), []);
  assert.equal((await apiCall('POST', '/me/students/child-3/pick-up', grandma.token, { latitude: 0, longitude: 0 })).status, 403);

  // The parent sees it as pending.
  const mine = await (await apiCall('GET', '/me/guardians', parent.token)).json();
  assert.equal(mine.requests.find(r => r.fullName === 'Grandma Kid').status, 'PENDING');

  // Front desk can't decide; another school's admin can't even find it.
  const admin = await login('admin@school.test', 'password');
  const requests = await (await apiCall('GET', '/admin/guardian-requests', admin.token)).json();
  const request = requests.find(r => r.email === email);
  assert.equal(request.status, 'PENDING');
  assert.deepEqual(request.students, ['Casey Kid']);
  assert.equal(request.requestedByName, 'Morgan Guardian');
  const frontDesk = await login('front-desk@test.local', 'password');
  assert.equal((await apiCall('POST', `/admin/guardian-requests/${request.batchId}/approve`, frontDesk.token)).status, 403);
  const otherSchool = await login('admin-b@test.local', 'password');
  assert.equal((await apiCall('POST', `/admin/guardian-requests/${request.batchId}/approve`, otherSchool.token)).status, 404);

  // Approved: pickup rights only, and the parent is told.
  assert.equal((await apiCall('POST', `/admin/guardian-requests/${request.batchId}/approve`, admin.token, {})).status, 204);
  const link = await db.prepare(`SELECT can_pick_up, can_manage FROM student_guardians sg JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id WHERE u.email=? AND sg.student_id='child-3'`).get(email);
  assert.deepEqual(link, { can_pick_up: 1, can_manage: 0 });
  assert.equal((await (await apiCall('GET', '/me/students', grandma.token)).json()).length, 1);
  assert.ok(await db.prepare(`SELECT 1 FROM notices WHERE target_parent_user_id='parent-2' AND title='Guardian approved'`).get());
  assert.ok(await waitForAudit(`action='PICKUP_AUTHORIZATION_APPROVED' AND details LIKE ?`, [`%${request.batchId}%`]));
  assert.equal((await apiCall('POST', `/admin/guardian-requests/${request.batchId}/approve`, admin.token, {})).status, 404);

  // A pickup-only adult can't add further adults.
  const chained = await apiCall('POST', '/me/guardians', grandma.token, { fullName: 'Stranger', email: `stranger-${randomUUID()}@test.local`, relationship: 'Other', temporaryPassword: 'temporary-123' });
  assert.equal(chained.status, 403);
});

test('a rejected adult never gets linked, and the request is kept as history', async () => {
  const parent = await login('morgan@school.test', 'password');
  const email = `uncle-${randomUUID()}@test.local`;
  assert.equal((await apiCall('POST', '/me/guardians', parent.token, { fullName: 'Uncle Kid', email, relationship: 'Uncle', temporaryPassword: 'temporary-123' })).status, 201);
  const admin = await login('admin@school.test', 'password');
  const request = (await (await apiCall('GET', '/admin/guardian-requests', admin.token)).json()).find(r => r.email === email);
  assert.equal((await apiCall('POST', `/admin/guardian-requests/${request.batchId}/reject`, admin.token, { note: 'Not on the emergency contact form' })).status, 204);
  assert.equal(await db.prepare(`SELECT 1 FROM student_guardians sg JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id WHERE u.email=?`).get(email), undefined);
  const history = (await (await apiCall('GET', '/admin/guardian-requests', admin.token)).json()).find(r => r.batchId === request.batchId);
  assert.equal(history.status, 'REJECTED');
  assert.equal(history.decisionNote, 'Not on the emergency contact form');
  assert.equal(history.decidedByName, 'Alex Admin');
});

test('a pickup needs the one-time code from the requesting parent\'s phone', async () => {
  await db.prepare(`UPDATE campuses SET latitude=40, longitude=-74 WHERE id=(SELECT campus_id FROM students WHERE id='child-3')`).run();
  await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id='child-3'`).run();
  const parent = await login('morgan@school.test', 'password');
  const requested = await apiCall('POST', '/me/students/child-3/pick-up', parent.token, { latitude: 40, longitude: -74 });
  assert.equal(requested.status, 201);
  const { id: queueId, pickupCode } = await requested.json();
  assert.match(pickupCode, /^\d{6}$/);

  // Only the requesting adult sees the code — not the child's other guardians.
  const children = await (await apiCall('GET', '/me/students', parent.token)).json();
  assert.equal(children.find(c => c.id === 'child-3').pickupCode, pickupCode);
  const grandma = await db.prepare(`SELECT u.email FROM student_guardians sg JOIN guardians gu ON gu.id=sg.guardian_id JOIN users u ON u.id=gu.user_id WHERE sg.student_id='child-3' AND u.id<>'parent-2' AND u.email LIKE 'grandma-%'`).get();
  const other = await login(grandma.email, 'temporary-123');
  assert.equal((await (await apiCall('GET', '/me/students', other.token)).json()).find(c => c.id === 'child-3').pickupCode, null);

  // The teacher's queue says a code is needed but never shows it.
  const teacher = await login('jordan@school.test', 'password');
  const queued = (await (await apiCall('GET', '/teacher/queue', teacher.token)).json()).find(item => item.id === queueId);
  assert.equal(queued.requiresCode, true);
  assert.equal(JSON.stringify(queued).includes(pickupCode), false);

  const wrongCode = pickupCode === '000000' ? '111111' : '000000';
  assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, teacher.token, {})).status, 422);
  const wrong = await apiCall('POST', `/queue/${queueId}/approve`, teacher.token, { code: wrongCode });
  assert.equal(wrong.status, 422);
  assert.match((await wrong.json()).error, /3 tries left/);
  assert.ok(await waitForAudit(`action='PICKUP_CODE_REJECTED' AND details LIKE ?`, [`%${queueId}%`]));
  // A teacher can't skip the code.
  assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, teacher.token, { overrideReason: 'trust me' })).status, 403);

  assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, teacher.token, { code: pickupCode })).status, 204);
  const done = await db.prepare(`SELECT status, pickup_code, verification_method FROM queue_items WHERE id=?`).get(queueId);
  assert.deepEqual(done, { status: 'APPROVED', pickup_code: null, verification_method: 'CODE' });
  const entry = await waitForAudit(`action='PICKUP_ACCEPTED' AND details LIKE ?`, [`%${queueId}%`]);
  assert.match(entry.details, /"verificationMethod":"CODE"/);
});

test('an admin can release a child without the code only by giving a reason', async () => {
  await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id='child-3'`).run();
  const parent = await login('morgan@school.test', 'password');
  const { id: queueId } = await (await apiCall('POST', '/me/students/child-3/pick-up', parent.token, { latitude: 40, longitude: -74 })).json();
  const admin = await login('admin@school.test', 'password');
  assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, admin.token, { overrideReason: 'Phone battery dead; checked driver\'s license' })).status, 204);
  const done = await db.prepare(`SELECT verification_method, override_reason FROM queue_items WHERE id=?`).get(queueId);
  assert.deepEqual(done, { verification_method: 'ADMIN_OVERRIDE', override_reason: 'Phone battery dead; checked driver\'s license' });
  const entry = await waitForAudit(`action='PICKUP_ACCEPTED' AND details LIKE ?`, [`%${queueId}%`]);
  assert.match(entry.details, /ADMIN_OVERRIDE/);
});

test('too many wrong pickup codes cancel the request', async () => {
  await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id='child-3'`).run();
  const parent = await login('morgan@school.test', 'password');
  const { id: queueId, pickupCode } = await (await apiCall('POST', '/me/students/child-3/pick-up', parent.token, { latitude: 40, longitude: -74 })).json();
  const wrongCode = pickupCode === '000000' ? '111111' : '000000';
  const teacher = await login('jordan@school.test', 'password');
  for (let attempt = 1; attempt < 5; attempt++) {
    assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, teacher.token, { code: wrongCode })).status, 422);
  }
  assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, teacher.token, { code: wrongCode })).status, 409);
  assert.equal((await db.prepare(`SELECT status FROM queue_items WHERE id=?`).get(queueId)).status, 'CANCELLED');
  assert.equal((await db.prepare(`SELECT pickup_status FROM students WHERE id='child-3'`).get()).pickup_status, 'PRESENT');
  // The right code no longer works either.
  assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, teacher.token, { code: pickupCode })).status, 404);
});

test('admins must set up two-step verification, then need a code to sign in', async () => {
  const { totpNow } = await import('../mfa.js');
  process.env.REQUIRE_ADMIN_MFA = 'true';
  try {
    await addSchoolUser('mfa-admin', 'admin', 'school_admin');
    const first = await (await apiCall('POST', '/auth/login', null, { identifier: 'mfa-admin@test.local', password: 'password' })).json();
    assert.equal(first.mfaSetupRequired, true);
    assert.equal(first.token, undefined);

    const { secret, otpauthUri } = await (await apiCall('POST', '/auth/mfa/setup', null, { mfaToken: first.mfaToken })).json();
    assert.match(otpauthUri, /^otpauth:\/\/totp\//);
    assert.match((await db.prepare(`SELECT mfa_pending_secret FROM users WHERE id='mfa-admin'`).get()).mfa_pending_secret, /^v1:/);
    const wrongSetupCode = totpNow(secret) === '000000' ? '111111' : '000000';
    assert.equal((await apiCall('POST', '/auth/mfa/setup/confirm', null, { mfaToken: first.mfaToken, code: wrongSetupCode })).status, 401);
    const enrolled = await (await apiCall('POST', '/auth/mfa/setup/confirm', null, { mfaToken: first.mfaToken, code: totpNow(secret) })).json();
    assert.ok(enrolled.token);
    assert.equal(enrolled.recoveryCodes.length, 10);
    assert.ok(await waitForAudit(`action='MFA_ENABLED' AND target_id=?`, ['mfa-admin']));

    // Next sign-in: password alone isn't enough.
    const challenge = await (await apiCall('POST', '/auth/login', null, { identifier: 'mfa-admin@test.local', password: 'password' })).json();
    assert.equal(challenge.mfaRequired, true);
    assert.equal(challenge.token, undefined);
    // The setup code's 30-second step was already used — replaying it fails.
    assert.equal((await apiCall('POST', '/auth/mfa/verify', null, { mfaToken: challenge.mfaToken, code: totpNow(secret) })).status, 401);
    const nextCode = totpNow(secret, Date.now() + 30_000);
    const signedIn = await (await apiCall('POST', '/auth/mfa/verify', null, { mfaToken: challenge.mfaToken, code: nextCode })).json();
    assert.ok(signedIn.token);
    assert.equal((await apiCall('GET', '/admin/students', signedIn.token)).status, 200);
    // A finished challenge can't be reused.
    assert.equal((await apiCall('POST', '/auth/mfa/verify', null, { mfaToken: challenge.mfaToken, code: nextCode })).status, 410);

    // A recovery code works exactly once.
    const recovery = enrolled.recoveryCodes[0];
    const again = await (await apiCall('POST', '/auth/login', null, { identifier: 'mfa-admin@test.local', password: 'password' })).json();
    const viaRecovery = await (await apiCall('POST', '/auth/mfa/verify', null, { mfaToken: again.mfaToken, code: recovery.toLowerCase() })).json();
    assert.ok(viaRecovery.token);
    assert.equal(viaRecovery.recoveryCodesLeft, 9);
    const reuse = await (await apiCall('POST', '/auth/login', null, { identifier: 'mfa-admin@test.local', password: 'password' })).json();
    assert.equal((await apiCall('POST', '/auth/mfa/verify', null, { mfaToken: reuse.mfaToken, code: recovery })).status, 401);

    // Required accounts can't switch it off.
    assert.equal((await apiCall('POST', '/me/mfa/disable', signedIn.token, { password: 'password' })).status, 403);

    // Five wrong codes and the half-finished sign-in is thrown away.
    const guessing = await (await apiCall('POST', '/auth/login', null, { identifier: 'mfa-admin@test.local', password: 'password' })).json();
    const wrong = totpNow(secret) === '123456' ? '654321' : '123456';
    for (let attempt = 1; attempt < 5; attempt++) {
      assert.equal((await apiCall('POST', '/auth/mfa/verify', null, { mfaToken: guessing.mfaToken, code: wrong })).status, 401);
    }
    const lastTry = await apiCall('POST', '/auth/mfa/verify', null, { mfaToken: guessing.mfaToken, code: wrong });
    assert.equal(lastTry.status, 410);
    assert.equal((await lastTry.json()).restart, true);
  } finally {
    process.env.REQUIRE_ADMIN_MFA = 'false';
  }
});

test('teachers can opt in to two-step verification and turn it off with their password', async () => {
  const { totpNow } = await import('../mfa.js');
  await addSchoolUser('mfa-teacher', 'teacher', 'teacher');
  const { token } = await login('mfa-teacher@test.local', 'password');
  assert.deepEqual(await (await apiCall('GET', '/me/mfa', token)).json(), { enabled: false, enabledAt: null, required: false, recoveryCodesLeft: 0 });
  const { secret } = await (await apiCall('POST', '/me/mfa/setup', token)).json();
  const { recoveryCodes } = await (await apiCall('POST', '/me/mfa/confirm', token, { code: totpNow(secret) })).json();
  assert.equal(recoveryCodes.length, 10);
  assert.equal((await login('mfa-teacher@test.local', 'password')).mfaRequired, true);

  assert.equal((await apiCall('POST', '/me/mfa/disable', token, { password: 'wrong' })).status, 401);
  assert.equal((await apiCall('POST', '/me/mfa/disable', token, { password: 'password' })).status, 204);
  assert.ok((await login('mfa-teacher@test.local', 'password')).token);
});

test('an admin can reset a staff member\'s lost two-step verification, which signs them out', async () => {
  const { totpNow } = await import('../mfa.js');
  await addSchoolUser('mfa-lost', 'teacher', 'teacher');
  const { token } = await login('mfa-lost@test.local', 'password');
  const { secret } = await (await apiCall('POST', '/me/mfa/setup', token)).json();
  await apiCall('POST', '/me/mfa/confirm', token, { code: totpNow(secret) });

  const frontDesk = await login('front-desk@test.local', 'password');
  assert.equal((await apiCall('POST', '/admin/staff/mfa-lost/reset-mfa', frontDesk.token)).status, 403);
  const admin = await login('admin@school.test', 'password');
  assert.equal((await apiCall('POST', '/admin/staff/admin-1/reset-mfa', admin.token)).status, 400);
  assert.equal((await apiCall('POST', '/admin/staff/mfa-lost/reset-mfa', admin.token)).status, 204);
  assert.equal((await apiCall('GET', '/me/mfa', token)).status, 401);
  assert.ok((await login('mfa-lost@test.local', 'password')).token);
  assert.ok(await waitForAudit(`action='MFA_RESET' AND target_id=?`, ['mfa-lost']));
});

test('an admin can export one student\'s full record, and front desk cannot', async () => {
  const admin = await login('admin@school.test', 'password');
  const response = await apiCall('GET', '/admin/students/child-3/export', admin.token);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-disposition'), /attachment; filename="student-casey-kid-/);
  const data = await response.json();
  assert.equal(data.student.firstName, 'Casey');
  assert.ok(data.guardians.some(g => g.fullName === 'Morgan Guardian'));
  assert.ok(data.pickupHistory.length > 0);
  assert.ok(data.guardianRequests.length > 0);
  assert.doesNotMatch(JSON.stringify(data), /password_hash|passwordHash|mfa_secret|mfaSecret|scrypt\$|"pickup_code"|"pickupCode"|recovery_code/);
  assert.ok(await waitForAudit(`action='STUDENT_RECORD_EXPORTED' AND target_id=?`, ['child-3']));

  const frontDesk = await login('front-desk@test.local', 'password');
  assert.equal((await apiCall('GET', '/admin/students/child-3/export', frontDesk.token)).status, 403);
  const otherSchool = await login('admin-b@test.local', 'password');
  assert.equal((await apiCall('GET', '/admin/students/child-3/export', otherSchool.token)).status, 404);
});

test('a whole-school export contains the school\'s records but no secrets', async () => {
  const admin = await login('admin@school.test', 'password');
  const data = await (await apiCall('GET', '/admin/export', admin.token)).json();
  assert.ok(data.students.some(s => s.id === 'child-1'));
  assert.ok(data.students.every(s => s.id !== 'student-b'));
  assert.ok(data.staff.length > 0 && data.parents.length > 0);
  assert.doesNotMatch(JSON.stringify(data), /password_hash|passwordHash|mfa_secret|mfaSecret|scrypt\$|"pickup_code"|"pickupCode"|recovery_code/);
});

test('a removed student leaves the list, can be restored, and can be permanently erased', async () => {
  await db.prepare(`INSERT INTO students (id,first_name,last_name,student_number,school_id) VALUES ('student-erase','Erin','Erase','E-77','school-default')`).run();
  await db.prepare(`INSERT INTO student_enrollments (id,student_id,school_year_id,grade_level_id,class_id,school_id) VALUES ('enrollment-erase','student-erase','year-current','grade-2','class-1','school-default')`).run();
  await db.prepare(`INSERT INTO student_guardians (student_id,guardian_id) VALUES ('student-erase','guardian-1')`).run();
  await db.prepare(`INSERT INTO attendance_records (id,school_id,student_id,class_id,date,status,marked_by_user_id) VALUES ('attendance-erase','school-default','student-erase','class-1','2026-09-01','PRESENT','teacher-1')`).run();
  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,request_type,requested_by_user_id,status) VALUES ('queue-erase','school-default','student-erase','DROP_OFF','parent-1','APPROVED')`).run();

  const admin = await login('admin@school.test', 'password');
  const listed = async () => (await (await apiCall('GET', '/admin/students', admin.token)).json()).some(s => s.id === 'student-erase');
  const removedList = async () => (await (await apiCall('GET', '/admin/students/removed', admin.token)).json()).some(s => s.id === 'student-erase');
  assert.equal(await listed(), true);

  // Can't erase a student who hasn't been removed first.
  assert.equal((await apiCall('DELETE', '/admin/students/student-erase/permanent', admin.token, { confirmName: 'Erin Erase' })).status, 404);

  assert.equal((await apiCall('DELETE', '/admin/students/student-erase', admin.token)).status, 204);
  assert.equal(await listed(), false);
  assert.equal(await removedList(), true);
  assert.equal((await apiCall('POST', '/admin/students/student-erase/restore', admin.token)).status, 204);
  assert.equal(await listed(), true);
  assert.equal((await apiCall('DELETE', '/admin/students/student-erase', admin.token)).status, 204);

  const otherSchool = await login('admin-b@test.local', 'password');
  assert.equal((await apiCall('DELETE', '/admin/students/student-erase/permanent', otherSchool.token, { confirmName: 'Erin Erase' })).status, 404);
  assert.equal((await apiCall('DELETE', '/admin/students/student-erase/permanent', admin.token, { confirmName: 'Erin' })).status, 400);
  const erased = await apiCall('DELETE', '/admin/students/student-erase/permanent', admin.token, { confirmName: ' erin  erase ', reason: 'Parent request' });
  assert.equal(erased.status, 200);
  assert.deepEqual((await erased.json()).deleted, { guardianRequests: 0, attendanceRecords: 1, pickupHistory: 1, guardianLinks: 1, enrollments: 1 });
  for (const table of ['students', 'student_enrollments', 'student_guardians', 'attendance_records', 'queue_items']) {
    const column = table === 'students' ? 'id' : 'student_id';
    assert.equal(await db.prepare(`SELECT 1 FROM ${table} WHERE ${column}='student-erase'`).get(), undefined, table);
  }
  const entry = await waitForAudit(`action='STUDENT_PERMANENTLY_DELETED' AND target_id=?`, ['student-erase']);
  assert.equal(entry.target_label, 'E.E. (deleted, #E-77)');
  assert.match(entry.details, /Parent request/);
});

test('retention erases long-removed students and old pickup history on schedule', async () => {
  await db.prepare(`INSERT INTO students (id,first_name,last_name,school_id,status,archived_at) VALUES ('student-old','Old','Leaver','school-default','ARCHIVED','2020-01-01 00:00:00'), ('student-recent','Recent','Leaver','school-default','ARCHIVED',to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'))`).run();
  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,request_type,requested_by_user_id,status,requested_at) VALUES ('queue-old','school-default','child-1','DROP_OFF','parent-1','APPROVED','2020-01-01 08:00:00'), ('queue-old-pending','school-default','child-1','DROP_OFF','parent-1','PENDING','2020-01-01 08:00:00')`).run();
  const admin = await login('admin@school.test', 'password');
  assert.equal((await apiCall('PATCH', '/admin/retention', admin.token, { removedStudentRetentionDays: 7 })).status, 400);
  assert.equal((await apiCall('PATCH', '/admin/retention', admin.token, { removedStudentRetentionDays: 365, queueHistoryRetentionDays: 730 })).status, 204);
  const settings = await (await apiCall('GET', '/admin/retention', admin.token)).json();
  assert.equal(settings.removedStudentRetentionDays, 365);
  assert.ok(settings.wouldDeleteNow.removedStudents >= 1);
  assert.ok(settings.wouldDeleteNow.pickupHistory >= 1);

  const { applyRetentionEverywhere } = await import('../dataRights.js');
  await applyRetentionEverywhere();
  assert.equal(await db.prepare(`SELECT 1 FROM students WHERE id='student-old'`).get(), undefined);
  assert.ok(await db.prepare(`SELECT 1 FROM students WHERE id='student-recent'`).get());
  assert.equal(await db.prepare(`SELECT 1 FROM queue_items WHERE id='queue-old'`).get(), undefined);
  assert.ok(await db.prepare(`SELECT 1 FROM queue_items WHERE id='queue-old-pending'`).get(), 'pending requests are never purged');
  const entry = await db.prepare(`SELECT actor_name, actor_role, details FROM audit_logs WHERE action='STUDENT_PERMANENTLY_DELETED' AND target_id='student-old'`).get();
  assert.equal(entry.actor_name, 'Automatic retention');
  assert.match(entry.details, /Retention/);
  await db.prepare('UPDATE schools SET removed_student_retention_days=NULL, queue_history_retention_days=NULL').run();
});

test('a district admin manages every school in their district and nothing outside it', async () => {
  const { organization_id: districtId } = await db.prepare(`SELECT organization_id FROM schools WHERE id='school-default'`).get();
  await db.prepare(`INSERT INTO schools (id,organization_id,name,code) VALUES ('school-c',?,'School C','SCHOOLC')`).run(districtId);
  await db.prepare(`INSERT INTO students (id,first_name,last_name,school_id) VALUES ('student-c','Cee','Student','school-c')`).run();
  await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES ('district-admin','Dana District','district@test.local',?,'admin')`).run(passwordHash('password'));
  await db.prepare(`INSERT INTO district_memberships (id,user_id,organization_id) VALUES ('district-membership-1','district-admin',?)`).run(districtId);

  const session = await login('district@test.local', 'password');
  const schoolIds = session.user.memberships.map(m => m.schoolId).sort();
  assert.deepEqual(schoolIds, ['school-c', 'school-default']);
  assert.ok(session.user.memberships.every(m => m.role === 'district_admin'));

  const inSchool = (method, path, schoolId, body) => fetch(`${apiBaseUrl}/api${path}`, {
    method, headers: { Authorization: `Bearer ${session.token}`, 'Content-Type': 'application/json', 'X-School-ID': schoolId }, body: body ? JSON.stringify(body) : undefined,
  });
  const schoolCStudents = await (await inSchool('GET', '/admin/students', 'school-c')).json();
  assert.ok(Array.isArray(schoolCStudents));
  assert.equal((await inSchool('GET', '/admin/students', 'school-b')).status, 403);
  assert.equal((await inSchool('GET', '/admin/students/student-b/export', 'school-b')).status, 403);
  // Full admin rights inside the district, audited as a district admin.
  assert.equal((await inSchool('PATCH', '/admin/school', 'school-c', { startTime: '08:15' })).status, 204);
  const entry = await waitForAudit(`action='SCHOOL_SETTINGS_UPDATED' AND school_id='school-c'`, []);
  assert.equal(entry.actor_role, 'district_admin');

  const overview = await (await apiCall('GET', '/district/overview', session.token)).json();
  assert.deepEqual(overview.map(s => s.schoolId).sort(), ['school-c', 'school-default']);
  const teacher = await login('teacher@school.test', 'password');
  assert.equal((await apiCall('GET', '/district/overview', teacher.token)).status, 403);

  // Removing them from the district cuts off access immediately.
  await db.prepare(`UPDATE district_memberships SET status='SUSPENDED' WHERE id='district-membership-1'`).run();
  assert.equal((await apiCall('GET', '/district/overview', session.token)).status, 401);
  assert.equal(await login('district@test.local', 'password'), null);
});

test('a removed staff member can be added back, but other people\'s accounts can\'t be taken over', async () => {
  const admin = await login('admin@school.test', 'password');
  const add = body => apiCall('POST', '/admin/staff', admin.token, { fullName: 'Returning Teacher', password: 'new-password-1', role: 'teacher', ...body });

  const created = await add({ email: 'returning@test.local' });
  assert.equal(created.status, 201);
  const { id: staffId, restored } = await created.json();
  assert.equal(restored, false);
  // Already on staff → refused with a clear message.
  const duplicate = await add({ email: 'returning@test.local' });
  assert.equal(duplicate.status, 400);
  assert.match((await duplicate.json()).error, /already on your staff/);

  assert.equal((await apiCall('DELETE', `/admin/staff/${staffId}`, admin.token)).status, 204);
  const back = await add({ email: 'RETURNING@test.local', role: 'front_desk', password: 'another-pass-2' });
  assert.equal(back.status, 201);
  const backBody = await back.json();
  assert.equal(backBody.id, staffId);
  assert.equal(backBody.restored, true);
  // No email server in tests, so the link comes back for the admin to pass on.
  assert.equal(backBody.emailSent, false);
  assert.match(backBody.setupLink, /\/set-password\?token=/);
  assert.ok((await login('returning@test.local', 'another-pass-2'))?.token);
  const memberships = await db.prepare(`SELECT role, status FROM memberships WHERE user_id=?`).all(staffId);
  assert.deepEqual(memberships, [{ role: 'staff', status: 'ACTIVE' }]);

  // A parent's email, or another school's staff, can't be claimed.
  const parentEmail = await add({ email: 'parent@school.test' });
  assert.equal(parentEmail.status, 400);
  assert.match((await parentEmail.json()).error, /different email/);
  assert.ok((await login('parent@school.test', 'password'))?.token, 'the parent keeps their own password');
  const otherSchool = await add({ email: 'admin-b@test.local' });
  assert.equal(otherSchool.status, 400);
});

test('the primary location stays; an added location can be removed and its students move to the primary', async () => {
  const admin = await login('admin@school.test', 'password');
  const before = (await (await apiCall('GET', '/admin/setup', admin.token)).json()).campuses;
  const primary = before.find(c => c.isPrimary);
  assert.ok(primary);
  assert.equal(before.filter(c => c.isPrimary).length, 1);

  await db.prepare(`INSERT INTO campuses (id,school_id,name,created_at) VALUES ('campus-annex','school-default','Annex','2999-01-01 00:00:00')`).run();
  await db.prepare(`INSERT INTO students (id,first_name,last_name,school_id,campus_id) VALUES ('student-annex','Annie','Annex','school-default','campus-annex')`).run();
  const withAnnex = (await (await apiCall('GET', '/admin/setup', admin.token)).json()).campuses;
  assert.equal(withAnnex.find(c => c.id === 'campus-annex').isPrimary, false);

  assert.equal((await apiCall('DELETE', `/admin/campuses/${primary.id}`, admin.token)).status, 400);
  const frontDesk = await login('front-desk@test.local', 'password');
  assert.equal((await apiCall('DELETE', '/admin/campuses/campus-annex', frontDesk.token)).status, 403);

  const removed = await apiCall('DELETE', '/admin/campuses/campus-annex', admin.token);
  assert.equal(removed.status, 200);
  assert.equal((await removed.json()).moved.students, 1);
  assert.equal((await db.prepare(`SELECT campus_id FROM students WHERE id='student-annex'`).get()).campus_id, primary.id);
  const after = (await (await apiCall('GET', '/admin/setup', admin.token)).json()).campuses;
  assert.ok(after.every(c => c.id !== 'campus-annex'));
  assert.equal((await apiCall('PATCH', '/admin/campuses/campus-annex', admin.token, { name: 'Back again' })).status, 404);
  assert.ok(await waitForAudit(`action='LOCATION_REMOVED' AND target_id=?`, ['campus-annex']));
});

test('a suspended location refuses drop-off and pick-up until reactivated', async () => {
  const { campus_id: campusId } = await db.prepare(`SELECT campus_id FROM students WHERE id='child-3'`).get();
  await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id='child-3'`).run();
  await db.prepare(`UPDATE queue_items SET status='CANCELLED' WHERE student_id='child-3' AND status='PENDING'`).run();
  const admin = await login('admin@school.test', 'password');
  const frontDesk = await login('front-desk@test.local', 'password');
  assert.equal((await apiCall('POST', `/admin/campuses/${campusId}/status`, frontDesk.token, { active: false })).status, 403);
  assert.equal((await apiCall('POST', `/admin/campuses/${campusId}/status`, admin.token, { active: false })).status, 204);
  const setup = await (await apiCall('GET', '/admin/setup', admin.token)).json();
  const campus = setup.campuses.find(c => c.id === campusId);
  assert.equal(campus.status, 'SUSPENDED');
  assert.match(campus.createdAt, /^\d{4}-\d{2}-\d{2}/);

  const parent = await login('morgan@school.test', 'password');
  const paused = await apiCall('POST', '/me/students/child-3/pick-up', parent.token, { latitude: 40, longitude: -74 });
  assert.equal(paused.status, 409);
  assert.match((await paused.json()).error, /paused/);

  assert.equal((await apiCall('POST', `/admin/campuses/${campusId}/status`, admin.token, { active: true })).status, 204);
  assert.equal((await apiCall('POST', '/me/students/child-3/pick-up', parent.token, { latitude: 40, longitude: -74 })).status, 201);
});

test('new accounts choose their own password through an emailed invite link', async () => {
  const admin = await login('admin@school.test', 'password');
  const created = await apiCall('POST', '/admin/staff', admin.token, { fullName: 'Invited Teacher', email: 'invited@test.local', role: 'teacher' });
  assert.equal(created.status, 201);
  const { id: userId, emailSent, setupLink } = await created.json();
  assert.equal(emailSent, false);
  const token = new URL(setupLink).searchParams.get('token');
  assert.ok(token);
  const stored = await db.prepare('SELECT token_hash, purpose FROM account_links WHERE user_id=?').get(userId);
  assert.equal(stored.purpose, 'INVITE');
  assert.notEqual(stored.token_hash, token, 'only a hash of the token is stored');
  assert.equal((await db.prepare('SELECT needs_password_setup FROM users WHERE id=?').get(userId)).needs_password_setup, 1);

  const check = await apiCall('POST', '/auth/account-link', null, { token });
  assert.equal(check.status, 200);
  assert.deepEqual(await check.json(), { purpose: 'INVITE', fullName: 'Invited Teacher', email: 'invited@test.local' });

  assert.equal((await apiCall('POST', '/auth/set-password', null, { token, password: 'short' })).status, 400);
  assert.equal((await apiCall('POST', '/auth/set-password', null, { token: 'not-a-real-token', password: 'chosen-password-1' })).status, 404);
  assert.equal((await apiCall('POST', '/auth/set-password', null, { token, password: 'chosen-password-1' })).status, 200);
  assert.ok((await login('invited@test.local', 'chosen-password-1'))?.token);
  assert.equal((await db.prepare('SELECT needs_password_setup FROM users WHERE id=?').get(userId)).needs_password_setup, 0);
  // A link works once.
  assert.equal((await apiCall('POST', '/auth/set-password', null, { token, password: 'other-password-2' })).status, 404);
  assert.equal((await apiCall('POST', '/auth/account-link', null, { token })).status, 404);
  assert.ok(await waitForAudit(`action='ACCOUNT_SET_UP' AND target_id=?`, [userId]));
});

test('forgot password never reveals whether an email is registered, and a reset link signs out old sessions', async () => {
  const { createAccountLink } = await import('../accountLinks.js');
  const known = await apiCall('POST', '/auth/forgot-password', null, { email: 'jordan@school.test' });
  const unknown = await apiCall('POST', '/auth/forgot-password', null, { email: 'nobody-here@test.local' });
  assert.equal(known.status, 200);
  assert.deepEqual(await known.json(), await unknown.json());
  assert.equal((await apiCall('POST', '/auth/forgot-password', null, { email: 'not-an-email' })).status, 400);
  assert.ok(await waitForAudit(`action='PASSWORD_RESET_REQUESTED' AND target_id='teacher-2'`, []));

  const before = await login('jordan@school.test', 'password');
  const link = await createAccountLink('teacher-2', 'RESET');
  const token = new URL(link).searchParams.get('token');
  // A newer link replaces the older one.
  const newer = new URL(await createAccountLink('teacher-2', 'RESET')).searchParams.get('token');
  assert.equal((await apiCall('POST', '/auth/account-link', null, { token })).status, 404);
  assert.equal((await apiCall('POST', '/auth/set-password', null, { token: newer, password: 'reset-password-9' })).status, 200);
  assert.equal(await login('jordan@school.test', 'password'), null);
  assert.equal((await apiCall('GET', '/me/schools', before.token)).status, 401, 'old sessions end');
  await db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(passwordHash('password'), 'teacher-2');

  // Expired links don't work.
  const expired = new URL(await createAccountLink('teacher-2', 'RESET', -1000)).searchParams.get('token');
  assert.equal((await apiCall('POST', '/auth/set-password', null, { token: expired, password: 'reset-password-9' })).status, 404);
});

test('an admin can email a sign-in link only to people in their own school', async () => {
  const admin = await login('admin@school.test', 'password');
  const own = await apiCall('POST', '/admin/members/teacher-1/send-link', admin.token);
  assert.equal(own.status, 200);
  const body = await own.json();
  assert.equal(body.emailSent, false);
  assert.match(body.setupLink, /set-password/);
  assert.equal((await db.prepare(`SELECT purpose FROM account_links WHERE user_id='teacher-1' AND used_at IS NULL`).get()).purpose, 'RESET');
  assert.equal((await apiCall('POST', '/admin/members/admin-b/send-link', admin.token)).status, 404);
  assert.equal((await apiCall('POST', `/admin/members/${admin.user.id}/send-link`, admin.token)).status, 400);
  const teacher = await login('teacher@school.test', 'password');
  assert.equal((await apiCall('POST', '/admin/members/parent-1/send-link', teacher.token)).status, 403);
});

test('a parent can ask for another adult without choosing a password for them', async () => {
  const parent = await login('parent@school.test', 'password');
  const response = await apiCall('POST', '/me/guardians', parent.token, { fullName: 'Grandma Invite', email: 'grandma-invite@test.local', relationship: 'Grandmother' });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.status, 'PENDING');
  assert.match(body.setupLink, /set-password/);
  assert.ok(await waitForAudit(`action='PICKUP_AUTHORIZATION_REQUESTED' AND target_id=?`, [body.id]));
  // Let the background "new message" emails to the office finish before the database is dropped.
  await new Promise(resolve => setTimeout(resolve, 300));
});
