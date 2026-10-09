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

test('production website can preflight cross-origin API requests', async () => {
  const response = await fetch(`${apiBaseUrl}/api/auth/forgot-password`, {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://www.sdpmplus.com',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type',
    },
  });
  assert.equal(response.status, 204);
  assert.equal(response.headers.get('access-control-allow-origin'), 'https://www.sdpmplus.com');
  assert.match(response.headers.get('access-control-allow-methods'), /POST/);
  assert.match(response.headers.get('access-control-allow-headers'), /Content-Type/i);
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

const MORGAN_PIN = '482913';

test('a pickup needs the parent\'s own 6-digit PIN, created the first time; a drop-off does not', async () => {
  await db.prepare(`UPDATE campuses SET latitude=40, longitude=-74 WHERE id=(SELECT campus_id FROM students WHERE id='child-3')`).run();
  await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id='child-3'`).run();
  const parent = await login('morgan@school.test', 'password');
  const here = { latitude: 40, longitude: -74 };
  const pickUp = pin => apiCall('POST', '/me/students/child-3/pick-up', parent.token, { ...here, ...(pin === undefined ? {} : { pin }) });

  // No PIN yet: the pickup is refused with a code the apps use to show "Create your PIN".
  assert.deepEqual(await (await apiCall('GET', '/me/pin', parent.token)).json(), { hasPin: false });
  const noPin = await pickUp();
  assert.equal(noPin.status, 428);
  assert.equal((await noPin.json()).code, 'PIN_NOT_SET');

  // Creating one: 6 digits, not an obvious one.
  const create = pin => apiCall('POST', '/me/pin', parent.token, { pin });
  for (const bad of ['12345', '1234567', 'abcdef', '000000', '123456', 482913]) assert.equal((await create(bad)).status, 400, String(bad));
  assert.equal((await create(MORGAN_PIN)).status, 204);
  assert.equal((await create('771904')).status, 409, 'a second "create" can\'t replace it');
  assert.deepEqual(await (await apiCall('GET', '/me/pin', parent.token)).json(), { hasPin: true });
  const stored = await db.prepare(`SELECT pickup_pin_hash FROM users WHERE id='parent-2'`).get();
  assert.match(stored.pickup_pin_hash, /^scrypt\$/);
  assert.ok(!stored.pickup_pin_hash.includes(MORGAN_PIN));

  // Missing or wrong PIN: refused, with tries left; nothing is requested.
  assert.equal((await pickUp()).status, 403);
  const wrong = await pickUp('111222');
  assert.equal(wrong.status, 403);
  assert.deepEqual({ ...(await wrong.json()), error: undefined }, { code: 'PIN_WRONG', triesLeft: 3, error: undefined });
  assert.equal((await db.prepare(`SELECT pickup_status FROM students WHERE id='child-3'`).get()).pickup_status, 'PRESENT');
  assert.ok(await waitForAudit(`action='PICKUP_PIN_FAILED' AND actor_user_id='parent-2'`, []));

  // The right PIN: requested, and recorded as PIN-verified. A correct PIN clears the wrong-try count.
  const requested = await pickUp(MORGAN_PIN);
  assert.equal(requested.status, 201);
  const requestText = await requested.text();
  assert.ok(!requestText.includes(MORGAN_PIN));
  const queueId = JSON.parse(requestText).id;
  assert.equal((await db.prepare('SELECT verification_method FROM queue_items WHERE id=?').get(queueId)).verification_method, 'PIN');
  assert.equal(await db.prepare(`SELECT 1 FROM rate_limits WHERE key='pin:parent-2'`).get(), undefined);

  // The teacher just confirms; there is nothing to type.
  const teacher = await login('jordan@school.test', 'password');
  const queued = (await (await apiCall('GET', '/teacher/queue', teacher.token)).json()).find(item => item.id === queueId);
  assert.ok(queued);
  const otherTeacher = await login('teacher@school.test', 'password');
  assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, otherTeacher.token)).status, 403);
  assert.equal((await apiCall('POST', `/queue/${queueId}/approve`, teacher.token)).status, 204);
  assert.equal((await db.prepare(`SELECT pickup_status FROM students WHERE id='child-3'`).get()).pickup_status, 'PICKED_UP');

  // Drop-off needs no PIN.
  await db.prepare(`UPDATE students SET pickup_status='AT_HOME' WHERE id='child-3'`).run();
  const dropOff = await apiCall('POST', '/me/students/child-3/drop-off', parent.token, here);
  assert.equal(dropOff.status, 201);
  await apiCall('POST', `/queue/${(await dropOff.json()).id}/approve`, teacher.token);

  // The PIN is in no audit entry, and only parents have one.
  const leaked = await db.prepare(`SELECT COUNT(*)::int AS n FROM audit_logs WHERE details LIKE ?`).get(`%${MORGAN_PIN}%`);
  assert.equal(leaked.n, 0);
  assert.equal((await apiCall('GET', '/me/pin', teacher.token)).status, 403);
  assert.equal((await apiCall('POST', '/me/pin', teacher.token, { pin: '771904' })).status, 403);
});

test('five wrong PINs lock pickup requests for a while; changing the PIN needs the current one', async () => {
  await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id='child-3'`).run();
  const parent = await login('morgan@school.test', 'password');
  const pickUp = pin => apiCall('POST', '/me/students/child-3/pick-up', parent.token, { latitude: 40, longitude: -74, pin });

  // Changing: wrong current PIN is refused (and counts as a wrong try); weak new PIN is refused.
  const change = (currentPin, newPin) => apiCall('POST', '/me/pin/change', parent.token, { currentPin, newPin });
  assert.equal((await change('999888', '771904')).status, 403);
  assert.equal((await change(MORGAN_PIN, '111111')).status, 400);
  assert.equal((await change(MORGAN_PIN, MORGAN_PIN)).status, 400);
  assert.equal((await change(MORGAN_PIN, '771904')).status, 204);
  assert.equal((await pickUp(MORGAN_PIN)).status, 403, 'the old PIN no longer works');
  assert.ok(await waitForAudit(`action='PICKUP_PIN_CHANGED' AND actor_user_id='parent-2'`, []));

  // Four more wrong tries (five in all) lock it — even the right PIN is refused until the window passes.
  for (let i = 0; i < 3; i++) assert.equal((await pickUp('000111')).status, 403);
  const fifth = await pickUp('000111');
  assert.equal(fifth.status, 429);
  assert.equal((await fifth.json()).code, 'PIN_LOCKED');
  assert.equal((await pickUp('771904')).status, 429);
  assert.equal((await db.prepare(`SELECT count FROM rate_limits WHERE key='pin:parent-2'`).get()).count, 5, 'counted in the shared table');
  assert.ok(await waitForAudit(`action='PICKUP_PIN_LOCKED_OUT' AND actor_user_id='parent-2'`, []));
  assert.equal((await db.prepare(`SELECT pickup_status FROM students WHERE id='child-3'`).get()).pickup_status, 'PRESENT');
});

test('Forgot PIN emails a one-time link that sets a new PIN and nothing else', async () => {
  const { createAccountLink } = await import('../accountLinks.js');
  const parent = await login('morgan@school.test', 'password');
  // No email server in tests: the request is refused clearly rather than pretending it was sent.
  const forgot = await apiCall('POST', '/me/pin/forgot', parent.token);
  assert.equal(forgot.status, 503);
  assert.equal((await forgot.json()).code, 'EMAIL_NOT_SENT');
  const logged = await db.prepare(`SELECT args FROM notification_deliveries WHERE template='pinReset' ORDER BY created_at DESC LIMIT 1`).get();
  assert.doesNotMatch(logged.args, /set-pin|token/);

  const pinLink = await createAccountLink('parent-2', 'PIN_RESET');
  assert.match(pinLink, /\/set-pin\?token=/);
  const pinToken = new URL(pinLink).searchParams.get('token');
  assert.equal((await (await apiCall('POST', '/auth/account-link', null, { token: pinToken })).json()).purpose, 'PIN_RESET');
  // A PIN link can't set a password, and a password link can't set a PIN.
  assert.equal((await apiCall('POST', '/auth/set-password', null, { token: pinToken, password: 'new-password-123' })).status, 404);
  const passwordToken = new URL(await createAccountLink('parent-2', 'RESET')).searchParams.get('token');
  assert.equal((await apiCall('POST', '/auth/set-pin', null, { token: passwordToken, pin: MORGAN_PIN })).status, 404);

  assert.equal((await apiCall('POST', '/auth/set-pin', null, { token: pinToken, pin: '123456' })).status, 400);
  assert.equal((await apiCall('POST', '/auth/set-pin', null, { token: pinToken, pin: MORGAN_PIN })).status, 204);
  assert.equal((await apiCall('POST', '/auth/set-pin', null, { token: pinToken, pin: '771904' })).status, 404, 'a link works once');
  assert.ok(await waitForAudit(`action='PICKUP_PIN_RESET' AND target_id='parent-2'`, []));
  assert.ok((await login('morgan@school.test', 'password'))?.token, 'the password is untouched and they stay signed in');
  assert.equal((await apiCall('GET', '/me/pin', parent.token)).status, 200);

  // Resetting also lifts the lockout from the previous test: the new PIN works straight away.
  await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id='child-3'`).run();
  const requested = await apiCall('POST', '/me/students/child-3/pick-up', parent.token, { latitude: 40, longitude: -74, pin: MORGAN_PIN });
  assert.equal(requested.status, 201);
  await db.prepare(`UPDATE queue_items SET status='CANCELLED' WHERE id=?`).run((await requested.json()).id);
  await db.prepare(`UPDATE students SET pickup_status='PRESENT' WHERE id='child-3'`).run();
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
  assert.equal((await apiCall('POST', '/me/students/child-3/pick-up', parent.token, { latitude: 40, longitude: -74, pin: MORGAN_PIN })).status, 201);
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

// ---- Phase 1: platform administration ------------------------------------------------

async function addPlatformAdmin(userId, role) {
  await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES (?,?,?,?,'admin')`).run(userId, `Platform ${role}`, `${userId}@test.local`, passwordHash('password'));
  await db.prepare(`INSERT INTO platform_admins (user_id,role) VALUES (?,?)`).run(userId, role);
  return login(`${userId}@test.local`, 'password');
}

test('a School B admin cannot read or change any School A record by id, however the school is named', async () => {
  const adminB = await login('admin-b@test.local', 'password');
  const { id: campusA } = await db.prepare(`SELECT id FROM campuses WHERE school_id='school-default' ORDER BY created_at LIMIT 1`).get();
  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,request_type,requested_by_user_id) VALUES ('queue-a','school-default','child-1','PICK_UP','parent-1')`).run();
  const before = await db.prepare(`SELECT status, pickup_status FROM students WHERE id='child-1'`).get();

  const attempts = [
    ['GET', '/admin/students/child-1/export'],
    ['PATCH', '/admin/students/child-1', { status: 'SUSPENDED' }],
    ['DELETE', '/admin/students/child-1'],
    ['POST', '/admin/students/child-1/restore'],
    ['DELETE', '/admin/students/child-1/permanent', { confirmName: 'x' }],
    ['POST', '/admin/students/child-1/guardians', { guardianId: 'guardian-1' }],
    ['PATCH', '/admin/guardians/guardian-1', { active: false }],
    ['DELETE', '/admin/guardians/guardian-1'],
    ['PATCH', '/admin/staff/teacher-1', { active: false }],
    ['POST', '/admin/staff/teacher-1/reset-mfa'],
    ['DELETE', '/admin/staff/teacher-1'],
    ['PATCH', '/admin/teachers/teacher-1', { fullName: 'Taken Over' }],
    ['POST', '/admin/members/parent-1/send-link'],
    ['POST', '/attendance', { studentId: 'child-1', date: '2026-01-05', status: 'ABSENT' }],
    ['GET', '/admin/attendance?classId=class-1'],
    ['POST', '/queue/queue-a/approve'],
    ['POST', '/queue/queue-a/decline'],
    ['PATCH', `/admin/campuses/${campusA}`, { name: 'Taken' }],
  ];
  // As themselves, then claiming School A by header, query string and body.
  for (const [method, path, body] of attempts) {
    for (const variant of ['own', 'header', 'query', 'body']) {
      const url = variant === 'query' ? `${path}${path.includes('?') ? '&' : '?'}schoolId=school-default` : path;
      const response = await fetch(`${apiBaseUrl}/api${url}`, {
        method,
        headers: { Authorization: `Bearer ${adminB.token}`, 'Content-Type': 'application/json', ...(variant === 'header' ? { 'X-School-ID': 'school-default' } : {}) },
        body: method === 'GET' ? undefined : JSON.stringify({ ...(body ?? {}), ...(variant === 'body' ? { schoolId: 'school-default' } : {}) }),
      });
      if (method === 'GET' && response.ok) {
        // A list read may succeed, but only ever with the caller's own school's rows.
        const rows = await response.json();
        assert.ok(Array.isArray(rows) && rows.every(row => row.studentId !== 'child-1' && row.id !== 'child-1'), `${method} ${url} (${variant}) leaked School A data`);
      } else {
        assert.ok([400, 403, 404].includes(response.status), `${method} ${url} (${variant}) returned ${response.status}`);
      }
    }
  }
  // Lists never include the other school's records either.
  const students = await (await apiCall('GET', '/admin/students', adminB.token)).json();
  assert.ok(students.every(s => s.id !== 'child-1'));
  const guardians = await (await apiCall('GET', '/admin/guardians', adminB.token)).json();
  assert.ok(guardians.every(g => g.id !== 'guardian-1'));

  assert.deepEqual(await db.prepare(`SELECT status, pickup_status FROM students WHERE id='child-1'`).get(), before);
  assert.equal((await db.prepare(`SELECT status FROM queue_items WHERE id='queue-a'`).get()).status, 'PENDING');
  assert.equal((await db.prepare(`SELECT full_name FROM users WHERE id='teacher-1'`).get()).full_name !== 'Taken Over', true);
  await db.prepare(`UPDATE queue_items SET status='CANCELLED' WHERE id='queue-a'`).run();
});

test('a platform role alone never opens a school, and the old super-admin membership no longer does either', async () => {
  const superAdmin = await addPlatformAdmin('super-1', 'SUPER_ADMIN');
  assert.ok(superAdmin.token, 'a platform admin with no school can sign in');
  assert.equal(superAdmin.user.platform.role, 'SUPER_ADMIN');
  for (const headers of [{}, { 'X-School-ID': 'school-b' }]) {
    const response = await fetch(`${apiBaseUrl}/api/admin/students`, { headers: { Authorization: `Bearer ${superAdmin.token}`, ...headers } });
    assert.equal(response.status, 403);
  }
  // A leftover platform_super_admin membership (the old design) is just ignored.
  await addSchoolUser('legacy-super', 'admin', 'platform_super_admin');
  const legacy = await login('legacy-super@test.local', 'password');
  for (const headers of [{}, { 'X-School-ID': 'school-b' }, { 'X-School-ID': 'school-default' }]) {
    const response = await fetch(`${apiBaseUrl}/api/admin/students`, { headers: { Authorization: `Bearer ${legacy.token}`, ...headers } });
    assert.equal(response.status, 403, 'a legacy super-admin membership grants no school access');
  }
  assert.equal((await apiCall('GET', '/superadmin/me', legacy.token)).status, 403);
  // ...and the platform's own API is closed to school staff.
  const schoolAdmin = await login('admin@school.test', 'password');
  for (const path of ['/superadmin/me', '/superadmin/schools', '/superadmin/audit-logs', '/superadmin/admins']) {
    assert.equal((await apiCall('GET', path, schoolAdmin.token)).status, 403, path);
  }
  assert.equal((await apiCall('POST', '/superadmin/support-sessions', schoolAdmin.token, { schoolId: 'school-b', reason: 'curious' })).status, 403);
});

test('each platform role can do only what its permissions allow', async () => {
  const billing = await addPlatformAdmin('billing-1', 'BILLING_ADMIN');
  const support = await addPlatformAdmin('support-1', 'SUPPORT_ADMIN');
  assert.deepEqual((await (await apiCall('GET', '/superadmin/me', billing.token)).json()).role, 'BILLING_ADMIN');
  assert.equal((await apiCall('GET', '/superadmin/schools', billing.token)).status, 200);
  assert.equal((await apiCall('GET', '/superadmin/audit-logs', billing.token)).status, 403);
  assert.equal((await apiCall('POST', '/superadmin/schools/school-b/suspend', billing.token, { reason: 'Billing test only' })).status, 403);
  assert.equal((await apiCall('POST', '/superadmin/support-sessions', billing.token, { schoolId: 'school-b', reason: 'Billing question' })).status, 403);
  assert.equal((await apiCall('GET', '/superadmin/audit-logs', support.token)).status, 200);
  assert.equal((await apiCall('POST', '/superadmin/schools', support.token, { name: 'Nope', adminFullName: 'X', adminEmail: 'nope@test.local' })).status, 403);
  assert.equal((await apiCall('GET', '/superadmin/admins', support.token)).status, 403);
  // Responses never carry secrets.
  const body = await (await apiCall('GET', '/superadmin/schools/school-b', support.token)).text();
  assert.doesNotMatch(body, /password|scrypt\$|mfa_secret|token_hash/i);
});

test('platform admins must use two-step verification', async () => {
  process.env.REQUIRE_ADMIN_MFA = 'true';
  try {
    const result = await login('support-1@test.local', 'password');
    assert.equal(result.mfaSetupRequired, true);
    assert.equal(result.token, undefined);
  } finally {
    process.env.REQUIRE_ADMIN_MFA = 'false';
  }
});

test('a support session needs a reason, stays in one school, is read-only, audited, and ends', async () => {
  const support = await login('support-1@test.local', 'password');
  const start = body => apiCall('POST', '/superadmin/support-sessions', support.token, body);
  assert.equal((await start({ schoolId: 'school-b' })).status, 400, 'reason required');
  assert.equal((await start({ schoolId: 'school-b', reason: 'Parent cannot see child', allowChanges: true })).status, 403, 'support admins are read-only');
  const started = await start({ schoolId: 'school-b', reason: 'Parent cannot see child' });
  assert.equal(started.status, 201);
  const { id: sessionId } = await started.json();

  const setup = await apiCall('GET', '/admin/setup', support.token);
  assert.equal(setup.status, 200);
  assert.equal((await setup.json()).school.name, 'School B');
  const list = await apiCall('GET', '/admin/students', support.token);
  assert.equal(list.status, 200);
  assert.ok((await list.json()).every(s => s.schoolId === 'school-b'));
  const other = await fetch(`${apiBaseUrl}/api/admin/students`, { headers: { Authorization: `Bearer ${support.token}`, 'X-School-ID': 'school-default' } });
  assert.equal(other.status, 403, 'only the school the session is for');
  assert.equal((await apiCall('PATCH', '/admin/students/student-b', support.token, { status: 'SUSPENDED' })).status, 403, 'read-only');
  assert.equal((await db.prepare(`SELECT status FROM students WHERE id='student-b'`).get()).status, 'ACTIVE');

  const startedEntry = await waitForAudit(`action='SUPPORT_SESSION_STARTED' AND support_session_id=?`, [sessionId]);
  assert.equal(startedEntry.school_id, 'school-b', 'the school can see who looked in');
  assert.equal(startedEntry.reason, 'Parent cannot see child');
  assert.equal(startedEntry.actor_role, 'SUPPORT_ADMIN');
  assert.ok(startedEntry.request_id);
  assert.ok(await waitForAudit(`action='SUPPORT_VIEWED' AND support_session_id=?`, [sessionId]));

  const me = await (await apiCall('GET', '/superadmin/me', support.token)).json();
  assert.equal(me.supportSession.schoolName, 'School B');
  assert.equal(me.supportSession.allowChanges, false);

  assert.equal((await apiCall('POST', '/superadmin/support-sessions/end', support.token)).status, 204);
  assert.equal((await apiCall('GET', '/admin/students', support.token)).status, 403);
  assert.ok(await waitForAudit(`action='SUPPORT_SESSION_ENDED' AND support_session_id=?`, [sessionId]));

  // Sessions expire on their own.
  await start({ schoolId: 'school-b', reason: 'Checking expiry works' });
  await db.prepare(`UPDATE support_sessions SET expires_at=? WHERE platform_user_id='support-1' AND ended_at IS NULL`).run(Date.now() - 1);
  assert.equal((await apiCall('GET', '/admin/students', support.token)).status, 403);
});

test('a super admin can make changes in a support session only when it allows them, and each change is audited', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const started = await apiCall('POST', '/superadmin/support-sessions', superAdmin.token, { schoolId: 'school-b', reason: 'Fixing a wrong enrollment', allowChanges: true });
  assert.equal(started.status, 201);
  const { id: sessionId } = await started.json();
  assert.equal((await apiCall('PATCH', '/admin/students/student-b', superAdmin.token, { status: 'SUSPENDED' })).status, 204);
  const entry = await waitForAudit(`action='STUDENT_STATUS_CHANGED' AND support_session_id=?`, [sessionId]);
  assert.equal(entry.actor_user_id, 'super-1');
  assert.equal(entry.actor_role, 'SUPER_ADMIN');
  assert.ok(await waitForAudit(`action='SUPPORT_CHANGE' AND support_session_id=?`, [sessionId]));
  await apiCall('PATCH', '/admin/students/student-b', superAdmin.token, { status: 'ACTIVE' });
  await apiCall('POST', '/superadmin/support-sessions/end', superAdmin.token);
});

test('suspending a school locks its users out until it is reactivated, with a reason each way', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const adminB = await login('admin-b@test.local', 'password');
  assert.equal((await apiCall('POST', '/superadmin/schools/school-b/suspend', superAdmin.token, {})).status, 400, 'reason required');
  await apiCall('POST', '/superadmin/support-sessions', superAdmin.token, { schoolId: 'school-b', reason: 'Looking before suspension' });
  assert.equal((await apiCall('POST', '/superadmin/schools/school-b/suspend', superAdmin.token, { reason: 'Contract ended' })).status, 204);
  assert.equal((await apiCall('GET', '/admin/students', adminB.token)).status, 401, 'signed in users are cut off');
  assert.equal(await login('admin-b@test.local', 'password'), null);
  assert.equal((await apiCall('GET', '/admin/students', superAdmin.token)).status, 403, 'support sessions into it end');
  assert.equal((await apiCall('POST', '/superadmin/schools/school-b/archive', (await login('support-1@test.local', 'password')).token, { reason: 'Not allowed' })).status, 403);
  const suspended = await waitForAudit(`action='SCHOOL_SUSPENDED' AND school_id='school-b'`, []);
  assert.equal(suspended.reason, 'Contract ended');

  const list = await (await apiCall('GET', '/superadmin/schools?status=SUSPENDED', superAdmin.token)).json();
  assert.ok(list.items.some(s => s.id === 'school-b' && s.suspendedReason === 'Contract ended'));

  assert.equal((await apiCall('POST', '/superadmin/schools/school-b/reactivate', superAdmin.token, { reason: 'Contract renewed' })).status, 204);
  assert.ok((await login('admin-b@test.local', 'password'))?.token);
  assert.ok(await waitForAudit(`action='SCHOOL_REACTIVATED' AND school_id='school-b'`, []));
});

test('a platform admin can create a school with an invited administrator, and find it', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const created = await apiCall('POST', '/superadmin/schools', superAdmin.token, { name: 'Oak Valley Elementary', campusName: 'Main', adminFullName: 'Olive Admin', adminEmail: 'olive@oakvalley.test' });
  assert.equal(created.status, 201);
  const { id: schoolId, setupLink } = await created.json();
  assert.match(setupLink, /set-password/);
  assert.equal((await apiCall('POST', '/superadmin/schools', superAdmin.token, { name: 'Again', adminFullName: 'X', adminEmail: 'olive@oakvalley.test' })).status, 400);

  const found = await (await apiCall('GET', '/superadmin/schools?search=oak%20valley', superAdmin.token)).json();
  assert.equal(found.total, 1);
  assert.equal(found.items[0].staff, 1);
  const detail = await (await apiCall('GET', `/superadmin/schools/${schoolId}`, superAdmin.token)).json();
  assert.equal(detail.admins[0].email, 'olive@oakvalley.test');
  assert.equal(detail.admins[0].needsSetup, true);
  assert.equal(detail.setup.find(item => item.key === 'year').done, true);
  assert.equal(detail.setup.find(item => item.key === 'students').done, false);
  assert.ok(await waitForAudit(`action='SCHOOL_CREATED' AND school_id=?`, [schoolId]));

  // Paging and sorting are bounded.
  const pageOne = await (await apiCall('GET', '/superadmin/schools?pageSize=1&sort=name&dir=desc', superAdmin.token)).json();
  assert.equal(pageOne.items.length, 1);
  assert.ok(pageOne.total >= 3);
});

test('platform admins are managed by super admins, and the last super admin cannot be removed', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const added = await apiCall('POST', '/superadmin/admins', superAdmin.token, { email: 'new-platform@test.local', fullName: 'New Platform', role: 'PLATFORM_ADMIN' });
  assert.equal(added.status, 201);
  const { id: newId } = await added.json();
  assert.equal((await apiCall('PATCH', `/superadmin/admins/${newId}`, superAdmin.token, { role: 'SUPPORT_ADMIN' })).status, 400, 'reason required');
  assert.equal((await apiCall('PATCH', `/superadmin/admins/${newId}`, superAdmin.token, { role: 'SUPPORT_ADMIN', reason: 'Moved to support team' })).status, 204);
  assert.ok(await waitForAudit(`action='ROLE_CHANGED' AND target_id=?`, [newId]));
  assert.equal((await apiCall('PATCH', '/superadmin/admins/super-1', superAdmin.token, { status: 'DISABLED', reason: 'Trying myself' })).status, 400);

  // Disabling signs them out and closes the platform API to them.
  const support = await login('support-1@test.local', 'password');
  assert.equal((await apiCall('PATCH', '/superadmin/admins/support-1', superAdmin.token, { status: 'DISABLED', reason: 'Left the company' })).status, 204);
  assert.equal((await apiCall('GET', '/superadmin/me', support.token)).status, 401);
  assert.equal(await login('support-1@test.local', 'password'), null);
});

test('the platform audit search spans schools and filters by action', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const result = await (await apiCall('GET', '/superadmin/audit-logs?action=SCHOOL_SUSPENDED', superAdmin.token)).json();
  assert.ok(result.entries.length >= 1);
  assert.ok(result.entries.every(e => e.action === 'SCHOOL_SUSPENDED'));
  assert.equal(result.entries[0].schoolName, 'School B');
  const paged = await (await apiCall('GET', '/superadmin/audit-logs?limit=2', superAdmin.token)).json();
  assert.equal(paged.entries.length, 2);
  const last = paged.entries[1];
  const next = await (await apiCall('GET', `/superadmin/audit-logs?limit=2&beforeCreatedAt=${encodeURIComponent(last.createdAt)}&beforeId=${last.id}`, superAdmin.token)).json();
  assert.ok(next.entries.every(e => e.id !== paged.entries[0].id && e.id !== last.id));
});

test('a message from another school cannot be marked read', async () => {
  const adminB = await login('admin-b@test.local', 'password');
  const { id: noticeA } = await db.prepare(`SELECT id FROM notices WHERE school_id='school-default' LIMIT 1`).get() ?? {};
  if (noticeA) assert.equal((await apiCall('POST', `/notices/${noticeA}/read`, adminB.token)).status, 404);
});

// ---- Phase 2: platform dashboard, Needs Attention, school detail tabs ----------------

test('the platform dashboard counts today\'s activity across schools, for platform roles only', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const before = await (await apiCall('GET', '/superadmin/dashboard?refresh=1', superAdmin.token)).json();
  const nowUtc = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const localToday = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York' }).format(new Date());
  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,request_type,requested_by_user_id,status,approved_at) VALUES ('dash-pickup','school-default','child-2','PICK_UP','parent-1','APPROVED',?)`).run(nowUtc);
  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,request_type,requested_by_user_id,status,declined_at,declined_by_user_id) VALUES ('dash-declined','school-default','child-2','DROP_OFF','parent-1','DECLINED',?,'teacher-1')`).run(nowUtc);
  await db.prepare(`INSERT INTO attendance_records (id,school_id,student_id,date,status) VALUES ('dash-att','school-b','student-b',?,'PRESENT') ON CONFLICT (student_id,date) DO NOTHING`).run(localToday);

  const after = await (await apiCall('GET', '/superadmin/dashboard?refresh=1', superAdmin.token)).json();
  assert.equal(after.operations.pickUps, before.operations.pickUps + 1);
  assert.equal(after.operations.declined, before.operations.declined + 1);
  assert.equal('overrides' in after.operations, false);
  assert.equal(after.operations.exceptions, before.operations.exceptions + 1);
  assert.ok(after.operations.present >= 1);
  assert.equal(after.daily.length, 30);
  assert.equal(after.daily.at(-1).date, localToday);
  assert.ok(after.daily.at(-1).pickUps >= 1);
  assert.ok(after.totals.totalSchools >= 3 && after.totals.activeSchools >= 2);
  assert.ok(after.totals.activeUsers >= 1);

  const billing = await login('billing-1@test.local', 'password');
  assert.equal((await apiCall('GET', '/superadmin/dashboard', billing.token)).status, 200);
  const schoolAdmin = await login('admin@school.test', 'password');
  assert.equal((await apiCall('GET', '/superadmin/dashboard', schoolAdmin.token)).status, 403);
  assert.equal((await apiCall('GET', '/superadmin/needs-attention', schoolAdmin.token)).status, 403);
  await db.prepare(`UPDATE queue_items SET status='CANCELLED' WHERE id='dash-pickup'`).run();
});

test('Needs Attention lists real problems with links, and says what it does not track yet', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const result = await (await apiCall('GET', '/superadmin/needs-attention', superAdmin.token)).json();
  const ids = result.items.map(item => item.id);
  assert.ok(ids.includes('email-not-configured'), 'no SMTP settings in tests');
  const oakValley = (await db.prepare(`SELECT id FROM schools WHERE name='Oak Valley Elementary'`).get()).id;
  const setup = result.items.find(item => item.id === `setup-${oakValley}`);
  assert.ok(setup && setup.link === `/platform/schools/${oakValley}`);
  assert.match(setup.detail, /no location mapped/);
  assert.ok(ids.includes('locked-accounts'), 'an earlier test locked an account name');
  assert.ok(ids.every(itemId => !itemId.startsWith('override-') && !itemId.startsWith('pickup-lockout-')), 'pickup-code items are gone');
  assert.ok(result.items.every(item => item.link === null || item.link.startsWith('/platform/')));
  assert.equal(result.items[0].severity, 'critical');
  assert.ok(result.notTracked.length > 0);
  assert.doesNotMatch(JSON.stringify(result), /password_hash|scrypt\$/);
});

test('school detail tabs show people and children without credentials, and every look is audited', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const staff = await (await apiCall('GET', '/superadmin/schools/school-default/users?kind=staff&pageSize=1', superAdmin.token)).json();
  assert.equal(staff.items.length, 1);
  assert.ok(staff.total > 1);
  assert.equal((await apiCall('POST', '/auth/login', null, { identifier: 'teacher@school.test', password: 'password' })).status, 200);
  await waitForAudit(`action='SIGNED_IN' AND actor_user_id='teacher-1'`, []);
  const allStaff = await (await apiCall('GET', '/superadmin/schools/school-default/users?kind=staff&pageSize=100', superAdmin.token)).json();
  assert.ok(allStaff.items.some(u => u.id === 'teacher-1' && u.lastSignIn));
  const parents = await (await apiCall('GET', '/superadmin/schools/school-default/users?kind=parents&search=parent', superAdmin.token)).json();
  assert.ok(parents.items.every(u => u.role === 'parent'));
  assert.ok(await waitForAudit(`action='PLATFORM_USERS_VIEWED' AND school_id='school-default' AND actor_user_id='super-1'`, []));

  const studentsResponse = await apiCall('GET', '/superadmin/schools/school-default/students', superAdmin.token);
  const studentsBody = await studentsResponse.text();
  assert.equal(studentsResponse.status, 200);
  assert.doesNotMatch(studentsBody, /dateOfBirth|date_of_birth|photo/i);
  assert.ok(JSON.parse(studentsBody).items.some(s => s.id === 'child-1'));
  assert.ok(await waitForAudit(`action='PLATFORM_STUDENTS_VIEWED' AND school_id='school-default'`, []));
  const billing = await login('billing-1@test.local', 'password');
  assert.equal((await apiCall('GET', '/superadmin/schools/school-default/students', billing.token)).status, 403);
  assert.equal((await apiCall('GET', '/superadmin/schools/school-default/users', billing.token)).status, 403);

  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,request_type,requested_by_user_id) VALUES ('ops-secret','school-default','child-3','PICK_UP','parent-1')`).run();
  const ops = await (await apiCall('GET', '/superadmin/schools/school-default/operations', superAdmin.token)).text();
  assert.doesNotMatch(ops, /pickup_code|pickupCode|verificationMethod/);
  assert.ok(JSON.parse(ops).today.pending >= 1);
  await db.prepare(`UPDATE queue_items SET status='CANCELLED' WHERE id='ops-secret'`).run();

  const attendance = await (await apiCall('GET', '/superadmin/schools/school-b/attendance', superAdmin.token)).json();
  assert.equal(attendance.days.length, 14);
  const security = await (await apiCall('GET', '/superadmin/schools/school-b/security', superAdmin.token)).json();
  assert.ok(security.supportSessions.some(s => s.reason === 'Parent cannot see child'));
  const notifications = await (await apiCall('GET', '/superadmin/schools/school-b/notifications', superAdmin.token)).json();
  assert.equal(notifications.emailConfigured, false);
  assert.equal((await apiCall('GET', '/superadmin/schools/no-such-school/users', superAdmin.token)).status, 404);
});

// ---- Phase 3: platform operations ----------------------------------------------------------

test('live operations show each school\'s waiting requests, oldest first, with children named only as "First L."', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const fortyMinutesAgo = new Date(Date.now() - 40 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,request_type,requested_by_user_id,requested_at) VALUES ('ops-wait-b','school-b','student-b','PICK_UP','admin-b',?)`).run(fortyMinutesAgo);

  const schools = await (await apiCall('GET', '/superadmin/operations/schools', superAdmin.token)).json();
  const schoolB = schools.items.find(sc => sc.id === 'school-b');
  assert.ok(schoolB.pendingPickUps >= 1 && schoolB.oldestWaitMinutes >= 39);
  const waits = schools.items.map(sc => sc.oldestWaitMinutes).filter(w => w !== null);
  assert.deepEqual(waits, [...waits].sort((a, b) => b - a), 'longest wait first');

  const waiting = await apiCall('GET', '/superadmin/operations/requests?state=waiting&schoolId=school-b', superAdmin.token);
  const body = await waiting.text();
  assert.doesNotMatch(body, /pickup_code|pickupCode|Private Student/);
  const item = JSON.parse(body).items.find(i => i.id === 'ops-wait-b');
  assert.equal(item.studentName, 'Private S.');
  assert.ok(item.waitMinutes >= 39);
  const dropOffsOnly = await (await apiCall('GET', '/superadmin/operations/requests?state=waiting&type=DROP_OFF&schoolId=school-b', superAdmin.token)).json();
  assert.ok(dropOffsOnly.items.every(i => i.requestType === 'DROP_OFF'));
  assert.ok(await waitForAudit(`action='PLATFORM_OPERATIONS_VIEWED' AND actor_user_id='super-1'`, []));

  const schoolAdmin = await login('admin@school.test', 'password');
  for (const path of ['/superadmin/operations/schools', '/superadmin/operations/requests', '/superadmin/operations/attendance', '/superadmin/operations/incidents']) {
    assert.equal((await apiCall('GET', path, schoolAdmin.token)).status, 403, path);
  }
  const billing = await login('billing-1@test.local', 'password');
  assert.equal((await apiCall('GET', '/superadmin/operations/requests', billing.token)).status, 403, 'billing admins have no pickup:view');
  await db.prepare(`UPDATE queue_items SET status='CANCELLED' WHERE id='ops-wait-b'`).run();
});

test('attendance by school for a day counts present, late, absent and not marked', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  await db.prepare(`INSERT INTO attendance_records (id,school_id,student_id,date,status,late) VALUES ('ops-att','school-b','student-b','2026-03-02','PRESENT',1) ON CONFLICT (student_id,date) DO NOTHING`).run();
  const result = await (await apiCall('GET', '/superadmin/operations/attendance?date=2026-03-02', superAdmin.token)).json();
  const schoolB = result.items.find(s => s.id === 'school-b');
  assert.equal(schoolB.present, 1);
  assert.equal(schoolB.late, 1);
  assert.equal(schoolB.unmarked, schoolB.students - 1);
  assert.ok(result.totals.present >= 1);
});

test('incidents list declined requests, and can be marked reviewed once, with a note', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const nowUtc = new Date().toISOString().replace('T', ' ').slice(0, 19);
  await db.prepare(`INSERT INTO queue_items (id,school_id,student_id,request_type,requested_by_user_id,status,declined_at,declined_by_user_id) VALUES ('incident-declined','school-default','child-1','PICK_UP','parent-1','DECLINED',?,'teacher-1')`).run(nowUtc);

  const open = await (await apiCall('GET', '/superadmin/operations/incidents', superAdmin.token)).json();
  const declined = open.items.find(i => i.key === 'declined:incident-declined');
  assert.ok(declined);
  assert.equal(declined.type, 'REQUEST_DECLINED');
  assert.equal(declined.requestType, 'PICK_UP');
  assert.match(declined.studentName, /^\S+ \S\.$/);
  assert.ok(declined.actorName);
  assert.ok(open.items.every(i => i.type === 'REQUEST_DECLINED'), 'pickup-code incidents are gone');
  const oneSchool = await (await apiCall('GET', '/superadmin/operations/incidents?type=REQUEST_DECLINED&schoolId=school-default', superAdmin.token)).json();
  assert.ok(oneSchool.items.length >= 1 && oneSchool.items.every(i => i.schoolId === 'school-default'));
  assert.equal((await apiCall('GET', '/superadmin/operations/incidents?from=2026-05-02&to=2026-05-01', superAdmin.token)).status, 400);

  const review = body => apiCall('POST', '/superadmin/operations/incidents/review', superAdmin.token, body);
  assert.equal((await review({ key: 'declined:incident-declined' })).status, 400, 'a note is required');
  assert.equal((await review({ key: 'declined:no-such-item', note: 'Checked with school' })).status, 404);
  assert.equal((await review({ key: 'override:incident-declined', note: 'Old kind of incident' })).status, 404);
  assert.equal((await review({ key: 'declined:incident-declined', note: 'Called the school; wrong adult at the gate' })).status, 204);
  assert.equal((await review({ key: 'declined:incident-declined', note: 'Again' })).status, 409);
  const stillOpen = await (await apiCall('GET', '/superadmin/operations/incidents', superAdmin.token)).json();
  assert.ok(stillOpen.items.every(i => i.key !== 'declined:incident-declined'));
  const reviewed = await (await apiCall('GET', '/superadmin/operations/incidents?state=reviewed', superAdmin.token)).json();
  const done = reviewed.items.find(i => i.key === 'declined:incident-declined');
  assert.equal(done.reviewNote, 'Called the school; wrong adult at the gate');
  assert.equal(done.reviewedBy, 'Platform SUPER_ADMIN');
  const entry = await waitForAudit(`action='INCIDENT_REVIEWED' AND target_id='incident-declined'`, []);
  assert.equal(entry.school_id, 'school-default');
  assert.equal(entry.reason, 'Called the school; wrong adult at the gate');
});

// ---- Phase 4: Security Center and Compliance Center ------------------------------------------

test('the Security Center shows sign-in trouble and two-step coverage, and can end an admin session without exposing tokens', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const overview = await (await apiCall('GET', '/superadmin/security/overview', superAdmin.token)).json();
  assert.ok(overview.lockoutsWeek >= 1, 'earlier tests locked an account name');
  assert.ok(overview.mfa.platformAdmins.total >= 1 && overview.mfa.parents.total >= 1);
  assert.ok(Array.isArray(overview.suspicious.targetedAccounts));

  const adminB = await login('admin-b@test.local', 'password');
  const sessionsResponse = await apiCall('GET', '/superadmin/security/sessions', superAdmin.token);
  const sessionsText = await sessionsResponse.text();
  assert.ok(!sessionsText.includes(adminB.token) && !sessionsText.includes(superAdmin.token), 'session tokens are never returned');
  const sessions = JSON.parse(sessionsText);
  const mine = sessions.find(s => s.current);
  const theirs = sessions.find(s => s.userId === 'admin-b');
  assert.match(theirs.id, /^[0-9a-f]{64}$/);
  assert.equal((await apiCall('POST', `/superadmin/security/sessions/${mine.id}/end`, superAdmin.token, { reason: 'Testing my own session' })).status, 400);
  assert.equal((await apiCall('POST', `/superadmin/security/sessions/${theirs.id}/end`, superAdmin.token, {})).status, 400, 'reason required');
  assert.equal((await apiCall('POST', `/superadmin/security/sessions/${theirs.id}/end`, superAdmin.token, { reason: 'Laptop reported stolen' })).status, 204);
  assert.equal((await apiCall('GET', '/admin/students', adminB.token)).status, 401, 'that session is signed out');
  assert.equal((await apiCall('POST', `/superadmin/security/sessions/${theirs.id}/end`, superAdmin.token, { reason: 'Laptop reported stolen' })).status, 404);
  const ended = await waitForAudit(`action='SESSION_ENDED_BY_PLATFORM' AND target_id='admin-b'`, []);
  assert.equal(ended.reason, 'Laptop reported stolen');

  const logins = await (await apiCall('GET', '/superadmin/security/events?category=logins&outcome=failed', superAdmin.token)).json();
  assert.ok(logins.entries.length > 0 && logins.entries.every(e => e.action === 'SIGN_IN_FAILED'));
  const changes = await (await apiCall('GET', '/superadmin/security/events?category=changes', superAdmin.token)).json();
  assert.ok(changes.entries.some(e => e.action === 'SESSION_ENDED_BY_PLATFORM'));

  const billing = await login('billing-1@test.local', 'password');
  assert.equal((await apiCall('GET', '/superadmin/security/overview', billing.token)).status, 403);
  const schoolAdmin = await login('admin@school.test', 'password');
  assert.equal((await apiCall('GET', '/superadmin/security/sessions', schoolAdmin.token)).status, 403);
});

test('an export request is reviewed, approved, downloaded and completed, with every step in the audit log', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const create = body => apiCall('POST', '/superadmin/compliance/data-requests', superAdmin.token, body);
  assert.equal((await create({ schoolId: 'school-b', kind: 'EXPORT', subjectType: 'STUDENT', subjectId: 'child-1', requesterName: 'Someone' })).status, 400, "another school's student");
  const created = await create({ schoolId: 'school-default', kind: 'EXPORT', subjectType: 'STUDENT', subjectId: 'child-1', requesterName: 'Parker Parent', requesterRelationship: 'Parent', receivedVia: 'Email to the school' });
  assert.equal(created.status, 201);
  const request = await created.json();
  assert.equal(request.status, 'REQUESTED');
  assert.ok(request.dueAt > request.createdAt);
  const status = (to, note) => apiCall('POST', `/superadmin/compliance/data-requests/${request.id}/status`, superAdmin.token, { status: to, note });

  assert.equal((await apiCall('GET', `/superadmin/compliance/data-requests/${request.id}/export`, superAdmin.token)).status, 409, 'not approved yet');
  assert.equal((await status('APPROVED', 'Skipping review')).status, 409, 'must be reviewed first');
  assert.equal((await status('UNDER_REVIEW')).status, 200);
  assert.equal((await status('APPROVED')).status, 400, 'approval needs a note');
  assert.equal((await status('APPROVED', 'Identity of parent confirmed by the school')).status, 200);
  const download = await apiCall('GET', `/superadmin/compliance/data-requests/${request.id}/export`, superAdmin.token);
  assert.equal(download.status, 200);
  assert.match(download.headers.get('content-disposition'), /attachment/);
  const exported = await download.text();
  assert.doesNotMatch(exported, /password_hash|scrypt\$|pickup_code/);
  assert.equal((await (await apiCall('GET', `/superadmin/compliance/data-requests/${request.id}`, superAdmin.token)).json()).status, 'PROCESSING');
  assert.equal((await status('COMPLETED', 'Sent to the parent through the school')).status, 200);
  assert.equal((await status('UNDER_REVIEW')).status, 409, 'completed requests are final');

  const detail = await (await apiCall('GET', `/superadmin/compliance/data-requests/${request.id}`, superAdmin.token)).json();
  assert.deepEqual(detail.history.map(h => h.action), ['DATA_EXPORT_REQUESTED', 'DATA_REQUEST_UNDER_REVIEW', 'DATA_REQUEST_APPROVED', 'DATA_EXPORTED', 'DATA_REQUEST_COMPLETED']);
  const list = await (await apiCall('GET', '/superadmin/compliance/data-requests?status=COMPLETED&kind=EXPORT', superAdmin.token)).json();
  assert.ok(list.items.some(r => r.id === request.id));
});

test('a deletion needs a second person to approve, is blocked by a legal hold, and leaves only initials behind', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const second = await addPlatformAdmin('platform-2', 'PLATFORM_ADMIN');
  await db.prepare(`INSERT INTO students (id,first_name,last_name,student_number,school_id,campus_id) VALUES ('student-forget','Fiona','Forget','B-99','school-b','campus-b')`).run();
  await db.prepare(`INSERT INTO attendance_records (id,school_id,student_id,date,status) VALUES ('att-forget','school-b','student-forget','2026-03-03','PRESENT')`).run();

  const created = await (await apiCall('POST', '/superadmin/compliance/data-requests', superAdmin.token, { schoolId: 'school-b', kind: 'DELETION', subjectType: 'STUDENT', subjectId: 'student-forget', requesterName: 'Fiona\'s parent' })).json();
  const status = (token, to, note) => apiCall('POST', `/superadmin/compliance/data-requests/${created.id}/status`, token, { status: to, note });
  assert.equal((await status(superAdmin.token, 'UNDER_REVIEW')).status, 200);
  assert.equal((await status(superAdmin.token, 'APPROVED', 'I logged it and approve it')).status, 403, 'four eyes');

  // A legal hold blocks approval and deletion, everywhere.
  assert.equal((await apiCall('POST', '/superadmin/compliance/schools/school-b/legal-hold', second.token, { reason: 'Not my call' })).status, 403, 'super admins only');
  assert.equal((await apiCall('POST', '/superadmin/compliance/schools/school-b/legal-hold', superAdmin.token, { reason: 'District records request pending' })).status, 204);
  assert.equal((await status(second.token, 'APPROVED', 'Parent identity confirmed')).status, 409);
  const adminB = await login('admin-b@test.local', 'password');
  await db.prepare(`UPDATE students SET status='ARCHIVED', archived_at='2020-01-01 00:00:00' WHERE id='student-b'`).run();
  const held = await apiCall('DELETE', '/admin/students/student-b/permanent', adminB.token, { confirmName: 'Private Student' });
  assert.equal(held.status, 409, "the school's own permanent delete is blocked too");
  assert.match((await held.json()).error, /legal hold/);
  await db.prepare(`UPDATE schools SET removed_student_retention_days=30 WHERE id='school-b'`).run();
  const retention = await (await apiCall('POST', '/admin/retention/run', adminB.token)).json();
  assert.equal(retention.onLegalHold, true);
  assert.ok(await db.prepare(`SELECT 1 FROM students WHERE id='student-b'`).get(), 'retention skipped the held school');
  await db.prepare(`UPDATE schools SET removed_student_retention_days=NULL WHERE id='school-b'`).run();
  await db.prepare(`UPDATE students SET status='ACTIVE', archived_at=NULL WHERE id='student-b'`).run();
  assert.equal((await apiCall('POST', '/superadmin/compliance/schools/school-b/legal-hold', superAdmin.token, { hold: false, reason: 'Records request answered' })).status, 204);
  assert.ok(await waitForAudit(`action='LEGAL_HOLD_SET' AND school_id='school-b'`, []));

  assert.equal((await status(second.token, 'APPROVED', 'Parent identity confirmed')).status, 200);
  const run = body => apiCall('POST', `/superadmin/compliance/data-requests/${created.id}/run-deletion`, superAdmin.token, body);
  assert.equal((await run({ confirmName: 'Fiona' })).status, 400);
  const done = await run({ confirmName: 'fiona  forget' });
  assert.equal(done.status, 200);
  const result = await done.json();
  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.subjectLabel, 'Student F.F. (deleted, #B-99)');
  assert.equal(result.outcome.erased.attendanceRecords, 1);
  assert.equal(await db.prepare(`SELECT 1 FROM students WHERE id='student-forget'`).get(), undefined);
  assert.doesNotMatch(JSON.stringify(result), /Fiona Forget/);
  assert.ok(await waitForAudit(`action='STUDENT_PERMANENTLY_DELETED' AND target_id='student-forget'`, []));
});

test('the Compliance Center reports controls it can check, without secrets', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const response = await apiCall('GET', '/superadmin/compliance/overview', superAdmin.token);
  const text = await response.text();
  const overview = JSON.parse(text);
  assert.equal(overview.controls.auditLogAppendOnly, true);
  assert.ok(overview.controls.auditEntriesLast30Days > 0);
  assert.ok(overview.requests.some(r => r.kind === 'DELETION' && r.status === 'COMPLETED'));
  assert.doesNotMatch(text, /postgres:\/\/|MFA_ENCRYPTION_KEY=|SMTP_PASSWORD/);
  const billing = await login('billing-1@test.local', 'password');
  assert.equal((await apiCall('GET', '/superadmin/compliance/overview', billing.token)).status, 403);
  assert.equal((await apiCall('POST', '/superadmin/compliance/data-requests', billing.token, { schoolId: 'school-b', kind: 'EXPORT', subjectType: 'SCHOOL', requesterName: 'X' })).status, 403);
});

// ---- Phase 5: notifications, announcements, reports, billing ----------------------------------

test('every email is logged without its sign-in link, and a retried invite gets a fresh link', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const admin = await login('admin@school.test', 'password');
  assert.equal((await apiCall('POST', '/admin/guardians', admin.token, { fullName: 'Logged Parent', email: 'logged-parent@test.local' })).status, 201);
  const logged = await (await apiCall('GET', '/superadmin/notifications/deliveries?template=invite&search=logged-parent', superAdmin.token)).json();
  const delivery = logged.items[0];
  assert.equal(delivery.status, 'SKIPPED', 'no email server in tests');
  const row = await db.prepare('SELECT args FROM notification_deliveries WHERE id=?').get(delivery.id);
  assert.doesNotMatch(row.args, /set-password|token|link/i, 'links are never stored');
  assert.equal((await apiCall('GET', '/superadmin/notifications/deliveries', admin.token)).status, 403);
  assert.equal((await apiCall('POST', `/superadmin/notifications/deliveries/${delivery.id}/retry`, superAdmin.token)).status, 409, 'retrying while email is off would be skipped again');

  // With an (unreachable) email server configured, the retry runs: a new
  // link is made, the attempt is logged against the original, and it fails.
  const smtp = { SMTP_HOST: '127.0.0.1', SMTP_PORT: '1', SMTP_USER: 'u', SMTP_PASSWORD: 'p', SMTP_FROM: 'test@test.local' };
  Object.assign(process.env, smtp);
  try {
    const user = await db.prepare(`SELECT id FROM users WHERE email='logged-parent@test.local'`).get();
    const linksBefore = (await db.prepare('SELECT COUNT(*)::int AS n FROM account_links WHERE user_id=?').get(user.id)).n;
    const retried = await apiCall('POST', `/superadmin/notifications/deliveries/${delivery.id}/retry`, superAdmin.token);
    assert.equal(retried.status, 200);
    assert.equal((await retried.json()).sent, false);
    assert.equal((await db.prepare('SELECT COUNT(*)::int AS n FROM account_links WHERE user_id=?').get(user.id)).n, linksBefore + 1);
    assert.equal((await db.prepare('SELECT status FROM notification_deliveries WHERE id=?').get(delivery.id)).status, 'RETRIED');
    const attempt = await db.prepare('SELECT status, error FROM notification_deliveries WHERE retry_of=?').get(delivery.id);
    assert.equal(attempt.status, 'FAILED');
    const needs = await (await apiCall('GET', '/superadmin/needs-attention', superAdmin.token)).json();
    assert.ok(needs.items.some(i => i.id === 'failed-emails'));
    assert.equal((await apiCall('POST', `/superadmin/notifications/deliveries/${delivery.id}/retry`, superAdmin.token)).status, 409, 'already retried');
  } finally {
    for (const key of Object.keys(smtp)) delete process.env[key];
  }
});

test('a platform announcement reaches the chosen schools as a message from SDPMPlus', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  const platformAdmin = await login('platform-2@test.local', 'password');
  assert.equal((await apiCall('POST', '/superadmin/announcements', platformAdmin.token, { title: 'Hi', body: 'There' })).status, 403, 'super admins only');
  assert.equal((await apiCall('POST', '/superadmin/announcements', superAdmin.token, { title: '', body: 'Missing title' })).status, 400);
  const sent = await apiCall('POST', '/superadmin/announcements', superAdmin.token, { title: 'Maintenance Saturday', body: 'SDPMPlus will be down 1-2 AM.', audience: 'SCHOOL_ADMINS', schoolIds: ['school-b'] });
  assert.equal(sent.status, 201);
  assert.equal((await sent.json()).schoolCount, 1);
  const adminB = await login('admin-b@test.local', 'password');
  const inbox = await (await apiCall('GET', '/admin/notices', adminB.token)).json();
  const notice = inbox.find(n => n.title === 'Maintenance Saturday');
  assert.equal(notice.senderName, 'SDPMPlus');
  const schoolA = await (await apiCall('GET', '/admin/notices', (await login('admin@school.test', 'password')).token)).json();
  assert.ok(schoolA.every(n => n.title !== 'Maintenance Saturday'), 'only the chosen school');
  const list = await (await apiCall('GET', '/superadmin/announcements', superAdmin.token)).json();
  assert.equal(list[0].title, 'Maintenance Saturday');
  assert.ok(await waitForAudit(`action='ANNOUNCEMENT_SENT'`, []));
});

test('reports preview every type, export through a background job, and only the person who asked can download', async () => {
  const { runPendingJobs } = await import('../jobs.js');
  const superAdmin = await login('super-1@test.local', 'password');
  const types = await (await apiCall('GET', '/superadmin/reports', superAdmin.token)).json();
  assert.equal(types.length, 6);
  for (const type of types) {
    const response = await apiCall('GET', `/superadmin/reports/${type.key}?from=2026-01-01&to=2026-12-31`, superAdmin.token);
    assert.equal(response.status, 200, type.key);
    const body = await response.json();
    assert.deepEqual(body.columns.map(c => c.key), type.columns.map(c => c.key));
  }
  assert.equal((await apiCall('GET', '/superadmin/reports/attendance?from=2026-03-01&to=2026-03-31&schoolId=school-b', superAdmin.token)).status, 200);
  assert.equal((await apiCall('GET', '/superadmin/reports/attendance?from=2024-01-01&to=2026-01-01', superAdmin.token)).status, 400, 'at most a year');
  assert.equal((await apiCall('GET', '/superadmin/reports/attendance?from=2026-05-02&to=2026-05-01', superAdmin.token)).status, 400);

  // A school name that a spreadsheet would run as a formula stays text in the CSV.
  await db.prepare(`INSERT INTO organizations (id,name) VALUES ('org-formula','Formula Org')`).run();
  await db.prepare(`INSERT INTO schools (id,organization_id,name,code) VALUES ('school-formula','org-formula','=HYPERLINK("http://evil.test")','FORMULA')`).run();
  const queued = await apiCall('POST', '/superadmin/reports/school-usage/export', superAdmin.token, { from: '2026-01-01', to: '2026-12-31' });
  assert.equal(queued.status, 202);
  const { jobId } = await queued.json();
  assert.equal((await apiCall('GET', `/superadmin/jobs/${jobId}/download`, superAdmin.token)).status, 409, 'not ready yet');
  await runPendingJobs();
  const jobs = await (await apiCall('GET', '/superadmin/jobs', superAdmin.token)).json();
  assert.equal(jobs.find(j => j.id === jobId).status, 'SUCCEEDED');
  const download = await apiCall('GET', `/superadmin/jobs/${jobId}/download`, superAdmin.token);
  assert.equal(download.status, 200);
  assert.match(download.headers.get('content-type'), /text\/csv/);
  const csv = await download.text();
  assert.match(csv, /^﻿?School,Students,Staff/);
  assert.match(csv, /"'=HYPERLINK\(""http:\/\/evil\.test""\)"/);
  assert.ok(csv.includes('Demo School'));
  const billing = await login('billing-1@test.local', 'password');
  assert.equal((await apiCall('GET', `/superadmin/jobs/${jobId}/download`, billing.token)).status, 404, "someone else's export");
  assert.ok(await waitForAudit(`action='REPORT_EXPORTED' AND target_id=?`, [jobId]));
  await db.prepare(`UPDATE schools SET status='ARCHIVED' WHERE id='school-formula'`).run();
});

test('billing: a plan prices an invoice, payments mark it paid, and an overdue invoice needs attention', async () => {
  const billing = await login('billing-1@test.local', 'password');
  const superAdmin = await login('super-1@test.local', 'password');
  const platformAdmin = await login('platform-2@test.local', 'password');
  assert.equal((await apiCall('GET', '/superadmin/billing/plans', platformAdmin.token)).status, 403, 'platform admins have no billing access');

  const plan = await apiCall('POST', '/superadmin/billing/plans', billing.token, { name: 'Per student yearly', pricingModel: 'PER_STUDENT', priceCents: 500, interval: 'YEAR' });
  assert.equal(plan.status, 201);
  const { id: planId } = await plan.json();
  assert.equal((await apiCall('PUT', '/superadmin/billing/schools/school-default/subscription', billing.token, { planId, status: 'ACTIVE', startedOn: '2026-08-01', currentPeriodEnd: '2027-07-31' })).status, 204);
  const { n: students } = await db.prepare(`SELECT COUNT(*)::int AS n FROM students WHERE school_id='school-default' AND status='ACTIVE'`).get();

  const created = await (await apiCall('POST', '/superadmin/billing/invoices', billing.token, { schoolId: 'school-default', periodStart: '2026-08-01', periodEnd: '2027-07-31', dueOn: '2099-01-01' })).json();
  assert.equal(created.amountCents, 500 * students);
  assert.match(created.number, /^INV-\d{4}-\d+$/);
  const pay = body => apiCall('POST', `/superadmin/billing/invoices/${created.id}/payments`, billing.token, body);
  assert.equal((await pay({ amountCents: 100, method: 'CHECK' })).status, 409, 'issue it first');
  assert.equal((await apiCall('POST', `/superadmin/billing/invoices/${created.id}/issue`, billing.token)).status, 204);
  assert.equal((await (await pay({ amountCents: 100, method: 'CHECK', reference: '#1001' })).json()).fullyPaid, false);
  assert.equal((await pay({ amountCents: created.amountCents, method: 'ACH' })).status, 400, 'more than owed');
  assert.equal((await (await pay({ amountCents: created.amountCents - 100, method: 'ACH' })).json()).fullyPaid, true);
  const paid = await (await apiCall('GET', `/superadmin/billing/invoices/${created.id}`, billing.token)).json();
  assert.equal(paid.status, 'PAID');
  assert.equal(paid.payments.length, 2);
  assert.equal((await apiCall('POST', `/superadmin/billing/invoices/${created.id}/void`, billing.token, { reason: 'Changed my mind' })).status, 409, 'a paid invoice cannot be voided');

  const late = await (await apiCall('POST', '/superadmin/billing/invoices', superAdmin.token, { schoolId: 'school-default', description: 'Setup fee', amountCents: 25000, dueOn: '2020-01-01' })).json();
  await apiCall('POST', `/superadmin/billing/invoices/${late.id}/issue`, superAdmin.token);
  const summary = await (await apiCall('GET', '/superadmin/billing/summary', billing.token)).json();
  assert.ok(summary.overdueCount >= 1 && summary.overdueCents >= 25000);
  const needs = await (await apiCall('GET', '/superadmin/needs-attention', superAdmin.token)).json();
  assert.ok(needs.items.some(i => i.id === 'billing-school-default'));
  const overdue = await (await apiCall('GET', '/superadmin/billing/invoices?status=OVERDUE', billing.token)).json();
  assert.ok(overdue.items.some(i => i.id === late.id && i.overdue));
  assert.equal((await apiCall('POST', `/superadmin/billing/invoices/${late.id}/void`, billing.token, { reason: 'Waived for pilot' })).status, 204);
  const schoolBilling = await (await apiCall('GET', '/superadmin/billing/schools/school-default', billing.token)).json();
  assert.equal(schoolBilling.subscription.planName, 'Per student yearly');
  assert.ok(await waitForAudit(`action='PAYMENT_RECORDED'`, []));
  assert.ok(await waitForAudit(`action='SUBSCRIPTION_CHANGED' AND school_id='school-default'`, []));
});

// ---- Phase 6: system health and production hardening ------------------------------------------

test('System Health reports each part of the platform without revealing settings', async () => {
  const superAdmin = await login('super-1@test.local', 'password');
  await fetch(`${apiBaseUrl}/api/health`, { headers: { 'X-Client': 'mobile-ios/1.4.0' } });
  await fetch(`${apiBaseUrl}/api/health`, { headers: { 'X-Client': 'not a real client' } });
  const response = await apiCall('GET', '/superadmin/system/health', superAdmin.token);
  assert.equal(response.status, 200);
  const text = await response.text();
  const health = JSON.parse(text);
  assert.equal(health.database.status, 'ok');
  assert.equal(health.database.migrationsApplied, health.database.migrationsExpected);
  assert.equal(health.email.status, 'not_configured');
  assert.equal(health.sms.status, 'not_offered');
  assert.ok(['ok', 'degraded'].includes(health.jobs.status));
  assert.ok(health.database.largestTables.length > 0);
  assert.ok(health.clients.some(c => c.client === 'mobile-ios' && c.version === '1.4.0'));
  assert.ok(health.clients.every(c => c.client !== 'not a real client'));
  assert.ok(!text.includes(process.env.DATABASE_URL), 'no connection string');
  assert.doesNotMatch(text, /postgres:\/\/|password/i);

  const check = await (await apiCall('POST', '/superadmin/system/email-check', superAdmin.token)).json();
  assert.equal(check.ok, false);
  assert.match(check.message, /not set up/);
  const billing = await login('billing-1@test.local', 'password');
  assert.equal((await apiCall('GET', '/superadmin/system/health', billing.token)).status, 403);
  const platformAdmin = await login('platform-2@test.local', 'password');
  assert.equal((await apiCall('GET', '/superadmin/system/health', platformAdmin.token)).status, 200);
  assert.equal((await apiCall('POST', '/superadmin/system/email-check', platformAdmin.token)).status, 403);
  const schoolAdmin = await login('admin@school.test', 'password');
  assert.equal((await apiCall('GET', '/superadmin/system/health', schoolAdmin.token)).status, 403);
});

test('sign-in lockouts live in the database, so every server enforces them', async () => {
  const identifier = `shared-${randomUUID()}@test.local`;
  // Failures recorded by "another server" (straight into the shared table) lock this one too.
  await db.prepare('INSERT INTO rate_limits (key,count,reset_at) VALUES (?,?,?)').run(`account:${identifier}`, 5, Date.now() + 60_000);
  assert.equal((await apiCall('POST', '/auth/login', null, { identifier, password: 'whatever' })).status, 429);
  // An expired window counts as nothing.
  await db.prepare('UPDATE rate_limits SET reset_at=? WHERE key=?').run(Date.now() - 1, `account:${identifier}`);
  assert.equal((await apiCall('POST', '/auth/login', null, { identifier, password: 'whatever' })).status, 401);
  assert.equal((await db.prepare('SELECT count FROM rate_limits WHERE key=?').get(`account:${identifier}`)).count, 1, 'a new window started');
});

test('unknown API paths get a JSON 404, and the hot-path indexes exist', async () => {
  const response = await apiCall('GET', '/no-such-thing');
  assert.equal(response.status, 404);
  assert.match(response.headers.get('content-type'), /application\/json/);
  assert.deepEqual(await response.json(), { error: 'Not found' });
  const { rows } = await (await import('../db.js')).pool.query(`SELECT indexname FROM pg_indexes WHERE schemaname='public'`);
  const names = new Set(rows.map(r => r.indexname));
  for (const name of ['student_guardians_guardian_idx', 'classes_teacher_idx', 'queue_items_student_status_idx', 'schools_organization_idx', 'audit_logs_created_idx']) {
    assert.ok(names.has(name), name);
  }
});

test('production settings that are unsafe are flagged without printing their values', async () => {
  const { configWarnings } = await import('../config.js');
  assert.deepEqual(configWarnings({ NODE_ENV: 'development', REQUIRE_ADMIN_MFA: 'false' }), [], 'development is not checked');
  const warnings = configWarnings({ RAILWAY_ENVIRONMENT: 'production', REQUIRE_ADMIN_MFA: 'false', SEED_DEMO_DATA: 'true', PUBLIC_APP_URL: 'http://localhost:5173', SMTP_PASSWORD: 'hunter2' });
  const settings = warnings.map(w => w.setting);
  for (const setting of ['MFA_ENCRYPTION_KEY', 'REQUIRE_ADMIN_MFA', 'SEED_DEMO_DATA', 'PUBLIC_APP_URL', 'SMTP_*']) assert.ok(settings.includes(setting), setting);
  assert.doesNotMatch(JSON.stringify(warnings), /hunter2|localhost:5173/);
  const clean = configWarnings({
    RAILWAY_ENVIRONMENT: 'production', MFA_ENCRYPTION_KEY: 'k', PUBLIC_APP_URL: 'https://www.sdpmplus.com',
    SMTP_HOST: 'h', SMTP_PORT: '587', SMTP_USER: 'u', SMTP_PASSWORD: 'p', SMTP_FROM: 'f',
    AWS_S3_BUCKET: 'b', AWS_ACCESS_KEY_ID: 'a', AWS_SECRET_ACCESS_KEY: 's',
  });
  assert.deepEqual(clean, []);
});

// A real 1x1 PNG, and a text file that only claims to be one.
const TINY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
const FAKE_PNG = `data:image/png;base64,${Buffer.from('<script>alert(1)</script> not an image').toString('base64')}`;

test('a school can register with a logo, and everyone in that school sees it (only theirs)', async () => {
  const email = `logo-${randomUUID()}@test.local`;
  const base = { schoolName: 'Logo Academy', campusName: 'Main', adminFullName: 'Logo Admin', email, password: 'password-1' };
  for (const bad of [FAKE_PNG, 'data:image/svg+xml;base64,PHN2Zy8+', 'data:image/gif;base64,R0lGODlhAQABAAAAACw=', 'https://example.com/logo.png']) {
    const refused = await apiCall('POST', '/auth/register-school', null, { ...base, logoDataUrl: bad });
    assert.equal(refused.status, 400, `refused: ${bad.slice(0, 30)}`);
    assert.match((await refused.json()).error, /Logo must be a PNG, JPEG, or WEBP image/);
  }
  assert.equal(await db.prepare('SELECT 1 FROM users WHERE email=?').get(email), undefined, 'a refused logo registers nothing');

  assert.equal((await apiCall('POST', '/auth/register-school', null, { ...base, logoDataUrl: TINY_PNG })).status, 201);
  const admin = await login(email, 'password-1');
  const mine = await (await apiCall('GET', '/me/school', admin.token)).json();
  assert.equal(mine.name, 'Logo Academy');
  assert.equal(mine.logoUrl, TINY_PNG);
  assert.equal((await (await apiCall('GET', '/admin/setup', admin.token)).json()).school.logoUrl, TINY_PNG);

  // Parents and teachers of another school see their own school, never this logo.
  for (const who of ['morgan@school.test', 'teacher@school.test']) {
    const other = await (await apiCall('GET', '/me/school', (await login(who, 'password')).token)).json();
    assert.equal(other.name, 'Demo School');
    assert.equal(other.logoUrl, null);
  }
  const crossSchool = await fetch(`${apiBaseUrl}/api/me/school`, { headers: { Authorization: `Bearer ${(await login('morgan@school.test', 'password')).token}`, 'X-School-ID': mine.id } });
  assert.equal(crossSchool.status, 403);
  assert.equal((await apiCall('GET', '/me/school')).status, 401);

  // Only an administrator changes it; '' removes it.
  assert.equal((await apiCall('PATCH', '/admin/school', (await login('teacher@school.test', 'password')).token, { logoDataUrl: TINY_PNG })).status, 403);
  assert.equal((await apiCall('PATCH', '/admin/school', admin.token, { logoDataUrl: FAKE_PNG })).status, 400);
  assert.equal((await apiCall('PATCH', '/admin/school', admin.token, { name: 'Logo Academy 2' })).status, 204);
  assert.equal((await (await apiCall('GET', '/me/school', admin.token)).json()).logoUrl, TINY_PNG, 'saving other settings keeps the logo');
  assert.equal((await apiCall('PATCH', '/admin/school', admin.token, { logoDataUrl: '' })).status, 204);
  assert.equal((await (await apiCall('GET', '/me/school', admin.token)).json()).logoUrl, null);
});

test('with S3 storage, images are uploaded privately, served by expiring links, and deleted with their record', async () => {
  const { createServer } = await import('node:http');
  // A stand-in for S3: remembers what was put, serves it back, forgets what is deleted.
  const objects = new Map();
  const fakeS3 = createServer((req, res) => {
    const key = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (req.method === 'PUT') {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => { objects.set(key, { body: Buffer.concat(chunks), type: req.headers['content-type'], sse: req.headers['x-amz-server-side-encryption'] }); res.writeHead(200, { ETag: '"x"' }).end(); });
    } else if (req.method === 'GET') {
      const object = objects.get(key);
      // Like the real thing, an unsigned request is refused.
      if (!/X-Amz-Signature=|AWS4-HMAC-SHA256/.test(req.url + (req.headers.authorization ?? ''))) return res.writeHead(403).end();
      if (!object) return res.writeHead(404, { 'Content-Type': 'application/xml' }).end('<Error><Code>NoSuchKey</Code></Error>');
      res.writeHead(200, { 'Content-Type': object.type, 'Content-Length': object.body.length }).end(object.body);
    } else if (req.method === 'DELETE') { objects.delete(key); res.writeHead(204).end(); } else res.writeHead(405).end();
  }).listen(0);
  await new Promise(resolve => fakeS3.once('listening', resolve));
  const endpoint = `http://127.0.0.1:${fakeS3.address().port}`;
  const saved = {};
  for (const [name, value] of Object.entries({ AWS_S3_BUCKET: 'test-bucket', AWS_REGION: 'us-east-1', AWS_S3_ENDPOINT: endpoint, AWS_ACCESS_KEY_ID: 'test', AWS_SECRET_ACCESS_KEY: 'test' })) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  try {
    const admin = await login('admin@school.test', 'password');
    const setup = await (await apiCall('GET', '/admin/setup', admin.token)).json();
    const year = setup.schoolYears.find(y => y.status === 'ACTIVE');
    const room = setup.classes.find(c => c.schoolYearId === year.id);
    const child = { firstName: 'Photo', lastName: 'Kid', schoolYearId: year.id, gradeLevelId: room.gradeLevelId, classId: room.id };

    // A refused student leaves nothing behind in the bucket.
    assert.equal((await apiCall('POST', '/admin/students', admin.token, { ...child, photoDataUrl: FAKE_PNG })).status, 400);
    assert.equal((await apiCall('POST', '/admin/students', admin.token, { ...child, photoDataUrl: TINY_PNG, guardian: { id: 'guardian-of-nobody' } })).status, 400);
    assert.equal(objects.size, 0, 'the photo of a student that was not saved is removed');

    const created = await apiCall('POST', '/admin/students', admin.token, { ...child, photoDataUrl: TINY_PNG });
    assert.equal(created.status, 201);
    const studentId = (await created.json()).id;
    const stored = (await db.prepare('SELECT photo_url FROM students WHERE id=?').get(studentId)).photo_url;
    assert.match(stored, /^s3:\/\/schools\/school-default\/students\/[0-9a-f-]+\.png$/, 'the database holds a reference, not the image');
    const [[objectPath, object]] = [...objects];
    assert.equal(objectPath, `/test-bucket/${stored.slice(5)}`);
    assert.equal(object.type, 'image/png');
    assert.equal(object.sse, 'AES256');
    assert.ok(object.body.equals(Buffer.from(TINY_PNG.split(',')[1], 'base64')));

    // The API hands out a signed, expiring link — never the reference.
    const listText = await (await apiCall('GET', '/admin/students', admin.token)).text();
    assert.doesNotMatch(listText, /s3:\/\//);
    const listed = JSON.parse(listText).find(s => s.id === studentId);
    assert.ok(listed.photoUrl.startsWith(`${endpoint}/test-bucket/schools/school-default/students/`));
    assert.match(listed.photoUrl, /X-Amz-Expires=3600/);
    assert.match(listed.photoUrl, /X-Amz-Signature=/);
    const image = await fetch(listed.photoUrl);
    assert.equal(image.status, 200);
    assert.ok(Buffer.from(await image.arrayBuffer()).equals(object.body));
    assert.equal((await fetch(listed.photoUrl.split('?')[0])).status, 403, 'the plain address does not work');
    const again = JSON.parse(await (await apiCall('GET', '/admin/students', admin.token)).text()).find(s => s.id === studentId);
    assert.equal(again.photoUrl, listed.photoUrl, 'the link is stable between requests, so it can be cached');
    // The page is allowed to load images from the bucket.
    assert.match((await apiCall('GET', '/health')).headers.get('content-security-policy'), new RegExp(`img-src 'self' data: blob: ${endpoint.replace(/[.]/g, '\\.')}`));

    // An export carries the photo itself.
    const exported = await (await apiCall('GET', `/admin/students/${studentId}/export`, admin.token)).json();
    assert.equal(exported.student.photoUrl, TINY_PNG);

    // School logo: uploaded, linked, replaced (old file deleted), removed.
    assert.equal((await apiCall('PATCH', '/admin/school', admin.token, { logoDataUrl: TINY_PNG })).status, 204);
    const firstLogo = (await db.prepare(`SELECT logo_url FROM schools WHERE id='school-default'`).get()).logo_url;
    assert.match(firstLogo, /^s3:\/\/schools\/school-default\/logo\//);
    const parentView = await (await apiCall('GET', '/me/school', (await login('morgan@school.test', 'password')).token)).json();
    assert.equal((await fetch(parentView.logoUrl)).status, 200);
    assert.equal((await apiCall('PATCH', '/admin/school', admin.token, { logoDataUrl: TINY_PNG })).status, 204);
    assert.equal(objects.has(`/test-bucket/${firstLogo.slice(5)}`), false, 'the replaced logo is deleted');
    assert.equal(objects.size, 2);
    assert.equal((await apiCall('PATCH', '/admin/school', admin.token, { logoDataUrl: null })).status, 204);
    assert.equal(objects.size, 1);

    // Erasing the student erases the photo file.
    assert.equal((await apiCall('DELETE', `/admin/students/${studentId}`, admin.token)).status, 204);
    assert.equal((await apiCall('DELETE', `/admin/students/${studentId}/permanent`, admin.token, { confirmName: 'Photo Kid' })).status, 200);
    assert.equal(objects.size, 0, 'nothing of the student is left in the bucket');

    // Storage being unreachable is a clear message, not a crash or a leak of details.
    process.env.AWS_S3_ENDPOINT = 'http://127.0.0.1:1';
    const down = await apiCall('POST', '/admin/students', admin.token, { ...child, firstName: 'Down', photoDataUrl: TINY_PNG });
    assert.equal(down.status, 400);
    assert.match((await down.json()).error, /^Photo could not be saved right now/);
  } finally {
    for (const [name, value] of Object.entries(saved)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
    await new Promise(resolve => fakeS3.close(resolve));
  }
});
