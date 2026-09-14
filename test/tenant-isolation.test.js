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

const { db, passwordHash } = await import('../db.js');
const { canAccessSchool, getMemberships, requireSchoolAccess } = await import('../tenant.js');

await db.prepare(`INSERT INTO organizations (id,name) VALUES ('organization-b','Organization B')`).run();
await db.prepare(`INSERT INTO schools (id,organization_id,name,code) VALUES ('school-b','organization-b','School B','SCHOOLB')`).run();
await db.prepare(`INSERT INTO campuses (id,school_id,name) VALUES ('campus-b','school-b','School B Main')`).run();
await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES ('admin-b','School B Admin','admin-b@test.local',?,'admin')`).run(passwordHash('password'));
await db.prepare(`INSERT INTO memberships (id,user_id,school_id,role) VALUES ('membership-admin-b','admin-b','school-b','school_admin')`).run();
await db.prepare(`INSERT INTO students (id,first_name,last_name,student_number,school_id,campus_id) VALUES ('student-b','Private','Student','B-1','school-b','campus-b')`).run();

after(async () => {
  await db.close();
  const cleanup = new Client({ connectionString: adminUrl.toString() });
  await cleanup.connect();
  await cleanup.query(`DROP DATABASE IF EXISTS "${testDbName}"`);
  await cleanup.end();
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
