import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const testDirectory = mkdtempSync(path.join(tmpdir(), 'school-tenant-test-'));
process.env.DATABASE_PATH = path.join(testDirectory, 'school.db');

const { db, passwordHash } = await import('../database.js');
const { canAccessSchool, getMemberships, requireSchoolAccess } = await import('../tenant.js');

db.prepare(`INSERT INTO organizations (id,name) VALUES ('organization-b','Organization B')`).run();
db.prepare(`INSERT INTO schools (id,organization_id,name,code) VALUES ('school-b','organization-b','School B','SCHOOLB')`).run();
db.prepare(`INSERT INTO campuses (id,school_id,name) VALUES ('campus-b','school-b','School B Main')`).run();
db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES ('admin-b','School B Admin','admin-b@test.local',?,'admin')`).run(passwordHash('password'));
db.prepare(`INSERT INTO memberships (id,user_id,school_id,role) VALUES ('membership-admin-b','admin-b','school-b','school_admin')`).run();
db.prepare(`INSERT INTO students (id,first_name,last_name,student_number,school_id,campus_id) VALUES ('student-b','Private','Student','B-1','school-b','campus-b')`).run();

after(() => {
  db.close();
  rmSync(testDirectory, { recursive: true, force: true });
});

test('existing users are backfilled into the default school', () => {
  const memberships = getMemberships('admin-1');
  assert.equal(memberships.length, 1);
  assert.equal(memberships[0].schoolId, 'school-default');
  assert.equal(memberships[0].role, 'school_admin');
});

test('School A admin cannot access School B', () => {
  assert.equal(canAccessSchool('admin-1', 'school-b', ['school_admin']), null);
  assert.equal(canAccessSchool('admin-b', 'school-b', ['school_admin']).schoolId, 'school-b');
});

test('forging X-School-ID is rejected by middleware', () => {
  const req = { user: { id: 'admin-1' }, headers: { 'x-school-id': 'school-b' }, query: {}, body: {} };
  let statusCode; let responseBody; let nextCalled = false;
  const res = { status(code) { statusCode = code; return this; }, json(body) { responseBody = body; return this; } };
  requireSchoolAccess('school_admin')(req, res, () => { nextCalled = true; });
  assert.equal(statusCode, 403);
  assert.equal(nextCalled, false);
  assert.match(responseBody.error, /do not have access/i);
});

test('school-scoped student query cannot return another school student', () => {
  const schoolAStudents = db.prepare('SELECT id FROM students WHERE school_id=?').all('school-default');
  const schoolBStudents = db.prepare('SELECT id FROM students WHERE school_id=?').all('school-b');
  assert.equal(schoolAStudents.some(student => student.id === 'student-b'), false);
  assert.deepEqual(schoolBStudents.map(student => student.id), ['student-b']);
});
