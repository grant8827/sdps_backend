import pg from 'pg';
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID, scryptSync } from 'node:crypto';
import { runMigrations } from './migrations.js';

const { Pool, types } = pg;

// pg returns bigint/COUNT(*) (OID 20) as strings by default, to avoid
// silent precision loss on values bigger than Number.MAX_SAFE_INTEGER.
// Every id in this schema is an app-generated TEXT uuid — never a real
// bigint — so there's nothing here that could lose precision, and
// several call sites (promotion year-count checks, overview counts)
// depend on COUNT(*) being a number.
types.setTypeParser(20, value => parseInt(value, 10));

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
});

// Lets `db.prepare(...).get/all/run` transparently use whichever
// Postgres client is active for the *calling* async context — the pool
// itself outside a transaction, or a single checked-out client while
// inside withTransaction(). See withTransaction() below for why this is
// safe under concurrent requests.
const als = new AsyncLocalStorage();
const currentExecutor = () => als.getStore() || pool;

// Translates SQLite's positional `?` placeholders to Postgres's
// $1,$2,... so every existing call site can keep writing `?` and pass
// positional args, unchanged.
const toPgSql = sql => {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
};

function prepare(sql) {
  const text = toPgSql(sql);
  return {
    async get(...params) {
      return (await currentExecutor().query(text, params)).rows[0];
    },
    async all(...params) {
      return (await currentExecutor().query(text, params)).rows;
    },
    async run(...params) {
      const result = await currentExecutor().query(text, params);
      return { changes: result.rowCount };
    },
  };
}

async function exec(sql) {
  await currentExecutor().query(sql);
}

export const db = { prepare, exec, close: () => pool.end() };

export async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await als.run(client, fn);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // transaction was already aborted by the failing statement; nothing more to undo
    }
    throw err;
  } finally {
    client.release();
  }
}

// Postgres's unique-violation SQLSTATE code — used in place of SQLite's
// error.message.includes('UNIQUE') checks, since pg's error messages
// read "duplicate key value violates unique constraint ..." instead.
export const isUniqueViolation = error => error?.code === '23505';

export const id = prefix => `${prefix}-${randomUUID()}`;
export const passwordHash = password => scryptSync(password, 'school-dropoff-local-v1', 64).toString('hex');

// Timestamp default that reproduces SQLite's CURRENT_TIMESTAMP string
// shape exactly ('YYYY-MM-DD HH:MM:SS', UTC) instead of switching to
// Postgres's native timestamptz format — the frontend sorts some of
// these fields with string.localeCompare and parses others with a bare
// `new Date(x)`, which V8 treats as local time for this bare shape but
// as UTC for an offset-suffixed ISO string. Keeping the shape avoids
// silently shifting every displayed timestamp by the local UTC offset.
const CURRENT_TIMESTAMP = `to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')`;

await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL,
    phone TEXT, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('parent','teacher','admin')),
    active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT ${CURRENT_TIMESTAMP}
  );
  CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (LOWER(email));
  CREATE TABLE IF NOT EXISTS guardians (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS students (
    id TEXT PRIMARY KEY, first_name TEXT NOT NULL, last_name TEXT NOT NULL, date_of_birth TEXT,
    student_number TEXT UNIQUE, status TEXT NOT NULL DEFAULT 'ACTIVE', pickup_status TEXT NOT NULL DEFAULT 'AT_HOME',
    created_at TEXT NOT NULL DEFAULT ${CURRENT_TIMESTAMP}
  );
  CREATE TABLE IF NOT EXISTS student_guardians (
    student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    guardian_id TEXT NOT NULL REFERENCES guardians(id) ON DELETE CASCADE,
    relationship TEXT NOT NULL DEFAULT 'Guardian', is_primary INTEGER NOT NULL DEFAULT 0,
    can_pick_up INTEGER NOT NULL DEFAULT 1, can_manage INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(student_id, guardian_id)
  );
  CREATE TABLE IF NOT EXISTS school_years (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, starts_on TEXT NOT NULL, ends_on TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PLANNING','ACTIVE','CLOSED'))
  );
  CREATE TABLE IF NOT EXISTS grade_levels (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, sort_order INTEGER NOT NULL UNIQUE,
    next_grade_level_id TEXT REFERENCES grade_levels(id)
  );
  CREATE TABLE IF NOT EXISTS classes (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, room_name TEXT, school_year_id TEXT NOT NULL REFERENCES school_years(id),
    grade_level_id TEXT NOT NULL REFERENCES grade_levels(id), teacher_user_id TEXT REFERENCES users(id),
    UNIQUE(name, school_year_id)
  );
  CREATE TABLE IF NOT EXISTS student_enrollments (
    id TEXT PRIMARY KEY, student_id TEXT NOT NULL REFERENCES students(id), school_year_id TEXT NOT NULL REFERENCES school_years(id),
    grade_level_id TEXT NOT NULL REFERENCES grade_levels(id), class_id TEXT REFERENCES classes(id),
    status TEXT NOT NULL DEFAULT 'ENROLLED', promoted_from_id TEXT REFERENCES student_enrollments(id),
    UNIQUE(student_id, school_year_id)
  );
  CREATE TABLE IF NOT EXISTS promotion_runs (
    id TEXT PRIMARY KEY, from_school_year_id TEXT NOT NULL, to_school_year_id TEXT NOT NULL,
    created_by TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT ${CURRENT_TIMESTAMP},
    UNIQUE(from_school_year_id, to_school_year_id)
  );
`);

async function seed() {
  const addUser = db.prepare(`INSERT INTO users (id,full_name,email,phone,password_hash,role) VALUES (?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING`);
  await addUser.run('admin-1', 'Alex Admin', 'admin@school.test', null, passwordHash('password'), 'admin');
  await addUser.run('teacher-1', 'Taylor Teacher', 'teacher@school.test', null, passwordHash('password'), 'teacher');
  await addUser.run('teacher-2', 'Jordan Jones', 'jordan@school.test', null, passwordHash('password'), 'teacher');
  await addUser.run('parent-1', 'Parker Parent', 'parent@school.test', '555-0100', passwordHash('password'), 'parent');
  await addUser.run('parent-2', 'Morgan Guardian', 'morgan@school.test', '555-0101', passwordHash('password'), 'parent');
  await db.prepare('INSERT INTO guardians (id,user_id) VALUES (?,?) ON CONFLICT (id) DO NOTHING').run('guardian-1', 'parent-1');
  await db.prepare('INSERT INTO guardians (id,user_id) VALUES (?,?) ON CONFLICT (id) DO NOTHING').run('guardian-2', 'parent-2');

  const grades = ['Pre-K', 'Kindergarten', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12'];
  const addGrade = db.prepare('INSERT INTO grade_levels (id,name,sort_order) VALUES (?,?,?) ON CONFLICT (id) DO NOTHING');
  for (const [index, name] of grades.entries()) await addGrade.run(`grade-${index}`, name, index);
  for (const index of grades.keys()) {
    if (index < grades.length - 1) await db.prepare('UPDATE grade_levels SET next_grade_level_id=? WHERE id=?').run(`grade-${index + 1}`, `grade-${index}`);
  }
  await db.prepare(`INSERT INTO school_years (id,name,starts_on,ends_on,status) VALUES ('year-current','2026-2027','2026-08-01','2027-06-30','ACTIVE') ON CONFLICT (id) DO NOTHING`).run();
  await db.prepare(`INSERT INTO school_years (id,name,starts_on,ends_on,status) VALUES ('year-next','2027-2028','2027-08-01','2028-06-30','PLANNING') ON CONFLICT (id) DO NOTHING`).run();
  await db.prepare(`INSERT INTO classes (id,name,room_name,school_year_id,grade_level_id,teacher_user_id) VALUES ('class-1','Grade 1 - Room 12','Room 12','year-current','grade-2','teacher-1') ON CONFLICT (id) DO NOTHING`).run();
  await db.prepare(`INSERT INTO classes (id,name,room_name,school_year_id,grade_level_id,teacher_user_id) VALUES ('class-2','Grade 2 - Room 4','Room 4','year-current','grade-3','teacher-2') ON CONFLICT (id) DO NOTHING`).run();

  const addStudent = db.prepare(`INSERT INTO students (id,first_name,last_name,student_number,pickup_status) VALUES (?,?,?,?,?) ON CONFLICT (id) DO NOTHING`);
  await addStudent.run('child-1', 'Sam', 'Parent-Kid', 'S1001', 'AT_HOME');
  await addStudent.run('child-2', 'Riley', 'Parent-Kid', 'S1002', 'AT_HOME');
  await addStudent.run('child-3', 'Casey', 'Kid', 'S1003', 'PRESENT');
  const link = db.prepare(`INSERT INTO student_guardians (student_id,guardian_id,relationship,is_primary) VALUES (?,?,?,1) ON CONFLICT (student_id,guardian_id) DO NOTHING`);
  await link.run('child-1', 'guardian-1', 'Parent');
  await link.run('child-2', 'guardian-1', 'Parent');
  await link.run('child-3', 'guardian-2', 'Guardian');
  const enroll = db.prepare(`INSERT INTO student_enrollments (id,student_id,school_year_id,grade_level_id,class_id) VALUES (?,?,?,?,?) ON CONFLICT (id) DO NOTHING`);
  await enroll.run('enrollment-1', 'child-1', 'year-current', 'grade-2', 'class-1');
  await enroll.run('enrollment-2', 'child-2', 'year-current', 'grade-2', 'class-1');
  await enroll.run('enrollment-3', 'child-3', 'year-current', 'grade-3', 'class-2');
}

await seed();
await runMigrations(db, withTransaction);
