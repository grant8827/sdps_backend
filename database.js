import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, scryptSync } from 'node:crypto';
import { runMigrations } from './migrations.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(here, 'data');
mkdirSync(dataDir, { recursive: true });

export const db = new DatabaseSync(process.env.DATABASE_PATH || path.join(dataDir, 'school.db'));
db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');

export const id = prefix => `${prefix}-${randomUUID()}`;
export const passwordHash = password => scryptSync(password, 'school-dropoff-local-v1', 64).toString('hex');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    phone TEXT, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('parent','teacher','admin')),
    active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS guardians (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS students (
    id TEXT PRIMARY KEY, first_name TEXT NOT NULL, last_name TEXT NOT NULL, date_of_birth TEXT,
    student_number TEXT UNIQUE, status TEXT NOT NULL DEFAULT 'ACTIVE', pickup_status TEXT NOT NULL DEFAULT 'AT_HOME',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
    created_by TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(from_school_year_id, to_school_year_id)
  );
`);

function seed() {
  const addUser = db.prepare(`INSERT OR IGNORE INTO users (id,full_name,email,phone,password_hash,role) VALUES (?,?,?,?,?,?)`);
  addUser.run('admin-1', 'Alex Admin', 'admin@school.test', null, passwordHash('password'), 'admin');
  addUser.run('teacher-1', 'Taylor Teacher', 'teacher@school.test', null, passwordHash('password'), 'teacher');
  addUser.run('teacher-2', 'Jordan Jones', 'jordan@school.test', null, passwordHash('password'), 'teacher');
  addUser.run('parent-1', 'Parker Parent', 'parent@school.test', '555-0100', passwordHash('password'), 'parent');
  addUser.run('parent-2', 'Morgan Guardian', 'morgan@school.test', '555-0101', passwordHash('password'), 'parent');
  db.prepare('INSERT OR IGNORE INTO guardians (id,user_id) VALUES (?,?)').run('guardian-1', 'parent-1');
  db.prepare('INSERT OR IGNORE INTO guardians (id,user_id) VALUES (?,?)').run('guardian-2', 'parent-2');

  const grades = ['Pre-K','Kindergarten','1','2','3','4','5','6','7','8','9','10','11','12'];
  const addGrade = db.prepare('INSERT OR IGNORE INTO grade_levels (id,name,sort_order) VALUES (?,?,?)');
  grades.forEach((name, index) => addGrade.run(`grade-${index}`, name, index));
  grades.forEach((_, index) => {
    if (index < grades.length - 1) db.prepare('UPDATE grade_levels SET next_grade_level_id=? WHERE id=?').run(`grade-${index + 1}`, `grade-${index}`);
  });
  db.prepare(`INSERT OR IGNORE INTO school_years (id,name,starts_on,ends_on,status) VALUES ('year-current','2026-2027','2026-08-01','2027-06-30','ACTIVE')`).run();
  db.prepare(`INSERT OR IGNORE INTO school_years (id,name,starts_on,ends_on,status) VALUES ('year-next','2027-2028','2027-08-01','2028-06-30','PLANNING')`).run();
  db.prepare(`INSERT OR IGNORE INTO classes (id,name,room_name,school_year_id,grade_level_id,teacher_user_id) VALUES ('class-1','Grade 1 - Room 12','Room 12','year-current','grade-2','teacher-1')`).run();
  db.prepare(`INSERT OR IGNORE INTO classes (id,name,room_name,school_year_id,grade_level_id,teacher_user_id) VALUES ('class-2','Grade 2 - Room 4','Room 4','year-current','grade-3','teacher-2')`).run();

  const addStudent = db.prepare(`INSERT OR IGNORE INTO students (id,first_name,last_name,student_number,pickup_status) VALUES (?,?,?,?,?)`);
  addStudent.run('child-1','Sam','Parent-Kid','S1001','AT_HOME');
  addStudent.run('child-2','Riley','Parent-Kid','S1002','AT_HOME');
  addStudent.run('child-3','Casey','Kid','S1003','PRESENT');
  const link = db.prepare(`INSERT OR IGNORE INTO student_guardians (student_id,guardian_id,relationship,is_primary) VALUES (?,?,?,1)`);
  link.run('child-1','guardian-1','Parent'); link.run('child-2','guardian-1','Parent'); link.run('child-3','guardian-2','Guardian');
  const enroll = db.prepare(`INSERT OR IGNORE INTO student_enrollments (id,student_id,school_year_id,grade_level_id,class_id) VALUES (?,?,?,?,?)`);
  enroll.run('enrollment-1','child-1','year-current','grade-2','class-1');
  enroll.run('enrollment-2','child-2','year-current','grade-2','class-1');
  enroll.run('enrollment-3','child-3','year-current','grade-3','class-2');
}

seed();
runMigrations(db);
