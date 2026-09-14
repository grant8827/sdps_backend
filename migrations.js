const DEFAULT_ORGANIZATION_ID = 'organization-default';
export const DEFAULT_SCHOOL_ID = 'school-default';
export const DEFAULT_CAMPUS_ID = 'campus-default';

function hasColumn(db, table, column) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(item => item.name === column);
}

function addColumn(db, table, definition) {
  const column = definition.trim().split(/\s+/)[0];
  if (!hasColumn(db, table, column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
}

const migrations = [
  {
    version: 1,
    name: 'tenant foundation and existing-data backfill',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS organizations (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS schools (
          id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
          name TEXT NOT NULL, code TEXT NOT NULL UNIQUE COLLATE NOCASE, timezone TEXT NOT NULL DEFAULT 'America/New_York',
          status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS campuses (
          id TEXT PRIMARY KEY, school_id TEXT NOT NULL REFERENCES schools(id), name TEXT NOT NULL,
          address TEXT, latitude REAL, longitude REAL, geofence_radius REAL,
          timezone TEXT NOT NULL DEFAULT 'America/New_York', status TEXT NOT NULL DEFAULT 'ACTIVE',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(school_id, name)
        );
        CREATE TABLE IF NOT EXISTS memberships (
          id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          school_id TEXT NOT NULL REFERENCES schools(id), campus_id TEXT REFERENCES campuses(id),
          role TEXT NOT NULL CHECK(role IN ('platform_super_admin','school_admin','teacher','staff','parent')),
          status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE UNIQUE INDEX IF NOT EXISTS memberships_scope_unique
          ON memberships(user_id, school_id, IFNULL(campus_id, ''), role);
      `);

      addColumn(db, 'students', 'school_id TEXT REFERENCES schools(id)');
      addColumn(db, 'students', 'campus_id TEXT REFERENCES campuses(id)');
      addColumn(db, 'school_years', 'school_id TEXT REFERENCES schools(id)');
      addColumn(db, 'classes', 'school_id TEXT REFERENCES schools(id)');
      addColumn(db, 'classes', 'campus_id TEXT REFERENCES campuses(id)');
      addColumn(db, 'student_enrollments', 'school_id TEXT REFERENCES schools(id)');
      addColumn(db, 'student_enrollments', 'campus_id TEXT REFERENCES campuses(id)');
      addColumn(db, 'promotion_runs', 'school_id TEXT REFERENCES schools(id)');

      db.prepare('INSERT OR IGNORE INTO organizations (id,name) VALUES (?,?)').run(DEFAULT_ORGANIZATION_ID, 'Default Organization');
      db.prepare('INSERT OR IGNORE INTO schools (id,organization_id,name,code) VALUES (?,?,?,?)').run(DEFAULT_SCHOOL_ID, DEFAULT_ORGANIZATION_ID, 'Demo School', 'DEMO');
      db.prepare('INSERT OR IGNORE INTO campuses (id,school_id,name) VALUES (?,?,?)').run(DEFAULT_CAMPUS_ID, DEFAULT_SCHOOL_ID, 'Main Campus');

      db.prepare('UPDATE students SET school_id=?,campus_id=? WHERE school_id IS NULL').run(DEFAULT_SCHOOL_ID, DEFAULT_CAMPUS_ID);
      db.prepare('UPDATE school_years SET school_id=? WHERE school_id IS NULL').run(DEFAULT_SCHOOL_ID);
      db.prepare('UPDATE classes SET school_id=?,campus_id=? WHERE school_id IS NULL').run(DEFAULT_SCHOOL_ID, DEFAULT_CAMPUS_ID);
      db.prepare(`UPDATE student_enrollments SET school_id=(SELECT school_id FROM students WHERE students.id=student_enrollments.student_id), campus_id=(SELECT campus_id FROM students WHERE students.id=student_enrollments.student_id) WHERE school_id IS NULL`).run();
      db.prepare('UPDATE promotion_runs SET school_id=? WHERE school_id IS NULL').run(DEFAULT_SCHOOL_ID);

      const addMembership = db.prepare(`INSERT OR IGNORE INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?,?)`);
      for (const user of db.prepare('SELECT id,role FROM users').all()) {
        const role = user.role === 'admin' ? 'school_admin' : user.role;
        addMembership.run(`membership-${user.id}`, user.id, DEFAULT_SCHOOL_ID, role === 'parent' || role === 'school_admin' ? null : DEFAULT_CAMPUS_ID, role);
      }

      db.exec(`
        CREATE INDEX IF NOT EXISTS students_school_campus_idx ON students(school_id,campus_id,status);
        CREATE INDEX IF NOT EXISTS classes_school_campus_idx ON classes(school_id,campus_id,school_year_id);
        CREATE INDEX IF NOT EXISTS enrollments_school_student_idx ON student_enrollments(school_id,student_id,school_year_id);
        CREATE INDEX IF NOT EXISTS memberships_user_status_idx ON memberships(user_id,status,school_id);
        CREATE INDEX IF NOT EXISTS memberships_school_role_idx ON memberships(school_id,role,status);
        CREATE INDEX IF NOT EXISTS promotion_runs_school_idx ON promotion_runs(school_id,from_school_year_id,to_school_year_id);
      `);
    },
  },
  {
    version: 2,
    name: 'scope school_years uniqueness to (school_id, name) instead of a global name',
    up(db) {
      // school_years.name was UNIQUE across the whole database, a
      // leftover from before multi-tenancy — every self-registered
      // school lands on the same auto-generated year label (e.g.
      // "2026-2027"), so the second school to sign up would fail here.
      // SQLite can't ALTER a constraint in place; rebuild the table.
      // (Only school_years itself needs recreating — the FK
      // declarations on classes/student_enrollments/promotion_runs
      // live on those tables, not on this one, and SQLite doesn't
      // validate cross-table FKs against a DROP TABLE.)
      db.exec(`
        CREATE TABLE school_years_new (
          id TEXT PRIMARY KEY, school_id TEXT REFERENCES schools(id), name TEXT NOT NULL,
          starts_on TEXT NOT NULL, ends_on TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PLANNING','ACTIVE','CLOSED')),
          UNIQUE(school_id, name)
        );
        INSERT INTO school_years_new (id, school_id, name, starts_on, ends_on, status)
          SELECT id, school_id, name, starts_on, ends_on, status FROM school_years;
        DROP TABLE school_years;
        ALTER TABLE school_years_new RENAME TO school_years;
      `);
    },
  },
  {
    version: 3,
    name: 'real drop-off/pick-up queue (was in-memory-only mock state per client)',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS queue_items (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          student_id TEXT NOT NULL REFERENCES students(id),
          teacher_user_id TEXT REFERENCES users(id),
          request_type TEXT NOT NULL CHECK(request_type IN ('DROP_OFF','PICK_UP')),
          requested_by_user_id TEXT NOT NULL REFERENCES users(id),
          status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','CANCELLED')),
          requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          approved_at TEXT,
          approved_by_user_id TEXT REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS queue_items_teacher_status_idx ON queue_items(teacher_user_id, status);
        CREATE INDEX IF NOT EXISTS queue_items_school_status_idx ON queue_items(school_id, status);
      `);
    },
  },
  {
    version: 4,
    name: 'student photos + a real daily attendance table',
    up(db) {
      addColumn(db, 'students', 'photo_url TEXT');
      db.exec(`
        CREATE TABLE IF NOT EXISTS attendance_records (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          student_id TEXT NOT NULL REFERENCES students(id),
          class_id TEXT REFERENCES classes(id),
          date TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PRESENT','ABSENT')),
          marked_by_user_id TEXT REFERENCES users(id),
          marked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(student_id, date)
        );
        CREATE INDEX IF NOT EXISTS attendance_class_date_idx ON attendance_records(class_id, date);
        CREATE INDEX IF NOT EXISTS attendance_school_date_idx ON attendance_records(school_id, date);
      `);
    },
  },
  {
    version: 5,
    name: 'teacher photos (reuses users.photo_url for any user, not just students)',
    up(db) {
      addColumn(db, 'users', 'photo_url TEXT');
    },
  },
  {
    version: 6,
    name: 'attendance: allow SICK/SUSPENDED/HOLIDAY in addition to PRESENT/ABSENT',
    up(db) {
      // WEEKEND is deliberately not in this list — nobody marks a
      // weekend, it's just a calendar fact the client computes from the
      // date itself, never a stored row.
      db.exec(`
        CREATE TABLE attendance_records_new (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          student_id TEXT NOT NULL REFERENCES students(id),
          class_id TEXT REFERENCES classes(id),
          date TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PRESENT','ABSENT','SICK','SUSPENDED','HOLIDAY')),
          marked_by_user_id TEXT REFERENCES users(id),
          marked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(student_id, date)
        );
        INSERT INTO attendance_records_new SELECT * FROM attendance_records;
        DROP TABLE attendance_records;
        ALTER TABLE attendance_records_new RENAME TO attendance_records;
        CREATE INDEX IF NOT EXISTS attendance_class_date_idx ON attendance_records(class_id, date);
        CREATE INDEX IF NOT EXISTS attendance_school_date_idx ON attendance_records(school_id, date);
      `);
    },
  },
  {
    version: 7,
    name: 'sessions: persist logins in the database instead of an in-memory Map, so a backend restart no longer force-logs-out every user',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
      `);
    },
  },
  {
    version: 8,
    name: 'attendance: allow WEEKEND as an explicit status too, so a teacher can override the Sat/Sun default from the same dropdown as PRESENT/ABSENT/etc',
    up(db) {
      db.exec(`
        CREATE TABLE attendance_records_new (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          student_id TEXT NOT NULL REFERENCES students(id),
          class_id TEXT REFERENCES classes(id),
          date TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PRESENT','ABSENT','SICK','SUSPENDED','HOLIDAY','WEEKEND')),
          marked_by_user_id TEXT REFERENCES users(id),
          marked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(student_id, date)
        );
        INSERT INTO attendance_records_new SELECT * FROM attendance_records;
        DROP TABLE attendance_records;
        ALTER TABLE attendance_records_new RENAME TO attendance_records;
        CREATE INDEX IF NOT EXISTS attendance_class_date_idx ON attendance_records(class_id, date);
        CREATE INDEX IF NOT EXISTS attendance_school_date_idx ON attendance_records(school_id, date);
      `);
    },
  },
  {
    version: 9,
    name: 'queue: allow a teacher/admin to decline a request, not just approve it',
    up(db) {
      db.exec(`
        CREATE TABLE queue_items_new (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          student_id TEXT NOT NULL REFERENCES students(id),
          teacher_user_id TEXT REFERENCES users(id),
          request_type TEXT NOT NULL CHECK(request_type IN ('DROP_OFF','PICK_UP')),
          requested_by_user_id TEXT NOT NULL REFERENCES users(id),
          status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','CANCELLED','DECLINED')),
          requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          approved_at TEXT,
          approved_by_user_id TEXT REFERENCES users(id),
          declined_at TEXT,
          declined_by_user_id TEXT REFERENCES users(id)
        );
        INSERT INTO queue_items_new (id,school_id,campus_id,student_id,teacher_user_id,request_type,requested_by_user_id,status,requested_at,approved_at,approved_by_user_id)
          SELECT id,school_id,campus_id,student_id,teacher_user_id,request_type,requested_by_user_id,status,requested_at,approved_at,approved_by_user_id FROM queue_items;
        DROP TABLE queue_items;
        ALTER TABLE queue_items_new RENAME TO queue_items;
        CREATE INDEX IF NOT EXISTS queue_items_teacher_status_idx ON queue_items(teacher_user_id, status);
        CREATE INDEX IF NOT EXISTS queue_items_school_status_idx ON queue_items(school_id, status);
      `);
    },
  },
  {
    version: 10,
    name: 'real notices (was in-memory-only mock state per client, same problem the queue used to have)',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS notices (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          sender_user_id TEXT NOT NULL REFERENCES users(id),
          sender_name TEXT NOT NULL,
          sender_role TEXT NOT NULL CHECK(sender_role IN ('teacher','admin')),
          title TEXT NOT NULL,
          body TEXT NOT NULL,
          target_type TEXT NOT NULL CHECK(target_type IN ('SCHOOL','CLASS','PARENT')),
          target_teacher_id TEXT REFERENCES users(id),
          target_parent_user_id TEXT REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS notices_school_idx ON notices(school_id);
        CREATE INDEX IF NOT EXISTS notices_target_teacher_idx ON notices(target_teacher_id);
        CREATE INDEX IF NOT EXISTS notices_target_parent_idx ON notices(target_parent_user_id);

        -- Read state is per-recipient, not global — a school-wide
        -- broadcast one parent has read must still show unread for
        -- everyone else.
        CREATE TABLE IF NOT EXISTS notice_reads (
          notice_id TEXT NOT NULL REFERENCES notices(id) ON DELETE CASCADE,
          user_id TEXT NOT NULL REFERENCES users(id),
          read_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY(notice_id, user_id)
        );
      `);
    },
  },
  {
    version: 11,
    name: 'notices: allow a parent-invited co-guardian to auto-notify the school admin',
    up(db) {
      db.exec(`
        CREATE TABLE notices_new (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          sender_user_id TEXT NOT NULL REFERENCES users(id),
          sender_name TEXT NOT NULL,
          sender_role TEXT NOT NULL CHECK(sender_role IN ('teacher','admin','parent')),
          title TEXT NOT NULL,
          body TEXT NOT NULL,
          target_type TEXT NOT NULL CHECK(target_type IN ('SCHOOL','CLASS','PARENT','ADMIN')),
          target_teacher_id TEXT REFERENCES users(id),
          target_parent_user_id TEXT REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO notices_new (id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_teacher_id,target_parent_user_id,created_at)
          SELECT id,school_id,campus_id,sender_user_id,sender_name,sender_role,title,body,target_type,target_teacher_id,target_parent_user_id,created_at FROM notices;
        DROP TABLE notices;
        ALTER TABLE notices_new RENAME TO notices;
        CREATE INDEX IF NOT EXISTS notices_school_idx ON notices(school_id);
        CREATE INDEX IF NOT EXISTS notices_target_teacher_idx ON notices(target_teacher_id);
        CREATE INDEX IF NOT EXISTS notices_target_parent_idx ON notices(target_parent_user_id);
      `);
    },
  },
  {
    version: 12,
    name: 'school profile (start/dismissal/extended-day times), per-student daycare flag, and a late marker on attendance',
    up(db) {
      // Stored as 'HH:MM' (24-hour, school-local) so they sort/compare
      // lexicographically like any other string — no date math needed
      // to tell whether a drop-off landed before or after start time.
      addColumn(db, 'schools', 'start_time TEXT');
      addColumn(db, 'schools', 'dismissal_time TEXT');
      addColumn(db, 'schools', 'extended_time TEXT');
      addColumn(db, 'students', 'daycare INTEGER NOT NULL DEFAULT 0');
      addColumn(db, 'attendance_records', 'late INTEGER NOT NULL DEFAULT 0');
    },
  },
  {
    version: 13,
    name: 'per-location (campus) hours, for schools with more than one location on different bell schedules',
    up(db) {
      addColumn(db, 'campuses', 'start_time TEXT');
      addColumn(db, 'campuses', 'dismissal_time TEXT');
      addColumn(db, 'campuses', 'extended_time TEXT');
    },
  },
];

export function runMigrations(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
  const applied = db.prepare('SELECT 1 FROM schema_migrations WHERE version=?');
  const record = db.prepare('INSERT INTO schema_migrations (version,name) VALUES (?,?)');
  for (const migration of migrations) {
    if (applied.get(migration.version)) continue;
    // Off outside the transaction, not inside it: SQLite ignores pragma
    // changes made mid-transaction, and a rebuild like migration 2's
    // (DROP + RENAME a table other tables still hold FKs into) needs it
    // off for the DROP to be allowed at all.
    db.exec('PRAGMA foreign_keys = OFF');
    db.exec('BEGIN IMMEDIATE');
    try {
      migration.up(db);
      record.run(migration.version, migration.name);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    } finally {
      db.exec('PRAGMA foreign_keys = ON');
    }
  }
}
