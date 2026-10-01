const DEFAULT_ORGANIZATION_ID = 'organization-default';
export const DEFAULT_SCHOOL_ID = 'school-default';
export const DEFAULT_CAMPUS_ID = 'campus-default';

const migrations = [
  {
    version: 1,
    name: 'tenant foundation and existing-data backfill',
    async up(db) {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS organizations (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE',
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE TABLE IF NOT EXISTS schools (
          id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
          name TEXT NOT NULL, code TEXT NOT NULL, timezone TEXT NOT NULL DEFAULT 'America/New_York',
          status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE UNIQUE INDEX IF NOT EXISTS schools_code_unique ON schools (LOWER(code));
        CREATE TABLE IF NOT EXISTS campuses (
          id TEXT PRIMARY KEY, school_id TEXT NOT NULL REFERENCES schools(id), name TEXT NOT NULL,
          address TEXT, latitude DOUBLE PRECISION, longitude DOUBLE PRECISION, geofence_radius DOUBLE PRECISION,
          timezone TEXT NOT NULL DEFAULT 'America/New_York', status TEXT NOT NULL DEFAULT 'ACTIVE',
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          UNIQUE(school_id, name)
        );
        CREATE TABLE IF NOT EXISTS memberships (
          id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          school_id TEXT NOT NULL REFERENCES schools(id), campus_id TEXT REFERENCES campuses(id),
          role TEXT NOT NULL CHECK(role IN ('platform_super_admin','school_admin','teacher','staff','parent')),
          status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE UNIQUE INDEX IF NOT EXISTS memberships_scope_unique
          ON memberships(user_id, school_id, COALESCE(campus_id, ''), role);

        ALTER TABLE students ADD COLUMN IF NOT EXISTS school_id TEXT REFERENCES schools(id);
        ALTER TABLE students ADD COLUMN IF NOT EXISTS campus_id TEXT REFERENCES campuses(id);
        ALTER TABLE school_years ADD COLUMN IF NOT EXISTS school_id TEXT REFERENCES schools(id);
        ALTER TABLE classes ADD COLUMN IF NOT EXISTS school_id TEXT REFERENCES schools(id);
        ALTER TABLE classes ADD COLUMN IF NOT EXISTS campus_id TEXT REFERENCES campuses(id);
        ALTER TABLE student_enrollments ADD COLUMN IF NOT EXISTS school_id TEXT REFERENCES schools(id);
        ALTER TABLE student_enrollments ADD COLUMN IF NOT EXISTS campus_id TEXT REFERENCES campuses(id);
        ALTER TABLE promotion_runs ADD COLUMN IF NOT EXISTS school_id TEXT REFERENCES schools(id);
      `);

      await db.prepare('INSERT INTO organizations (id,name) VALUES (?,?) ON CONFLICT (id) DO NOTHING').run(DEFAULT_ORGANIZATION_ID, 'Default Organization');
      await db.prepare('INSERT INTO schools (id,organization_id,name,code) VALUES (?,?,?,?) ON CONFLICT (id) DO NOTHING').run(DEFAULT_SCHOOL_ID, DEFAULT_ORGANIZATION_ID, 'Demo School', 'DEMO');
      await db.prepare('INSERT INTO campuses (id,school_id,name) VALUES (?,?,?) ON CONFLICT (id) DO NOTHING').run(DEFAULT_CAMPUS_ID, DEFAULT_SCHOOL_ID, 'Main Campus');

      await db.prepare('UPDATE students SET school_id=?,campus_id=? WHERE school_id IS NULL').run(DEFAULT_SCHOOL_ID, DEFAULT_CAMPUS_ID);
      await db.prepare('UPDATE school_years SET school_id=? WHERE school_id IS NULL').run(DEFAULT_SCHOOL_ID);
      await db.prepare('UPDATE classes SET school_id=?,campus_id=? WHERE school_id IS NULL').run(DEFAULT_SCHOOL_ID, DEFAULT_CAMPUS_ID);
      await db.prepare(`UPDATE student_enrollments SET school_id=(SELECT school_id FROM students WHERE students.id=student_enrollments.student_id), campus_id=(SELECT campus_id FROM students WHERE students.id=student_enrollments.student_id) WHERE school_id IS NULL`).run();
      await db.prepare('UPDATE promotion_runs SET school_id=? WHERE school_id IS NULL').run(DEFAULT_SCHOOL_ID);

      const addMembership = db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role) VALUES (?,?,?,?,?) ON CONFLICT (user_id, school_id, COALESCE(campus_id, ''), role) DO NOTHING`);
      for (const user of await db.prepare('SELECT id,role FROM users').all()) {
        const role = user.role === 'admin' ? 'school_admin' : user.role;
        await addMembership.run(`membership-${user.id}`, user.id, DEFAULT_SCHOOL_ID, role === 'parent' || role === 'school_admin' ? null : DEFAULT_CAMPUS_ID, role);
      }

      await db.exec(`
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
    async up(db) {
      // school_years.name was UNIQUE across the whole database, a
      // leftover from before multi-tenancy — every self-registered
      // school lands on the same auto-generated year label (e.g.
      // "2026-2027"), so the second school to sign up would fail here.
      // Postgres can alter a constraint in place, unlike SQLite —
      // school_years_name_key is the name Postgres auto-generated for
      // the base schema's column-level `name TEXT NOT NULL UNIQUE`.
      await db.exec(`
        ALTER TABLE school_years DROP CONSTRAINT school_years_name_key;
        ALTER TABLE school_years ADD CONSTRAINT school_years_school_id_name_key UNIQUE (school_id, name);
      `);
    },
  },
  {
    version: 3,
    name: 'real drop-off/pick-up queue (was in-memory-only mock state per client)',
    async up(db) {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS queue_items (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          student_id TEXT NOT NULL REFERENCES students(id),
          teacher_user_id TEXT REFERENCES users(id),
          request_type TEXT NOT NULL CHECK(request_type IN ('DROP_OFF','PICK_UP')),
          requested_by_user_id TEXT NOT NULL REFERENCES users(id),
          status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','CANCELLED')),
          requested_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
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
    async up(db) {
      await db.exec(`
        ALTER TABLE students ADD COLUMN IF NOT EXISTS photo_url TEXT;
        CREATE TABLE IF NOT EXISTS attendance_records (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          campus_id TEXT REFERENCES campuses(id),
          student_id TEXT NOT NULL REFERENCES students(id),
          class_id TEXT REFERENCES classes(id),
          date TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('PRESENT','ABSENT')),
          marked_by_user_id TEXT REFERENCES users(id),
          marked_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
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
    async up(db) {
      await db.exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_url TEXT;`);
    },
  },
  {
    version: 6,
    name: 'attendance: allow SICK/SUSPENDED/HOLIDAY in addition to PRESENT/ABSENT',
    async up(db) {
      // WEEKEND is deliberately not in this list — nobody marks a
      // weekend, it's just a calendar fact the client computes from the
      // date itself, never a stored row.
      await db.exec(`
        ALTER TABLE attendance_records DROP CONSTRAINT attendance_records_status_check;
        ALTER TABLE attendance_records ADD CONSTRAINT attendance_records_status_check
          CHECK(status IN ('PRESENT','ABSENT','SICK','SUSPENDED','HOLIDAY'));
      `);
    },
  },
  {
    version: 7,
    name: 'sessions: persist logins in the database instead of an in-memory Map, so a backend restart no longer force-logs-out every user',
    async up(db) {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at BIGINT NOT NULL,
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
      `);
    },
  },
  {
    version: 8,
    name: 'attendance: allow WEEKEND as an explicit status too, so a teacher can override the Sat/Sun default from the same dropdown as PRESENT/ABSENT/etc',
    async up(db) {
      await db.exec(`
        ALTER TABLE attendance_records DROP CONSTRAINT attendance_records_status_check;
        ALTER TABLE attendance_records ADD CONSTRAINT attendance_records_status_check
          CHECK(status IN ('PRESENT','ABSENT','SICK','SUSPENDED','HOLIDAY','WEEKEND'));
      `);
    },
  },
  {
    version: 9,
    name: 'queue: allow a teacher/admin to decline a request, not just approve it',
    async up(db) {
      await db.exec(`
        ALTER TABLE queue_items DROP CONSTRAINT queue_items_status_check;
        ALTER TABLE queue_items ADD CONSTRAINT queue_items_status_check
          CHECK(status IN ('PENDING','APPROVED','CANCELLED','DECLINED'));
        ALTER TABLE queue_items ADD COLUMN IF NOT EXISTS declined_at TEXT;
        ALTER TABLE queue_items ADD COLUMN IF NOT EXISTS declined_by_user_id TEXT REFERENCES users(id);
      `);
    },
  },
  {
    version: 10,
    name: 'real notices (was in-memory-only mock state per client, same problem the queue used to have)',
    async up(db) {
      await db.exec(`
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
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
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
          read_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          PRIMARY KEY(notice_id, user_id)
        );
      `);
    },
  },
  {
    version: 11,
    name: 'notices: allow a parent-invited co-guardian to auto-notify the school admin',
    async up(db) {
      await db.exec(`
        ALTER TABLE notices DROP CONSTRAINT notices_sender_role_check;
        ALTER TABLE notices ADD CONSTRAINT notices_sender_role_check
          CHECK(sender_role IN ('teacher','admin','parent'));
        ALTER TABLE notices DROP CONSTRAINT notices_target_type_check;
        ALTER TABLE notices ADD CONSTRAINT notices_target_type_check
          CHECK(target_type IN ('SCHOOL','CLASS','PARENT','ADMIN'));
      `);
    },
  },
  {
    version: 12,
    name: 'school profile (start/dismissal/extended-day times), per-student daycare flag, and a late marker on attendance',
    async up(db) {
      // Stored as 'HH:MM' (24-hour, school-local) so they sort/compare
      // lexicographically like any other string — no date math needed
      // to tell whether a drop-off landed before or after start time.
      await db.exec(`
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS start_time TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS dismissal_time TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS extended_time TEXT;
        ALTER TABLE students ADD COLUMN IF NOT EXISTS daycare INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE attendance_records ADD COLUMN IF NOT EXISTS late INTEGER NOT NULL DEFAULT 0;
      `);
    },
  },
  {
    version: 13,
    name: 'per-location (campus) hours, for schools with more than one location on different bell schedules',
    async up(db) {
      await db.exec(`
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS start_time TEXT;
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS dismissal_time TEXT;
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS extended_time TEXT;
      `);
    },
  },
  {
    version: 14,
    name: 'school-wide mailing address, separate from each campus/location address',
    async up(db) {
      await db.exec(`ALTER TABLE schools ADD COLUMN IF NOT EXISTS address TEXT;`);
    },
  },
  {
    version: 15,
    name: 'structured address fields for schools and campus locations',
    async up(db) {
      await db.exec(`
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS address_line1 TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS address_line2 TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS city TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS state TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS postal_code TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS country TEXT;
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS address_line1 TEXT;
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS address_line2 TEXT;
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS city TEXT;
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS state TEXT;
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS postal_code TEXT;
        ALTER TABLE campuses ADD COLUMN IF NOT EXISTS country TEXT;
      `);
    },
  },
  {
    version: 16,
    name: 'notices: let an admin target all staff or one staff member, same as it already can for parents',
    async up(db) {
      await db.exec(`
        ALTER TABLE notices DROP CONSTRAINT notices_target_type_check;
        ALTER TABLE notices ADD CONSTRAINT notices_target_type_check
          CHECK(target_type IN ('SCHOOL','CLASS','PARENT','ADMIN','STAFF'));
        ALTER TABLE notices ADD COLUMN IF NOT EXISTS target_staff_user_id TEXT REFERENCES users(id);
        CREATE INDEX IF NOT EXISTS notices_target_staff_idx ON notices(target_staff_user_id);
      `);
    },
  },
  {
    version: 17,
    name: 'audit_logs: append-only record of sensitive actions (views, pickup authorization, queue, record changes)',
    async up(db) {
      // No foreign keys on purpose: an entry must outlive the user,
      // student or school it mentions, so names are copied in at write
      // time. The trigger makes the table append-only at the database
      // level — even a bug (or an attacker) going through the app can't
      // rewrite or erase history; only a deliberate migration that drops
      // the trigger could.
      await db.exec(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          school_id TEXT,
          actor_user_id TEXT,
          actor_name TEXT,
          actor_role TEXT,
          action TEXT NOT NULL,
          target_type TEXT,
          target_id TEXT,
          target_label TEXT,
          details TEXT,
          ip_address TEXT,
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE INDEX IF NOT EXISTS audit_logs_school_created_idx ON audit_logs(school_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS audit_logs_target_idx ON audit_logs(target_type, target_id);
        CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'audit_logs is append-only';
        END;
        $$ LANGUAGE plpgsql;
        DROP TRIGGER IF EXISTS audit_logs_no_change ON audit_logs;
        CREATE TRIGGER audit_logs_no_change BEFORE UPDATE OR DELETE ON audit_logs
          FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
      `);
    },
  },
  {
    version: 18,
    name: 'guardian_requests: a parent-added adult waits for admin approval before getting any access to a child',
    async up(db) {
      // Kept separate from student_guardians on purpose: nothing that
      // reads student_guardians (pickup checks, parent screens, teacher
      // messaging, ...) can ever see a pending adult, because they only
      // get a student_guardians row once approved. One parent submission
      // is one batch_id (one row per child it covers), approved or
      // rejected together. Rows are kept after a decision as the history
      // of who asked, who decided, and when.
      await db.exec(`
        CREATE TABLE IF NOT EXISTS guardian_requests (
          id TEXT PRIMARY KEY,
          batch_id TEXT NOT NULL,
          school_id TEXT NOT NULL REFERENCES schools(id),
          student_id TEXT NOT NULL REFERENCES students(id),
          guardian_id TEXT NOT NULL REFERENCES guardians(id) ON DELETE CASCADE,
          relationship TEXT NOT NULL,
          can_pick_up INTEGER NOT NULL DEFAULT 1,
          can_manage INTEGER NOT NULL DEFAULT 0,
          requested_by_user_id TEXT NOT NULL REFERENCES users(id),
          requested_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','REJECTED')),
          decided_by_user_id TEXT REFERENCES users(id),
          decided_at TEXT,
          decision_note TEXT
        );
        CREATE INDEX IF NOT EXISTS guardian_requests_school_status_idx ON guardian_requests(school_id, status);
        CREATE INDEX IF NOT EXISTS guardian_requests_batch_idx ON guardian_requests(batch_id);
        CREATE UNIQUE INDEX IF NOT EXISTS guardian_requests_one_pending_idx ON guardian_requests(student_id, guardian_id) WHERE status='PENDING';
      `);
    },
  },  {
    version: 19,
    name: 'queue_items: one-time pickup verification code the teacher must enter to release a child',
    async up(db) {
      // pickup_code is cleared as soon as the request is decided, so a
      // code only ever exists while its pickup is pending.
      // verification_method records how a pickup was released: CODE, or
      // ADMIN_OVERRIDE (an admin checked identity another way and gave
      // override_reason).
      await db.exec(`
        ALTER TABLE queue_items ADD COLUMN IF NOT EXISTS pickup_code TEXT;
        ALTER TABLE queue_items ADD COLUMN IF NOT EXISTS pickup_code_attempts INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE queue_items ADD COLUMN IF NOT EXISTS verification_method TEXT;
        ALTER TABLE queue_items ADD COLUMN IF NOT EXISTS override_reason TEXT;
      `);
    },
  },  {
    version: 20,
    name: 'two-step verification: authenticator-app secrets, recovery codes and sign-in challenges',
    async up(db) {
      // mfa_secret / mfa_pending_secret are AES-GCM encrypted (mfa.js).
      // mfa_pending_secret holds a secret during setup until the user
      // proves their app works by entering a code from it.
      // mfa_last_step stops a code from being used twice.
      // An mfa_challenges row is the half-finished sign-in between "password
      // was right" and "code was right" — stored hashed, short-lived, and
      // only good for a few wrong codes before the password is needed again.
      await db.exec(`
        ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_pending_secret TEXT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled_at TEXT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_step BIGINT;
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          code_hash TEXT NOT NULL,
          used_at TEXT
        );
        CREATE INDEX IF NOT EXISTS mfa_recovery_codes_user_idx ON mfa_recovery_codes(user_id);
        CREATE TABLE IF NOT EXISTS mfa_challenges (
          token_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          purpose TEXT NOT NULL CHECK(purpose IN ('VERIFY','SETUP')),
          expires_at BIGINT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0
        );
      `);
    },
  },  {
    version: 21,
    name: 'data retention: when a student was removed, and per-school retention settings',
    async up(db) {
      // archived_at starts the retention clock for a removed student;
      // students removed before this existed start theirs now. NULL
      // retention settings mean "keep until deleted by hand".
      await db.exec(`
        ALTER TABLE students ADD COLUMN IF NOT EXISTS archived_at TEXT;
        UPDATE students SET archived_at=to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS') WHERE status='ARCHIVED' AND archived_at IS NULL;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS removed_student_retention_days INTEGER;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS queue_history_retention_days INTEGER;
      `);
    },
  },  {
    version: 22,
    name: 'district admins: a person who administers every school in a district (organization)',
    async up(db) {
      // A district is an organizations row; its schools are the schools
      // with that organization_id. A district admin gets school-admin
      // rights in each ACTIVE school of the district (tenant.js expands
      // this into one membership per school) and nothing outside it.
      await db.exec(`
        CREATE TABLE IF NOT EXISTS district_memberships (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          organization_id TEXT NOT NULL REFERENCES organizations(id),
          status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','SUSPENDED')),
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          UNIQUE(user_id, organization_id)
        );
      `);
    },
  },
];

export async function runMigrations(db, withTransaction) {
  await db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'))`);
  const applied = db.prepare('SELECT 1 FROM schema_migrations WHERE version=?');
  const record = db.prepare('INSERT INTO schema_migrations (version,name) VALUES (?,?)');
  for (const migration of migrations) {
    if (await applied.get(migration.version)) continue;
    await withTransaction(async () => {
      await migration.up(db);
      await record.run(migration.version, migration.name);
    });
  }
}
