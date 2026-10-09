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
  {
    version: 23,
    name: 'account links: emailed one-time links to set up an account or reset a password',
    async up(db) {
      // Only the SHA-256 of a link's token is stored, so a database leak
      // can't be turned into working links. INVITE links last days (a new
      // account's first password), RESET links an hour.
      await db.exec(`
        CREATE TABLE IF NOT EXISTS account_links (
          token_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          purpose TEXT NOT NULL CHECK(purpose IN ('INVITE','RESET')),
          expires_at BIGINT NOT NULL,
          used_at BIGINT,
          created_at BIGINT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS account_links_user ON account_links (user_id);
        -- 1 while an invited account hasn't chosen its first password yet.
        ALTER TABLE users ADD COLUMN IF NOT EXISTS needs_password_setup INTEGER NOT NULL DEFAULT 0;
      `);
    },
  },
  {
    version: 24,
    name: 'platform administration: platform admins, support sessions, school suspension, audit request ids',
    async up(db) {
      await db.exec(`
        -- People who run SDPMPlus itself, above any one school. Their
        -- permissions come from the role (permissions.js); none of them
        -- gets school data except through a support session.
        CREATE TABLE IF NOT EXISTS platform_admins (
          user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          role TEXT NOT NULL CHECK(role IN ('SUPER_ADMIN','PLATFORM_ADMIN','SUPPORT_ADMIN','BILLING_ADMIN')),
          status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','DISABLED')),
          created_by_user_id TEXT,
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );

        -- A platform admin's time-limited, audited look into one school,
        -- tied to the sign-in session it was started from (SHA-256 of the
        -- session token). Read-only unless allow_changes was granted.
        CREATE TABLE IF NOT EXISTS support_sessions (
          id TEXT PRIMARY KEY,
          platform_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          school_id TEXT NOT NULL REFERENCES schools(id),
          session_token_hash TEXT NOT NULL,
          reason TEXT NOT NULL,
          allow_changes INTEGER NOT NULL DEFAULT 0,
          ip_address TEXT,
          started_at BIGINT NOT NULL,
          expires_at BIGINT NOT NULL,
          ended_at BIGINT,
          end_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS support_sessions_open_idx ON support_sessions(session_token_hash) WHERE ended_at IS NULL;
        CREATE INDEX IF NOT EXISTS support_sessions_school_idx ON support_sessions(school_id, started_at DESC);

        -- Schools are suspended or archived, never deleted.
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS suspended_at TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS suspended_reason TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS archived_at TEXT;
        CREATE INDEX IF NOT EXISTS schools_status_idx ON schools(status, created_at DESC);

        -- Which request an entry came from, the reason given for it, and
        -- the support session it happened in (adding columns doesn't touch
        -- the append-only rule on existing rows).
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id TEXT;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS reason TEXT;
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS support_session_id TEXT;
        -- Platform-wide audit search: newest first across all schools, and by action.
        CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON audit_logs(created_at DESC, id DESC);
        CREATE INDEX IF NOT EXISTS audit_logs_action_created_idx ON audit_logs(action, created_at DESC);
        CREATE INDEX IF NOT EXISTS audit_logs_actor_idx ON audit_logs(actor_user_id, created_at DESC);

        -- The old super admin was a membership in one school, which gave
        -- silent access to every school. Carry those people over as
        -- SUPER_ADMIN platform admins, then archive (not delete) the old rows.
        INSERT INTO platform_admins (user_id, role)
          SELECT DISTINCT user_id, 'SUPER_ADMIN' FROM memberships WHERE role='platform_super_admin' AND status='ACTIVE'
          ON CONFLICT (user_id) DO NOTHING;
        UPDATE memberships SET status='ARCHIVED' WHERE role='platform_super_admin' AND status <> 'ARCHIVED';
      `);
    },
  },  {
    version: 25,
    name: 'platform dashboard: indexes for date-range counts across all schools',
    async up(db) {
      // The platform dashboard counts the last 30 days across every
      // school; without these each count would read the whole table.
      await db.exec(`
        -- Drop-offs/pickups completed per day, and overrides.
        CREATE INDEX IF NOT EXISTS queue_items_approved_at_idx ON queue_items(approved_at) WHERE approved_at IS NOT NULL;
        -- Requests made per day (active schools), and waiting requests by age.
        CREATE INDEX IF NOT EXISTS queue_items_requested_at_idx ON queue_items(requested_at);
        CREATE INDEX IF NOT EXISTS queue_items_pending_idx ON queue_items(requested_at) WHERE status='PENDING';
        -- Attendance per day across schools (the existing index leads with school_id).
        CREATE INDEX IF NOT EXISTS attendance_date_status_idx ON attendance_records(date, status);
        -- Sessions alive right now (active users).
        CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
      `);
    },
  },  {
    version: 26,
    name: 'platform operations: incident reviews',
    async up(db) {
      // A platform admin marks a drop-off/pickup exception (an admin
      // override, or a pickup cancelled for wrong codes) as reviewed, with
      // a note. The incident itself stays where it is (queue_items or
      // audit_logs); this only records that someone looked at it.
      await db.exec(`
        CREATE TABLE IF NOT EXISTS incident_reviews (
          incident_key TEXT PRIMARY KEY,
          school_id TEXT REFERENCES schools(id),
          note TEXT NOT NULL,
          reviewed_by_user_id TEXT NOT NULL REFERENCES users(id),
          reviewed_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        -- Incident list: overrides by date.
        CREATE INDEX IF NOT EXISTS queue_items_override_idx ON queue_items(approved_at) WHERE verification_method='ADMIN_OVERRIDE';
      `);
    },
  },  {
    version: 27,
    name: 'compliance: data requests and legal holds',
    async up(db) {
      await db.exec(`
        -- Export and deletion requests (from a parent, a school or a
        -- district) tracked from receipt to completion. Nothing is deleted
        -- until a request is reviewed and approved; the audit log records
        -- every step (target_type 'data_request').
        CREATE TABLE IF NOT EXISTS data_requests (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL REFERENCES schools(id),
          kind TEXT NOT NULL CHECK(kind IN ('EXPORT','DELETION')),
          subject_type TEXT NOT NULL CHECK(subject_type IN ('STUDENT','PARENT','SCHOOL')),
          subject_id TEXT,
          subject_label TEXT NOT NULL,
          requester_name TEXT NOT NULL,
          requester_relationship TEXT,
          received_via TEXT,
          details TEXT,
          status TEXT NOT NULL DEFAULT 'REQUESTED'
            CHECK(status IN ('REQUESTED','UNDER_REVIEW','APPROVED','PROCESSING','COMPLETED','REJECTED')),
          status_note TEXT,
          due_at TEXT NOT NULL,
          created_by_user_id TEXT NOT NULL REFERENCES users(id),
          approved_by_user_id TEXT REFERENCES users(id),
          outcome TEXT,
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          completed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS data_requests_status_idx ON data_requests(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS data_requests_school_idx ON data_requests(school_id, created_at DESC);

        -- A school's records must be kept (litigation, investigation,
        -- contract dispute): no permanent deletion of any kind, including
        -- the daily retention run, until the hold is released.
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS legal_hold_reason TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS legal_hold_at TEXT;
        ALTER TABLE schools ADD COLUMN IF NOT EXISTS legal_hold_by_user_id TEXT REFERENCES users(id);
      `);
    },
  },  {
    version: 28,
    name: 'audit log: insertion order',
    async up(db) {
      // created_at only has one-second precision, so entries written in
      // the same second (one request's steps) had no reliable order.
      // seq numbers every entry in the order it was written; existing
      // rows are numbered in their current order. Adding a column does
      // not touch the append-only rule (it guards UPDATE and DELETE).
      await db.exec(`
        ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS seq BIGSERIAL;
        CREATE INDEX IF NOT EXISTS audit_logs_target_seq_idx ON audit_logs(target_type, target_id, seq);
      `);
    },
  },  {
    version: 29,
    name: 'platform: background jobs, email delivery log, announcements, billing',
    async up(db) {
      await db.exec(`
        -- Work too slow for a web request (report exports). One worker in
        -- each server process claims jobs with SKIP LOCKED, so several
        -- servers never run the same job. Results are kept 7 days.
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY,
          type TEXT NOT NULL,
          params TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED')),
          attempts INTEGER NOT NULL DEFAULT 0,
          error TEXT,
          result BYTEA,
          result_name TEXT,
          result_type TEXT,
          result_size INTEGER,
          created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          started_at TEXT,
          finished_at TEXT
        );
        CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs(created_at) WHERE status='QUEUED';
        CREATE INDEX IF NOT EXISTS jobs_creator_idx ON jobs(created_by_user_id, created_at DESC);

        -- Every email the app tries to send. Sign-in links are never
        -- stored: retrying an invite or reset makes a fresh link.
        CREATE TABLE IF NOT EXISTS notification_deliveries (
          id TEXT PRIMARY KEY,
          channel TEXT NOT NULL DEFAULT 'EMAIL',
          template TEXT NOT NULL,
          recipient TEXT NOT NULL,
          subject TEXT NOT NULL,
          school_name TEXT,
          args TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL CHECK(status IN ('SENDING','SENT','FAILED','SKIPPED','RETRIED')),
          error TEXT,
          retry_of TEXT,
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE INDEX IF NOT EXISTS notification_deliveries_created_idx ON notification_deliveries(created_at DESC, id);
        CREATE INDEX IF NOT EXISTS notification_deliveries_status_idx ON notification_deliveries(status, created_at DESC);

        -- Messages from SDPMPlus to schools' admins or staff, delivered as
        -- ordinary notices (sender_role 'platform') in each school.
        CREATE TABLE IF NOT EXISTS announcements (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          body TEXT NOT NULL,
          audience TEXT NOT NULL CHECK(audience IN ('SCHOOL_ADMINS','ALL_STAFF')),
          school_count INTEGER NOT NULL,
          created_by_user_id TEXT NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        ALTER TABLE notices ADD COLUMN IF NOT EXISTS announcement_id TEXT REFERENCES announcements(id);
        ALTER TABLE notices DROP CONSTRAINT IF EXISTS notices_sender_role_check;
        ALTER TABLE notices ADD CONSTRAINT notices_sender_role_check CHECK(sender_role IN ('teacher','admin','parent','platform'));

        -- Billing, independent of any payment company: what each school is
        -- on, what it was invoiced, and what was paid. external_* fields
        -- hold a provider's ids if one is connected later. Nothing here
        -- switches a school's service on or off.
        CREATE TABLE IF NOT EXISTS plans (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          description TEXT,
          pricing_model TEXT NOT NULL CHECK(pricing_model IN ('FLAT','PER_STUDENT')),
          price_cents INTEGER NOT NULL CHECK(price_cents >= 0),
          currency TEXT NOT NULL DEFAULT 'USD',
          billing_interval TEXT NOT NULL CHECK(billing_interval IN ('MONTH','YEAR')),
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
          id TEXT PRIMARY KEY,
          school_id TEXT NOT NULL UNIQUE REFERENCES schools(id),
          plan_id TEXT NOT NULL REFERENCES plans(id),
          status TEXT NOT NULL CHECK(status IN ('TRIALING','ACTIVE','PAST_DUE','CANCELED')),
          started_on TEXT NOT NULL,
          current_period_end TEXT,
          notes TEXT,
          external_provider TEXT,
          external_id TEXT,
          updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE TABLE IF NOT EXISTS invoices (
          id TEXT PRIMARY KEY,
          number TEXT NOT NULL UNIQUE,
          school_id TEXT NOT NULL REFERENCES schools(id),
          subscription_id TEXT REFERENCES subscriptions(id),
          period_start TEXT,
          period_end TEXT,
          description TEXT NOT NULL,
          amount_cents INTEGER NOT NULL CHECK(amount_cents >= 0),
          currency TEXT NOT NULL DEFAULT 'USD',
          status TEXT NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','OPEN','PAID','VOID')),
          due_on TEXT,
          issued_at TEXT,
          paid_at TEXT,
          void_reason TEXT,
          external_id TEXT,
          created_by_user_id TEXT REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE INDEX IF NOT EXISTS invoices_school_idx ON invoices(school_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS invoices_status_idx ON invoices(status, due_on);
        CREATE TABLE IF NOT EXISTS payments (
          id TEXT PRIMARY KEY,
          invoice_id TEXT NOT NULL REFERENCES invoices(id),
          amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
          method TEXT NOT NULL CHECK(method IN ('CHECK','ACH','CARD','WIRE','OTHER')),
          reference TEXT,
          received_on TEXT NOT NULL,
          recorded_by_user_id TEXT REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')
        );
        CREATE INDEX IF NOT EXISTS payments_invoice_idx ON payments(invoice_id);
        CREATE SEQUENCE IF NOT EXISTS invoice_number_seq START 1001;
      `);
    },
  },  {
    version: 30,
    name: 'production hardening: shared rate limits, app versions, indexes for hot lookups',
    async up(db) {
      await db.exec(`
        -- Rate limits (sign-in lockouts, password-reset requests, platform
        -- API) shared by every server process, instead of each keeping
        -- its own count in memory. Expired rows are swept hourly.
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT PRIMARY KEY,
          count INTEGER NOT NULL,
          reset_at BIGINT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS rate_limits_reset_idx ON rate_limits(reset_at);

        -- Which app versions are in use (the mobile app sends X-Client).
        CREATE TABLE IF NOT EXISTS client_versions (
          client TEXT NOT NULL,
          version TEXT NOT NULL,
          first_seen TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          last_seen TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS'),
          PRIMARY KEY (client, version)
        );

        -- Foreign keys on hot paths that had no index (see docs/database-indexes.md):
        CREATE INDEX IF NOT EXISTS student_guardians_guardian_idx ON student_guardians(guardian_id);          -- every parent screen
        CREATE INDEX IF NOT EXISTS student_enrollments_class_idx ON student_enrollments(class_id);            -- class rosters, attendance by class
        CREATE INDEX IF NOT EXISTS student_enrollments_student_idx ON student_enrollments(student_id, school_year_id); -- a student's current class
        CREATE INDEX IF NOT EXISTS classes_teacher_idx ON classes(teacher_user_id);                           -- teacher queue/class (polled)
        CREATE INDEX IF NOT EXISTS queue_items_student_status_idx ON queue_items(student_id, status);         -- open request per child
        CREATE INDEX IF NOT EXISTS queue_items_requested_by_idx ON queue_items(requested_by_user_id);         -- a parent's requests, adoption report
        CREATE INDEX IF NOT EXISTS guardian_requests_guardian_idx ON guardian_requests(guardian_id, status);  -- pending requests for an adult
        CREATE INDEX IF NOT EXISTS schools_organization_idx ON schools(organization_id);                      -- district admins' schools, every request
      `);
    },
  },  {
    version: 31,
    name: 'pickup codes removed',
    async up(db) {
      // The one-time pickup code is no longer used: a pickup is released
      // by the teacher's or an administrator's confirmation alone. The
      // columns stay (verification_method / override_reason describe how
      // past pickups were released); any code still waiting on an open
      // request is cleared so no unused secret is left behind.
      await db.exec(`UPDATE queue_items SET pickup_code=NULL WHERE pickup_code IS NOT NULL;`);
    },
  },  {
    version: 32,
    name: 'pickup PIN: a private 6-digit PIN each parent enters to request a pickup',
    async up(db) {
      // Stored only as a salted scrypt hash (same as passwords), never
      // readable. PIN_RESET links are the "Forgot PIN?" emails.
      await db.exec(`
        ALTER TABLE users ADD COLUMN IF NOT EXISTS pickup_pin_hash TEXT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS pickup_pin_set_at TEXT;
        ALTER TABLE account_links DROP CONSTRAINT IF EXISTS account_links_purpose_check;
        ALTER TABLE account_links ADD CONSTRAINT account_links_purpose_check CHECK(purpose IN ('INVITE','RESET','PIN_RESET'));
      `);
    },
  },
  {
    version: 33,
    name: 'school logo, shown on every dashboard of that school',
    async up(db) {
      // Like the photo_url columns: an "s3://…" reference when S3 storage
      // is set up (storage.js), otherwise the image itself as a data URL.
      await db.exec(`ALTER TABLE schools ADD COLUMN IF NOT EXISTS logo_url TEXT;`);
    },
  },
  {
    version: 34,
    name: 'email confirmation codes (school registration)',
    async up(db) {
      // One live code per address and purpose, stored as a salted hash
      // (emailCodes.js). expires_at is epoch milliseconds.
      await db.exec(`
        CREATE TABLE IF NOT EXISTS email_codes (
          email TEXT NOT NULL,
          purpose TEXT NOT NULL,
          code_hash TEXT NOT NULL,
          expires_at BIGINT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (email, purpose)
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

/** The newest migration this code knows about (System Health compares it with the database). */
export const LATEST_MIGRATION = migrations[migrations.length - 1].version;
