// Operator tool: set a new temporary password for an account, for when
// "Forgot password?" can't help (email not set up, or the person no
// longer has access to their inbox). Run against the target
// database, e.g. production through the Railway CLI:
//
//   railway run npm run reset-password -- someone@example.com
//   railway run npm run reset-password -- someone@example.com --clear-mfa
//
// It prints a random temporary password, signs the account out
// everywhere, and (with --clear-mfa) removes two-step verification so it
// can be set up again — use that only when the authenticator was lost too.
//
// Deliberately talks to the database directly instead of importing
// db.js: importing db.js runs migrations and seeding, which must not
// happen to production from a developer's machine ahead of a deploy.
// For the same reason the password is written in the original
// fixed-salt format, which every version of the server accepts; newer
// servers upgrade it to a per-user salt at the next sign-in.
import { randomBytes, scryptSync } from 'node:crypto';
import pg from 'pg';

const [email, ...flags] = process.argv.slice(2);
const clearMfa = flags.includes('--clear-mfa');
if (!email?.includes('@')) {
  console.error('Usage: npm run reset-password -- <email> [--clear-mfa]');
  process.exit(1);
}

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
});
const columnExists = async (table, column) =>
  (await pool.query('SELECT 1 FROM information_schema.columns WHERE table_name=$1 AND column_name=$2', [table, column])).rowCount > 0;
const tableExists = async table => (await pool.query('SELECT to_regclass($1) AS t', [table])).rows[0].t !== null;

try {
  const { rows: [user] } = await pool.query('SELECT id, full_name, role, active FROM users WHERE LOWER(email)=LOWER($1)', [email.trim()]);
  if (!user) {
    console.error(`No account with the email ${email} in this database (${new URL(process.env.DATABASE_URL).hostname}).`);
    process.exitCode = 1;
  } else {
    const temporaryPassword = randomBytes(9).toString('base64url');
    const legacyHash = scryptSync(temporaryPassword, 'school-dropoff-local-v1', 64).toString('hex');
    await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [legacyHash, user.id]);
    if (await tableExists('sessions')) await pool.query('DELETE FROM sessions WHERE user_id=$1', [user.id]);

    let mfaNote = '';
    if (await columnExists('users', 'mfa_enabled_at')) {
      const { rows: [{ enabled }] } = await pool.query('SELECT mfa_enabled_at IS NOT NULL AS enabled FROM users WHERE id=$1', [user.id]);
      if (clearMfa) {
        await pool.query('UPDATE users SET mfa_secret=NULL, mfa_pending_secret=NULL, mfa_enabled_at=NULL, mfa_last_step=NULL WHERE id=$1', [user.id]);
        await pool.query('DELETE FROM mfa_recovery_codes WHERE user_id=$1', [user.id]);
        mfaNote = 'Two-step verification was cleared; it will be set up again at sign-in where required.';
      } else if (enabled) {
        mfaNote = 'Two-step verification is still on — they will need their authenticator app or a recovery code. Re-run with --clear-mfa if those are lost too.';
      }
    }

    if (await tableExists('audit_logs')) {
      const { rows: schools } = await pool.query('SELECT DISTINCT school_id FROM memberships WHERE user_id=$1', [user.id]);
      for (const { school_id: schoolId } of schools.length ? schools : [{ school_id: null }]) {
        await pool.query(
          `INSERT INTO audit_logs (id,school_id,actor_name,actor_role,action,target_type,target_id,target_label,details) VALUES ($1,$2,'Platform operator','platform_operator','PASSWORD_RESET','user',$3,$4,$5)`,
          [`audit-${randomBytes(16).toString('hex')}`, schoolId, user.id, user.full_name, JSON.stringify({ mfaCleared: clearMfa })],
        );
      }
    }

    console.log(`Password reset for ${user.full_name} <${email}> (${user.role}${user.active ? '' : ', account is DEACTIVATED'}).`);
    console.log(`Temporary password: ${temporaryPassword}`);
    console.log('They have been signed out everywhere. Sign in with this password, then change it.');
    if (mfaNote) console.log(mfaNote);
  }
} finally {
  await pool.end();
}
