// Operator tool: manage platform administrators (super admins etc.).
// Run against the target database after the server with migration 24 has
// deployed, e.g. production through the Railway CLI:
//
//   railway run npm run platform-admin -- list
//   railway run npm run platform-admin -- add you@example.com SUPER_ADMIN "Your Name"
//   railway run npm run platform-admin -- role someone@example.com SUPPORT_ADMIN
//   railway run npm run platform-admin -- disable someone@example.com
//
// `add` works for an existing account (any role), or creates a new one
// with no usable password — they then use "Forgot password?" on the
// sign-in page to choose one. Platform admins must set up two-step
// verification at their first sign-in. After the first super admin
// exists, manage the rest from the website (Platform → Administrators).
//
// Talks to the database directly instead of importing db.js, which would
// run migrations and seeding from a developer's machine.
import { randomBytes, randomUUID, scryptSync } from 'node:crypto';
import pg from 'pg';

const ROLES = ['SUPER_ADMIN', 'PLATFORM_ADMIN', 'SUPPORT_ADMIN', 'BILLING_ADMIN'];
const [command, email, roleArg, ...nameParts] = process.argv.slice(2);
const usage = () => {
  console.error('Usage: npm run platform-admin -- list | add <email> <ROLE> ["Full Name"] | role <email> <ROLE> | disable <email> | enable <email>');
  console.error(`Roles: ${ROLES.join(', ')}`);
  process.exit(1);
};
if (!['list', 'add', 'role', 'disable', 'enable'].includes(command)) usage();
if (command !== 'list' && !email?.includes('@')) usage();
if (['add', 'role'].includes(command) && !ROLES.includes(roleArg)) usage();

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
});
const audit = (action, user, details) => pool.query(
  `INSERT INTO audit_logs (id,school_id,actor_name,actor_role,action,target_type,target_id,target_label,details) VALUES ($1,NULL,'Platform operator','platform_operator',$2,'user',$3,$4,$5)`,
  [`audit-${randomUUID()}`, action, user.id, user.full_name, JSON.stringify(details)],
);

try {
  const { rows: [table] } = await pool.query(`SELECT to_regclass('platform_admins') AS t`);
  if (!table.t) throw new Error('This database has no platform_admins table yet. Deploy the latest server first (migration 24), then run this again.');

  if (command === 'list') {
    const { rows } = await pool.query(`
      SELECT u.email, u.full_name, pa.role, pa.status, u.mfa_enabled_at IS NOT NULL AS mfa
      FROM platform_admins pa JOIN users u ON u.id=pa.user_id ORDER BY pa.status, u.email`);
    if (rows.length === 0) console.log('No platform administrators yet.');
    for (const r of rows) console.log(`${r.email.padEnd(36)} ${r.role.padEnd(15)} ${r.status.padEnd(9)} 2-step: ${r.mfa ? 'on' : 'not set up'}  (${r.full_name})`);
  } else {
    let { rows: [user] } = await pool.query('SELECT id, full_name, email FROM users WHERE LOWER(email)=LOWER($1)', [email.trim()]);
    if (command === 'add') {
      let created = false;
      if (!user) {
        const fullName = nameParts.join(' ').trim();
        if (!fullName) throw new Error(`No account for ${email} yet. Add their full name: npm run platform-admin -- add ${email} ${roleArg} "Full Name"`);
        // A random password nobody knows; they choose their own via "Forgot password?".
        const salt = randomBytes(16).toString('hex');
        const hash = `scrypt$${salt}$${scryptSync(randomBytes(32).toString('hex'), salt, 64).toString('hex')}`;
        user = { id: `platform-${randomUUID()}`, full_name: fullName, email: email.trim().toLowerCase() };
        await pool.query(`INSERT INTO users (id,full_name,email,password_hash,needs_password_setup,role) VALUES ($1,$2,$3,$4,1,'admin')`, [user.id, user.full_name, user.email, hash]);
        created = true;
      }
      const result = await pool.query(`INSERT INTO platform_admins (user_id,role) VALUES ($1,$2) ON CONFLICT (user_id) DO NOTHING`, [user.id, roleArg]);
      if (result.rowCount === 0) throw new Error(`${user.email} is already a platform administrator. Use "role" to change their role.`);
      await audit('PLATFORM_ADMIN_ADDED', user, { role: roleArg, viaScript: true });
      console.log(`${user.full_name} <${user.email}> is now ${roleArg}.`);
      console.log(created
        ? 'A new account was created. They should open the sign-in page, choose "Forgot password?" and set a password, then set up two-step verification.'
        : 'They sign in with their usual password and will be asked to set up two-step verification if it is not on yet.');
    } else {
      if (!user) throw new Error(`No account with the email ${email}.`);
      const { rows: [current] } = await pool.query('SELECT role, status FROM platform_admins WHERE user_id=$1', [user.id]);
      if (!current) throw new Error(`${email} is not a platform administrator.`);
      const next = command === 'role' ? { role: roleArg, status: current.status } : { role: current.role, status: command === 'disable' ? 'DISABLED' : 'ACTIVE' };
      if (current.role === 'SUPER_ADMIN' && current.status === 'ACTIVE' && (next.role !== 'SUPER_ADMIN' || next.status !== 'ACTIVE')) {
        const { rows: [{ n }] } = await pool.query(`SELECT COUNT(*)::int AS n FROM platform_admins WHERE role='SUPER_ADMIN' AND status='ACTIVE'`);
        if (n <= 1) throw new Error('That is the last active super admin. Add another one first.');
      }
      await pool.query('UPDATE platform_admins SET role=$1, status=$2 WHERE user_id=$3', [next.role, next.status, user.id]);
      if (next.status === 'DISABLED') {
        await pool.query('DELETE FROM sessions WHERE user_id=$1', [user.id]);
        await pool.query(`UPDATE support_sessions SET ended_at=$1, end_reason='ACCESS_DISABLED' WHERE platform_user_id=$2 AND ended_at IS NULL`, [Date.now(), user.id]);
      }
      const action = command === 'role' ? 'ROLE_CHANGED' : command === 'disable' ? 'PLATFORM_ADMIN_DISABLED' : 'PLATFORM_ADMIN_REACTIVATED';
      await audit(action, user, { before: current, after: next, viaScript: true });
      console.log(`${user.email}: ${current.role}/${current.status} → ${next.role}/${next.status}`);
    }
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
