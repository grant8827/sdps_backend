// Provision the isolated Apple/Google review administrator from inside Railway.
// Usage: node scripts/app-review-account.js <email> <password>
import { db, passwordHash, withTransaction } from '../db.js';

const [email, password] = process.argv.slice(2);
if (!email?.includes('@') || !password || password.length < 12) {
  throw new Error('Usage: node scripts/app-review-account.js <email> <password-of-at-least-12-characters>');
}

await withTransaction(async () => {
  const duplicate = await db.prepare(`SELECT id FROM users WHERE LOWER(email)=LOWER(?) AND id<>'admin-app-review'`).get(email);
  if (duplicate) throw new Error('The review email belongs to another account.');
  await db.prepare(`INSERT INTO organizations (id,name,status) VALUES ('organization-app-review','App Review School','ACTIVE')
    ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,status='ACTIVE'`).run();
  await db.prepare(`INSERT INTO schools (id,organization_id,name,code,timezone,status) VALUES ('school-app-review','organization-app-review','App Review School','APPREVIEW','America/New_York','ACTIVE')
    ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,status='ACTIVE',suspended_at=NULL,suspended_reason=NULL,archived_at=NULL`).run();
  await db.prepare(`INSERT INTO campuses (id,school_id,name,address,timezone,status) VALUES ('campus-app-review','school-app-review','Main Campus','100 Review Way, Orlando, FL 32801','America/New_York','ACTIVE')
    ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,status='ACTIVE'`).run();
  await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role,active,needs_password_setup) VALUES ('admin-app-review','App Review Administrator',?,?,'admin',1,0)
    ON CONFLICT (id) DO UPDATE SET full_name=EXCLUDED.full_name,email=EXCLUDED.email,password_hash=EXCLUDED.password_hash,role='admin',active=1,needs_password_setup=0,mfa_secret=NULL,mfa_pending_secret=NULL,mfa_enabled_at=NULL,mfa_last_step=NULL`).run(email, passwordHash(password));
  await db.prepare(`DELETE FROM mfa_recovery_codes WHERE user_id='admin-app-review'`).run();
  await db.prepare(`DELETE FROM sessions WHERE user_id='admin-app-review'`).run();
  await db.prepare(`INSERT INTO memberships (id,user_id,school_id,campus_id,role,status) VALUES ('membership-app-review','admin-app-review','school-app-review',NULL,'school_admin','ACTIVE')
    ON CONFLICT (id) DO UPDATE SET role='school_admin',status='ACTIVE'`).run();
  await db.prepare(`INSERT INTO school_years (id,name,starts_on,ends_on,status,school_id) VALUES ('year-app-review','2026-2027','2026-08-01','2027-06-30','ACTIVE','school-app-review')
    ON CONFLICT (id) DO UPDATE SET status='ACTIVE'`).run();
});
console.log(`Review school administrator is ready: ${email}`);
await db.close();
