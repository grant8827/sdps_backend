// Operator tool for setting up districts (there's no platform-admin UI
// yet). Run from backend/ with the target database in DATABASE_URL:
//
//   npm run district -- list
//   npm run district -- create "Springfield Public Schools"
//   npm run district -- add-school SCHOOLCODE "Springfield Public Schools"
//   npm run district -- add-admin "Springfield Public Schools" admin@district.org "Dana District"
//   npm run district -- remove-admin "Springfield Public Schools" admin@district.org
//
// A district admin gets school-admin rights in every active school of
// their district, must set up two-step verification at first sign-in,
// and every change made here is written to each affected school's audit
// log as "Platform operator".
import { randomBytes } from 'node:crypto';
import { db, id, passwordHash } from '../db.js';
import { endAllSessions } from '../auth.js';
import { writeAudit } from '../audit.js';

const OPERATOR = { id: null, full_name: 'Platform operator' };
const [command, ...args] = process.argv.slice(2);

const fail = message => { console.error(message); process.exitCode = 1; };
const findDistrict = name => db.prepare(`SELECT id, name FROM organizations WHERE LOWER(name)=LOWER(?)`).get(name);
const districtSchools = districtId => db.prepare(`SELECT id, name, code FROM schools WHERE organization_id=? ORDER BY name`).all(districtId);
async function auditDistrict(districtId, action, details) {
  for (const school of await districtSchools(districtId)) {
    await writeAudit({ schoolId: school.id, actor: OPERATOR, actorRole: 'platform_operator', action, details });
  }
}

async function main() {
  if (command === 'list') {
    const districts = await db.prepare(`
      SELECT o.id, o.name, (SELECT COUNT(*) FROM schools s WHERE s.organization_id=o.id) AS schools
      FROM organizations o ORDER BY o.name`).all();
    for (const district of districts) {
      const admins = await db.prepare(`SELECT u.email, dm.status FROM district_memberships dm JOIN users u ON u.id=dm.user_id WHERE dm.organization_id=? ORDER BY u.email`).all(district.id);
      console.log(`\n${district.name}  (${district.schools} school${district.schools === 1 ? '' : 's'})`);
      for (const school of await districtSchools(district.id)) console.log(`  school: ${school.name} [${school.code}]`);
      for (const admin of admins) console.log(`  district admin: ${admin.email}${admin.status === 'ACTIVE' ? '' : ` (${admin.status})`}`);
    }
    return;
  }

  if (command === 'create') {
    const [name] = args;
    if (!name?.trim()) return fail('Usage: create "<district name>"');
    if (await findDistrict(name.trim())) return fail(`A district or organization named "${name}" already exists.`);
    const districtId = id('org');
    await db.prepare('INSERT INTO organizations (id,name) VALUES (?,?)').run(districtId, name.trim());
    console.log(`Created district "${name.trim()}".`);
    return;
  }

  if (command === 'add-school') {
    const [code, districtName] = args;
    const district = districtName && await findDistrict(districtName);
    if (!district) return fail(`Usage: add-school <school code> "<district name>" — district "${districtName ?? ''}" not found.`);
    const school = await db.prepare('SELECT id, name, organization_id FROM schools WHERE LOWER(code)=LOWER(?)').get(code ?? '');
    if (!school) return fail(`No school with code "${code}".`);
    await db.prepare('UPDATE schools SET organization_id=? WHERE id=?').run(district.id, school.id);
    await writeAudit({ schoolId: school.id, actor: OPERATOR, actorRole: 'platform_operator', action: 'SCHOOL_ADDED_TO_DISTRICT', details: { district: district.name } });
    console.log(`"${school.name}" is now part of "${district.name}". Its district admins can now manage it.`);
    return;
  }

  if (command === 'add-admin') {
    const [districtName, email, fullName] = args;
    const district = districtName && await findDistrict(districtName);
    if (!district || !email?.includes('@')) return fail('Usage: add-admin "<district name>" <email> "<full name>"');
    let user = await db.prepare('SELECT id, role FROM users WHERE LOWER(email)=LOWER(?)').get(email);
    let temporaryPassword = null;
    if (user && user.role !== 'admin') return fail(`${email} is a ${user.role} account; use a separate email for the district admin.`);
    if (!user) {
      if (!fullName?.trim()) return fail('A full name is needed to create a new account.');
      temporaryPassword = randomBytes(9).toString('base64url');
      user = { id: id('district-admin') };
      await db.prepare(`INSERT INTO users (id,full_name,email,password_hash,role) VALUES (?,?,?,?,'admin')`).run(user.id, fullName.trim(), email.trim(), passwordHash(temporaryPassword));
    }
    await db.prepare(`INSERT INTO district_memberships (id,user_id,organization_id) VALUES (?,?,?) ON CONFLICT (user_id, organization_id) DO UPDATE SET status='ACTIVE'`).run(id('district-membership'), user.id, district.id);
    await auditDistrict(district.id, 'DISTRICT_ADMIN_ADDED', { email });
    console.log(`${email} is now a district admin for "${district.name}".`);
    if (temporaryPassword) console.log(`Temporary password (share securely; they set up two-step verification at first sign-in): ${temporaryPassword}`);
    return;
  }

  if (command === 'remove-admin') {
    const [districtName, email] = args;
    const district = districtName && await findDistrict(districtName);
    const user = email && await db.prepare('SELECT id FROM users WHERE LOWER(email)=LOWER(?)').get(email);
    if (!district || !user) return fail('Usage: remove-admin "<district name>" <email> — district or user not found.');
    const result = await db.prepare(`UPDATE district_memberships SET status='SUSPENDED' WHERE user_id=? AND organization_id=?`).run(user.id, district.id);
    if (!result.changes) return fail(`${email} is not a district admin of "${district.name}".`);
    await endAllSessions(user.id);
    await auditDistrict(district.id, 'DISTRICT_ADMIN_REMOVED', { email });
    console.log(`${email} is no longer a district admin for "${district.name}" and has been signed out.`);
    return;
  }

  fail('Commands: list | create "<district>" | add-school <code> "<district>" | add-admin "<district>" <email> "<name>" | remove-admin "<district>" <email>');
}

try { await main(); } finally { await db.close(); }
