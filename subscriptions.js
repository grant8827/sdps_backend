import { db, id, pool } from './db.js';

// Student-based subscriptions: what each school's plan allows, and how
// many students it has.
//
// The rules:
// - Every plan has every feature. A plan only sets how many ACTIVE
//   students a school may have (student_limit; none = no limit).
// - Only students with status ACTIVE count. Suspended and removed
//   (archived) students, and parents, teachers and staff, never count.
// - The limit is a hard cap on ADDING: a student who would take the
//   school over its limit is refused with a clear message. Nobody is
//   ever removed or hidden, the school is never moved to another plan
//   or charged without an administrator choosing to, and drop-off,
//   pickup and attendance never depend on any of this.
// - A school with no subscription at all (schools from before billing)
//   has no limit until the platform gives it a plan.
// - A new school starts a free trial (no card) on the trial plan.

export const DEFAULT_SETTINGS = { trialDays: 30, graceDays: 14, trialPlanId: 'plan-professional' };
const SETTING_KEYS = { trialDays: 'billing.trial_days', graceDays: 'billing.grace_days', trialPlanId: 'billing.trial_plan_id' };

const today = () => new Date().toISOString().slice(0, 10);
const addDays = (isoDate, days) => new Date(Date.parse(`${isoDate}T00:00:00Z`) + days * 86400000).toISOString().slice(0, 10);
const utcNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);

export async function billingSettings() {
  const rows = await db.prepare(`SELECT key, value FROM platform_settings WHERE key LIKE 'billing.%'`).all();
  const stored = Object.fromEntries(rows.map(row => [row.key, row.value]));
  const number = (key, fallback) => (/^\d+$/.test(stored[key] ?? '') ? Number(stored[key]) : fallback);
  return {
    trialDays: number(SETTING_KEYS.trialDays, DEFAULT_SETTINGS.trialDays),
    graceDays: number(SETTING_KEYS.graceDays, DEFAULT_SETTINGS.graceDays),
    trialPlanId: stored[SETTING_KEYS.trialPlanId] || DEFAULT_SETTINGS.trialPlanId,
  };
}

export async function saveBillingSettings(changes) {
  for (const [name, value] of Object.entries(changes)) {
    if (!SETTING_KEYS[name] || value === undefined) continue;
    await db.prepare('INSERT INTO platform_settings (key, value) VALUES (?,?) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value').run(SETTING_KEYS[name], String(value));
  }
}

const PLAN_COLUMNS = `p.id, p.name, p.description, p.student_limit AS "studentLimit", p.monthly_price_cents AS "monthlyPriceCents",
  p.annual_price_cents AS "annualPriceCents", (p.custom_pricing = 1) AS "customPricing", p.currency, p.sort_order AS "sortOrder"`;

/** Plans a school can choose from, smallest first. */
export function availablePlans() {
  return db.prepare(`SELECT ${PLAN_COLUMNS} FROM plans p WHERE p.active=1 ORDER BY p.sort_order, p.student_limit NULLS LAST, p.name`).all();
}

export async function activeStudentCount(schoolId) {
  return (await db.prepare(`SELECT COUNT(*)::int AS n FROM students WHERE school_id=? AND status='ACTIVE'`).get(schoolId)).n;
}

/** What the plan price is for an interval, or null when it is agreed case by case. */
export const planPrice = (plan, interval) => (plan.customPricing ? null : (interval === 'YEAR' ? plan.annualPriceCents : plan.monthlyPriceCents) ?? null);

/** The smallest available plan that fits `students` and is larger than the current limit. */
export function recommendedPlan(plans, students, currentLimit) {
  return plans.find(plan => plan.studentLimit !== null && plan.studentLimit >= students && (currentLimit === null || plan.studentLimit > currentLimit))
    ?? plans.find(plan => plan.studentLimit === null) ?? null;
}

/**
 * A school's subscription and how full its plan is.
 * level: 'OK' | 'NEAR' (80%+) | 'CLOSE' (90%+) | 'FULL' (100%), or 'OK' with no limit.
 */
export async function schoolCapacity(schoolId) {
  const subscription = await db.prepare(`
    SELECT sub.id, sub.status, sub.plan_id AS "planId", p.name AS "planName", p.student_limit AS "studentLimit",
      (p.custom_pricing = 1) AS "customPricing", sub.billing_interval AS "interval", sub.price_cents AS "priceCents",
      p.monthly_price_cents AS "planMonthlyCents", p.annual_price_cents AS "planAnnualCents", p.currency,
      sub.started_on AS "startedOn", sub.current_period_end AS "currentPeriodEnd", sub.trial_ends_on AS "trialEndsOn",
      (sub.cancel_at_period_end = 1) AS "cancelAtPeriodEnd"
    FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id WHERE sub.school_id=?`).get(schoolId);
  const activeStudents = await activeStudentCount(schoolId);
  const studentLimit = subscription?.studentLimit ?? null;
  const percentUsed = studentLimit ? Math.floor((activeStudents / studentLimit) * 100) : null;
  const level = percentUsed === null ? 'OK' : percentUsed >= 100 ? 'FULL' : percentUsed >= 90 ? 'CLOSE' : percentUsed >= 80 ? 'NEAR' : 'OK';
  let view = null;
  if (subscription) {
    const { planMonthlyCents, planAnnualCents, ...rest } = subscription;
    const interval = rest.interval ?? 'MONTH';
    // The price agreed when they subscribed wins; a later change to the plan's price doesn't touch it.
    const priceCents = rest.priceCents ?? (rest.customPricing ? null : (interval === 'YEAR' ? planAnnualCents : planMonthlyCents) ?? null);
    const trialDaysLeft = rest.status === 'TRIALING' && rest.trialEndsOn ? Math.max(0, Math.round((Date.parse(rest.trialEndsOn) - Date.parse(today())) / 86400000)) : null;
    view = { ...rest, interval, priceCents, trialDaysLeft, trialEnded: rest.status === 'TRIALING' && Boolean(rest.trialEndsOn) && rest.trialEndsOn < today() };
  }
  return {
    subscription: view, activeStudents, studentLimit,
    remaining: studentLimit === null ? null : Math.max(0, studentLimit - activeStudents),
    percentUsed, level,
  };
}

export class StudentLimitError extends Error {
  constructor(message, details) {
    super(message);
    this.code = 'STUDENT_LIMIT_REACHED';
    this.details = details;
  }
}

/**
 * Call inside the transaction that adds (or re-activates) a student.
 * Takes a per-school lock, so two people adding the last place at the
 * same moment can't both get it, then throws StudentLimitError if the
 * school's plan is full.
 */
export async function assertRoomForStudent(schoolId, studentName = 'This student') {
  await db.prepare('SELECT pg_advisory_xact_lock(hashtext(?))').get(`students:${schoolId}`);
  const plan = await db.prepare(`
    SELECT p.name, p.student_limit AS "studentLimit" FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id WHERE sub.school_id=?`).get(schoolId);
  if (!plan || plan.studentLimit === null) return;
  const activeStudents = await activeStudentCount(schoolId);
  if (activeStudents < plan.studentLimit) return;
  throw new StudentLimitError(
    `Your ${plan.name} plan covers up to ${plan.studentLimit.toLocaleString('en-US')} active students, and your school has ${activeStudents.toLocaleString('en-US')}. ${studentName} was not added. `
    + "You don't have to upgrade, but to add more students an administrator can choose a larger plan under Subscription.",
    { planName: plan.name, studentLimit: plan.studentLimit, activeStudents },
  );
}

/** The JSON body for a StudentLimitError (HTTP 409). */
export const studentLimitResponse = error => ({ error: error.message, code: error.code, ...error.details });

/**
 * Keeps the history of a school's enrollment: one row each time the
 * active count is different from the last one recorded. Never throws.
 */
export async function recordEnrollment(schoolId, reason) {
  try {
    await pool.query(`
      INSERT INTO enrollment_history (school_id, active_students, reason)
      SELECT $1, c.n, $2 FROM (SELECT COUNT(*)::int AS n FROM students WHERE school_id=$1 AND status='ACTIVE') c
      WHERE c.n IS DISTINCT FROM (SELECT active_students FROM enrollment_history WHERE school_id=$1 ORDER BY id DESC LIMIT 1)`, [schoolId, reason]);
  } catch (error) {
    console.error('Could not record enrollment history:', error?.message || error);
  }
}

/**
 * Starts a new school's free trial (inside its registration
 * transaction). A school has one subscription row for life, so it can
 * only ever get this once; later trials are a platform decision.
 */
export async function startTrial(schoolId) {
  const settings = await billingSettings();
  const plan = await db.prepare('SELECT id FROM plans WHERE id=? AND active=1').get(settings.trialPlanId)
    ?? await db.prepare('SELECT id FROM plans WHERE active=1 AND student_limit IS NOT NULL ORDER BY student_limit DESC LIMIT 1').get();
  if (!plan) return null; // no plans set up: the school simply has no subscription yet
  const trialEndsOn = addDays(today(), settings.trialDays);
  await db.prepare(`
    INSERT INTO subscriptions (id,school_id,plan_id,status,started_on,current_period_end,trial_ends_on,billing_interval,notes,updated_at)
    VALUES (?,?,?,'TRIALING',?,?,?,'MONTH',?,?) ON CONFLICT (school_id) DO NOTHING`)
    .run(id('subscription'), schoolId, plan.id, today(), trialEndsOn, trialEndsOn, `Free trial (${settings.trialDays} days) started at registration.`, utcNow());
  return { planId: plan.id, trialEndsOn };
}

export { addDays, today as billingToday };
