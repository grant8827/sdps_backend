import { db, id, isUniqueViolation, pool } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { requireAuth } from './auth.js';
import { requireSchoolAccess } from './tenant.js';
import { availablePlans, billingSettings, billingToday, planPrice, recommendedPlan, schoolCapacity } from './subscriptions.js';

// A school administrator's own Subscription page: the plan, how many
// students it covers and how many the school has, the trial or renewal
// date, invoices, and asking for a change (another plan, monthly or
// annual billing, or cancelling).
//
// A change is a request: the platform team approves it (platformBilling.js)
// because it changes what the school is charged. Nothing here ever
// switches drop-off, pickup or attendance on or off.

const utcNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const text = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');

const REQUEST_SELECT = `
  SELECT r.id, r.type, r.plan_id AS "planId", p.name AS "planName", r.billing_interval AS "interval", r.note, r.status,
    r.requested_by_name AS "requestedBy", r.resolved_by_name AS "resolvedBy", r.resolution_note AS "resolutionNote",
    r.created_at AS "createdAt", r.resolved_at AS "resolvedAt"
  FROM subscription_requests r LEFT JOIN plans p ON p.id=r.plan_id`;

export function registerSchoolBilling(app) {
  const admin = [requireAuth, requireSchoolAccess('school_admin')];

  app.get('/api/admin/subscription', ...admin, asyncRoute(async (req, res) => {
    const schoolId = req.school.id;
    const [capacity, plans, settings] = await Promise.all([schoolCapacity(schoolId), availablePlans(), billingSettings()]);
    const recommended = capacity.level === 'OK' ? null : recommendedPlan(plans, capacity.activeStudents + 1, capacity.studentLimit);
    const { rows: invoices } = await pool.query(`
      SELECT i.id, i.number, i.description, i.amount_cents AS "amountCents", i.currency, i.status, i.period_start AS "periodStart",
        i.period_end AS "periodEnd", i.due_on AS "dueOn", i.issued_at AS "issuedAt", i.paid_at AS "paidAt",
        COALESCE((SELECT SUM(p.amount_cents) FROM payments p WHERE p.invoice_id=i.id), 0)::int AS "paidCents",
        (i.status='OPEN' AND i.due_on IS NOT NULL AND i.due_on < $2) AS overdue
      FROM invoices i WHERE i.school_id=$1 AND i.status <> 'DRAFT' ORDER BY i.created_at DESC LIMIT 50`, [schoolId, billingToday()]);
    const requests = await db.prepare(`${REQUEST_SELECT} WHERE r.school_id=? ORDER BY r.created_at DESC LIMIT 10`).all(schoolId);
    const enrollmentHistory = await db.prepare(`SELECT active_students AS "activeStudents", reason, created_at AS "at" FROM enrollment_history WHERE school_id=? ORDER BY id DESC LIMIT 30`).all(schoolId);
    res.json({
      ...capacity,
      plans: plans.map(plan => ({
        ...plan,
        current: plan.id === capacity.subscription?.planId,
        recommended: plan.id === recommended?.id,
        // A plan smaller than the school can't be chosen; nobody is removed to make it fit.
        tooSmall: plan.studentLimit !== null && plan.studentLimit < capacity.activeStudents,
      })),
      graceDays: settings.graceDays,
      openRequest: requests.find(request => request.status === 'OPEN') ?? null,
      requests, invoices, enrollmentHistory,
    });
  }));

  // Ask for another plan and/or billing interval, or to cancel at the
  // end of the paid period. `confirm: true` is required: it changes billing.
  app.post('/api/admin/subscription/requests', ...admin, asyncRoute(async (req, res) => {
    const schoolId = req.school.id;
    const type = ['CHANGE_PLAN', 'CANCEL'].includes(req.body?.type) ? req.body.type : null;
    if (!type) return res.status(400).json({ error: 'Choose what to change.' });
    if (req.body.confirm !== true) return res.status(400).json({ error: 'Please confirm this change: it affects what your school is billed.', code: 'CONFIRMATION_REQUIRED' });
    const capacity = await schoolCapacity(schoolId);
    let plan = null;
    let interval = null;
    if (type === 'CHANGE_PLAN') {
      plan = (await availablePlans()).find(candidate => candidate.id === req.body.planId);
      interval = ['MONTH', 'YEAR'].includes(req.body.interval) ? req.body.interval : null;
      if (!plan || !interval) return res.status(400).json({ error: 'Choose a plan and monthly or annual billing.' });
      if (plan.studentLimit !== null && plan.studentLimit < capacity.activeStudents) {
        return res.status(400).json({ error: `The ${plan.name} plan covers up to ${plan.studentLimit} students and your school has ${capacity.activeStudents} active students.`, code: 'PLAN_TOO_SMALL' });
      }
      const sameAsNow = capacity.subscription && capacity.subscription.planId === plan.id && capacity.subscription.interval === interval && capacity.subscription.status !== 'TRIALING' && capacity.subscription.status !== 'CANCELED';
      if (sameAsNow) return res.status(400).json({ error: 'Your school is already on that plan and billing.' });
    } else if (!capacity.subscription || capacity.subscription.status === 'CANCELED') {
      return res.status(400).json({ error: 'There is no subscription to cancel.' });
    }
    const requestId = id('subreq');
    try {
      await db.prepare(`INSERT INTO subscription_requests (id,school_id,type,plan_id,billing_interval,note,requested_by_user_id,requested_by_name) VALUES (?,?,?,?,?,?,?,?)`)
        .run(requestId, schoolId, type, plan?.id ?? null, interval, text(req.body.note, 500) || null, req.user.id, req.user.full_name);
    } catch (error) {
      if (isUniqueViolation(error)) return res.status(409).json({ error: 'Your school already has a request waiting. Withdraw it first to make a different one.', code: 'REQUEST_OPEN' });
      throw error;
    }
    await writeAudit({
      schoolId, actor: req.user, actorRole: req.membership?.role, action: 'SUBSCRIPTION_CHANGE_REQUESTED', targetType: 'school', targetId: schoolId,
      details: type === 'CANCEL' ? { type } : { type, plan: plan.name, interval, priceCents: planPrice(plan, interval) }, ip: req.ip, requestId: req.requestId,
    });
    res.status(201).json({ id: requestId });
  }));

  app.delete('/api/admin/subscription/requests/:id', ...admin, asyncRoute(async (req, res) => {
    const result = await db.prepare(`UPDATE subscription_requests SET status='WITHDRAWN', resolved_at=?, resolved_by_name=? WHERE id=? AND school_id=? AND status='OPEN'`)
      .run(utcNow(), req.user.full_name, req.params.id, req.school.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Request not found' });
    await writeAudit({ schoolId: req.school.id, actor: req.user, actorRole: req.membership?.role, action: 'SUBSCRIPTION_CHANGE_WITHDRAWN', targetType: 'school', targetId: req.school.id, ip: req.ip, requestId: req.requestId });
    res.status(204).end();
  }));
}

/** A subscription set to cancel becomes Canceled once its paid period has ended. */
export async function finishCancellations() {
  const { rows } = await pool.query(`
    UPDATE subscriptions SET status='CANCELED', cancel_at_period_end=0, updated_at=$2
    WHERE cancel_at_period_end=1 AND status <> 'CANCELED' AND current_period_end IS NOT NULL AND current_period_end < $1
    RETURNING school_id`, [billingToday(), utcNow()]);
  for (const row of rows) {
    await writeAudit({ schoolId: row.school_id, actor: { id: null, full_name: 'Billing' }, actorRole: 'system', action: 'SUBSCRIPTION_CANCELED', targetType: 'school', targetId: row.school_id, details: { reason: 'The paid period ended after a cancellation.' } });
  }
  return rows.length;
}

export function startBillingSweeper() {
  setInterval(() => finishCancellations().catch(error => console.error('Billing sweep failed', error)), 60 * 60 * 1000).unref();
}
