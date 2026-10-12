import { db, id, isUniqueViolation, pool } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { requireAuth } from './auth.js';
import { requireSchoolAccess } from './tenant.js';
import { availablePlans, billingSettings, billingToday, planPrice, recommendedPlan, schoolCapacity } from './subscriptions.js';
import { billingPortalUrl, changePaidPlan, createCheckout, setCancelAtPeriodEnd, stripeEnabled, stripeProblem } from './stripeBilling.js';

// A school administrator's own Subscription page: the plan, how many
// students it covers and how many the school has, the trial or renewal
// date, invoices, and asking for a change (another plan, monthly or
// annual billing, or cancelling).
//
// With online payment set up (stripeBilling.js) a school pays by card on
// Stripe's hosted page, and changes plan or cancels itself. Without it —
// and always for custom-priced plans such as Enterprise — a change is a
// request that the platform team approves (platformBilling.js).
// Nothing here ever switches drop-off, pickup or attendance on or off.

const utcNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const text = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');

const REQUEST_SELECT = `
  SELECT r.id, r.type, r.plan_id AS "planId", p.name AS "planName", r.billing_interval AS "interval", r.note, r.status,
    r.requested_by_name AS "requestedBy", r.resolved_by_name AS "resolvedBy", r.resolution_note AS "resolutionNote",
    r.created_at AS "createdAt", r.resolved_at AS "resolvedAt"
  FROM subscription_requests r LEFT JOIN plans p ON p.id=r.plan_id`;

/** The school's Stripe subscription, when it has one that is still running. */
async function paidOnline(schoolId) {
  const row = await db.prepare(`
    SELECT sub.external_id AS "subscriptionId", s.stripe_customer_id AS "customerId" FROM subscriptions sub JOIN schools s ON s.id=sub.school_id
    WHERE sub.school_id=? AND sub.external_provider='stripe' AND sub.external_id IS NOT NULL AND sub.status <> 'CANCELED'`).get(schoolId);
  return row ?? null;
}

export function registerSchoolBilling(app) {
  // The price list, for the public Pricing section and the sign-up flow.
  // No sign-in needed: it is what anyone can see on the website.
  app.get('/api/plans', asyncRoute(async (req, res) => {
    const [plans, settings] = await Promise.all([availablePlans(), billingSettings()]);
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.json({ plans, trialDays: settings.trialDays });
  }));

  const admin = [requireAuth, requireSchoolAccess('school_admin')];
  const auditSchool = (req, action, details) => writeAudit({ schoolId: req.school.id, actor: req.user, actorRole: req.membership?.role, action, targetType: 'school', targetId: req.school.id, details, ip: req.ip, requestId: req.requestId });
  const failed = (res, error) => res.status(error.status ?? 500).json({ error: error.message, code: error.code });

  // Pay for a plan by card, or (already paying by card) move to another
  // plan or interval. Answers { url } to send the administrator to
  // Stripe's page, or { changed: true } when the change was made there
  // and then. `confirm: true` is required: it changes billing.
  app.post('/api/admin/subscription/checkout', ...admin, asyncRoute(async (req, res) => {
    if (!stripeEnabled()) return res.status(503).json({ error: 'Online payment is not available yet. Choose a plan to send us a request instead.', code: 'ONLINE_PAYMENT_OFF' });
    if (req.body?.confirm !== true) return res.status(400).json({ error: 'Please confirm this change: it affects what your school is billed.', code: 'CONFIRMATION_REQUIRED' });
    const schoolId = req.school.id;
    const plan = (await availablePlans()).find(candidate => candidate.id === req.body.planId);
    const interval = ['MONTH', 'YEAR'].includes(req.body.interval) ? req.body.interval : null;
    if (!plan || !interval) return res.status(400).json({ error: 'Choose a plan and monthly or annual billing.' });
    if (planPrice(plan, interval) === null) return res.status(400).json({ error: `${plan.name} is priced for each school. Send us a request and we'll be in touch.`, code: 'CUSTOM_PRICING' });
    const capacity = await schoolCapacity(schoolId);
    if (plan.studentLimit !== null && plan.studentLimit < capacity.activeStudents) {
      return res.status(400).json({ error: `The ${plan.name} plan covers up to ${plan.studentLimit} students and your school has ${capacity.activeStudents} active students.`, code: 'PLAN_TOO_SMALL' });
    }
    const school = await db.prepare('SELECT id, name, stripe_customer_id FROM schools WHERE id=?').get(schoolId);
    const paying = await paidOnline(schoolId);
    try {
      if (paying) {
        if (capacity.subscription.planId === plan.id && capacity.subscription.interval === interval) return res.status(400).json({ error: 'Your school is already on that plan and billing.' });
        await changePaidPlan({ school, subscriptionId: paying.subscriptionId, plan, interval });
        await auditSchool(req, 'SUBSCRIPTION_PLAN_CHANGED', { from: capacity.subscription.planName, to: plan.name, interval, priceCents: planPrice(plan, interval) });
        return res.json({ changed: true });
      }
      // startNow: pay from today instead of keeping the rest of the free trial.
      const trial = req.body.startNow !== true && capacity.subscription?.status === 'TRIALING' && !capacity.subscription.trialEnded ? capacity.subscription.trialEndsOn : null;
      const url = await createCheckout({ school, user: req.user, plan, interval, trialEndsOn: trial, returnTo: req.body.returnTo === 'dashboard' ? 'dashboard' : 'subscription' });
      await auditSchool(req, 'SUBSCRIPTION_CHECKOUT_STARTED', { plan: plan.name, interval, priceCents: planPrice(plan, interval) });
      res.json({ url });
    } catch (error) {
      failed(res, error.status ? error : stripeProblem(error, 'start a checkout or change the plan'));
    }
  }));

  // Which plan the school's free trial is on (chosen during sign-up, or
  // changed later in the trial). Only while the trial is running and no
  // card is on file: it changes the student limit, never what is charged.
  app.post('/api/admin/subscription/trial', ...admin, asyncRoute(async (req, res) => {
    const schoolId = req.school.id;
    const capacity = await schoolCapacity(schoolId);
    const sub = capacity.subscription;
    if (!sub || sub.status !== 'TRIALING' || sub.trialEnded || await paidOnline(schoolId)) {
      return res.status(409).json({ error: 'Your school is not in a free trial, so choose a plan on the Subscription page instead.', code: 'NOT_IN_TRIAL' });
    }
    const plan = (await availablePlans()).find(candidate => candidate.id === req.body?.planId);
    if (!plan) return res.status(400).json({ error: 'Choose a plan.' });
    if (plan.studentLimit !== null && plan.studentLimit < capacity.activeStudents) {
      return res.status(400).json({ error: `The ${plan.name} plan covers up to ${plan.studentLimit} students and your school has ${capacity.activeStudents} active students.`, code: 'PLAN_TOO_SMALL' });
    }
    const interval = ['MONTH', 'YEAR'].includes(req.body.interval) ? req.body.interval : sub.interval;
    await db.prepare(`UPDATE subscriptions SET plan_id=?, billing_interval=?, price_cents=NULL, updated_at=? WHERE school_id=? AND status='TRIALING'`).run(plan.id, interval, utcNow(), schoolId);
    await auditSchool(req, 'SUBSCRIPTION_TRIAL_PLAN_CHOSEN', { from: sub.planName, to: plan.name, interval, trialEndsOn: sub.trialEndsOn });
    res.status(204).end();
  }));

  // Cancel at the end of the paid period, or undo that (card subscriptions).
  app.post('/api/admin/subscription/cancel', ...admin, asyncRoute(async (req, res) => {
    const paying = await paidOnline(req.school.id);
    if (!paying) return res.status(409).json({ error: 'Your school does not pay by card, so send a cancellation request instead.', code: 'NOT_PAID_ONLINE' });
    const resume = req.body?.resume === true;
    if (!resume && req.body?.confirm !== true) return res.status(400).json({ error: 'Please confirm the cancellation.', code: 'CONFIRMATION_REQUIRED' });
    try {
      await setCancelAtPeriodEnd(paying.subscriptionId, !resume);
    } catch (error) {
      return failed(res, stripeProblem(error, 'change the cancellation'));
    }
    await auditSchool(req, resume ? 'SUBSCRIPTION_CANCEL_UNDONE' : 'SUBSCRIPTION_CANCEL_SCHEDULED', null);
    res.status(204).end();
  }));

  // Stripe's own page for the card on file and receipts.
  app.post('/api/admin/subscription/portal', ...admin, asyncRoute(async (req, res) => {
    const school = await db.prepare('SELECT stripe_customer_id FROM schools WHERE id=?').get(req.school.id);
    if (!stripeEnabled() || !school?.stripe_customer_id) return res.status(409).json({ error: 'There is no card on file for your school yet.', code: 'NOT_PAID_ONLINE' });
    try {
      res.json({ url: await billingPortalUrl(school.stripe_customer_id) });
    } catch (error) {
      failed(res, stripeProblem(error, 'open the billing portal'));
    }
  }));

  app.get('/api/admin/subscription', ...admin, asyncRoute(async (req, res) => {
    const schoolId = req.school.id;
    const [capacity, plans, settings] = await Promise.all([schoolCapacity(schoolId), availablePlans(), billingSettings()]);
    const recommended = capacity.level === 'OK' ? null : recommendedPlan(plans, capacity.activeStudents + 1, capacity.studentLimit);
    const { rows: invoices } = await pool.query(`
      SELECT i.id, i.number, i.description, i.amount_cents AS "amountCents", i.currency, i.status, i.period_start AS "periodStart",
        i.period_end AS "periodEnd", i.due_on AS "dueOn", i.issued_at AS "issuedAt", i.paid_at AS "paidAt", i.hosted_url AS "hostedUrl", i.pdf_url AS "pdfUrl",
        COALESCE((SELECT SUM(p.amount_cents) FROM payments p WHERE p.invoice_id=i.id), 0)::int AS "paidCents",
        (i.status='OPEN' AND i.due_on IS NOT NULL AND i.due_on < $2) AS overdue
      FROM invoices i WHERE i.school_id=$1 AND i.status <> 'DRAFT' ORDER BY i.created_at DESC LIMIT 50`, [schoolId, billingToday()]);
    const requests = await db.prepare(`${REQUEST_SELECT} WHERE r.school_id=? ORDER BY r.created_at DESC LIMIT 10`).all(schoolId);
    const enrollmentHistory = await db.prepare(`SELECT active_students AS "activeStudents", reason, created_at AS "at" FROM enrollment_history WHERE school_id=? ORDER BY id DESC LIMIT 30`).all(schoolId);
    const paying = await paidOnline(schoolId);
    res.json({
      ...capacity,
      // onlinePayment: card payment is offered. paidOnline: this school already pays by card.
      onlinePayment: stripeEnabled(), paidOnline: Boolean(paying),
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
    if (type === 'CANCEL' && await paidOnline(schoolId)) return res.status(409).json({ error: 'Your school pays by card: use Cancel subscription on this page.', code: 'PAID_ONLINE' });
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
