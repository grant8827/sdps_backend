import { db, id, pool, withTransaction } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { requirePlatformPermission } from './permissions.js';
import { DEFAULT_SETTINGS, addDays, billingSettings, planPrice, saveBillingSettings, schoolCapacity } from './subscriptions.js';

// Billing: plans, each school's subscription, invoices and the payments
// against them. Independent of any payment company — invoices and
// payments are recorded here (external_* columns can hold a provider's
// ids later). Billing never switches a school's service on or off;
// suspending a school stays a separate, deliberate action.
//
// Plans are student-based (subscriptions.js): each has a student limit
// and a monthly and an annual price, and every plan has every feature.

const today = () => new Date().toISOString().slice(0, 10);
const utcNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const text = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');
const validDate = value => (/^\d{4}-\d{2}-\d{2}$/.test(value ?? '') ? value : null);
const optionalCents = value => (value === null || value === undefined || value === '' ? null : cents(value) ?? undefined); // undefined = invalid
const cents = value => (Number.isInteger(value) && value >= 0 && value <= 100_000_000 ? value : null);
const SUBSCRIPTION_STATUSES = ['TRIALING', 'ACTIVE', 'PAST_DUE', 'CANCELED'];
const PAYMENT_METHODS = ['CHECK', 'ACH', 'CARD', 'WIRE', 'OTHER'];

const audit = (req, entry) => writeAudit({ actor: req.user, actorRole: req.platformAdmin.role, ip: req.ip, requestId: req.requestId, ...entry });

const INVOICE_SELECT = `
  SELECT i.id, i.number, i.school_id AS "schoolId", s.name AS "schoolName", i.description, i.amount_cents AS "amountCents", i.currency,
    i.status, i.period_start AS "periodStart", i.period_end AS "periodEnd", i.due_on AS "dueOn", i.issued_at AS "issuedAt", i.paid_at AS "paidAt",
    i.void_reason AS "voidReason", i.created_at AS "createdAt",
    COALESCE((SELECT SUM(p.amount_cents) FROM payments p WHERE p.invoice_id=i.id), 0)::int AS "paidCents",
    (i.status='OPEN' AND i.due_on IS NOT NULL AND i.due_on < $today) AS overdue
  FROM invoices i JOIN schools s ON s.id=i.school_id`;

export async function billingProblems() {
  const { rows } = await pool.query(`
    SELECT s.id, s.name,
      COUNT(i.id) FILTER (WHERE i.status='OPEN' AND i.due_on < $1)::int AS "overdueInvoices",
      COALESCE(SUM(i.amount_cents) FILTER (WHERE i.status='OPEN' AND i.due_on < $1), 0)::int AS "overdueCents",
      BOOL_OR(sub.status='PAST_DUE') AS "pastDue"
    FROM schools s LEFT JOIN invoices i ON i.school_id=s.id LEFT JOIN subscriptions sub ON sub.school_id=s.id
    WHERE s.status <> 'ARCHIVED'
    GROUP BY s.id, s.name
    HAVING COUNT(i.id) FILTER (WHERE i.status='OPEN' AND i.due_on < $1) > 0 OR BOOL_OR(sub.status='PAST_DUE')
    ORDER BY "overdueCents" DESC LIMIT 20`, [today()]);
  return rows;
}

export function registerPlatformBilling(router) {
  router.get('/billing/summary', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    const monthAgo = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const { rows: [invoices] } = await pool.query(`
      SELECT COALESCE(SUM(i.amount_cents - COALESCE(p.paid,0)) FILTER (WHERE i.status='OPEN'), 0)::int AS "openCents",
        COUNT(*) FILTER (WHERE i.status='OPEN')::int AS "openCount",
        COALESCE(SUM(i.amount_cents - COALESCE(p.paid,0)) FILTER (WHERE i.status='OPEN' AND i.due_on < $1), 0)::int AS "overdueCents",
        COUNT(*) FILTER (WHERE i.status='OPEN' AND i.due_on < $1)::int AS "overdueCount"
      FROM invoices i LEFT JOIN (SELECT invoice_id, SUM(amount_cents) AS paid FROM payments GROUP BY invoice_id) p ON p.invoice_id=i.id`, [today()]);
    const { rows: [{ receivedCents }] } = await pool.query(`SELECT COALESCE(SUM(amount_cents),0)::int AS "receivedCents" FROM payments WHERE received_on >= $1`, [monthAgo]);
    const { rows: subscriptions } = await pool.query(`
      SELECT COALESCE(sub.status, 'NONE') AS status, COUNT(*)::int AS n FROM schools s LEFT JOIN subscriptions sub ON sub.school_id=s.id
      WHERE s.status <> 'ARCHIVED' GROUP BY 1`);
    // Recurring revenue from paying (Active) subscriptions, at the price
    // each one agreed; an annual price counts as a twelfth per month.
    const { rows: [revenue] } = await pool.query(`
      SELECT COALESCE(SUM(CASE WHEN COALESCE(sub.billing_interval,'MONTH')='YEAR'
          THEN COALESCE(sub.price_cents, p.annual_price_cents, 0) / 12.0
          ELSE COALESCE(sub.price_cents, p.monthly_price_cents, 0) END), 0)::float AS mrr
      FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id JOIN schools s ON s.id=sub.school_id
      WHERE sub.status='ACTIVE' AND s.status <> 'ARCHIVED'`);
    const monthlyRecurringCents = Math.round(revenue.mrr);
    const { rows: [{ openRequests }] } = await pool.query(`SELECT COUNT(*)::int AS "openRequests" FROM subscription_requests WHERE status='OPEN'`);
    res.json({ ...invoices, monthlyRecurringCents, annualRecurringCents: monthlyRecurringCents * 12, openRequests, receivedLast30DaysCents: receivedCents, subscriptions: Object.fromEntries(subscriptions.map(r => [r.status, r.n])), problems: await billingProblems() });
  }));

  // ---- plans ----
  router.get('/billing/plans', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    res.json(await db.prepare(`
      SELECT p.id, p.name, p.description, p.pricing_model AS "pricingModel", p.price_cents AS "priceCents", p.currency,
        p.billing_interval AS "interval", p.student_limit AS "studentLimit", p.monthly_price_cents AS "monthlyPriceCents",
        p.annual_price_cents AS "annualPriceCents", (p.custom_pricing = 1) AS "customPricing", p.sort_order AS "sortOrder",
        p.active = 1 AS active, (SELECT COUNT(*)::int FROM subscriptions s WHERE s.plan_id=p.id AND s.status <> 'CANCELED') AS schools
      FROM plans p ORDER BY p.active DESC, p.sort_order, p.student_limit NULLS LAST, p.name`).all());
  }));

  // Every change to a plan's limit or prices, newest first.
  router.get('/billing/plans/:id/history', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    res.json(await db.prepare(`
      SELECT student_limit AS "studentLimit", monthly_price_cents AS "monthlyPriceCents", annual_price_cents AS "annualPriceCents",
        (custom_pricing = 1) AS "customPricing", changed_by_name AS "changedBy", created_at AS "at"
      FROM plan_price_history WHERE plan_id=? ORDER BY id DESC LIMIT 100`).all(req.params.id));
  }));

  // Trial length, grace period and which plan a new school's trial is on.
  router.get('/billing/settings', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    res.json({ ...(await billingSettings()), defaults: DEFAULT_SETTINGS });
  }));
  router.put('/billing/settings', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const days = value => (Number.isInteger(value) && value >= 0 && value <= 365 ? value : null);
    const changes = {};
    if (req.body.trialDays !== undefined) { changes.trialDays = days(req.body.trialDays); if (changes.trialDays === null || changes.trialDays < 1) return res.status(400).json({ error: 'The trial must be between 1 and 365 days.' }); }
    if (req.body.graceDays !== undefined) { changes.graceDays = days(req.body.graceDays); if (changes.graceDays === null) return res.status(400).json({ error: 'The grace period must be between 0 and 365 days.' }); }
    if (req.body.trialPlanId !== undefined) {
      if (!(await db.prepare('SELECT 1 FROM plans WHERE id=? AND active=1').get(String(req.body.trialPlanId)))) return res.status(400).json({ error: 'Choose an available plan for trials.' });
      changes.trialPlanId = String(req.body.trialPlanId);
    }
    const before = await billingSettings();
    await saveBillingSettings(changes);
    await audit(req, { action: 'BILLING_SETTINGS_CHANGED', targetType: 'platform', details: { before, after: await billingSettings() } });
    res.status(204).end();
  }));

  // What a plan's limit and prices may be: a whole number of students
  // (or none = no limit), and either two prices or "custom pricing"
  // (agreed with each school, e.g. Enterprise).
  const planTerms = (body, current = {}) => {
    const has = key => body[key] !== undefined;
    const customPricing = has('customPricing') ? Boolean(body.customPricing) : Boolean(current.custom_pricing);
    const studentLimit = has('studentLimit') ? (body.studentLimit === null || body.studentLimit === '' ? null : body.studentLimit) : current.student_limit ?? null;
    const monthly = customPricing ? null : has('monthlyPriceCents') ? optionalCents(body.monthlyPriceCents) : current.monthly_price_cents ?? null;
    const annual = customPricing ? null : has('annualPriceCents') ? optionalCents(body.annualPriceCents) : current.annual_price_cents ?? null;
    if (studentLimit !== null && !(Number.isInteger(studentLimit) && studentLimit > 0 && studentLimit <= 1_000_000)) return { error: 'The student limit must be a whole number above zero, or empty for no limit.' };
    if (monthly === undefined || annual === undefined) return { error: 'Prices must be amounts like 49.00.' };
    if (!customPricing && (monthly === null || annual === null)) return { error: 'Enter a monthly and an annual price, or mark the plan as custom pricing.' };
    return { customPricing, studentLimit, monthly, annual };
  };
  const recordPlanTerms = (req, planId, terms) => db.prepare(`
    INSERT INTO plan_price_history (plan_id,student_limit,monthly_price_cents,annual_price_cents,custom_pricing,changed_by_user_id,changed_by_name) VALUES (?,?,?,?,?,?,?)`)
    .run(planId, terms.studentLimit, terms.monthly, terms.annual, terms.customPricing ? 1 : 0, req.user.id, req.user.full_name);

  router.post('/billing/plans', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const name = text(req.body.name, 80);
    if (!name) return res.status(400).json({ error: 'Give the plan a name.' });
    if (await db.prepare('SELECT 1 FROM plans WHERE LOWER(name)=LOWER(?)').get(name)) return res.status(400).json({ error: 'A plan with that name already exists.' });
    const terms = planTerms(req.body);
    if (terms.error) return res.status(400).json({ error: terms.error });
    const planId = id('plan');
    const sortOrder = Number.isInteger(req.body.sortOrder) ? req.body.sortOrder : 100;
    await withTransaction(async () => {
      await db.prepare(`INSERT INTO plans (id,name,description,pricing_model,price_cents,currency,billing_interval,student_limit,monthly_price_cents,annual_price_cents,custom_pricing,sort_order) VALUES (?,?,?,'FLAT',?,'USD','MONTH',?,?,?,?,?)`)
        .run(planId, name, text(req.body.description, 500) || null, terms.monthly ?? 0, terms.studentLimit, terms.monthly, terms.annual, terms.customPricing ? 1 : 0, sortOrder);
      await recordPlanTerms(req, planId, terms);
    });
    await audit(req, { action: 'BILLING_PLAN_CREATED', targetType: 'plan', targetId: planId, targetLabel: name, details: { studentLimit: terms.studentLimit, monthlyPriceCents: terms.monthly, annualPriceCents: terms.annual, customPricing: terms.customPricing } });
    res.status(201).json({ id: planId });
  }));

  // A change to the limit or prices is kept in the plan's history, and
  // applies to schools that subscribe afterwards: a school already on
  // the plan keeps the price it agreed (subscriptions.price_cents) until
  // someone changes that school's subscription.
  router.patch('/billing/plans/:id', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const plan = await db.prepare('SELECT * FROM plans WHERE id=?').get(req.params.id);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    const name = req.body.name !== undefined ? text(req.body.name, 80) : plan.name;
    if (!name) return res.status(400).json({ error: 'Give the plan a name.' });
    const terms = planTerms(req.body, plan);
    if (terms.error) return res.status(400).json({ error: terms.error });
    const active = req.body.active !== undefined ? (req.body.active ? 1 : 0) : plan.active;
    const description = req.body.description !== undefined ? text(req.body.description, 500) || null : plan.description;
    const sortOrder = Number.isInteger(req.body.sortOrder) ? req.body.sortOrder : plan.sort_order;
    // Lowering a limit below what a school on the plan already has would
    // leave that school over its limit, so it is refused.
    if (terms.studentLimit !== null && (plan.student_limit === null || terms.studentLimit < plan.student_limit)) {
      const { rows: [largest] } = await pool.query(`
        SELECT s.name, COUNT(st.id)::int AS students FROM subscriptions sub JOIN schools s ON s.id=sub.school_id
          LEFT JOIN students st ON st.school_id=s.id AND st.status='ACTIVE'
        WHERE sub.plan_id=$1 AND sub.status <> 'CANCELED' GROUP BY s.id, s.name ORDER BY students DESC LIMIT 1`, [plan.id]);
      if (largest && largest.students > terms.studentLimit) return res.status(409).json({ error: `${largest.name} is on this plan with ${largest.students} active students. Move it to a larger plan before lowering the limit.` });
    }
    const termsChanged = terms.studentLimit !== plan.student_limit || terms.monthly !== plan.monthly_price_cents || terms.annual !== plan.annual_price_cents || (terms.customPricing ? 1 : 0) !== plan.custom_pricing;
    await withTransaction(async () => {
      if (termsChanged) {
        // Schools already on the plan keep today's price: write it onto
        // any subscription that was still following the plan's price.
        await db.prepare(`
          UPDATE subscriptions SET price_cents = CASE WHEN COALESCE(billing_interval,'MONTH')='YEAR' THEN ?::int ELSE ?::int END
          WHERE plan_id=? AND price_cents IS NULL AND status <> 'CANCELED'`).run(plan.annual_price_cents, plan.monthly_price_cents, plan.id);
        await recordPlanTerms(req, plan.id, terms);
      }
      await db.prepare('UPDATE plans SET name=?, description=?, price_cents=?, active=?, student_limit=?, monthly_price_cents=?, annual_price_cents=?, custom_pricing=?, sort_order=? WHERE id=?')
        .run(name, description, terms.monthly ?? plan.price_cents, active, terms.studentLimit, terms.monthly, terms.annual, terms.customPricing ? 1 : 0, sortOrder, plan.id);
    });
    await audit(req, {
      action: 'BILLING_PLAN_UPDATED', targetType: 'plan', targetId: plan.id, targetLabel: name,
      details: {
        before: { name: plan.name, studentLimit: plan.student_limit, monthlyPriceCents: plan.monthly_price_cents, annualPriceCents: plan.annual_price_cents, customPricing: plan.custom_pricing === 1, active: plan.active === 1 },
        after: { name, studentLimit: terms.studentLimit, monthlyPriceCents: terms.monthly, annualPriceCents: terms.annual, customPricing: terms.customPricing, active: active === 1 },
      },
    });
    res.status(204).end();
  }));

  // ---- subscriptions ----
  router.get('/billing/subscriptions', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    const pageNumber = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, Number.parseInt(req.query.pageSize, 10) || 50));
    const status = [...SUBSCRIPTION_STATUSES, 'NONE'].includes(req.query.status) ? req.query.status : null;
    const search = text(req.query.search, 100);
    const planId = text(req.query.planId, 100) || null;
    const renewsBefore = validDate(req.query.renewsBefore);
    const params = [status, search || null, planId, renewsBefore];
    const where = `s.status <> 'ARCHIVED' AND ($1::text IS NULL OR COALESCE(sub.status,'NONE')=$1) AND ($2::text IS NULL OR s.name ILIKE '%' || $2 || '%')
      AND ($3::text IS NULL OR sub.plan_id=$3) AND ($4::text IS NULL OR (sub.current_period_end IS NOT NULL AND sub.current_period_end <= $4))`;
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM schools s LEFT JOIN subscriptions sub ON sub.school_id=s.id WHERE ${where}`, params);
    const { rows } = await pool.query(`
      SELECT s.id AS "schoolId", s.name AS "schoolName", s.status AS "schoolStatus", sub.id, COALESCE(sub.status,'NONE') AS status,
        p.id AS "planId", p.name AS "planName", p.student_limit AS "studentLimit", (p.custom_pricing = 1) AS "customPricing",
        COALESCE(sub.billing_interval, 'MONTH') AS "interval",
        COALESCE(sub.price_cents, CASE WHEN COALESCE(sub.billing_interval,'MONTH')='YEAR' THEN p.annual_price_cents ELSE p.monthly_price_cents END) AS "priceCents",
        (sub.price_cents IS NOT NULL) AS "agreedPrice", (sub.external_provider='stripe' AND sub.external_id IS NOT NULL AND sub.status <> 'CANCELED') AS "paidOnline", sub.trial_ends_on AS "trialEndsOn", (sub.cancel_at_period_end = 1) AS "cancelAtPeriodEnd",
        sub.started_on AS "startedOn", sub.current_period_end AS "currentPeriodEnd", sub.notes,
        (SELECT COUNT(*)::int FROM students st WHERE st.school_id=s.id AND st.status='ACTIVE') AS students
      FROM schools s LEFT JOIN subscriptions sub ON sub.school_id=s.id LEFT JOIN plans p ON p.id=sub.plan_id
      WHERE ${where} ORDER BY s.name, s.id LIMIT ${pageSize} OFFSET ${(pageNumber - 1) * pageSize}`, params);
    res.json({ items: rows, total, page: pageNumber, pageSize });
  }));

  // Sets a school's plan, status, billing interval, price and dates.
  // - A trial can be put on ANY plan: status TRIALING with trialDays (or
  //   trialEndsOn). The school has every feature during it.
  // - priceCents is the price agreed with this school (a discount, or an
  //   Enterprise contract). Left out, the plan's current price is locked
  //   in; `reason` is required when it differs from the plan's price.
  router.put('/billing/schools/:id/subscription', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const school = await db.prepare('SELECT id, name FROM schools WHERE id=?').get(req.params.id);
    if (!school) return res.status(404).json({ error: 'School not found' });
    const plan = (await db.prepare(`
      SELECT id, name, student_limit AS "studentLimit", monthly_price_cents AS "monthlyPriceCents", annual_price_cents AS "annualPriceCents", (custom_pricing = 1) AS "customPricing"
      FROM plans WHERE id=?`).get(String(req.body.planId ?? '')));
    const status = SUBSCRIPTION_STATUSES.includes(req.body.status) ? req.body.status : null;
    if (!plan || !status) return res.status(400).json({ error: 'Choose a plan and a status.' });
    const before = await db.prepare(`SELECT sub.plan_id, p.name AS plan, sub.status, sub.billing_interval, sub.price_cents, sub.trial_ends_on, sub.current_period_end, sub.started_on FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id WHERE sub.school_id=?`).get(school.id);
    // A school paying by card is kept in step with Stripe; changing it here
    // would be overwritten by (or disagree with) what Stripe charges.
    const stripeManaged = await db.prepare(`SELECT 1 FROM subscriptions WHERE school_id=? AND external_provider='stripe' AND external_id IS NOT NULL AND status <> 'CANCELED'`).get(school.id);
    if (stripeManaged) return res.status(409).json({ error: `${school.name} pays by card through Stripe. Change or cancel its subscription in Stripe (or ask the school to on its Subscription page); this page updates by itself.`, code: 'STRIPE_MANAGED' });
    const interval = ['MONTH', 'YEAR'].includes(req.body.interval) ? req.body.interval : before?.billing_interval ?? 'MONTH';
    const startedOn = validDate(req.body.startedOn) ?? before?.started_on ?? today();
    if (req.body.currentPeriodEnd && !validDate(req.body.currentPeriodEnd)) return res.status(400).json({ error: 'The period end must be a date.' });
    let periodEnd = req.body.currentPeriodEnd ? validDate(req.body.currentPeriodEnd) : null;

    // The plan must fit the school as it is today: nobody is removed to make it fit.
    const { activeStudents } = await schoolCapacity(school.id);
    if (plan.studentLimit !== null && activeStudents > plan.studentLimit) {
      return res.status(409).json({ error: `${school.name} has ${activeStudents} active students and ${plan.name} covers up to ${plan.studentLimit}. Choose a larger plan.`, code: 'PLAN_TOO_SMALL' });
    }

    let trialEndsOn = null;
    if (status === 'TRIALING') {
      if (req.body.trialEndsOn !== undefined && req.body.trialEndsOn !== null && req.body.trialEndsOn !== '') {
        trialEndsOn = validDate(req.body.trialEndsOn);
        if (!trialEndsOn) return res.status(400).json({ error: 'The trial end must be a date.' });
      } else if (req.body.trialDays !== undefined && req.body.trialDays !== null && req.body.trialDays !== '') {
        if (!Number.isInteger(req.body.trialDays) || req.body.trialDays < 1 || req.body.trialDays > 365) return res.status(400).json({ error: 'A trial is between 1 and 365 days.' });
        trialEndsOn = addDays(today(), req.body.trialDays);
      } else {
        trialEndsOn = before?.status === 'TRIALING' && before.trial_ends_on ? before.trial_ends_on : addDays(today(), (await billingSettings()).trialDays);
      }
      periodEnd ??= trialEndsOn;
    }

    const listPrice = planPrice(plan, interval);
    let priceCents;
    if (req.body.priceCents !== undefined && req.body.priceCents !== null && req.body.priceCents !== '') {
      priceCents = cents(req.body.priceCents);
      if (priceCents === null) return res.status(400).json({ error: 'The price must be an amount like 49.00.' });
    } else if (before && before.plan_id === plan.id && (before.billing_interval ?? 'MONTH') === interval && before.price_cents !== null) {
      priceCents = before.price_cents; // same plan and billing: they keep the price they agreed
    } else {
      priceCents = listPrice;
    }
    if (priceCents === null && status !== 'TRIALING' && status !== 'CANCELED') return res.status(400).json({ error: `${plan.name} has custom pricing. Enter the price agreed with this school.` });
    const reason = text(req.body.reason, 500);
    const priceChanged = priceCents !== (before?.price_cents ?? null);
    if (priceCents !== null && priceCents !== listPrice && priceChanged && !reason) {
      return res.status(400).json({ error: "This price is different from the plan's price. Add a reason (for example the discount or contract it comes from).", code: 'REASON_REQUIRED' });
    }

    await db.prepare(`
      INSERT INTO subscriptions (id,school_id,plan_id,status,started_on,current_period_end,notes,billing_interval,price_cents,trial_ends_on,cancel_at_period_end,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?)
      ON CONFLICT (school_id) DO UPDATE SET plan_id=excluded.plan_id, status=excluded.status, started_on=excluded.started_on,
        current_period_end=excluded.current_period_end, notes=excluded.notes, billing_interval=excluded.billing_interval, price_cents=excluded.price_cents,
        trial_ends_on=excluded.trial_ends_on, cancel_at_period_end=0, updated_at=excluded.updated_at`)
      .run(id('subscription'), school.id, plan.id, status, startedOn, periodEnd, text(req.body.notes, 1000) || null, interval, priceCents, trialEndsOn, utcNow());
    await audit(req, {
      schoolId: school.id, action: 'SUBSCRIPTION_CHANGED', targetType: 'school', targetId: school.id, targetLabel: school.name, reason: reason || undefined,
      details: {
        before: before ? { plan: before.plan, status: before.status, interval: before.billing_interval, priceCents: before.price_cents, trialEndsOn: before.trial_ends_on, currentPeriodEnd: before.current_period_end } : null,
        after: { plan: plan.name, status, interval, priceCents, listPriceCents: listPrice, trialEndsOn, currentPeriodEnd: periodEnd },
      },
    });
    res.status(204).end();
  }));

  // ---- requests from schools (another plan or billing interval, or cancelling) ----
  router.get('/billing/requests', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    const status = ['OPEN', 'APPROVED', 'DECLINED', 'WITHDRAWN'].includes(req.query.status) ? req.query.status : 'OPEN';
    const { rows } = await pool.query(`
      SELECT r.id, r.school_id AS "schoolId", s.name AS "schoolName", r.type, r.plan_id AS "planId", p.name AS "planName", r.billing_interval AS "interval",
        CASE WHEN p.custom_pricing = 1 THEN NULL WHEN r.billing_interval='YEAR' THEN p.annual_price_cents ELSE p.monthly_price_cents END AS "priceCents",
        (p.custom_pricing = 1) AS "customPricing", r.note, r.status, r.requested_by_name AS "requestedBy", r.resolved_by_name AS "resolvedBy",
        r.resolution_note AS "resolutionNote", r.created_at AS "createdAt", r.resolved_at AS "resolvedAt",
        cur.name AS "currentPlanName", sub.status AS "currentStatus", sub.current_period_end AS "currentPeriodEnd",
        (SELECT COUNT(*)::int FROM students st WHERE st.school_id=s.id AND st.status='ACTIVE') AS students
      FROM subscription_requests r JOIN schools s ON s.id=r.school_id LEFT JOIN plans p ON p.id=r.plan_id
        LEFT JOIN subscriptions sub ON sub.school_id=s.id LEFT JOIN plans cur ON cur.id=sub.plan_id
      WHERE r.status=$1 ORDER BY r.created_at DESC LIMIT 200`, [status]);
    res.json(rows);
  }));

  // Approving applies it: a plan change takes the plan's price today (or
  // priceCents, required for custom-priced plans); a cancellation ends
  // the subscription when the paid period does.
  router.post('/billing/requests/:id/resolve', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const approve = req.body?.approve === true;
    const note = text(req.body?.note, 500);
    if (!approve && !note) return res.status(400).json({ error: 'Say why the request is declined; the school sees this.' });
    try {
      const outcome = await withTransaction(async () => {
        const request = await db.prepare(`SELECT * FROM subscription_requests WHERE id=? AND status='OPEN' FOR UPDATE`).get(req.params.id);
        if (!request) return null;
        const school = await db.prepare('SELECT id, name FROM schools WHERE id=?').get(request.school_id);
        const details = { type: request.type };
        if (approve && await db.prepare(`SELECT 1 FROM subscriptions WHERE school_id=? AND external_provider='stripe' AND external_id IS NOT NULL AND status <> 'CANCELED'`).get(school.id)) {
          throw Object.assign(new Error(`${school.name} pays by card through Stripe. Change or cancel its subscription in Stripe first, then answer this request.`), { status: 409 });
        }
        if (approve && request.type === 'CHANGE_PLAN') {
          const plan = await db.prepare(`SELECT id, name, student_limit AS "studentLimit", monthly_price_cents AS "monthlyPriceCents", annual_price_cents AS "annualPriceCents", (custom_pricing = 1) AS "customPricing" FROM plans WHERE id=?`).get(request.plan_id);
          const { activeStudents } = await schoolCapacity(school.id);
          if (plan.studentLimit !== null && activeStudents > plan.studentLimit) throw Object.assign(new Error(`${school.name} now has ${activeStudents} active students and ${plan.name} covers up to ${plan.studentLimit}.`), { status: 409 });
          let priceCents = planPrice(plan, request.billing_interval);
          if (req.body.priceCents !== undefined && req.body.priceCents !== null && req.body.priceCents !== '') {
            priceCents = cents(req.body.priceCents);
            if (priceCents === null) throw Object.assign(new Error('The price must be an amount like 49.00.'), { status: 400 });
          }
          if (priceCents === null) throw Object.assign(new Error(`${plan.name} has custom pricing. Enter the price agreed with this school.`), { status: 400 });
          const current = await db.prepare('SELECT status, trial_ends_on FROM subscriptions WHERE school_id=?').get(school.id);
          // A school still in its trial stays in it on the new plan; otherwise the plan is active.
          const status = current?.status === 'TRIALING' && current.trial_ends_on >= today() ? 'TRIALING' : 'ACTIVE';
          await db.prepare(`
            INSERT INTO subscriptions (id,school_id,plan_id,status,started_on,billing_interval,price_cents,updated_at) VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT (school_id) DO UPDATE SET plan_id=excluded.plan_id, status=excluded.status, billing_interval=excluded.billing_interval,
              price_cents=excluded.price_cents, cancel_at_period_end=0, updated_at=excluded.updated_at`)
            .run(id('subscription'), school.id, plan.id, status, today(), request.billing_interval, priceCents, utcNow());
          Object.assign(details, { plan: plan.name, interval: request.billing_interval, priceCents, status });
        } else if (approve) {
          const current = await db.prepare('SELECT current_period_end, status FROM subscriptions WHERE school_id=?').get(school.id);
          // With a paid period still running it ends then; otherwise now.
          if (current?.current_period_end && current.current_period_end >= today() && current.status !== 'TRIALING') {
            await db.prepare('UPDATE subscriptions SET cancel_at_period_end=1, updated_at=? WHERE school_id=?').run(utcNow(), school.id);
            details.endsOn = current.current_period_end;
          } else {
            await db.prepare(`UPDATE subscriptions SET status='CANCELED', cancel_at_period_end=0, updated_at=? WHERE school_id=?`).run(utcNow(), school.id);
            details.endsOn = today();
          }
        }
        await db.prepare('UPDATE subscription_requests SET status=?, resolved_by_name=?, resolution_note=?, resolved_at=? WHERE id=?')
          .run(approve ? 'APPROVED' : 'DECLINED', req.user.full_name, note || null, utcNow(), request.id);
        return { school, details };
      });
      if (!outcome) return res.status(404).json({ error: 'That request is no longer open.' });
      await audit(req, {
        schoolId: outcome.school.id, action: approve ? 'SUBSCRIPTION_REQUEST_APPROVED' : 'SUBSCRIPTION_REQUEST_DECLINED', targetType: 'school',
        targetId: outcome.school.id, targetLabel: outcome.school.name, reason: note || undefined, details: outcome.details,
      });
      res.status(204).end();
    } catch (error) {
      if (error.status) return res.status(error.status).json({ error: error.message });
      throw error;
    }
  }));

  // One school's billing, for its Subscription tab.
  router.get('/billing/schools/:id', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    const subscription = await db.prepare(`
      SELECT sub.status, sub.started_on AS "startedOn", sub.current_period_end AS "currentPeriodEnd", sub.notes, p.name AS "planName",
        p.pricing_model AS "pricingModel", p.student_limit AS "studentLimit", sub.trial_ends_on AS "trialEndsOn", (sub.cancel_at_period_end = 1) AS "cancelAtPeriodEnd",
        COALESCE(sub.price_cents, CASE WHEN COALESCE(sub.billing_interval,'MONTH')='YEAR' THEN p.annual_price_cents ELSE p.monthly_price_cents END, p.price_cents) AS "priceCents",
        COALESCE(sub.billing_interval, p.billing_interval) AS "interval"
      FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id WHERE sub.school_id=?`).get(req.params.id);
    const capacity = await schoolCapacity(req.params.id);
    const enrollmentHistory = await db.prepare(`SELECT active_students AS "activeStudents", reason, created_at AS "at" FROM enrollment_history WHERE school_id=? ORDER BY id DESC LIMIT 30`).all(req.params.id);
    const { rows: invoices } = await pool.query(`${INVOICE_SELECT.replace('$today', '$2')} WHERE i.school_id=$1 ORDER BY i.created_at DESC LIMIT 50`, [req.params.id, today()]);
    res.json({ subscription: subscription ?? null, invoices, activeStudents: capacity.activeStudents, studentLimit: capacity.studentLimit, level: capacity.level, enrollmentHistory });
  }));

  // ---- invoices ----
  router.get('/billing/invoices', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    const pageNumber = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, Number.parseInt(req.query.pageSize, 10) || 50));
    const overdueOnly = req.query.status === 'OVERDUE';
    const status = ['DRAFT', 'OPEN', 'PAID', 'VOID'].includes(req.query.status) ? req.query.status : null;
    const schoolId = text(req.query.schoolId, 100) || null;
    const params = [status, schoolId, overdueOnly, today()];
    const where = `($1::text IS NULL OR i.status=$1) AND ($2::text IS NULL OR i.school_id=$2) AND (NOT $3::boolean OR (i.status='OPEN' AND i.due_on < $4))`;
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM invoices i WHERE ${where}`, params);
    const { rows } = await pool.query(`${INVOICE_SELECT.replace('$today', '$4')} WHERE ${where} ORDER BY i.created_at DESC, i.id LIMIT ${pageSize} OFFSET ${(pageNumber - 1) * pageSize}`, params);
    res.json({ items: rows, total, page: pageNumber, pageSize });
  }));

  router.get('/billing/invoices/:id', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    const { rows: [invoice] } = await pool.query(`${INVOICE_SELECT.replace('$today', '$2')} WHERE i.id=$1`, [req.params.id, today()]);
    if (!invoice) return res.status(404).json({ error: 'Invoice not found' });
    const payments = await db.prepare(`
      SELECT p.id, p.amount_cents AS "amountCents", p.method, p.reference, p.received_on AS "receivedOn", u.full_name AS "recordedBy"
      FROM payments p LEFT JOIN users u ON u.id=p.recorded_by_user_id WHERE p.invoice_id=? ORDER BY p.received_on, p.id`).all(invoice.id);
    res.json({ ...invoice, payments });
  }));

  // A draft invoice. Without an amount, it's priced from the school's
  // plan: the flat price, or the per-student price × active students.
  router.post('/billing/invoices', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const school = await db.prepare('SELECT id, name FROM schools WHERE id=?').get(text(req.body.schoolId, 100));
    if (!school) return res.status(400).json({ error: 'Choose a school.' });
    const periodStart = validDate(req.body.periodStart);
    const periodEnd = validDate(req.body.periodEnd);
    const dueOn = validDate(req.body.dueOn);
    if (periodStart && periodEnd && periodStart > periodEnd) return res.status(400).json({ error: 'The period must start before it ends.' });
    const subscription = await db.prepare(`SELECT sub.id, p.name, p.pricing_model,
      COALESCE(sub.price_cents, CASE WHEN COALESCE(sub.billing_interval,'MONTH')='YEAR' THEN p.annual_price_cents ELSE p.monthly_price_cents END, p.price_cents) AS price_cents
      FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id WHERE sub.school_id=?`).get(school.id);
    let amountCents = req.body.amountCents !== undefined && req.body.amountCents !== null ? cents(req.body.amountCents) : null;
    let description = text(req.body.description, 300);
    if (amountCents === null) {
      if (req.body.amountCents !== undefined && req.body.amountCents !== null) return res.status(400).json({ error: 'The amount must be a whole number of cents.' });
      if (!subscription) return res.status(400).json({ error: "This school has no plan yet. Set its subscription, or enter an amount." });
      const { students } = await db.prepare(`SELECT COUNT(*)::int AS students FROM students WHERE school_id=? AND status='ACTIVE'`).get(school.id);
      amountCents = subscription.pricing_model === 'PER_STUDENT' ? subscription.price_cents * students : subscription.price_cents;
      description ||= `${subscription.name}${subscription.pricing_model === 'PER_STUDENT' ? ` (${students} students)` : ''}${periodStart ? `, ${periodStart} to ${periodEnd ?? ''}` : ''}`;
    }
    if (!description) return res.status(400).json({ error: 'Add a description.' });
    const invoiceId = id('invoice');
    const { rows: [{ seq }] } = await pool.query(`SELECT nextval('invoice_number_seq') AS seq`);
    const number = `INV-${new Date().getUTCFullYear()}-${seq}`;
    await db.prepare(`
      INSERT INTO invoices (id,number,school_id,subscription_id,period_start,period_end,description,amount_cents,currency,due_on,created_by_user_id)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run(invoiceId, number, school.id, subscription?.id ?? null, periodStart, periodEnd, description, amountCents, 'USD', dueOn, req.user.id);
    await audit(req, { schoolId: school.id, action: 'INVOICE_CREATED', targetType: 'invoice', targetId: invoiceId, targetLabel: number, details: { amountCents, dueOn } });
    res.status(201).json({ id: invoiceId, number, amountCents });
  }));

  router.post('/billing/invoices/:id/issue', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const invoice = await db.prepare(`UPDATE invoices SET status='OPEN', issued_at=? WHERE id=? AND status='DRAFT' RETURNING id, number, school_id`).get(utcNow(), req.params.id);
    if (!invoice) return res.status(409).json({ error: 'Only a draft invoice can be issued.' });
    await audit(req, { schoolId: invoice.school_id, action: 'INVOICE_ISSUED', targetType: 'invoice', targetId: invoice.id, targetLabel: invoice.number });
    res.status(204).end();
  }));

  router.post('/billing/invoices/:id/void', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const reason = text(req.body?.reason, 500);
    if (reason.length < 5) return res.status(400).json({ error: 'Please give a reason (at least 5 characters).' });
    const invoice = await db.prepare(`
      UPDATE invoices SET status='VOID', void_reason=? WHERE id=? AND status IN ('DRAFT','OPEN') AND NOT EXISTS (SELECT 1 FROM payments p WHERE p.invoice_id=invoices.id)
      RETURNING id, number, school_id`).get(reason, req.params.id);
    if (!invoice) return res.status(409).json({ error: "Only a draft or open invoice with no payments can be voided." });
    await audit(req, { schoolId: invoice.school_id, action: 'INVOICE_VOIDED', targetType: 'invoice', targetId: invoice.id, targetLabel: invoice.number, reason });
    res.status(204).end();
  }));

  // A payment received (cheque, bank transfer...). Fully paid → PAID.
  router.post('/billing/invoices/:id/payments', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const amountCents = cents(req.body.amountCents);
    const method = PAYMENT_METHODS.includes(req.body.method) ? req.body.method : null;
    const receivedOn = validDate(req.body.receivedOn) ?? today();
    if (!amountCents || !method) return res.status(400).json({ error: 'Enter the amount and how it was paid.' });
    const result = await withTransaction(async () => {
      const invoice = await db.prepare(`SELECT id, number, school_id, amount_cents, status FROM invoices WHERE id=? FOR UPDATE`).get(req.params.id);
      if (!invoice) return { error: 404, message: 'Invoice not found' };
      if (invoice.status !== 'OPEN') return { error: 409, message: 'Payments can only be recorded against an issued, unpaid invoice.' };
      const { paid } = await db.prepare('SELECT COALESCE(SUM(amount_cents),0)::int AS paid FROM payments WHERE invoice_id=?').get(invoice.id);
      if (paid + amountCents > invoice.amount_cents) return { error: 400, message: `That's more than the ${((invoice.amount_cents - paid) / 100).toFixed(2)} still owed.` };
      await db.prepare('INSERT INTO payments (id,invoice_id,amount_cents,method,reference,received_on,recorded_by_user_id) VALUES (?,?,?,?,?,?,?)')
        .run(id('payment'), invoice.id, amountCents, method, text(req.body.reference, 120) || null, receivedOn, req.user.id);
      const fullyPaid = paid + amountCents === invoice.amount_cents;
      if (fullyPaid) await db.prepare(`UPDATE invoices SET status='PAID', paid_at=? WHERE id=?`).run(utcNow(), invoice.id);
      return { invoice, fullyPaid };
    });
    if (result.error) return res.status(result.error).json({ error: result.message });
    await audit(req, {
      schoolId: result.invoice.school_id, action: 'PAYMENT_RECORDED', targetType: 'invoice', targetId: result.invoice.id, targetLabel: result.invoice.number,
      details: { amountCents, method, fullyPaid: result.fullyPaid },
    });
    res.status(201).json({ fullyPaid: result.fullyPaid });
  }));
}
