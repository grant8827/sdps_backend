import { db, id, pool, withTransaction } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { requirePlatformPermission } from './permissions.js';

// Billing: plans, each school's subscription, invoices and the payments
// against them. Independent of any payment company — invoices and
// payments are recorded here (external_* columns can hold a provider's
// ids later). Billing never switches a school's service on or off;
// suspending a school stays a separate, deliberate action.

const today = () => new Date().toISOString().slice(0, 10);
const utcNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const text = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : '');
const validDate = value => (/^\d{4}-\d{2}-\d{2}$/.test(value ?? '') ? value : null);
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
    res.json({ ...invoices, receivedLast30DaysCents: receivedCents, subscriptions: Object.fromEntries(subscriptions.map(r => [r.status, r.n])), problems: await billingProblems() });
  }));

  // ---- plans ----
  router.get('/billing/plans', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    res.json(await db.prepare(`
      SELECT p.id, p.name, p.description, p.pricing_model AS "pricingModel", p.price_cents AS "priceCents", p.currency,
        p.billing_interval AS "interval", p.active = 1 AS active, (SELECT COUNT(*)::int FROM subscriptions s WHERE s.plan_id=p.id AND s.status <> 'CANCELED') AS schools
      FROM plans p ORDER BY p.active DESC, p.name`).all());
  }));

  router.post('/billing/plans', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const name = text(req.body.name, 80);
    const priceCents = cents(req.body.priceCents);
    const pricingModel = ['FLAT', 'PER_STUDENT'].includes(req.body.pricingModel) ? req.body.pricingModel : null;
    const interval = ['MONTH', 'YEAR'].includes(req.body.interval) ? req.body.interval : null;
    if (!name || priceCents === null || !pricingModel || !interval) return res.status(400).json({ error: 'Name, price, pricing (flat or per student) and billing interval are required.' });
    const planId = id('plan');
    await db.prepare('INSERT INTO plans (id,name,description,pricing_model,price_cents,currency,billing_interval) VALUES (?,?,?,?,?,?,?)')
      .run(planId, name, text(req.body.description, 500) || null, pricingModel, priceCents, 'USD', interval);
    await audit(req, { action: 'BILLING_PLAN_CREATED', targetType: 'plan', targetId: planId, targetLabel: name, details: { pricingModel, priceCents, interval } });
    res.status(201).json({ id: planId });
  }));

  // Name, description and active can change; price changes apply to invoices created afterwards only.
  router.patch('/billing/plans/:id', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const plan = await db.prepare('SELECT * FROM plans WHERE id=?').get(req.params.id);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    const next = {
      name: req.body.name !== undefined ? text(req.body.name, 80) : plan.name,
      description: req.body.description !== undefined ? text(req.body.description, 500) || null : plan.description,
      price_cents: req.body.priceCents !== undefined ? cents(req.body.priceCents) : plan.price_cents,
      active: req.body.active !== undefined ? (req.body.active ? 1 : 0) : plan.active,
    };
    if (!next.name || next.price_cents === null) return res.status(400).json({ error: 'Invalid name or price.' });
    await db.prepare('UPDATE plans SET name=?, description=?, price_cents=?, active=? WHERE id=?').run(next.name, next.description, next.price_cents, next.active, plan.id);
    await audit(req, { action: 'BILLING_PLAN_UPDATED', targetType: 'plan', targetId: plan.id, targetLabel: next.name, details: { before: { name: plan.name, priceCents: plan.price_cents, active: plan.active }, after: { name: next.name, priceCents: next.price_cents, active: next.active } } });
    res.status(204).end();
  }));

  // ---- subscriptions ----
  router.get('/billing/subscriptions', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    const pageNumber = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, Number.parseInt(req.query.pageSize, 10) || 50));
    const status = [...SUBSCRIPTION_STATUSES, 'NONE'].includes(req.query.status) ? req.query.status : null;
    const search = text(req.query.search, 100);
    const params = [status, search || null];
    const where = `s.status <> 'ARCHIVED' AND ($1::text IS NULL OR COALESCE(sub.status,'NONE')=$1) AND ($2::text IS NULL OR s.name ILIKE '%' || $2 || '%')`;
    const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total FROM schools s LEFT JOIN subscriptions sub ON sub.school_id=s.id WHERE ${where}`, params);
    const { rows } = await pool.query(`
      SELECT s.id AS "schoolId", s.name AS "schoolName", s.status AS "schoolStatus", sub.id, COALESCE(sub.status,'NONE') AS status,
        p.id AS "planId", p.name AS "planName", p.pricing_model AS "pricingModel", p.price_cents AS "priceCents", p.billing_interval AS "interval",
        sub.started_on AS "startedOn", sub.current_period_end AS "currentPeriodEnd", sub.notes,
        (SELECT COUNT(*)::int FROM students st WHERE st.school_id=s.id AND st.status='ACTIVE') AS students
      FROM schools s LEFT JOIN subscriptions sub ON sub.school_id=s.id LEFT JOIN plans p ON p.id=sub.plan_id
      WHERE ${where} ORDER BY s.name, s.id LIMIT ${pageSize} OFFSET ${(pageNumber - 1) * pageSize}`, params);
    res.json({ items: rows, total, page: pageNumber, pageSize });
  }));

  router.put('/billing/schools/:id/subscription', requirePlatformPermission('billing:update'), asyncRoute(async (req, res) => {
    const school = await db.prepare('SELECT id, name FROM schools WHERE id=?').get(req.params.id);
    if (!school) return res.status(404).json({ error: 'School not found' });
    const plan = await db.prepare('SELECT id, name FROM plans WHERE id=?').get(String(req.body.planId ?? ''));
    const status = SUBSCRIPTION_STATUSES.includes(req.body.status) ? req.body.status : null;
    const startedOn = validDate(req.body.startedOn) ?? today();
    const periodEnd = req.body.currentPeriodEnd ? validDate(req.body.currentPeriodEnd) : null;
    if (!plan || !status) return res.status(400).json({ error: 'Choose a plan and a status.' });
    if (req.body.currentPeriodEnd && !periodEnd) return res.status(400).json({ error: 'The period end must be a date.' });
    const before = await db.prepare('SELECT plan_id, status, current_period_end FROM subscriptions WHERE school_id=?').get(school.id);
    await db.prepare(`
      INSERT INTO subscriptions (id,school_id,plan_id,status,started_on,current_period_end,notes,updated_at) VALUES (?,?,?,?,?,?,?,?)
      ON CONFLICT (school_id) DO UPDATE SET plan_id=excluded.plan_id, status=excluded.status, started_on=excluded.started_on,
        current_period_end=excluded.current_period_end, notes=excluded.notes, updated_at=excluded.updated_at`)
      .run(id('subscription'), school.id, plan.id, status, startedOn, periodEnd, text(req.body.notes, 1000) || null, utcNow());
    await audit(req, {
      schoolId: school.id, action: 'SUBSCRIPTION_CHANGED', targetType: 'school', targetId: school.id, targetLabel: school.name,
      details: { before: before ?? null, after: { plan: plan.name, status, currentPeriodEnd: periodEnd } },
    });
    res.status(204).end();
  }));

  // One school's billing, for its Subscription tab.
  router.get('/billing/schools/:id', requirePlatformPermission('billing:view'), asyncRoute(async (req, res) => {
    const subscription = await db.prepare(`
      SELECT sub.status, sub.started_on AS "startedOn", sub.current_period_end AS "currentPeriodEnd", sub.notes, p.name AS "planName",
        p.pricing_model AS "pricingModel", p.price_cents AS "priceCents", p.billing_interval AS "interval"
      FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id WHERE sub.school_id=?`).get(req.params.id);
    const { rows: invoices } = await pool.query(`${INVOICE_SELECT.replace('$today', '$2')} WHERE i.school_id=$1 ORDER BY i.created_at DESC LIMIT 50`, [req.params.id, today()]);
    res.json({ subscription: subscription ?? null, invoices });
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
    const subscription = await db.prepare(`SELECT sub.id, p.name, p.pricing_model, p.price_cents FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id WHERE sub.school_id=?`).get(school.id);
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
