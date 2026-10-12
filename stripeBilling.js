import Stripe from 'stripe';
import { db, id, withTransaction } from './db.js';
import { writeAudit } from './audit.js';
import { appBaseUrl, deliverLater, sendPaymentFailedEmail } from './mailer.js';
import { billingToday, planPrice } from './subscriptions.js';

// Online payment through Stripe.
//
// - A school pays on Stripe's own hosted Checkout page. Card details
//   never reach this server or the website, and nothing about a card is
//   stored here: only Stripe's ids for the customer and subscription.
// - Stripe is the record of what was charged. This server keeps its own
//   subscription row in step by listening to Stripe's webhook events
//   (signature checked, each event applied once) and by reading the
//   subscription straight back after a change made here.
// - Nothing here switches drop-off, pickup or attendance on or off.
//
// Settings: STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET. Without the
// secret key, online payment is simply not offered and schools ask for
// plan changes instead (schoolBilling.js). STRIPE_API_BASE is for tests.

export const stripeEnabled = () => Boolean(process.env.STRIPE_SECRET_KEY);

let cached = null;
function stripe() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error('Online payment is not set up.');
  const base = process.env.STRIPE_API_BASE || '';
  if (cached?.for !== `${key}|${base}`) {
    const options = { maxNetworkRetries: base ? 0 : 2, timeout: 20000 };
    if (base) {
      const url = new URL(base);
      Object.assign(options, { host: url.hostname, port: Number(url.port) || (url.protocol === 'https:' ? 443 : 80), protocol: url.protocol.replace(':', '') });
    }
    cached = { for: `${key}|${base}`, client: new Stripe(key, options) };
  }
  return cached.client;
}

const utcNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const isoDate = unixSeconds => (unixSeconds ? new Date(unixSeconds * 1000).toISOString().slice(0, 10) : null);
const SYSTEM = { id: null, full_name: 'Stripe' };
const audit = entry => writeAudit({ actor: SYSTEM, actorRole: 'system', ...entry });

// Stripe's subscription statuses, as ours. "incomplete" (the first
// payment hasn't gone through yet) is not a subscription for us.
const STATUS = { trialing: 'TRIALING', active: 'ACTIVE', past_due: 'PAST_DUE', unpaid: 'PAST_DUE', canceled: 'CANCELED', incomplete_expired: 'CANCELED', paused: 'PAST_DUE' };

/** A person-friendly message for a failed Stripe call; details go to the server log only. */
export function stripeProblem(error, doing) {
  console.error(`Stripe: could not ${doing}:`, error?.type || error?.name, error?.message || error);
  return Object.assign(new Error("We couldn't reach our payment provider just now. Please try again in a few minutes."), { status: 502, code: 'PAYMENT_PROVIDER_UNAVAILABLE' });
}

/** The Stripe product for a plan (made the first time the plan is sold). */
async function productFor(plan) {
  const row = await db.prepare('SELECT stripe_product_id FROM plans WHERE id=?').get(plan.id);
  if (row?.stripe_product_id) return row.stripe_product_id;
  const product = await stripe().products.create({ name: `SDPMPlus ${plan.name}`, description: plan.description || undefined, metadata: { plan_id: plan.id } }, { idempotencyKey: `product:${plan.id}` });
  await db.prepare('UPDATE plans SET stripe_product_id=? WHERE id=?').run(product.id, plan.id);
  return product.id;
}

/** The Stripe customer for a school (made the first time it pays). */
async function customerFor(school, user) {
  if (school.stripe_customer_id) return school.stripe_customer_id;
  const customer = await stripe().customers.create({ name: school.name, email: user.email, metadata: { school_id: school.id } }, { idempotencyKey: `customer:${school.id}` });
  await db.prepare('UPDATE schools SET stripe_customer_id=? WHERE id=?').run(customer.id, school.id);
  return customer.id;
}

const priceData = async (plan, interval) => ({
  currency: (plan.currency || 'USD').toLowerCase(),
  product: await productFor(plan),
  unit_amount: planPrice(plan, interval),
  recurring: { interval: interval === 'YEAR' ? 'year' : 'month' },
});

/**
 * Starts a hosted checkout for a school that is not paying online yet
 * and returns the page to send the administrator to. A free trial that
 * still has days left is kept: the first charge is on the day it ends.
 * Asking twice within a minute for the same plan gives the same page,
 * so a double click can't create two checkouts.
 */
export async function createCheckout({ school, user, plan, interval, trialEndsOn, returnTo = 'subscription' }) {
  const metadata = { school_id: school.id, plan_id: plan.id, interval };
  const trialEnd = trialEndsOn ? Math.floor(Date.parse(`${trialEndsOn}T23:59:59Z`) / 1000) : null;
  // Stripe needs a trial end at least two days ahead.
  const keepTrial = trialEnd && trialEnd - Date.now() / 1000 > 2 * 86400 + 3600;
  const session = await stripe().checkout.sessions.create({
    mode: 'subscription',
    customer: await customerFor(school, user),
    client_reference_id: school.id,
    line_items: [{ quantity: 1, price_data: await priceData(plan, interval) }],
    metadata,
    subscription_data: { metadata, ...(keepTrial ? { trial_end: trialEnd } : {}) },
    // From the sign-up flow, paying leads on to the dashboard; backing out returns to the plan choice.
    success_url: `${appBaseUrl()}${returnTo === 'dashboard' ? '/admin' : '/admin/subscription'}?checkout=success`,
    cancel_url: `${appBaseUrl()}${returnTo === 'dashboard' ? '/admin/choose-plan' : '/admin/subscription'}?checkout=cancelled`,
  }, { idempotencyKey: `checkout:${school.id}:${plan.id}:${interval}:${keepTrial ? 'trial' : 'now'}:${returnTo}:${Math.floor(Date.now() / 60000)}` });
  return session.url;
}

/** Moves a school that already pays online to another plan or interval. Stripe works out the pro-rated difference. */
export async function changePaidPlan({ school, subscriptionId, plan, interval }) {
  const current = await stripe().subscriptions.retrieve(subscriptionId);
  const item = current.items.data[0];
  const updated = await stripe().subscriptions.update(subscriptionId, {
    items: [{ id: item.id, price_data: await priceData(plan, interval) }],
    metadata: { school_id: school.id, plan_id: plan.id, interval },
    proration_behavior: 'create_prorations',
    cancel_at_period_end: false,
  });
  await syncSubscription(updated);
  return updated;
}

/** Cancels at the end of the paid period (or undoes that). The school keeps its plan until then. */
export async function setCancelAtPeriodEnd(subscriptionId, cancel) {
  const updated = await stripe().subscriptions.update(subscriptionId, { cancel_at_period_end: cancel });
  await syncSubscription(updated);
  return updated;
}

/** Stripe's own page for updating the card and seeing receipts. */
export async function billingPortalUrl(customerId) {
  const session = await stripe().billingPortal.sessions.create({ customer: customerId, return_url: `${appBaseUrl()}/admin/subscription` });
  return session.url;
}

/**
 * Brings our subscription row in step with Stripe's. Returns the school
 * id, or null when the Stripe subscription isn't one of ours or is an
 * old one that a newer subscription has replaced.
 */
export async function syncSubscription(sub) {
  const status = STATUS[sub.status];
  if (!status) return null; // incomplete: nothing has been paid yet
  const item = sub.items?.data?.[0];
  const row = await db.prepare('SELECT school_id, external_id, status, plan_id FROM subscriptions WHERE external_id=?').get(sub.id)
    ?? await db.prepare('SELECT school_id, external_id, status, plan_id FROM subscriptions WHERE school_id=?').get(sub.metadata?.school_id ?? '');
  const schoolId = row?.school_id ?? (await db.prepare('SELECT id FROM schools WHERE id=?').get(sub.metadata?.school_id ?? ''))?.id;
  if (!schoolId) return null;
  // A different, still-running Stripe subscription is already linked: this one must not overwrite it.
  if (row?.external_id && row.external_id !== sub.id && row.status !== 'CANCELED') return null;
  // An old subscription ending must not cancel a school that has since been set up another way.
  if (status === 'CANCELED' && row && row.external_id !== sub.id) return null;

  const plan = await db.prepare('SELECT id FROM plans WHERE id=?').get(sub.metadata?.plan_id ?? '') ?? (row ? { id: row.plan_id } : null);
  if (!plan) return null;
  const interval = item?.price?.recurring?.interval === 'year' ? 'YEAR' : 'MONTH';
  const periodEnd = isoDate(sub.current_period_end ?? item?.current_period_end ?? sub.trial_end);
  const customerId = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id ?? null;
  await db.prepare(`
    INSERT INTO subscriptions (id,school_id,plan_id,status,started_on,current_period_end,billing_interval,price_cents,trial_ends_on,cancel_at_period_end,external_provider,external_id,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,'stripe',?,?)
    ON CONFLICT (school_id) DO UPDATE SET plan_id=excluded.plan_id, status=excluded.status, current_period_end=excluded.current_period_end,
      billing_interval=excluded.billing_interval, price_cents=excluded.price_cents, trial_ends_on=excluded.trial_ends_on,
      cancel_at_period_end=excluded.cancel_at_period_end, external_provider='stripe', external_id=excluded.external_id, updated_at=excluded.updated_at`)
    .run(id('subscription'), schoolId, plan.id, status, billingToday(), periodEnd, interval, item?.price?.unit_amount ?? null,
      status === 'TRIALING' ? isoDate(sub.trial_end) : null, sub.cancel_at_period_end && status !== 'CANCELED' ? 1 : 0, sub.id, utcNow());
  if (customerId) await db.prepare('UPDATE schools SET stripe_customer_id=? WHERE id=? AND stripe_customer_id IS NULL').run(customerId, schoolId);
  return schoolId;
}

const schoolAdmins = schoolId => db.prepare(`
  SELECT u.email, u.full_name AS "fullName" FROM memberships m JOIN users u ON u.id=m.user_id
  WHERE m.school_id=? AND m.role='school_admin' AND m.status='ACTIVE' AND u.active=1`).all(schoolId);

/** Records a Stripe invoice (and its payment, once paid) in our own invoices, once. */
async function recordInvoice(invoice, paid) {
  const customerId = typeof invoice.customer === 'string' ? invoice.customer : invoice.customer?.id;
  const school = await db.prepare('SELECT id, name FROM schools WHERE stripe_customer_id=?').get(customerId ?? '');
  if (!school) return null;
  const total = invoice.total ?? invoice.amount_due ?? 0;
  if (total <= 0) return { school, skipped: true }; // e.g. the $0 invoice that starts a trial
  const line = invoice.lines?.data?.[0];
  const subscription = await db.prepare('SELECT id FROM subscriptions WHERE school_id=?').get(school.id);
  const saved = await db.prepare(`
    INSERT INTO invoices (id,number,school_id,subscription_id,period_start,period_end,description,amount_cents,currency,status,due_on,issued_at,paid_at,external_id,hosted_url,pdf_url)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT (external_id) WHERE external_id IS NOT NULL DO UPDATE SET status=CASE WHEN invoices.status='PAID' THEN 'PAID' ELSE excluded.status END,
      paid_at=COALESCE(invoices.paid_at, excluded.paid_at), hosted_url=excluded.hosted_url, pdf_url=excluded.pdf_url, amount_cents=excluded.amount_cents
    RETURNING id, number, status`).get(
    id('invoice'), invoice.number || `STRIPE-${invoice.id}`, school.id, subscription?.id ?? null, isoDate(line?.period?.start), isoDate(line?.period?.end),
    (line?.description || 'SDPMPlus subscription').slice(0, 300), total, (invoice.currency || 'usd').toUpperCase(), paid ? 'PAID' : 'OPEN',
    isoDate(invoice.due_date) ?? billingToday(), utcNow(), paid ? utcNow() : null, invoice.id, invoice.hosted_invoice_url ?? null, invoice.invoice_pdf ?? null);
  if (paid) {
    // One payment per Stripe invoice, however many times the event arrives.
    const reference = `Stripe ${invoice.id}`;
    if (!(await db.prepare('SELECT 1 FROM payments WHERE invoice_id=? AND reference=?').get(saved.id, reference))) {
      await db.prepare(`INSERT INTO payments (id,invoice_id,amount_cents,method,reference,received_on) VALUES (?,?,?,'CARD',?,?)`)
        .run(id('payment'), saved.id, invoice.amount_paid ?? total, reference, billingToday());
    }
  }
  return { school, invoice: saved, total };
}

async function applyEvent(event) {
  const object = event.data.object;
  switch (event.type) {
    case 'checkout.session.completed': {
      if (object.mode !== 'subscription' || !object.subscription) return;
      const sub = await stripe().subscriptions.retrieve(typeof object.subscription === 'string' ? object.subscription : object.subscription.id);
      const schoolId = await syncSubscription(sub);
      if (!schoolId) return;
      // A request the school had waiting is answered by having paid.
      await db.prepare(`UPDATE subscription_requests SET status='APPROVED', resolved_by_name='Paid online', resolved_at=? WHERE school_id=? AND status='OPEN' AND type='CHANGE_PLAN'`).run(utcNow(), schoolId);
      const plan = await db.prepare('SELECT p.name FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.school_id=?').get(schoolId);
      await audit({ schoolId, action: 'SUBSCRIPTION_STARTED', targetType: 'school', targetId: schoolId, details: { plan: plan?.name, interval: sub.metadata?.interval, status: STATUS[sub.status] } });
      return;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const schoolId = await syncSubscription(object);
      if (schoolId && event.type === 'customer.subscription.deleted') await audit({ schoolId, action: 'SUBSCRIPTION_CANCELED', targetType: 'school', targetId: schoolId, details: { reason: 'The subscription ended at the payment provider.' } });
      return;
    }
    case 'invoice.paid': {
      const result = await recordInvoice(object, true);
      if (result?.invoice) await audit({ schoolId: result.school.id, action: 'PAYMENT_RECEIVED', targetType: 'invoice', targetId: result.invoice.id, targetLabel: result.invoice.number, details: { amountCents: result.total, method: 'CARD' } });
      return;
    }
    case 'invoice.payment_failed': {
      const result = await recordInvoice(object, false);
      if (!result?.school) return;
      await db.prepare(`UPDATE subscriptions SET status='PAST_DUE', updated_at=? WHERE school_id=? AND external_provider='stripe' AND status IN ('ACTIVE','TRIALING')`).run(utcNow(), result.school.id);
      await audit({ schoolId: result.school.id, action: 'PAYMENT_FAILED', targetType: 'invoice', targetId: result.invoice?.id ?? null, targetLabel: result.invoice?.number, details: { amountCents: result.total ?? null } });
      for (const admin of await schoolAdmins(result.school.id)) {
        deliverLater(() => sendPaymentFailedEmail({ to: admin.email, fullName: admin.fullName, schoolName: result.school.name }));
      }
      return;
    }
    default: // an event we didn't ask for: acknowledged and ignored
  }
}

/**
 * POST /api/billing/stripe/webhook — the raw request body is required
 * (the signature is over the exact bytes), so this route is registered
 * before the JSON body parser. An event that fails the signature check
 * is refused; one already applied is acknowledged without being applied
 * again; one that fails part-way is rolled back so Stripe sends it again.
 */
export async function stripeWebhook(req, res) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!stripeEnabled() || !secret) return res.status(503).json({ error: 'Online payment is not set up.' });
  let event;
  try {
    event = stripe().webhooks.constructEvent(req.body, req.headers['stripe-signature'] ?? '', secret);
  } catch {
    return res.status(400).json({ error: 'Signature check failed.' });
  }
  const applied = await withTransaction(async () => {
    const first = await db.prepare('INSERT INTO stripe_events (id, type) VALUES (?,?) ON CONFLICT (id) DO NOTHING').run(event.id, event.type);
    if (first.changes === 0) return false;
    await applyEvent(event);
    return true;
  });
  res.json({ received: true, duplicate: !applied });
}
