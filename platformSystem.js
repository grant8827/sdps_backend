import { readFileSync } from 'node:fs';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { pool } from './db.js';
import { asyncRoute } from './asyncRoute.js';
import { writeAudit } from './audit.js';
import { configWarnings } from './config.js';
import { retentionStatus } from './dataRights.js';
import { workerLastTickAt } from './jobs.js';
import { emailConfigured, verifyEmailConnection } from './mailer.js';
import { LATEST_MIGRATION } from './migrations.js';
import { requirePlatformPermission } from './permissions.js';

// Platform → System Health: is each part of SDPMPlus working? API,
// database, email, background jobs, retention, storage and app versions.
// Reports state, never configuration values, hostnames or credentials.

const startedAt = new Date();
const APP_VERSION = (() => {
  try { return JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version; } catch { return 'unknown'; }
})();
const loopDelay = monitorEventLoopDelay({ resolution: 20 });
loopDelay.enable();

const minutesSince = iso => (iso ? Math.round((Date.now() - Date.parse(iso)) / 60000) : null);
const worst = statuses => (statuses.includes('down') ? 'down' : statuses.includes('degraded') ? 'degraded' : 'ok');
const mb = bytes => Math.round((Number(bytes) / 1024 / 1024) * 10) / 10;

async function databaseHealth() {
  const started = process.hrtime.bigint();
  try {
    await pool.query('SELECT 1');
    const latencyMs = Number(process.hrtime.bigint() - started) / 1e6;
    const { rows: [info] } = await pool.query(`
      SELECT current_setting('server_version_num')::int AS version, pg_database_size(current_database()) AS size,
        (SELECT MAX(version) FROM schema_migrations) AS migrations`);
    const { rows: tables } = await pool.query(`
      SELECT c.relname AS name, pg_total_relation_size(c.oid) AS bytes, GREATEST(c.reltuples, 0)::bigint AS rows
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE c.relkind='r' AND n.nspname='public' ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 8`);
    const behind = info.migrations < LATEST_MIGRATION;
    return {
      status: behind || latencyMs > 500 ? 'degraded' : 'ok',
      latencyMs: Math.round(latencyMs * 10) / 10,
      serverVersion: `PostgreSQL ${Math.floor(info.version / 10000)}`,
      sizeMb: mb(info.size),
      migrationsApplied: info.migrations,
      migrationsExpected: LATEST_MIGRATION,
      connections: { total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount },
      largestTables: tables.map(t => ({ name: t.name, sizeMb: mb(t.bytes), approxRows: Number(t.rows) })),
    };
  } catch {
    return { status: 'down', message: 'The database is not answering.' };
  }
}

export function registerPlatformSystem(router) {
  router.get('/system/health', requirePlatformPermission('system:view'), asyncRoute(async (req, res) => {
    const day = new Date(Date.now() - 86400000).toISOString().replace('T', ' ').slice(0, 19);
    const database = await databaseHealth();
    const dbUp = database.status !== 'down';

    let email = { status: emailConfigured() ? 'ok' : 'not_configured' };
    let jobs = { status: 'unknown' };
    let storage = {};
    let clients = [];
    if (dbUp) {
      const { rows: [mail] } = await pool.query(`
        SELECT COUNT(*) FILTER (WHERE status='SENT')::int AS sent, COUNT(*) FILTER (WHERE status='FAILED')::int AS failed,
          (SELECT MAX(created_at) FROM notification_deliveries WHERE status='SENT') AS "lastSentAt"
        FROM notification_deliveries WHERE created_at >= $1`, [day]);
      email = {
        status: !emailConfigured() ? 'not_configured' : mail.failed > 0 && mail.failed >= mail.sent ? 'down' : mail.failed > 0 ? 'degraded' : 'ok',
        sent24h: mail.sent, failed24h: mail.failed, lastSentAt: mail.lastSentAt,
      };
      const { rows: [job] } = await pool.query(`
        SELECT COUNT(*) FILTER (WHERE status='QUEUED')::int AS queued, COUNT(*) FILTER (WHERE status='RUNNING')::int AS running,
          COUNT(*) FILTER (WHERE status='FAILED' AND finished_at >= $1)::int AS "failed24h",
          COUNT(*) FILTER (WHERE status='SUCCEEDED' AND finished_at >= $1)::int AS "succeeded24h",
          MIN(created_at) FILTER (WHERE status='QUEUED') AS "oldestQueuedAt",
          COALESCE(SUM(result_size), 0)::bigint AS "resultBytes"
        FROM jobs`, [day]);
      const oldestQueuedMinutes = job.oldestQueuedAt ? minutesSince(`${job.oldestQueuedAt.replace(' ', 'T')}Z`) : null;
      const workerIdleMinutes = minutesSince(workerLastTickAt);
      jobs = {
        status: oldestQueuedMinutes !== null && oldestQueuedMinutes > 10 ? 'degraded' : job.failed24h > 0 ? 'degraded' : 'ok',
        queued: job.queued, running: job.running, failed24h: job.failed24h, succeeded24h: job.succeeded24h, oldestQueuedMinutes,
        workerLastTickAt, workerRunningHere: workerIdleMinutes !== null && workerIdleMinutes < 2,
      };
      const { rows: [audit] } = await pool.query(`SELECT GREATEST(reltuples, 0)::bigint AS rows FROM pg_class WHERE relname='audit_logs'`);
      storage = { databaseMb: database.sizeMb, exportFilesMb: mb(job.resultBytes), auditEntriesApprox: Number(audit?.rows ?? 0) };
      ({ rows: clients } = await pool.query(`SELECT client, version, first_seen AS "firstSeen", last_seen AS "lastSeen" FROM client_versions ORDER BY last_seen DESC LIMIT 20`));
    }

    const memory = process.memoryUsage();
    const api = {
      status: 'ok',
      version: APP_VERSION,
      commit: (process.env.RAILWAY_GIT_COMMIT_SHA || '').slice(0, 7) || null,
      environment: process.env.RAILWAY_ENVIRONMENT_NAME || process.env.NODE_ENV || 'development',
      startedAt: startedAt.toISOString(),
      uptimeMinutes: Math.round(process.uptime() / 60),
      nodeVersion: process.version,
      memoryMb: mb(memory.rss),
      eventLoopDelayMs: Math.round(loopDelay.percentile(99) / 1e6),
    };
    if (api.eventLoopDelayMs > 200) api.status = 'degraded';
    const retention = {
      status: retentionStatus.failures ? 'degraded' : 'ok',
      lastRunAt: retentionStatus.lastRunAt,
      failures: retentionStatus.failures,
    };
    const warnings = configWarnings();
    res.json({
      generatedAt: new Date().toISOString(),
      status: worst([api.status, database.status, email.status === 'down' ? 'down' : email.status === 'ok' ? 'ok' : 'degraded', jobs.status === 'unknown' ? 'ok' : jobs.status, retention.status, warnings.some(w => w.severity === 'critical') ? 'degraded' : 'ok']),
      api, database, email,
      sms: { status: 'not_offered' },
      push: { status: 'not_offered' },
      jobs, retention, storage, clients, warnings,
    });
  }));

  // Tests the email server connection now (Super Admins). Reports only whether it worked.
  router.post('/system/email-check', requirePlatformPermission('platform:settings'), asyncRoute(async (req, res) => {
    let ok = false;
    let message = 'Connected to the email server.';
    try {
      await Promise.race([verifyEmailConnection(), new Promise((_, reject) => setTimeout(() => reject(new Error('timed out')), 10_000))]);
      ok = true;
    } catch (error) {
      message = !emailConfigured() ? 'Email sending is not set up (SMTP_* settings are missing).'
        : /timed out/.test(error.message) ? 'The email server did not answer within 10 seconds.'
          : /auth|535|credentials/i.test(error.message) ? 'The email server refused the username or password.'
            : 'Could not connect to the email server.';
    }
    await writeAudit({ actor: req.user, actorRole: req.platformAdmin.role, action: 'EMAIL_CONNECTION_CHECKED', details: { ok }, ip: req.ip, requestId: req.requestId });
    res.json({ ok, message });
  }));
}
