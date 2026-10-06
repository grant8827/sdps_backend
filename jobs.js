import { id, pool } from './db.js';

// Background jobs for work too slow for a web request (report exports).
// Jobs live in the database; each server process runs one worker that
// claims the oldest queued job with FOR UPDATE SKIP LOCKED, so several
// servers never pick up the same one. A job is tried up to 3 times;
// results (a file) are kept 7 days and then removed.

// When this process's worker last checked the queue (System Health).
export let workerLastTickAt = null;

const handlers = new Map(); // type -> async (params) => ({ name, type, body })
const MAX_ATTEMPTS = 3;
const MAX_RESULT_BYTES = 25 * 1024 * 1024;
const KEEP_DAYS = 7;
const POLL_MS = 3000;
const utcNow = () => new Date().toISOString().replace('T', ' ').slice(0, 19);

export function registerJobHandler(type, handler) {
  handlers.set(type, handler);
}

export async function enqueueJob(type, params, userId) {
  if (!handlers.has(type)) throw new Error(`Unknown job type ${type}`);
  const jobId = id('job');
  await pool.query('INSERT INTO jobs (id,type,params,created_by_user_id) VALUES ($1,$2,$3,$4)', [jobId, type, JSON.stringify(params ?? {}), userId ?? null]);
  return jobId;
}

/** Claims and runs one queued job. Returns false when the queue is empty. */
export async function runNextJob() {
  const { rows: [job] } = await pool.query(`
    UPDATE jobs SET status='RUNNING', attempts=attempts+1, started_at=$1
    WHERE id = (SELECT id FROM jobs WHERE status='QUEUED' ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1)
    RETURNING id, type, params, attempts`, [utcNow()]);
  if (!job) return false;
  try {
    const handler = handlers.get(job.type);
    if (!handler) throw new Error(`No handler for job type ${job.type}`);
    const result = await handler(JSON.parse(job.params));
    const body = Buffer.isBuffer(result.body) ? result.body : Buffer.from(String(result.body), 'utf8');
    if (body.length > MAX_RESULT_BYTES) throw Object.assign(new Error('The result is too large. Narrow the date range or choose one school.'), { final: true });
    await pool.query(`UPDATE jobs SET status='SUCCEEDED', result=$1, result_name=$2, result_type=$3, result_size=$4, finished_at=$5, error=NULL WHERE id=$6`,
      [body, result.name, result.type, body.length, utcNow(), job.id]);
  } catch (error) {
    const retry = !error.final && job.attempts < MAX_ATTEMPTS;
    console.error(`Job ${job.id} (${job.type}) failed${retry ? ', will retry' : ''}:`, error?.message || error);
    // The message shown to the person is kept short; details stay in the server log.
    await pool.query(`UPDATE jobs SET status=$1, error=$2, finished_at=$3 WHERE id=$4`,
      [retry ? 'QUEUED' : 'FAILED', String(error?.message || 'Failed').slice(0, 300), retry ? null : utcNow(), job.id]);
  }
  return true;
}

/** Runs every queued job now (tests, and the worker's tick). */
export async function runPendingJobs() {
  while (await runNextJob()) { /* keep going until the queue is empty */ }
}

export async function cleanUpJobs() {
  const cutoff = new Date(Date.now() - KEEP_DAYS * 86400000).toISOString().replace('T', ' ').slice(0, 19);
  await pool.query(`DELETE FROM jobs WHERE status IN ('SUCCEEDED','FAILED') AND finished_at < $1`, [cutoff]);
  // A job left RUNNING by a server that stopped mid-way goes back in the queue.
  const stale = new Date(Date.now() - 30 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
  await pool.query(`UPDATE jobs SET status = CASE WHEN attempts >= $2 THEN 'FAILED' ELSE 'QUEUED' END WHERE status='RUNNING' AND started_at < $1`, [stale, MAX_ATTEMPTS]);
}

export function startJobWorker() {
  let busy = false;
  setInterval(async () => {
    if (busy) return;
    busy = true;
    workerLastTickAt = new Date().toISOString();
    try { await runPendingJobs(); } catch (error) { console.error('Job worker error', error); } finally { busy = false; }
  }, POLL_MS).unref();
  setInterval(() => cleanUpJobs().catch(error => console.error('Job clean-up failed', error)), 60 * 60 * 1000).unref();
}

export async function jobStatusCounts() {
  const day = new Date(Date.now() - 86400000).toISOString().replace('T', ' ').slice(0, 19);
  const { rows } = await pool.query(`SELECT status, COUNT(*)::int AS n FROM jobs WHERE created_at >= $1 OR status IN ('QUEUED','RUNNING') GROUP BY status`, [day]);
  return Object.fromEntries(rows.map(r => [r.status, r.n]));
}
