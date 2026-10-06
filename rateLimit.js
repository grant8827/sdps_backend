import { pool } from './db.js';

// Fixed-window rate limits kept in the database, so every server process
// shares the same counts (sign-in lockouts, reset-link requests, the
// platform API). One upsert per check; expired windows are swept hourly.

/** Adds one to `key`'s count for its window and returns the new count. */
export async function hit(key, windowMs) {
  const now = Date.now();
  const { rows: [row] } = await pool.query(`
    INSERT INTO rate_limits (key, count, reset_at) VALUES ($1, 1, $2)
    ON CONFLICT (key) DO UPDATE SET
      count = CASE WHEN rate_limits.reset_at <= $3 THEN 1 ELSE rate_limits.count + 1 END,
      reset_at = CASE WHEN rate_limits.reset_at <= $3 THEN $2 ELSE rate_limits.reset_at END
    RETURNING count`, [key, now + windowMs, now]);
  return row.count;
}

/** The current count for `key` (0 once its window has passed). */
export async function peek(key) {
  const { rows: [row] } = await pool.query('SELECT count FROM rate_limits WHERE key=$1 AND reset_at > $2', [key, Date.now()]);
  return row?.count ?? 0;
}

export async function clear(key) {
  await pool.query('DELETE FROM rate_limits WHERE key=$1', [key]);
}

export function startRateLimitSweeper() {
  setInterval(() => {
    pool.query('DELETE FROM rate_limits WHERE reset_at <= $1', [Date.now()]).catch(error => console.error('Rate limit sweep failed', error));
  }, 60 * 60 * 1000).unref();
}
