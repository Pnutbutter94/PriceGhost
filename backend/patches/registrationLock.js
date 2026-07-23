// #B346 low: first-user-admin check (create -> count -> setAdmin) was a
// classic TOCTOU under READ COMMITTED — two concurrent registrations could
// each see count===1 before the other's insert committed, both becoming admin.
// Serialize the critical section with a Postgres advisory lock.
const pool = require('../config/database').default;

const LOCK_KEY = 872634871;

async function withRegistrationLock(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [LOCK_KEY]);
    const result = await fn();
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { withRegistrationLock };
