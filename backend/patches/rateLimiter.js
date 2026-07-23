// #B346 medium: no rate limiting anywhere (no express-rate-limit/helmet dependency
// at all). Minimal in-memory fixed-window limiter, no new dependency.
const WINDOW_MS = 15 * 60 * 1000;
const MAX_REQUESTS = 300;
const buckets = new Map();

// Periodic sweep so the Map doesn't grow unbounded over long uptimes.
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    if (now - bucket.start > WINDOW_MS) buckets.delete(key);
  }
}, WINDOW_MS).unref();

function rateLimit(req, res, next) {
  const key = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket || now - bucket.start > WINDOW_MS) {
    bucket = { start: now, count: 0 };
    buckets.set(key, bucket);
  }
  bucket.count++;
  if (bucket.count > MAX_REQUESTS) {
    res.status(429).json({ error: 'Too many requests, please try again later.' });
    return;
  }
  next();
}

module.exports = { rateLimit };
