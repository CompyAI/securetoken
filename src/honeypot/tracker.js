// Tracks failed validation attempts per IP + User-Agent combo
const failMap = new Map();

/**
 * Record a failed attempt.
 * @param {string} ip
 * @param {string} ua
 * @returns {object} updated fail data
 */
function trackFail(ip, ua) {
  const key = `${ip}|${ua}`;
  const entry = failMap.get(key) || { count: 0, lastFail: Date.now() };
  entry.count += 1;
  entry.lastFail = Date.now();
  failMap.set(key, entry);
  return { ...entry };
}

/**
 * Check if honeypot should trigger.
 * @param {string} ip
 * @param {string} ua
 * @param {number} threshold
 * @returns {boolean}
 */
function shouldHoneypot(ip, ua, threshold) {
  const entry = failMap.get(`${ip}|${ua}`);
  return !!entry && entry.count >= threshold;
}

/**
 * Reset fail tracking for a source.
 * @param {string} ip
 * @param {string} ua
 */
function resetFail(ip, ua) {
  failMap.delete(`${ip}|${ua}`);
}

module.exports = { trackFail, shouldHoneypot, resetFail };
