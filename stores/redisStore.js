const Redis = require("ioredis");
const redis = new Redis({
  host: process.env.REDIS_HOST || "127.0.0.1",
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  db: process.env.REDIS_DB || 0,
});

const REFRESH_PREFIX = "stk:refresh:";
const SESSION_PREFIX = "stk:session:";

module.exports = {
  async saveRefresh(refreshId, data) {
    const key = REFRESH_PREFIX + refreshId;
    await redis.set(
      key,
      JSON.stringify(data),
      "EX",
      data.exp - Math.floor(Date.now() / 1000)
    );
  },

  async isRefreshRevoked(refreshId) {
    const key = REFRESH_PREFIX + refreshId;
    return !(await redis.exists(key));
  },

  async revokeRefresh(refreshId) {
    const key = REFRESH_PREFIX + refreshId;
    await redis.del(key);
  },

  async saveSession(sessionId, data) {
    const key = SESSION_PREFIX + sessionId;
    await redis.set(
      key,
      JSON.stringify(data),
      "EX",
      data.exp - Math.floor(Date.now() / 1000)
    );
  },

  async isSessionRevoked(sessionId) {
    const key = SESSION_PREFIX + sessionId;
    return !(await redis.exists(key));
  },

  async revokeSession(sessionId) {
    const key = SESSION_PREFIX + sessionId;
    await redis.del(key);
  },
};
