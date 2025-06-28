const refreshStore = new Map();
const sessionStore = new Map();

module.exports = {
  // Refresh token operations
  async saveRefresh(refreshId, data) {
    refreshStore.set(refreshId, data);
  },

  async isRefreshRevoked(refreshId) {
    return !refreshStore.has(refreshId);
  },

  async revokeRefresh(refreshId) {
    refreshStore.delete(refreshId);
  },

  // Session operations (optional)
  async saveSession(sessionId, data) {
    sessionStore.set(sessionId, data);
  },

  async isSessionRevoked(sessionId) {
    return !sessionStore.has(sessionId);
  },

  async revokeSession(sessionId) {
    sessionStore.delete(sessionId);
  },
};
