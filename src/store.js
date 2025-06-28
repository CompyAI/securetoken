let store = {
  // Refresh token storage
  saveRefresh: async (refreshId, data) => {},
  isRefreshRevoked: async (refreshId) => false,
  revokeRefresh: async (refreshId) => {},

  // Session token storage (optional, if implementing session revocation)
  saveSession: async (sessionId, data) => {},
  isSessionRevoked: async (sessionId) => false,
  revokeSession: async (sessionId) => {},
};

function registerStore(customStore = {}) {
  store = {
    ...store,
    ...customStore, // override defaults with user-defined methods
  };
}

function getStore() {
  return store;
}

module.exports = {
  registerStore,
  getStore,
};
