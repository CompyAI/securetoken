const { generateToken, verifyToken } = require("../crypto");

/**
 * Create a decoy token.
 * @param {object} payload - Claims for decoy
 * @param {string} key - Secret key
 * @returns {string} signed token
 */
function createDecoyToken(payload, key) {
  const decoyPayload = {
    ...payload,
    __decoy: true, // Mark this token internally
    issuedAt: Date.now(),
  };
  return generateToken(decoyPayload, key);
}

/**
 * Check if a token is a decoy.
 * @param {string} token
 * @param {string} key
 * @returns {boolean}
 */
function isDecoyToken(token, key) {
  try {
    const data = verifyToken(token, key);
    return !!data.__decoy;
  } catch {
    return false;
  }
}

module.exports = { createDecoyToken, isDecoyToken };
