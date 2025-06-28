const crypto = require("crypto");

// UUID v4
function generateUUID() {
  return crypto.randomUUID(); // Node 16+
}

// Unix timestamp in seconds
function now() {
  return Math.floor(Date.now() / 1000);
}

// SHA-256 hex hash (for IP/device/fingerprint hashing)
function hash(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

// Base64URL encode/decode helpers
function base64urlEncode(input) {
  return Buffer.from(input).toString("base64url");
}

function base64urlDecode(input) {
  return Buffer.from(input, "base64url").toString("utf8");
}

module.exports = {
  generateUUID,
  now,
  hash,
  base64urlEncode,
  base64urlDecode,
};
