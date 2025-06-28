const crypto = require("crypto");
require("dotenv").config();

const { STK_ENC_KEY, STK_HMAC_KEY } = process.env;

if (!STK_ENC_KEY || !STK_HMAC_KEY) {
  throw new Error(
    "Missing STK_ENC_KEY or STK_HMAC_KEY in environment variables"
  );
}

const encKey = Buffer.from(STK_ENC_KEY, "hex");
const hmacKey = Buffer.from(STK_HMAC_KEY, "hex");

function encrypt(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(plainText, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  // Format: iv(12) + tag(16) + encrypted data
  return Buffer.concat([iv, tag, encrypted]).toString("base64url");
}

function decrypt(cipherText) {
  const data = Buffer.from(cipherText, "base64url");
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const encrypted = data.slice(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", encKey, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

function sign(data) {
  return crypto.createHmac("sha512", hmacKey).update(data).digest("base64url");
}

function verifySignature(data, signature) {
  const expectedSig = sign(data);
  // Use timingSafeEqual to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(expectedSig),
    Buffer.from(signature)
  );
}

module.exports = {
  encrypt,
  decrypt,
  sign,
  verifySignature,
};
