const crypto = require("crypto");
const tracker = require("./honeypot/tracker");
const decoy = require("./honeypot/decoy");

function createSecureTokenToolkit(config) {
  if (!config.encKey || !config.hmacKey) {
    throw new Error("encKey and hmacKey are required");
  }

  const encKey = Buffer.from(config.encKey, "hex");
  const hmacKey = Buffer.from(config.hmacKey, "hex");
  const honeypot = {
    enabled: false,
    failThreshold: 5,
    decoyPayload: {},
    slowResponses: false,
    ...config.honeypot,
  };
  const store = config.store || null;

  const sign = (data) =>
    crypto.createHmac("sha512", hmacKey).update(data).digest("base64url");
  const verifySig = (data, sig) => {
    const expected = sign(data);
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  };

  const encrypt = (str) => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", encKey, iv);
    const enc = Buffer.concat([c.update(str, "utf8"), c.final()]);
    const tag = c.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString("base64url");
  };

  const decrypt = (data) => {
    const buf = Buffer.from(data, "base64url");
    const c = crypto.createDecipheriv("aes-256-gcm", encKey, buf.slice(0, 12));
    c.setAuthTag(buf.slice(12, 28));
    return Buffer.concat([c.update(buf.slice(28)), c.final()]).toString("utf8");
  };

  async function createToken(payload, opts = {}) {
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + (opts.expiresIn || 900);
    const sid = crypto.randomUUID();

    const data = { ...payload, iat, exp, sessionId: sid };
    if (opts.bindIp && opts.ip) data.ip = opts.ip;
    if (opts.bindFingerprint && opts.fingerprint)
      data.fingerprint = opts.fingerprint;

    const enc = encrypt(JSON.stringify(data));
    const sig = sign(enc);
    const accessToken = `${enc}.${sig}`;

    let refreshToken = null;
    if (opts.refresh) {
      const rData = {
        sessionId: sid,
        iat,
        exp: iat + (opts.refreshExpiresIn || 2592000),
        type: "refresh",
      };
      if (opts.bindIp && opts.ip) rData.ip = opts.ip;
      if (opts.bindFingerprint && opts.fingerprint)
        rData.fingerprint = opts.fingerprint;

      const rEnc = encrypt(JSON.stringify(rData));
      const rSig = sign(rEnc);
      refreshToken = `${rEnc}.${rSig}`;

      if (store?.saveRefresh) await store.saveRefresh(sid, rData);
    }

    if (store?.saveSession) await store.saveSession(sid, data);

    return { accessToken, refreshToken };
  }

  async function verifyToken(token, opts = {}) {
    const [enc, sig] = token.split(".");
    if (!enc || !sig || !verifySig(enc, sig)) {
      if (honeypot.enabled) {
        const f = tracker.trackFail(opts.ip || "unknown", opts.ua || "unknown");
        if (
          tracker.shouldHoneypot(
            opts.ip || "unknown",
            opts.ua || "unknown",
            honeypot.failThreshold
          )
        ) {
          honeypot.onTriggered?.(f);
          if (honeypot.slowResponses)
            await new Promise((r) => setTimeout(r, 1000));
          return decoy.createDecoyToken(
            honeypot.decoyPayload,
            encKey.toString("hex")
          );
        }
      }
      throw new Error("Invalid token");
    }

    const payload = JSON.parse(decrypt(enc));

    if (honeypot.enabled) {
      if (payload.__decoy) honeypot.onDecoyUse?.(payload);
      else tracker.resetFail(opts.ip || "unknown", opts.ua || "unknown");
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) throw new Error("Expired");
    if (opts.checkIp && payload.ip && payload.ip !== opts.ip)
      throw new Error("IP mismatch");
    if (
      opts.checkFingerprint &&
      payload.fingerprint &&
      payload.fingerprint !== opts.fingerprint
    )
      throw new Error("Fingerprint mismatch");

    if (
      store?.isSessionRevoked &&
      (await store.isSessionRevoked(payload.sessionId))
    )
      throw new Error("Revoked session");
    if (
      payload.type === "refresh" &&
      store?.isRefreshRevoked &&
      (await store.isRefreshRevoked(payload.sessionId))
    )
      throw new Error("Revoked refresh");

    return payload;
  }

  async function refreshToken(old, opts = {}) {
    if (!store) throw new Error("Store required");
    const oldPayload = await verifyToken(old, opts);
    if (oldPayload.type !== "refresh") throw new Error("Not a refresh token");
    if (store.revokeRefresh) await store.revokeRefresh(oldPayload.sessionId);

    return createToken(
      { userId: oldPayload.userId },
      {
        ...opts,
        refresh: true,
        bindIp: !!oldPayload.ip,
        bindFingerprint: !!oldPayload.fingerprint,
        ip: oldPayload.ip,
        fingerprint: oldPayload.fingerprint,
      }
    );
  }

  return { createToken, verifyToken, refreshToken };
}

module.exports = { createSecureTokenToolkit };
