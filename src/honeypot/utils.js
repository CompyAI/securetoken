function buildSourceKey(ip, ua) {
  return `${ip}|${ua}`;
}

module.exports = { buildSourceKey };
