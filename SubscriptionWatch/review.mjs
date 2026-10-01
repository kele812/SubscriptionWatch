import { createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { defaults, transaction } from "./model.mjs";
import {
  activeBlacklistedIP,
  blacklistSettings,
  collectBlacklistedIPs,
} from "./blacklist.mjs";

const DAY = 86400000;

function reply(res, status, data, secret = null) {
  const raw = JSON.stringify(data);
  const headers = { "Content-Type": "application/json", "Cache-Control": "no-store" };
  if (secret)
    headers["X-Watch-Decision-Signature"] = createHmac("sha256", secret)
      .update(raw)
      .digest("hex");
  res.writeHead(status, headers);
  res.end(raw);
}

function markRisk(db, panel, event, reason, now) {
  const subject = db.prepare("SELECT white FROM subjects WHERE panel=? AND uid=?")
    .get(panel.id, event.user_id);
  if (subject?.white) return;
  const old = db.prepare("SELECT * FROM risks WHERE panel=? AND uid=?")
    .get(panel.id, event.user_id);
  const reasons = old?.active ? JSON.parse(old.reasons) : [];
  if (reasons.some((item) => item.code === reason.code)) return;
  reasons.push(reason);
  db.prepare(
    "INSERT INTO risks(panel,uid,active,started,updated,reasons) VALUES(?,?,1,?,?,?) ON CONFLICT(panel,uid) DO UPDATE SET active=1,started=excluded.started,updated=excluded.updated,reasons=excluded.reasons",
  ).run(panel.id, event.user_id, old?.active ? old.started : now, now, JSON.stringify(reasons));
  db.prepare("INSERT INTO risk_history(panel,uid,email,ts,action,reasons) VALUES(?,?,?,?,?,?)")
    .run(panel.id, event.user_id, event.email, now, old?.active ? "风险原因变化" : "标记风险", JSON.stringify(reasons));
  if (panel.notify)
    db.prepare("INSERT INTO outbox(account,panel,uid,payload,created) VALUES(?,?,?,?,?)")
      .run(panel.owner, panel.id, event.user_id,
        JSON.stringify({ panel: panel.name, uid: event.user_id, email: event.email, reasons }), now);
}

function reason(code, label, rows, threshold, minutes, now, count = rows.length) {
  return {
    code, label, count, threshold,
    windowMinutes: minutes,
    windowStart: minutes ? now - minutes * 60000 : now,
    windowEnd: now,
    ips: [...new Set(rows.map((row) => row.ip))],
    evidence: rows.slice(0, 100).map((row) => ({
      time: row.ts, ip: row.ip, ua: row.ua, geo: row.geo || {}, included: true,
    })),
    evidenceLimited: rows.length > 100,
    evidenceCount: count,
    ruleVersion: "3.10.0",
  };
}

function regionRows(db, panel, event, geo, rules, subject, now, minutes, match) {
  const from = Math.max(now - minutes * 60000, subject?.dismissed || 0);
  const samples = db.prepare(
    "SELECT ip,ua,MAX(ts) ts FROM samples WHERE panel=? AND uid=? AND ts>? AND ts<=? AND status BETWEEN 200 AND 299 AND COALESCE(delivered,1)<>0 GROUP BY ip,ua",
  ).all(panel.id, event.user_id, from, now);
  const reviewed = db.prepare(
    "SELECT ip,ua,MAX(ts) ts FROM review_decisions WHERE panel=? AND uid=? AND denied=0 AND ts>? AND ts<=? AND (delivered=1 OR (delivered IS NULL AND ts>?)) GROUP BY ip,ua",
  ).all(panel.id, event.user_id, from, now, now - 180000);
  const latest = new Map();
  for (const row of [...samples, ...reviewed, { ip: event.ip, ua: event.ua, ts: now }]) {
    const place = geo?.lookup(row.ip) || {};
    if (rules.ipWhitelist.includes(row.ip) ||
        (rules.cloudflareExempt && /\bcloudflare\b/i.test(place.organization || "")) ||
        !match(place.countryCode || "")) continue;
    if (!latest.has(row.ip) || latest.get(row.ip).ts < row.ts)
      latest.set(row.ip, { ...row, geo: place });
  }
  return [...latest.values()].sort((a, b) => b.ts - a.ts);
}

function cloudRows(db, panel, event, subject, geo, now, minutes) {
  const prior = db.prepare(
    "SELECT ip,ua,ts FROM review_decisions WHERE panel=? AND uid=? AND ts>? AND ts<=? AND EXISTS (SELECT 1 FROM json_each(review_decisions.codes) WHERE value='cloud') ORDER BY ts DESC",
  ).all(panel.id, event.user_id,
    Math.max(now - minutes * 60000, subject?.dismissed || 0), now);
  return [{ ip: event.ip, ua: event.ua, ts: now }, ...prior]
    .map((row) => ({ ...row, geo: geo?.lookup(row.ip) || {} }));
}

function requestCount(db, panel, event, now) {
  const reviewed = db.prepare(
    "SELECT COUNT(*) total FROM review_decisions WHERE panel=? AND uid=? AND ts>? AND ts<=? AND (delivered=1 OR enforced=1 OR (delivered IS NULL AND enforced IS NULL))",
  ).get(panel.id, event.user_id, now - DAY, now).total;
  const legacy = db.prepare(
    "SELECT COUNT(*) total FROM visits v WHERE v.panel=? AND v.uid=? AND v.ts>? AND v.ts<=? AND (v.delivered=1 OR v.status IN (302,403)) AND (v.event_id IS NULL OR NOT EXISTS (SELECT 1 FROM review_decisions d WHERE d.panel=v.panel AND d.event_id=v.event_id))",
  ).get(panel.id, event.user_id, now - DAY, now).total;
  return reviewed + legacy;
}

function decide(db, panel, event, geo, now) {
  const rules = { ...defaults, ...JSON.parse(panel.rules) };
  const subject = db.prepare("SELECT white,dismissed FROM subjects WHERE panel=? AND uid=?")
    .get(panel.id, event.user_id);
  const codes = [];
  if (requestCount(db, panel, event, now) >= rules.dailyLimit)
    codes.push("daily-limit");
  if (subject?.white) return { codes, redirect: rules.reviewRedirectUrl };
  const active = db.prepare("SELECT 1 FROM risks WHERE panel=? AND uid=? AND active=1")
    .get(panel.id, event.user_id);
  if (active) codes.push("active-risk");
  const place = geo?.lookup(event.ip) || {};
  const exempt = rules.ipWhitelist.includes(event.ip) ||
    (rules.cloudflareExempt && /\bcloudflare\b/i.test(place.organization || ""));
  if (exempt || active) return { codes, redirect: rules.reviewRedirectUrl };

  if (rules.uaEnabled && !rules.uaKeywords.some((word) =>
    event.ua.toLowerCase().includes(word.toLowerCase()))) {
    codes.push("ua");
    markRisk(db, panel, event,
      reason("ua", "非指定客户端获取订阅", [{ ...event, geo: place, ts: now }], 1, null, now), now);
  }
  if (rules.dcEnabled && rules.dcKeywords.some((word) =>
    (place.organization || "").toLowerCase().includes(word.toLowerCase()))) {
    codes.push("cloud");
    for (const [suffix, minutes, limit] of [
      ["Short", rules.cloudShortMinutes, rules.cloudShortLimit],
      ["Long", rules.cloudLongMinutes, rules.cloudLongLimit],
    ]) {
      const rows = cloudRows(db, panel, event, subject, geo, now, minutes);
      if (rows.length < limit) continue;
      markRisk(db, panel, event,
        reason("cloud" + suffix, "云服务器 IP 频繁获取订阅",
          rows, limit, minutes, now), now);
    }
  }
  if (rules.reviewBlockBlacklist && blacklistSettings(db).enabled &&
      activeBlacklistedIP(db, event.ip, now)) {
    codes.push("blacklist");
    markRisk(db, panel, event,
      reason("blacklist", "黑名单 IP 获取订阅", [{ ...event, geo: place, ts: now }], 1, null, now), now);
  }
  for (const [enabled, prefix, label, match] of [
    [rules.chinaEnabled, "cn", "多个中国大陆 IP 获取订阅", (country) => country === "CN"],
    [rules.foreignEnabled, "foreign", "多个非中国大陆 IP 获取订阅",
      (country) => /^[A-Z]{2}$/.test(country) && !["CN", "XX", "ZZ"].includes(country)],
  ]) {
    if (!enabled || !match(place.countryCode || "")) continue;
    for (const [suffix, minutes, limit] of [
      ["60", rules[`${prefix}ShortMinutes`], rules[`${prefix}ShortLimit`]],
      ["720", rules[`${prefix}LongMinutes`], rules[`${prefix}LongLimit`]],
    ]) {
      const rows = regionRows(db, panel, event, geo, rules, subject, now, minutes, match);
      if (rows.length <= limit) continue;
      codes.push(prefix + suffix);
      markRisk(db, panel, event,
        reason(prefix + suffix, label, rows, limit + 1, minutes, now), now);
      if (prefix === "cn") collectBlacklistedIPs(db, panel, event.user_id, rows, now);
    }
  }
  return { codes, redirect: rules.reviewRedirectUrl };
}

export async function receiveReview(req, res, { db, decrypt, geo }) {
  const publicId = String(req.headers["x-watch-panel"] || "");
  const panel = publicId
    ? db.prepare("SELECT p.* FROM panels p JOIN accounts a ON a.id=p.owner WHERE p.public_id=? AND a.disabled=0").get(publicId)
    : db.prepare("SELECT p.* FROM panels p JOIN accounts a ON a.id=p.owner WHERE p.legacy=1 AND a.disabled=0").get();
  const timestamp = String(req.headers["x-watch-timestamp"] || "");
  const signature = String(req.headers["x-watch-signature"] || "");
  if (!panel || !/^\d{10}$/.test(timestamp) ||
      Math.abs(Date.now() / 1000 - Number(timestamp)) > 300 ||
      !/^[a-f0-9]{64}$/.test(signature))
    return reply(res, 401, { error: "invalid signature or panel" });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 4096) return reply(res, 413, { error: "request too large" });
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const secret = decrypt(panel.secret);
  const expected = createHmac("sha256", secret).update(timestamp + "\n").update(raw).digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, "hex")))
    return reply(res, 401, { error: "invalid signature" });
  let event;
  try { event = JSON.parse(raw); } catch { return reply(res, 400, { error: "invalid JSON" }); }
  const now = Date.now();
  if (event?.schema !== 1 || !/^[a-f0-9]{32}$/.test(event.event_id || "") ||
      !Number.isSafeInteger(event.ts) || Math.abs(now - event.ts) > 300000 ||
      !Number.isSafeInteger(event.user_id) || event.user_id < 1 ||
      typeof event.email !== "string" || !event.email || event.email.length > 254 ||
      typeof event.ua !== "string" || event.ua.length > 1024 || !isIP(event.ip))
    return reply(res, 422, { error: "invalid event" });
  const decision = transaction(db, () => {
    const prior = db.prepare("SELECT denied,codes FROM review_decisions WHERE panel=? AND event_id=?")
      .get(panel.id, event.event_id);
    const redirect = { ...defaults, ...JSON.parse(panel.rules) }.reviewRedirectUrl;
    if (prior)
      return { allow: !prior.denied, codes: JSON.parse(prior.codes), redirect: prior.denied ? redirect : null };
    db.prepare(
      "INSERT INTO subjects(panel,uid,email,verified) VALUES(?,?,?,1) ON CONFLICT(panel,uid) DO UPDATE SET white=CASE WHEN subjects.email=excluded.email THEN subjects.white ELSE 0 END,email=excluded.email,verified=1",
    ).run(panel.id, event.user_id, event.email);
    const result = decide(db, panel, event, geo, now);
    db.prepare(
      "INSERT INTO review_decisions(panel,event_id,uid,email,ip,ua,ts,denied,codes) VALUES(?,?,?,?,?,?,?,?,?)",
    ).run(panel.id, event.event_id, event.user_id, event.email, event.ip, event.ua,
      now, Number(result.codes.length > 0), JSON.stringify(result.codes));
    return { allow: result.codes.length === 0, codes: result.codes,
      redirect: result.codes.length ? result.redirect : null };
  });
  return reply(res, 200, { ...decision, event_id: event.event_id }, secret);
}

