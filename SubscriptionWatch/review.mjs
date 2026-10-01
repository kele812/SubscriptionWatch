import { createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { defaults, transaction } from "./model.mjs";
import { activeBlacklistedIP, blacklistSettings } from "./blacklist.mjs";

const WINDOW = 60 * 60 * 1000;
const LIMIT = 3;

function reply(res, status, data, secret = null) {
  const raw = JSON.stringify(data);
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };
  if (secret)
    headers["X-Watch-Decision-Signature"] = createHmac("sha256", secret)
      .update(raw)
      .digest("hex");
  res.writeHead(status, headers);
  res.end(raw);
}

function decide(db, panel, event, geo, now) {
  const rules = { ...defaults, ...JSON.parse(panel.rules) };
  const subject = db
    .prepare("SELECT white,dismissed FROM subjects WHERE panel=? AND uid=?")
    .get(panel.id, event.user_id);
  if (subject?.white) return [];
  const place = geo?.lookup(event.ip) || {};
  if (
    rules.ipWhitelist.includes(event.ip) ||
    (rules.cloudflareExempt && /\bcloudflare\b/i.test(place.organization || ""))
  )
    return [];
  const codes = [];
  if (
    rules.reviewBlockUa &&
    rules.uaEnabled &&
    !rules.uaKeywords.some((word) =>
      event.ua.toLowerCase().includes(word.toLowerCase()),
    )
  )
    codes.push("ua");
  if (
    rules.reviewBlockCloud &&
    rules.dcEnabled &&
    rules.dcKeywords.some((word) =>
      (place.organization || "").toLowerCase().includes(word.toLowerCase()),
    )
  )
    codes.push("cloud");
  if (
    rules.reviewBlockBlacklist &&
    blacklistSettings(db).enabled &&
    activeBlacklistedIP(db, event.ip, now)
  )
    codes.push("blacklist");
  const country = place.countryCode || "";
  for (const [active, region, prefix, inRegion] of [
    [
      rules.reviewBlockChina && rules.chinaEnabled,
      "CN",
      "cn",
      country === "CN",
    ],
    [
      rules.reviewBlockForeign && rules.foreignEnabled,
      "foreign",
      "foreign",
      /^[A-Z]{2}$/.test(country) && !["CN", "XX", "ZZ"].includes(country),
    ],
  ]) {
    if (!active || !inRegion) continue;
    for (const [length, suffix] of [
      ["Short", "60"],
      ["Long", "720"],
    ]) {
      const minutes = rules[`${prefix}${length}Minutes`];
      const rows = db
        .prepare(
          "SELECT DISTINCT ip FROM samples WHERE panel=? AND uid=? AND ts>? AND ts<=? AND status BETWEEN 200 AND 299 AND COALESCE(delivered,1)<>0",
        )
        .all(
          panel.id,
          event.user_id,
          Math.max(now - minutes * 60000, subject?.dismissed || 0),
          now,
        );
      const recent = db
        .prepare(
          "SELECT DISTINCT ip FROM review_decisions WHERE panel=? AND uid=? AND denied=0 AND ts>? AND ts<=? AND (delivered=1 OR (delivered IS NULL AND ts>?))",
        )
        .all(
          panel.id,
          event.user_id,
          Math.max(now - minutes * 60000, subject?.dismissed || 0),
          now,
          now - 180000,
        );
      const ips = new Set([event.ip]);
      for (const row of [...rows, ...recent]) {
        const location = geo?.lookup(row.ip) || {};
        const rowCountry = location.countryCode || "";
        const sameRegion =
          region === "CN"
            ? rowCountry === "CN"
            : /^[A-Z]{2}$/.test(rowCountry) &&
              !["CN", "XX", "ZZ"].includes(rowCountry);
        if (
          sameRegion &&
          !rules.ipWhitelist.includes(row.ip) &&
          !(
            rules.cloudflareExempt &&
            /\bcloudflare\b/i.test(location.organization || "")
          )
        )
          ips.add(row.ip);
      }
      if (ips.size > rules[`${prefix}${length}Limit`])
        codes.push(prefix + suffix);
    }
  }
  return codes;
}

export function markRepeatedDenial(db, panel, event, now) {
  const subject = db
    .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
    .get(panel.id, event.user_id);
  if (subject?.white) return;
  const from = Math.max(now - WINDOW, subject?.dismissed || 0);
  const count = db
    .prepare(
      "SELECT COUNT(*) total FROM review_decisions WHERE panel=? AND uid=? AND enforced=1 AND ts>? AND ts<=?",
    )
    .get(panel.id, event.user_id, from, now).total;
  if (count < LIMIT) return;
  const evidence = db
    .prepare(
      "SELECT ts,ip,ua FROM review_decisions WHERE panel=? AND uid=? AND enforced=1 AND ts>? AND ts<=? ORDER BY ts DESC LIMIT 100",
    )
    .all(panel.id, event.user_id, from, now);
  const old = db
    .prepare("SELECT * FROM risks WHERE panel=? AND uid=?")
    .get(panel.id, event.user_id);
  const reasons = old?.active ? JSON.parse(old.reasons) : [];
  if (reasons.some((reason) => reason.code === "review-denials")) return;
  reasons.push({
    code: "review-denials",
    label: "60 分钟内订阅审核拒绝 3 次",
    count,
    threshold: LIMIT,
    windowMinutes: 60,
    windowStart: now - WINDOW,
    windowEnd: now,
    ips: [...new Set(evidence.map((row) => row.ip))],
    evidence: evidence.map((row) => ({
      time: row.ts,
      ip: row.ip,
      ua: row.ua,
      included: true,
    })),
    ruleVersion: "3.9.9",
  });
  db.prepare(
    "INSERT INTO risks(panel,uid,active,started,updated,reasons) VALUES(?,?,1,?,?,?) ON CONFLICT(panel,uid) DO UPDATE SET active=1,started=excluded.started,updated=excluded.updated,reasons=excluded.reasons",
  ).run(
    panel.id,
    event.user_id,
    old?.active ? old.started : now,
    now,
    JSON.stringify(reasons),
  );
  db.prepare(
    "INSERT INTO risk_history(panel,uid,email,ts,action,reasons) VALUES(?,?,?,?,?,?)",
  ).run(
    panel.id,
    event.user_id,
    event.email,
    now,
    old?.active ? "风险原因变化" : "标记风险",
    JSON.stringify(reasons),
  );
  if (panel.notify)
    db.prepare(
      "INSERT INTO outbox(account,panel,uid,payload,created) VALUES(?,?,?,?,?)",
    ).run(
      panel.owner,
      panel.id,
      event.user_id,
      JSON.stringify({
        panel: panel.name,
        uid: event.user_id,
        email: event.email,
        reasons,
      }),
      now,
    );
}

export async function receiveReview(req, res, { db, decrypt, geo }) {
  const panel = db
    .prepare(
      "SELECT p.* FROM panels p JOIN accounts a ON a.id=p.owner WHERE p.public_id=? AND a.disabled=0",
    )
    .get(String(req.headers["x-watch-panel"] || ""));
  const timestamp = String(req.headers["x-watch-timestamp"] || "");
  const signature = String(req.headers["x-watch-signature"] || "");
  if (
    !panel ||
    !/^\d{10}$/.test(timestamp) ||
    Math.abs(Date.now() / 1000 - Number(timestamp)) > 300 ||
    !/^[a-f0-9]{64}$/.test(signature)
  )
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
  const expected = createHmac("sha256", secret)
    .update(timestamp + "\n")
    .update(raw)
    .digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, "hex")))
    return reply(res, 401, { error: "invalid signature" });
  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    return reply(res, 400, { error: "invalid JSON" });
  }
  const now = Date.now();
  if (
    event?.schema !== 1 ||
    !/^[a-f0-9]{32}$/.test(event.event_id || "") ||
    !Number.isSafeInteger(event.ts) ||
    Math.abs(now - event.ts) > 300000 ||
    !Number.isSafeInteger(event.user_id) ||
    event.user_id < 1 ||
    typeof event.email !== "string" ||
    !event.email ||
    event.email.length > 254 ||
    typeof event.ua !== "string" ||
    event.ua.length > 1024 ||
    !isIP(event.ip)
  )
    return reply(res, 422, { error: "invalid event" });
  const decision = transaction(db, () => {
    const prior = db
      .prepare(
        "SELECT denied,codes FROM review_decisions WHERE panel=? AND event_id=?",
      )
      .get(panel.id, event.event_id);
    if (prior) return { allow: !prior.denied, codes: JSON.parse(prior.codes) };
    db.prepare(
      "INSERT INTO subjects(panel,uid,email,verified) VALUES(?,?,?,1) ON CONFLICT(panel,uid) DO UPDATE SET white=CASE WHEN subjects.email=excluded.email THEN subjects.white ELSE 0 END,email=excluded.email,verified=1",
    ).run(panel.id, event.user_id, event.email);
    const codes = decide(db, panel, event, geo, now);
    db.prepare(
      "INSERT INTO review_decisions(panel,event_id,uid,email,ip,ua,ts,denied,codes) VALUES(?,?,?,?,?,?,?,?,?)",
    ).run(
      panel.id,
      event.event_id,
      event.user_id,
      event.email,
      event.ip,
      event.ua,
      now,
      Number(codes.length > 0),
      JSON.stringify(codes),
    );
    return { allow: codes.length === 0, codes };
  });
  return reply(res, 200, { ...decision, event_id: event.event_id }, secret);
}
