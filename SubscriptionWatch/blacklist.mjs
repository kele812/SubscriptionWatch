import { isIP } from "node:net";
import { defaults, getConfig, setConfig } from "./model.mjs";

const DAY = 86400000;
export const PERMANENT = Number.MAX_SAFE_INTEGER;
export function blacklistSettings(db) {
  const saved = getConfig(db, "sharedIpBlacklist") || {};
  return {
    enabled: true,
    recording: saved.enabled ?? true,
    days: 7,
    ...saved,
    ...(saved.days === 0 ? { days: 999 } : {}),
  };
}
export function activeBlacklistedIP(db, ip, now) {
  return db
    .prepare(
      "SELECT * FROM ip_blacklist WHERE ip=? AND removed_at=0 AND expires>?",
    )
    .get(ip, now);
}
// Latest source-event time controls expiry. Maintenance and replay cannot renew it.
export function collectBlacklistedIPs(db, panel, uid, rows, now) {
  const settings = blacklistSettings(db);
  if (!settings.recording) return 0;
  const latest = new Map();
  for (const e of rows) {
    if (
      !isIP(e.ip) ||
      !Number.isSafeInteger(e.ts) ||
      e.ts <= 0 ||
      e.ts > now ||
      (settings.days !== 999 && e.ts + settings.days * DAY <= now)
    )
      continue;
    if (!latest.has(e.ip) || latest.get(e.ip).ts < e.ts) latest.set(e.ip, e);
  }
  const insert =
    db.prepare(`INSERT INTO ip_blacklist(ip,source_panel,source_name,source_uid,source_ts,added,expires,removed_at)
    VALUES(?,?,?,?,?,?,?,0) ON CONFLICT(ip) DO UPDATE SET
    source_panel=excluded.source_panel,source_name=excluded.source_name,source_uid=excluded.source_uid,source_ts=excluded.source_ts,
    added=CASE WHEN ip_blacklist.removed_at>0 OR ip_blacklist.expires<=? THEN excluded.added ELSE ip_blacklist.added END,
    expires=excluded.expires,removed_at=0,
    reviewed_at=CASE WHEN ip_blacklist.removed_at>0 OR ip_blacklist.expires<=? THEN 0 ELSE ip_blacklist.reviewed_at END,
    reviewed_by=CASE WHEN ip_blacklist.removed_at>0 OR ip_blacklist.expires<=? THEN '' ELSE ip_blacklist.reviewed_by END
    WHERE excluded.source_ts>ip_blacklist.source_ts AND excluded.source_ts>ip_blacklist.removed_at`);
  let changed = 0;
  for (const e of latest.values())
    changed += insert.run(
      e.ip,
      panel.id,
      panel.name,
      uid,
      e.ts,
      now,
      settings.days === 999 ? PERMANENT : e.ts + settings.days * DAY,
      now,
      now,
      now,
    ).changes;
  return changed;
}
export function configureBlacklist(db, b) {
  if (
    typeof b.enabled !== "boolean" ||
    typeof b.recording !== "boolean" ||
    !Number.isInteger(b.days) ||
    b.days < 1 ||
    b.days > 999
  )
    throw Error(
      "黑名单保留天数须为1～999天，999为永久，记录和规则开关须为布尔值",
    );
  const previous = blacklistSettings(db);
  setConfig(db, "sharedIpBlacklist", {
    enabled: b.enabled,
    recording: b.recording,
    days: b.days,
  });
  // Apply shorter retention to existing entries, but never revive expired IPs.
  if (b.days === 999)
    db.prepare(
      "UPDATE ip_blacklist SET expires=? WHERE removed_at=0 AND expires>?",
    ).run(PERMANENT, Date.now());
  else if (previous.days === 999 || b.days < previous.days)
    db.prepare(
      "UPDATE ip_blacklist SET expires=MIN(expires,source_ts+?) WHERE removed_at=0",
    ).run(b.days * DAY);
}
export function removeBlacklistedIP(db, ip, now = Date.now()) {
  if (typeof ip !== "string" || !isIP(ip)) throw Error("请输入有效IP");
  db.prepare(
    "UPDATE ip_blacklist SET removed_at=?,expires=MIN(expires,?) WHERE ip=?",
  ).run(now, now, ip);
}
export function reviewBlacklistedIP(db, ip, username, now = Date.now()) {
  if (typeof ip !== "string" || !isIP(ip)) throw Error("请输入有效IP");
  if (typeof username !== "string" || !username.trim())
    throw Error("复核账号无效");
  const result = db
    .prepare(
      "UPDATE ip_blacklist SET reviewed_at=?,reviewed_by=? WHERE ip=? AND removed_at=0 AND expires>?",
    )
    .run(now, username, ip, now);
  if (!result.changes) throw Error("该IP已不在有效黑名单中，请刷新后重试");
}
export function blacklistRows(db, q, now = Date.now()) {
  const search = (q.get("ip") || "").trim();
  if (search && !isIP(search)) throw Error("请填写完整IP地址查询");
  const page = Math.max(1, Math.min(1000000, Number(q.get("page")) || 1));
  const removed = q.get("state") === "removed";
  const where =
    (removed ? "removed_at>0" : "removed_at=0 AND expires>?") +
    (search ? " AND ip=?" : "");
  const args = removed
    ? search
      ? [search]
      : []
    : search
      ? [now, search]
      : [now];
  return {
    settings: blacklistSettings(db),
    page,
    total: db
      .prepare(`SELECT COUNT(*) n FROM ip_blacklist WHERE ${where}`)
      .get(...args).n,
    rows: db
      .prepare(
        `SELECT * FROM ip_blacklist WHERE ${where} ORDER BY ${removed ? "removed_at" : "added"} DESC,ip LIMIT 100 OFFSET ?`,
      )
      .all(...args, (Math.floor(page) - 1) * 100),
  };
}
export function cleanBlacklist(db, now) {
  // Retain removal tombstones: permanent mode can import arbitrarily old evidence.
  db.prepare(
    "DELETE FROM ip_blacklist WHERE ip IN (SELECT ip FROM ip_blacklist WHERE removed_at=0 AND expires<=? LIMIT 10000)",
  ).run(now);
}
export function importBlacklistHistory(db, before = 0, now = Date.now(), geo) {
  if (!Number.isSafeInteger(before) || before < 0) throw Error("历史游标无效");
  const settings = blacklistSettings(db);
  if (!settings.recording) throw Error("请先开启记录 IP 黑名单");
  const history = db
    .prepare(
      "SELECT h.*,p.name,p.rules FROM risk_history h JOIN panels p ON p.id=h.panel WHERE h.id<? AND h.ts>? AND h.action IN ('标记风险','风险原因变化') ORDER BY h.id DESC LIMIT 200",
    )
    .all(
      before || Number.MAX_SAFE_INTEGER,
      settings.days === 999 ? 0 : now - settings.days * DAY,
    );
  let changed = 0,
    limited = 0;
  for (const h of history) {
    const subject = db
      .prepare("SELECT white FROM subjects WHERE panel=? AND uid=?")
      .get(h.panel, h.uid);
    if (!subject || subject.white) continue;
    const rules = { ...defaults, ...JSON.parse(h.rules) };
    const rows = [];
    for (const reason of JSON.parse(h.reasons)) {
      if (!["cn60", "cn720"].includes(reason.code)) continue;
      if (reason.evidenceLimited) limited++;
      for (const e of reason.evidence || []) {
        if (
          e.included !== true ||
          e.geo?.countryCode !== "CN" ||
          !(e.status >= 200 && e.status < 300) ||
          rules.ipWhitelist.includes(e.ip)
        )
          continue;
        const g = {
          organization: geo?.lookup(e.ip)?.organization || e.geo.organization,
        };
        if (
          rules.cloudflareExempt &&
          /\bcloudflare\b/i.test(g.organization || "")
        )
          continue;
        rows.push({ ip: e.ip, ts: e.time });
      }
    }
    changed += collectBlacklistedIPs(
      db,
      { id: h.panel, name: h.name },
      h.uid,
      rows,
      now,
    );
  }
  return {
    changed,
    scanned: history.length,
    limited,
    next: history.length === 200 ? history.at(-1).id : null,
  };
}
