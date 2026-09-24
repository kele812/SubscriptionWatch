import { defaults } from "./model.mjs";
import { activeBlacklistedIP, blacklistSettings } from "./blacklist.mjs";
// Only fresh accepted events may create UA/cloud signals; maintenance never replays them.
export function assess(
  db,
  panel,
  subject,
  now,
  geo,
  fresh = [],
  onChinaTrigger,
) {
  const r = { ...defaults, ...JSON.parse(panel.rules) };
  if (subject.white) return [];
  const blacklist = blacklistSettings(db),
    blacklistCache = new Map();
  const blackEntry = (ip) => {
    if (!blacklistCache.has(ip))
      blacklistCache.set(ip, activeBlacklistedIP(db, ip, now));
    return blacklistCache.get(ip);
  };
  const blackHit = (e) => {
    const entry = blackEntry(e.ip),
      ts = e.ts ?? e.time;
    return success(e) && entry && ts > entry.added && ts <= now;
  };
  const decorate = (e) => ({ ...e, geo: geo?.lookup(e.ip) || {} });
  const exempt = (e) =>
    r.ipWhitelist.includes(e.ip)
      ? "IP 白名单"
      : r.cloudflareExempt && /\bcloudflare\b/i.test(e.geo.organization || "")
        ? "Cloudflare 豁免"
        : "";
  const cloud = (e) =>
    r.dcKeywords.some((k) =>
      (e.geo.organization || "").toLowerCase().includes(k.toLowerCase()),
    );
  const badUa = (e) =>
    !r.uaKeywords.some((k) => e.ua.toLowerCase().includes(k.toLowerCase()));
  const success = (e) =>
    e.status >= 200 &&
    e.status < 300 &&
    e.delivered !== 0 &&
    e.delivered !== false;
  const observed = db
    .prepare(
      "SELECT ts,ip,ua,status,delivered FROM samples WHERE panel=? AND uid=? AND ts>? AND ts<=? ORDER BY ts DESC,id DESC",
    )
    .all(
      panel.id,
      subject.uid,
      Math.max(
        subject.dismissed,
        now -
          Math.max(
            r.cnShortMinutes,
            r.cnLongMinutes,
            r.foreignShortMinutes,
            r.foreignLongMinutes,
          ) *
            60000,
      ),
      now,
    )
    .map(decorate);
  const incoming = fresh
    .filter((e) => e.ts > subject.dismissed)
    .sort((a, b) => b.ts - a.ts)
    .map(decorate);
  const reasons = [],
    unique = (rows) => [...new Set(rows.map((e) => e.ip))];
  function add(code, label, rows, all, minutes, threshold, why) {
    const selected = new Set(rows),
      groups = new Map(),
      latest = new Map();
    for (const e of rows)
      latest.set(e.ip, Math.max(latest.get(e.ip) || 0, e.ts));
    for (const e of all)
      if (!selected.has(e)) {
        const reason = exempt(e) || why(e);
        if (!groups.has(reason)) groups.set(reason, []);
        groups.get(reason).push(e);
      }
    const pairs = new Map();
    for (const e of [...rows, ...all.filter((e) => !selected.has(e))]) {
      const key = JSON.stringify([
        e.ip,
        e.ua,
        selected.has(e),
        selected.has(e) ? "" : exempt(e) || why(e),
      ]);
      if (!pairs.has(key)) pairs.set(key, e);
    }
    reasons.push({
      code,
      label,
      count: minutes ? unique(rows).length : rows.length,
      threshold,
      ruleVersion: "3.8.2",
      ruleSnapshot: r,
      windowMinutes: minutes,
      windowStart: minutes
        ? now - minutes * 60000
        : Math.min(...all.map((e) => e.ts)),
      windowEnd: now,
      expires: minutes
        ? [...latest.values()].sort((a, b) => b - a)[threshold - 1] +
          minutes * 60000
        : null,
      ips: unique(rows).slice(0, 100),
      accounting: {
        totalIps: unique(all).length,
        totalRequests: all.length,
        includedIps: unique(rows).length,
        includedRequests: rows.length,
        mergedRequests: 0,
        unit: minutes ? "个不同 IP" : "次",
        exclusions: [...groups].map(([reason, entries]) => ({
          reason,
          requests: entries.length,
          ipCount: unique(entries).length,
          ips: unique(entries).slice(0, 100),
        })),
      },
      evidence: [...pairs.values()].slice(0, 100).map((e) => ({
        time: e.ts,
        ip: e.ip,
        ua: e.ua,
        status: e.status,
        geo: e.geo,
        included: selected.has(e),
        exclusion: selected.has(e) ? "" : exempt(e) || why(e),
        ...(code === "blacklist" && selected.has(e)
          ? {
              blacklistSourcePanel: blackEntry(e.ip).source_name,
              blacklistSourceUser: blackEntry(e.ip).source_uid,
              blacklistAdded: blackEntry(e.ip).added,
              blacklistExpires: blackEntry(e.ip).expires,
            }
          : {}),
      })),
      evidenceLimited: pairs.size > 100,
      evidenceCount: pairs.size,
    });
  }
  for (const [enabled, code, label, predicate, why] of [
    [
      blacklist.enabled,
      "blacklist",
      "黑名单 IP 获取订阅",
      blackHit,
      (e) =>
        !success(e) ? "请求未成功" : "未命中有效黑名单或请求早于入名单时间",
    ],
    [
      r.uaEnabled,
      "ua",
      "非指定客户端获取订阅",
      (e) => success(e) && badUa(e),
      (e) => (!success(e) ? "未确认返回订阅内容" : "UA 符合允许关键词"),
    ],
    [
      r.dcEnabled,
      "cloud",
      "云服务器 IP 获取订阅",
      (e) => success(e) && cloud(e),
      (e) => (!success(e) ? "请求未成功" : "未匹配云厂商关键词"),
    ],
  ]) {
    if (!enabled) continue;
    const rows = incoming.filter((e) => !exempt(e) && predicate(e));
    if (rows.length) add(code, label, rows, incoming, null, 1, why);
    else {
      const saved = db
        .prepare(
          "SELECT reasons FROM risks WHERE panel=? AND uid=? AND active=1",
        )
        .get(panel.id, subject.uid);
      const old =
        saved && JSON.parse(saved.reasons).find((e) => e.code === code);
      if (
        old &&
        (old.evidence || []).some(
          (e) =>
            e.included !== false &&
            !exempt(decorate(e)) &&
            predicate(decorate(e)),
        )
      )
        reasons.push(old);
    }
  }
  for (const [enabled, code, label, isRegion] of [
    [
      r.chinaEnabled,
      "cn",
      "多个中国大陆 IP 获取订阅",
      (e) => e.geo.countryCode === "CN",
    ],
    [
      r.foreignEnabled,
      "foreign",
      "多个非中国大陆 IP 获取订阅",
      (e) =>
        /^[A-Z]{2}$/.test(e.geo.countryCode || "") &&
        !["CN", "XX", "ZZ"].includes(e.geo.countryCode),
    ],
  ]) {
    if (!enabled) continue;
    for (const [w, suffix] of [
      ["Short", "60"],
      ["Long", "720"],
    ]) {
      const minutes = r[code + w + "Minutes"],
        threshold = r[code + w + "Limit"] + 1;
      const all = observed.filter((e) => e.ts > now - minutes * 60000),
        rows = all.filter((e) => !exempt(e) && success(e) && isRegion(e));
      if (unique(rows).length >= threshold) {
        add(`${code}${suffix}`, label, rows, all, minutes, threshold, (e) =>
          !success(e)
            ? "请求未成功或状态未知"
            : !e.geo.countryCode || ["XX", "ZZ"].includes(e.geo.countryCode)
              ? "归属未知"
              : "不属于本条规则的地域",
        );
        if (
          code === "cn" &&
          incoming.some((e) =>
            rows.some(
              (x) =>
                x.ip === e.ip &&
                x.ts === e.ts &&
                x.ua === e.ua &&
                x.status === e.status,
            ),
          )
        )
          onChinaTrigger?.(rows);
      }
    }
  }
  return reasons;
}
