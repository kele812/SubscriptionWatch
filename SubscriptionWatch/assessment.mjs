import { defaults } from "./model.mjs";

// Pure assessment: no database writes, notification or account-control effects.
export function assess(db, panel, subject, now, geo) {
  const r = { ...defaults, ...JSON.parse(panel.rules) };
  if (subject.white) return [];
  const horizon = Math.max(
    r.uaEnabled ? r.uaHours * 60 : 0,
    r.ipEnabled ? r.ipHours * 60 : 0,
    r.rateEnabled ? r.rateMinutes : 0,
    r.chinaEnabled ? r.chinaMinutes : 0,
    r.dcEnabled ? r.dcMinutes : 0,
    r.multiEnabled ? r.multiMinutes : 0,
    r.countryEnabled ? r.countryMinutes : 0,
    r.comboEnabled ? r.comboMinutes : 0,
  );
  const all = db
    .prepare(
      "SELECT ts,ip,ua,status FROM samples WHERE panel=? AND uid=? AND ts>? AND ts<=? ORDER BY ts DESC,id DESC",
    )
    .all(
      panel.id,
      subject.uid,
      Math.max(subject.dismissed, now - horizon * 60000),
      now,
    )
    .filter((e) => !r.ipWhitelist.includes(e.ip))
    .map((e) => ({ ...e, geo: geo?.lookup(e.ip) || {} }))
    .filter(
      (e) =>
        !(
          r.cloudflareExempt && /\bcloudflare\b/i.test(e.geo.organization || "")
        ),
    );
  const success = all.filter((e) => e.status >= 200 && e.status < 300);
  const within = (rows, minutes) =>
    rows.filter((e) => e.ts > now - minutes * 60000);
  const unique = (rows, key) =>
    [...new Map([...rows].reverse().map((e) => [key(e), e])).values()].sort(
      (a, b) => b.ts - a.ts,
    );
  const effective = (rows) => {
    const seen = new Set();
    return rows.filter((e) => {
      if (e.geo.countryCode !== "CN") return true;
      const key = JSON.stringify([e.ip, e.ua]);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };
  const china = (e) => !r.ownedIps.includes(e.ip) && e.geo.countryCode === "CN";
  const cloud = (e) =>
    !r.ownedIps.includes(e.ip) &&
    r.dcKeywords.some((k) =>
      (e.geo.organization || "").toLowerCase().includes(k.toLowerCase()),
    );
  const reasons = [];
  function add(
    code,
    label,
    minutes,
    threshold,
    count,
    expires,
    rows,
    extra = {},
  ) {
    // Keep representative IP/UA pairs first, so repeated downloads cannot hide other IPs.
    const pairs = unique(rows, (e) => JSON.stringify([e.ip, e.ua]));
    reasons.push({
      code,
      label,
      count,
      threshold,
      expires,
      windowMinutes: minutes,
      windowStart: now - minutes * 60000,
      windowEnd: now,
      ruleVersion: "3.7",
      ruleSnapshot: Object.fromEntries(
        Object.entries(r).filter(
          ([k]) => !["ipWhitelist", "ownedIps", "retentionDays"].includes(k),
        ),
      ),
      ips: [...new Set(rows.map((e) => e.ip))].slice(0, 100),
      evidence: pairs.slice(0, 100).map((e) => ({
        time: e.ts,
        ip: e.ip,
        ua: e.ua,
        status: e.status,
        geo: e.geo,
        owned: r.ownedIps.includes(e.ip),
      })),
      evidenceLimited: pairs.length > 100,
      evidenceCount: pairs.length,
      ...extra,
    });
  }
  if (r.uaEnabled) {
    const bad = within(all, r.uaHours * 60).filter(
      (e) =>
        !r.uaKeywords.some((k) => e.ua.toLowerCase().includes(k.toLowerCase())),
    );
    if (bad.length)
      add(
        "ua",
        "使用非指定客户端获取订阅",
        r.uaHours * 60,
        1,
        bad.length,
        bad[0].ts + r.uaHours * 3600000,
        bad,
        { ua: bad[0].ua, ip: bad[0].ip },
      );
  }
  for (const [code, enabled, minutes, limit, filter, label] of [
    [
      "ip",
      r.ipEnabled,
      r.ipHours * 60,
      r.ipLimit,
      () => true,
      "多个 IP 获取同一订阅",
    ],
    [
      "china",
      r.chinaEnabled,
      r.chinaMinutes,
      r.chinaLimit,
      china,
      "短时间内多个国内 IP 获取订阅",
    ],
    [
      "datacenter",
      r.dcEnabled,
      r.dcMinutes,
      r.dcLimit,
      cloud,
      "多个云服务器 IP 获取订阅",
    ],
  ]) {
    if (!enabled) continue;
    const rows = within(success, minutes).filter(filter),
      ips = unique(rows, (e) => e.ip);
    if (ips.length >= limit)
      add(
        code,
        label,
        minutes,
        limit,
        ips.length,
        ips[limit - 1].ts + minutes * 60000,
        rows,
      );
  }
  if (r.rateEnabled) {
    const rows = within(success, r.rateMinutes),
      hits = effective(rows);
    if (hits.length >= r.rateLimit)
      add(
        "rate",
        "频繁获取同一订阅",
        r.rateMinutes,
        r.rateLimit,
        hits.length,
        hits[r.rateLimit - 1].ts + r.rateMinutes * 60000,
        rows,
        {
          rawCount: rows.length,
          counting:
            "仅统计HTTP 2xx；同一个中国大陆IP且原始UA完全相同合并为1次；国外或未知IP逐次计数；白名单不计数",
        },
      );
  }
  if (r.multiEnabled) {
    const rows = within(success, r.multiMinutes),
      ips = unique(rows, (e) => e.ip),
      uas = unique(rows, (e) => e.ua);
    if (ips.length >= r.multiIpLimit && uas.length >= r.multiUaLimit)
      add(
        "multi",
        "多个 IP 和不同 UA 同时获取订阅",
        r.multiMinutes,
        r.multiIpLimit,
        ips.length,
        Math.min(ips[r.multiIpLimit - 1].ts, uas[r.multiUaLimit - 1].ts) +
          r.multiMinutes * 60000,
        rows,
        { uaCount: uas.length, uaThreshold: r.multiUaLimit },
      );
  }
  if (r.countryEnabled) {
    const rows = within(success, r.countryMinutes).filter(
      (e) =>
        !r.ownedIps.includes(e.ip) &&
        /^[A-Z]{2}$/.test(e.geo.countryCode || "") &&
        !["XX", "ZZ"].includes(e.geo.countryCode),
    );
    const countries = unique(rows, (e) => e.geo.countryCode);
    if (countries.length >= r.countryLimit)
      add(
        "country",
        "短时间跨多个国家或地区获取订阅",
        r.countryMinutes,
        r.countryLimit,
        countries.length,
        countries[r.countryLimit - 1].ts + r.countryMinutes * 60000,
        rows,
        { countries: countries.map((e) => e.geo.countryCode) },
      );
  }
  if (r.comboEnabled && r.rateEnabled) {
    // Both components use the SAME rolling window; older anomalies cannot combine.
    const rows = within(success, r.comboMinutes),
      hits = effective(rows);
    if (hits.length >= r.rateLimit)
      for (const [enabled, filter, limit, code, label] of [
        [
          r.chinaEnabled,
          china,
          r.chinaLimit,
          "comboChina",
          "国内多IP与频繁获取同时触发",
        ],
        [
          r.dcEnabled,
          cloud,
          r.dcLimit,
          "comboCloud",
          "云服务器多IP与频繁获取同时触发",
        ],
      ]) {
        const ips = unique(rows.filter(filter), (e) => e.ip);
        if (enabled && ips.length >= limit)
          add(
            code,
            label,
            r.comboMinutes,
            limit,
            ips.length,
            Math.min(ips[limit - 1].ts, hits[r.rateLimit - 1].ts) +
              r.comboMinutes * 60000,
            rows,
            { requestCount: hits.length, requestThreshold: r.rateLimit },
          );
      }
  }
  return reasons;
}
