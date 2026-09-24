import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import {
  defaults,
  initialize,
  migrateRiskV33,
  migrateRequestEvidence,
} from "../model.mjs";
import { evaluate, resolveRisk } from "../risk.mjs";
import { assess } from "../assessment.mjs";
import {
  blacklistRows,
  blacklistSettings,
  collectBlacklistedIPs,
  configureBlacklist,
  removeBlacklistedIP,
  cleanBlacklist,
  importBlacklistHistory,
  PERMANENT,
} from "../blacklist.mjs";

const now = Date.now(),
  DAY = 86400000;
const geo = {
  lookup: (ip) => ({
    countryCode: ip.startsWith("1.") ? "CN" : "US",
    organization: ip.endsWith(".99") ? "Cloudflare" : "ISP",
  }),
};
function fixture(fn) {
  const db = new DatabaseSync(":memory:");
  try {
    initialize(db, (s) => s);
    migrateRiskV33(db);
    migrateRequestEvidence(db);
    db.exec(
      "CREATE TABLE risk_observation(panel INTEGER,uid INTEGER,since INTEGER)",
    );
    db.prepare(
      "INSERT INTO accounts(id,username,password_hash,admin,created) VALUES(1,'owner','hash',1,?)",
    ).run(now);
    const rules = { ...defaults, uaEnabled: false, dcEnabled: false };
    for (const id of [1, 2])
      db.prepare(
        "INSERT INTO panels(id,owner,name,public_id,secret,rules,notify) VALUES(?,1,?,?,?, ?,0)",
      ).run(id, `Panel ${id}`, `public${id}`, "secret", JSON.stringify(rules));
    const panel = (id) => db.prepare("SELECT * FROM panels WHERE id=?").get(id);
    const subject = (id, uid) =>
      db.prepare("SELECT * FROM subjects WHERE panel=? AND uid=?").get(id, uid);
    const add = (id, uid, rows, at = now) => {
      db.prepare(
        "INSERT OR IGNORE INTO subjects(panel,uid,email,verified) VALUES(?,?,?,1)",
      ).run(id, uid, `${uid}@example.com`);
      for (const e of rows)
        db.prepare(
          "INSERT INTO samples(panel,uid,ts,ip,ua,status) VALUES(?,?,?,?,?,?)",
        ).run(id, uid, e.ts, e.ip, e.ua, e.status);
      evaluate(db, panel(id), uid, at, geo, rows);
    };
    const reasons = (id, uid) =>
      JSON.parse(
        db
          .prepare("SELECT reasons FROM risks WHERE panel=? AND uid=?")
          .get(id, uid)?.reasons || "[]",
      );
    fn({ db, panel, subject, add, reasons });
  } finally {
    db.close();
  }
}
const row = (ip, ts = now - 1000, status = 200) => ({
  ip,
  ts,
  status,
  ua: "NetFlow",
});
const source = () => [1, 2, 3, 4].map((n) => row(`1.0.0.${n}`));

test("共享黑名单收集全部有效参与IP，跨面板新请求命中，旧请求/失败请求不标记", () =>
  fixture(({ db, panel, subject, add, reasons }) => {
    add(1, 1, [...source(), row("2.0.0.1"), row("1.0.0.5", now - 1000, 500)]);
    assert.equal(blacklistRows(db, new URLSearchParams(), now).total, 4);
    add(2, 8, [row("1.0.0.1", now + 1000)], now + 1000);
    assert.equal(reasons(2, 8)[0].code, "blacklist");
    assert.equal(reasons(2, 8)[0].evidence[0].blacklistSourcePanel, "Panel 1");
    add(2, 9, [row("1.0.0.1", now - 500)], now + 1000);
    assert.equal(reasons(2, 9).length, 0);
    add(2, 10, [row("1.0.0.1", now + 1000, 500)], now + 1000);
    assert.equal(reasons(2, 10).length, 0);
    resolveRisk(db, 2, 8, { now: now + 2000 });
    evaluate(db, panel(2), 8, now + 3000, geo);
    assert.equal(reasons(2, 8).length, 0);
    add(2, 8, [row("1.0.0.1", now + 4000)], now + 4000);
    assert.equal(reasons(2, 8)[0].code, "blacklist");
    assert.equal(
      blacklistRows(db, new URLSearchParams(), now + 4000).total,
      4,
      "命中本身不扩散名单",
    );
  }));

test("白名单和CF豁免优先，关闭全站开关停止命中及收集", () =>
  fixture(({ db, panel, subject, add, reasons }) => {
    add(1, 1, source());
    db.prepare("UPDATE panels SET rules=? WHERE id=2").run(
      JSON.stringify({
        ...defaults,
        uaEnabled: false,
        dcEnabled: false,
        ipWhitelist: ["1.0.0.1"],
        cloudflareExempt: true,
      }),
    );
    add(2, 2, [row("1.0.0.1", now + 1000)], now + 1000);
    assert.equal(reasons(2, 2).length, 0);
    collectBlacklistedIPs(db, panel(1), 1, [row("1.0.0.99")], now);
    add(2, 3, [row("1.0.0.99", now + 1000)], now + 1000);
    assert.equal(reasons(2, 3).length, 0);
    add(2, 4, []);
    db.exec("UPDATE subjects SET white=1 WHERE panel=2 AND uid=4");
    add(2, 4, [row("1.0.0.2", now + 1000)], now + 1000);
    assert.equal(reasons(2, 4).length, 0);
    configureBlacklist(db, { enabled: false, recording: false, days: 7 });
    add(2, 5, [row("1.0.0.2", now + 1000)], now + 1000);
    assert.equal(reasons(2, 5).length, 0);
    assert.equal(
      collectBlacklistedIPs(db, panel(1), 1, [row("1.0.0.66")], now),
      0,
    );
  }));

test("自动收集不受100条展示限制，维护/预览不收集，移除旧证据不重新加入", () =>
  fixture(({ db, panel, subject, add, reasons }) => {
    const rows = Array.from({ length: 120 }, (_, i) => row(`1.0.1.${i + 1}`));
    add(1, 1, rows);
    assert.equal(reasons(1, 1)[0].evidence.length, 100);
    assert.equal(blacklistRows(db, new URLSearchParams(), now).total, 120);
    removeBlacklistedIP(db, rows[0].ip, now + 1);
    evaluate(db, panel(1), 1, now + 2000, geo);
    assess(db, panel(1), subject(1, 1), now + 2000, geo);
    assert.equal(
      blacklistRows(db, new URLSearchParams(), now + 2000).total,
      119,
    );
    importBlacklistHistory(db, 0, now + 2000, geo);
    assert.equal(
      blacklistRows(db, new URLSearchParams(), now + 2000).total,
      119,
    );
    add(1, 1, [row(rows[0].ip, now + 3000)], now + 3000);
    assert.equal(
      blacklistRows(db, new URLSearchParams(), now + 3000).total,
      120,
    );
  }));

test("有限期限、永久保留、缩短期限、移除和已有标记互不混淆", () =>
  fixture(({ db, panel, subject, add, reasons }) => {
    add(1, 1, source());
    add(2, 2, [row("1.0.0.1", now + 1000)], now + 1000);
    configureBlacklist(db, { enabled: true, recording: true, days: 999 });
    assert.equal(blacklistSettings(db).days, 999);
    assert.equal(
      db.prepare("SELECT expires FROM ip_blacklist LIMIT 1").get().expires,
      PERMANENT,
    );
    cleanBlacklist(db, now + 1000 * DAY);
    assert.equal(
      blacklistRows(db, new URLSearchParams(), now + 1000 * DAY).total,
      4,
    );
    removeBlacklistedIP(db, "1.0.0.1", now + 2000);
    assert.equal(
      assess(db, panel(2), subject(2, 2), now + 3000, geo).some(
        (r) => r.code === "blacklist",
      ),
      false,
      "移除后不再满足自动封禁复核",
    );
    evaluate(db, panel(2), 2, now + 3000, geo);
    assert.equal(reasons(2, 2)[0].code, "blacklist", "不自动解除已有标记");
    configureBlacklist(db, { enabled: true, recording: true, days: 1 });
    assert.equal(
      blacklistRows(db, new URLSearchParams(), now + 2 * DAY).total,
      0,
    );
    configureBlacklist(db, { enabled: true, recording: true, days: 999 });
    assert.equal(blacklistRows(db, new URLSearchParams(), now).total, 3);
    assert.throws(() =>
      configureBlacklist(db, { enabled: true, recording: true, days: -1 }),
    );
  }));

test("永久模式导入现存历史，限时模式排除过期证据；历史导入不直接标记用户", () =>
  fixture(({ db, panel, subject, add, reasons }) => {
    add(1, 1, source());
    db.exec("DELETE FROM ip_blacklist");
    db.prepare("UPDATE risk_history SET ts=?").run(now - 30 * DAY);
    assert.equal(importBlacklistHistory(db, 0, now, geo).changed, 0);
    configureBlacklist(db, { enabled: true, recording: true, days: 999 });
    assert.equal(importBlacklistHistory(db, 0, now, geo).changed, 4);
    assert.equal(reasons(2, 2).length, 0);
    assert.equal(
      importBlacklistHistory(db, 0, now, geo).changed,
      0,
      "重复导入不刷新期限",
    );
  }));

test("记录开关独立控制新增、续期和历史导入，已有黑名单仍可命中", () =>
  fixture(({ db, panel, add, reasons }) => {
    add(1, 1, source());
    const before = db.prepare("SELECT * FROM ip_blacklist ORDER BY ip").all();
    configureBlacklist(db, { enabled: true, recording: false, days: 7 });
    assert.equal(
      collectBlacklistedIPs(
        db,
        panel(1),
        1,
        [row("1.0.0.1", now + 1000), row("1.0.0.8", now + 1000)],
        now + 1000,
      ),
      0,
    );
    assert.deepEqual(
      db.prepare("SELECT * FROM ip_blacklist ORDER BY ip").all(),
      before,
    );
    assert.throws(
      () => importBlacklistHistory(db, 0, now, geo),
      /请先开启记录/,
    );
    add(2, 9, [row("1.0.0.1", now + 2000)], now + 2000);
    assert.equal(reasons(2, 9)[0].code, "blacklist");
    configureBlacklist(db, { enabled: false, recording: true, days: 999 });
    assert.equal(
      collectBlacklistedIPs(
        db,
        panel(1),
        1,
        [row("1.0.0.8", now + 3000)],
        now + 3000,
      ),
      1,
    );
    add(2, 10, [row("1.0.0.8", now + 4000)], now + 4000);
    assert.equal(
      reasons(2, 10).some((r) => r.code === "blacklist"),
      false,
    );
    assert.throws(() =>
      configureBlacklist(db, { enabled: true, recording: true, days: 0 }),
    );
  }));
