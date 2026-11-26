import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { randomBytes, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { defaults, validateRules } from "../model.mjs";
import { createApp } from "../server.mjs";
import {
  initRequestCounts,
  prepareRequestCount,
  requestCounts,
} from "../request-counts.mjs";

test("合并时间默认4小时，可设0关闭或最多24小时，拒绝负数/小数/超界", () => {
  assert.equal(defaults.requestDedupeMinutes, 240);
  for (const value of [0, 60, 240, 1440])
    assert.equal(
      validateRules({ ...defaults, requestDedupeMinutes: value })
        .requestDedupeMinutes,
      value,
    );
  for (const value of [-1, 0.5, 1441])
    assert.throws(() =>
      validateRules({ ...defaults, requestDedupeMinutes: value }),
    );
});

function fixture() {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE panels(id INTEGER PRIMARY KEY,rules TEXT);
    CREATE TABLE review_decisions(panel INTEGER,uid INTEGER,event_id TEXT,ts INTEGER,ip TEXT,codes TEXT,delivered INTEGER,enforced INTEGER,ip_whitelisted INTEGER);
    CREATE TABLE visits(id INTEGER PRIMARY KEY,panel INTEGER,uid INTEGER,event_id TEXT,ts INTEGER,ip TEXT,delivered INTEGER,status INTEGER);`);
  for (const id of [1, 2])
    db.prepare("INSERT INTO panels VALUES(?,?)").run(
      id,
      JSON.stringify(defaults),
    );
  const geo = {
    lookup: (ip) => ({
      organization: ip.startsWith("104.") ? "Cloudflare, Inc." : "ISP",
    }),
  };
  initRequestCounts(db, geo);
  initRequestCounts(db, geo);
  function add(ip, ts, uid = 7, panel = 1, codes = []) {
    const event = {
      ip,
      user_id: uid,
      event_id: randomBytes(16).toString("hex"),
    };
    const plan = prepareRequestCount(db, panel, event, ts);
    db.prepare(
      "INSERT INTO review_decisions(panel,uid,event_id,ts,ip,codes,delivered,enforced,ip_whitelisted,count_key,count_bucket,count_started) VALUES(?,?,?,?,?,?,1,0,0,?,?,?)",
    ).run(
      panel,
      uid,
      event.event_id,
      ts,
      ip,
      JSON.stringify(codes),
      plan.key,
      plan.bucket,
      plan.started,
    );
    return { ...event, ...plan };
  }
  return { db, add };
}

test("默认4小时固定窗口：同IP和跨CF IP合并，用户/面板隔离，修改时间与重置可重算", () => {
  const { db, add } = fixture();
  const hour = 3600000,
    t = Date.now() - 8 * hour;
  try {
    const a = add("8.8.8.8", t);
    add("104.16.0.1", t + 60000);
    assert.equal(add("8.8.8.8", t + hour).bucket, a.bucket);
    add("104.16.0.2", t + 3 * hour);
    assert.notEqual(
      add("8.8.8.8", t + 4 * hour).bucket,
      a.bucket,
      "duplicates do not prolong the window",
    );
    add("104.16.0.3", t + 4 * hour + 60000);
    const counts = requestCounts(db, 1, 7, t + 5 * hour);
    assert.equal(counts.total, 4);
    assert.equal(counts.cfCount, 2);
    assert.equal(counts.normalCount, 2);
    add("104.16.0.4", t + 5 * hour, 8);
    add("104.16.0.4", t + 5 * hour, 7, 2);
    assert.equal(requestCounts(db, 1, 8, t + 5 * hour).total, 1);
    assert.equal(requestCounts(db, 2, 7, t + 5 * hour).total, 1);
    db.prepare("UPDATE panels SET rules=? WHERE id=1").run(
      JSON.stringify({ ...defaults, requestDedupeMinutes: 60 }),
    );
    assert.equal(requestCounts(db, 1, 7, t + 5 * hour).total, 6);
    assert.equal(
      requestCounts(db, 1, 7, t + 5 * hour, t + 200 * 60000).total,
      2,
    );
    assert.equal(
      db.prepare("SELECT COUNT(*) n FROM review_decisions").get().n,
      8,
      "raw requests remain intact",
    );
    assert.equal(
      requestCounts(db, 1, 7, t + 30 * hour).total,
      0,
      "counts expire from their first counted timestamp",
    );
  } finally {
    db.close();
  }
});

test("失败撤回与旧记录回填：不双算审核/访问，IPv6格式归一，关闭合并恢复逐次计数", () => {
  const { db, add } = fixture(),
    t = Date.now() - 60000;
  try {
    const a = add("2001:db8::1", t);
    add("2001:0DB8:0:0:0:0:0:1", t + 1000);
    db.prepare(
      "INSERT INTO visits(panel,uid,event_id,ts,ip,delivered,status) VALUES(1,7,?,?,?,1,200)",
    ).run(a.event_id, t, "2001:db8::1");
    db.prepare(
      "INSERT INTO visits(panel,uid,ts,ip,delivered,status) VALUES(1,7,?,?,1,200)",
    ).run(t + 2000, "2001:db8::1");
    assert.equal(requestCounts(db, 1, 7, t + 3000).total, 1);
    db.prepare("UPDATE panels SET rules=? WHERE id=1").run(
      JSON.stringify({ ...defaults, requestDedupeMinutes: 0 }),
    );
    assert.equal(requestCounts(db, 1, 7, t + 3000).total, 3);
    const failed = add("9.9.9.9", t + 4000, 8);
    db.prepare(
      "UPDATE review_decisions SET delivered=0,enforced=0 WHERE event_id=?",
    ).run(failed.event_id);
    assert.equal(requestCounts(db, 1, 8, t + 5000).total, 0);
    assert.equal(add("9.9.9.9", t + 6000, 8).reuse, false);
    assert.equal(requestCounts(db, 1, 8, t + 7000).total, 1);
  } finally {
    db.close();
  }
});

test("真实审核：重复不多扣额度，CF换IP合并；被次数拒绝不能重试绕过，UA及设备仍检查", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-counts-"));
  const app = createApp({
    dataDir: dir,
    secureCookie: false,
    background: false,
  });
  await new Promise((r) => app.admin.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${app.admin.address().port}`;
  const post = (route, data, cookie = "") =>
    fetch(base + route, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Watch-Request": "1",
        Cookie: cookie,
      },
      body: JSON.stringify(data),
    });
  try {
    const auth = await post("/api/setup", {
      username: "owner",
      password: "test-password",
      confirmPassword: "test-password",
    });
    const cookie = auth.headers.get("set-cookie").split(";")[0];
    const p = await (
      await post("/api/panels", { name: "Test" }, cookie)
    ).json();
    const key = await (
      await post(`/api/panels/${p.id}/key`, {}, cookie)
    ).json();
    app.db.prepare("UPDATE panels SET rules=?,notify=0 WHERE id=?").run(
      JSON.stringify({
        ...defaults,
        chinaEnabled: false,
        foreignEnabled: false,
        dcEnabled: false,
        dailyLimit: 1,
        uaEnabled: true,
        uaKeywords: ["pa55wall"],
        cloudflareExempt: true,
      }),
      p.id,
    );
    app.geo.lookup = (ip) => ({
      countryCode: ip.startsWith("104.") ? "US" : "CN",
      organization: ip.startsWith("104.") ? "Cloudflare" : "ISP",
    });
    const signed = async (route, data) => {
      const body = JSON.stringify(data),
        ts = String(Math.floor(Date.now() / 1000));
      const r = await fetch(base + route, {
        method: "POST",
        headers: {
          "X-Watch-Panel": key.publicId,
          "X-Watch-Timestamp": ts,
          "X-Watch-Signature": createHmac("sha256", key.collectorKey)
            .update(ts + "\n" + body)
            .digest("hex"),
        },
        body,
      });
      assert.equal(r.status, 200);
      return r.json();
    };
    const review = async (extra = {}) => {
      const event = {
        schema: 1,
        event_id: randomBytes(16).toString("hex"),
        ts: Date.now(),
        user_id: 7,
        email: "a@example.com",
        ip: "8.8.8.8",
        ua: "Pa55wall/1.0.30 (Windows)",
        hwid: "a".repeat(64),
        device_limit: 1,
        ...extra,
      };
      return { event, ...(await signed("/api/collector/review", event)) };
    };
    const first = await review(),
      repeat = await review({
        ua: "Clash.Meta/1.19.34 Pa55wall/1.0.30 (Windows)",
      });
    assert.equal(first.allow, true);
    assert.equal(repeat.allow, true);
    const report = async (result, status = 200) =>
      signed("/api/collector/events", {
        schema: 1,
        version: "4.0.27",
        mode: "request",
        events: [
          {
            ...result.event,
            completed_at: Date.now(),
            peer_ip: result.event.ip,
            ip_source: "peer",
            flag: "",
            status,
            ms: 1,
            bytes: status === 200 ? 100 : 0,
            delivered: status === 200,
          },
        ],
      });
    await report(first);
    await report(repeat);
    assert.equal(
      app.db
        .prepare("SELECT COUNT(*) n FROM visits WHERE panel=? AND uid=7")
        .get(p.id).n,
      2,
    );
    assert.equal(
      requestCounts(app.db, p.id, 7, Date.now()).total,
      1,
      "raw visit records remain separate while the quota is merged",
    );
    assert.ok((await review({ ua: "browser" })).codes.includes("ua"));
    await post(
      `/api/panels/${p.id}/devices/settings`,
      { enabled: true, hours: 24 },
      cookie,
    );
    assert.equal((await review()).allow, true);
    assert.ok(
      (await review({ hwid: "b".repeat(64) })).codes.includes("device-limit"),
    );
    await post(
      `/api/panels/${p.id}/devices/settings`,
      { enabled: false, hours: 24 },
      cookie,
    );
    assert.equal((await review({ user_id: 8, ip: "104.16.0.1" })).allow, true);
    assert.equal((await review({ user_id: 8, ip: "104.16.0.2" })).allow, true);
    assert.ok(
      (await review({ user_id: 8, ip: "1.1.1.1" })).codes.includes(
        "daily-limit",
      ),
    );
    assert.ok(
      (await review({ user_id: 8, ip: "1.1.1.1" })).codes.includes(
        "daily-limit",
      ),
    );
    assert.equal((await review({ user_id: 8, ip: "104.16.0.3" })).allow, true);
    assert.equal(requestCounts(app.db, p.id, 8, Date.now()).cfCount, 1);
    assert.equal(requestCounts(app.db, p.id, 8, Date.now()).normalCount, 1);
    const changed = JSON.parse(
      app.db.prepare("SELECT rules FROM panels WHERE id=?").get(p.id).rules,
    );
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify({ ...changed, dailyLimit: 2 }), p.id);
    assert.equal(
      (await review({ user_id: 8, ip: "1.1.1.1" })).allow,
      true,
      "raising the quota may admit an already-counted group without spending another count",
    );
    const failed = await review({ user_id: 10 });
    await report(failed, 500);
    assert.equal(requestCounts(app.db, p.id, 10, Date.now()).total, 0);
    assert.equal((await review({ user_id: 10 })).allow, true);
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
