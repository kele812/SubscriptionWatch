import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { randomBytes, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  initDevices,
  saveDeviceSettings,
  reserveDevice,
  finishDeviceRequest,
  clearDevices,
  deviceRows,
  deviceCountsByUsers,
  RESERVATION_MS,
} from "../devices.mjs";
import { createApp } from "../server.mjs";
const HOUR = 3600000;
function fixture() {
  const db = new DatabaseSync(":memory:");
  db.exec(
    "CREATE TABLE panels(id INTEGER PRIMARY KEY); INSERT INTO panels VALUES(1),(2); CREATE TABLE subjects(panel INTEGER,uid INTEGER,email TEXT,white INTEGER DEFAULT 0);",
  );
  initDevices(db);
  initDevices(db);
  saveDeviceSettings(db, 1, { enabled: true, hours: 24 });
  const now = Date.now();
  function event(hwid = "a", extra = {}) {
    return {
      user_id: 7,
      email: "a@example.com",
      ip: "8.8.8.8",
      ua: "Pa55wall/1 (Windows)",
      platform: "Windows",
      hwid: hwid.repeat(64),
      device_limit: 2,
      event_id: randomBytes(16).toString("hex"),
      ts: now,
      ...extra,
    };
  }
  function finish(e, success = true, at = now + 10) {
    finishDeviceRequest(
      db,
      1,
      {
        ...e,
        completed_at: at,
        status: success ? 200 : 500,
        delivered: success,
        bytes: success ? 10 : 0,
      },
      { ...e, denied: 0 },
      at,
    );
  }
  return { db, now, event, finish };
}

test("同HWID的不同UA与IP占一席；满额拒绝新设备但允许原设备刷新", () => {
  const { db, now, event, finish } = fixture();
  try {
    const a = event();
    assert.deepEqual(reserveDevice(db, 1, a, now), {});
    finish(a);
    const same = event("a", {
      ua: "Clash.Meta/1.19 Pa55wall/1 (Windows)",
      ip: "1.1.1.1",
    });
    reserveDevice(db, 1, same, now + 20);
    finish(same, true, now + 30);
    assert.equal(deviceRows(db, 1, "", 1, now + 40).total, 1);
    const b = event("b");
    reserveDevice(db, 1, b, now + 40);
    finish(b, true, now + 50);
    assert.equal(
      reserveDevice(db, 1, event("c"), now + 60).code,
      "device-limit",
    );
    assert.deepEqual(reserveDevice(db, 1, event("a"), now + 60), {});
    assert.equal(deviceRows(db, 1, "7", 1, now + 60).total, 2);
  } finally {
    db.close();
  }
});

test("预留防止同时抢最后名额；失败不续期；预留过期释放", () => {
  const { db, now, event, finish } = fixture();
  try {
    const a = event("a", { device_limit: 1 });
    reserveDevice(db, 1, a, now);
    assert.equal(
      reserveDevice(db, 1, event("b", { device_limit: 1 }), now).code,
      "device-limit",
    );
    finish(a, false);
    const b = event("b", { device_limit: 1 });
    assert.deepEqual(reserveDevice(db, 1, b, now + 20), {});
    assert.deepEqual(
      reserveDevice(
        db,
        1,
        event("c", { device_limit: 1 }),
        now + RESERVATION_MS + 21,
      ),
      {},
    );
    assert.equal(db.prepare("SELECT COUNT(*) n FROM device_leases").get().n, 0);
  } finally {
    db.close();
  }
});

test("成功续期、24小时精确到期、自定义时长与0不限数量", () => {
  const { db, now, event, finish } = fixture();
  try {
    const a = event("a", { device_limit: 1 });
    reserveDevice(db, 1, a, now);
    finish(a, true, now + 10);
    assert.equal(
      reserveDevice(db, 1, event("b", { device_limit: 1 }), now + 24 * HOUR + 9)
        .code,
      "device-limit",
    );
    assert.deepEqual(
      reserveDevice(
        db,
        1,
        event("b", { device_limit: 1 }),
        now + 24 * HOUR + 10,
      ),
      {},
    );
    clearDevices(db, 1);
    saveDeviceSettings(db, 1, { enabled: true, hours: 2 });
    const c = event("c");
    reserveDevice(db, 1, c, now);
    finish(c);
    assert.equal(deviceRows(db, 1, "", 1, now + 2 * HOUR + 10).total, 0);
    for (const id of ["a", "b", "c", "d"])
      assert.deepEqual(
        reserveDevice(
          db,
          1,
          event(id, { device_limit: 0 }),
          now + 2 * HOUR + 20,
        ),
        {},
      );
    assert.throws(() => saveDeviceSettings(db, 1, { enabled: true, hours: 0 }));
    assert.throws(() =>
      saveDeviceSettings(db, 1, { enabled: true, hours: 1.5 }),
    );
  } finally {
    db.close();
  }
});

test("白名单免限且无需HWID；未升级插件拒绝；不同用户及面板隔离", () => {
  const { db, now, event } = fixture();
  try {
    db.prepare("INSERT INTO subjects VALUES(1,7,?,1)").run("a@example.com");
    assert.deepEqual(
      reserveDevice(
        db,
        1,
        event("a", { hwid: undefined, device_limit: undefined }),
        now,
      ),
      {},
    );
    db.exec("DELETE FROM subjects");
    assert.equal(
      reserveDevice(db, 1, event("a", { hwid: undefined }), now).code,
      "device-id-required",
    );
    assert.equal(
      reserveDevice(db, 1, event("a", { device_limit: undefined }), now).code,
      "device-metadata",
    );
    reserveDevice(db, 1, event("a", { device_limit: 1 }), now);
    assert.deepEqual(
      reserveDevice(db, 1, event("b", { user_id: 8, device_limit: 1 }), now),
      {},
    );
    assert.deepEqual(
      reserveDevice(db, 2, event("b", { device_limit: 1 }), now),
      {},
    );
  } finally {
    db.close();
  }
});

test("白名单只统计不限制，关闭限制仍登记；缺少编号放行，失败和清除不恢复设备", () => {
  const { db, now, event, finish } = fixture();
  try {
    db.prepare("INSERT INTO subjects VALUES(1,7,?,1)").run("a@example.com");
    for (const id of ["a", "b", "c"]) {
      const e = event(id, { device_limit: 1 });
      assert.deepEqual(reserveDevice(db, 1, e, now), {});
      finish(e);
    }
    assert.equal(
      deviceCountsByUsers(db, 1, [7], now + 20).get(7).count,
      3,
      "white user can exceed the plan without rejection",
    );
    saveDeviceSettings(db, 1, { enabled: false, hours: 24 });
    const same = event("a", { ua: "Different client", device_limit: 1 });
    reserveDevice(db, 1, same, now + 20);
    finish(same, true, now + 30);
    assert.equal(deviceCountsByUsers(db, 1, [7], now + 40).get(7).count, 3);
    const missing = event("d", { hwid: undefined, device_limit: undefined });
    assert.deepEqual(reserveDevice(db, 1, missing, now + 40), {});
    assert.equal(
      db
        .prepare("SELECT COUNT(*) n FROM device_reservations WHERE event_id=?")
        .get(missing.event_id).n,
      0,
    );
    const noLimit = event("d", { device_limit: undefined });
    assert.deepEqual(reserveDevice(db, 1, noLimit, now + 40), {});
    finish(noLimit, true, now + 50);
    assert.equal(deviceCountsByUsers(db, 1, [7], now + 60).get(7).count, 4);
    const failed = event("e", { device_limit: 1 });
    reserveDevice(db, 1, failed, now + 60);
    finish(failed, false, now + 70);
    assert.equal(deviceCountsByUsers(db, 1, [7], now + 80).get(7).count, 4);
    const late = event("f");
    reserveDevice(db, 1, late, now + 80);
    clearDevices(db, 1, 7);
    finish(late, true, now + 90);
    assert.equal(deviceCountsByUsers(db, 1, [7], now + 100).get(7).count, 0);
    const fresh = event("g");
    reserveDevice(db, 1, fresh, now + 100);
    finish(fresh, true, now + 110);
    assert.equal(
      deviceCountsByUsers(db, 1, [7], now + 110 + 24 * HOUR).get(7).count,
      0,
    );
  } finally {
    db.close();
  }
});

test("清除用户/全体设备连同预留清除，迟到成功与错误响应不能恢复名额", () => {
  const { db, now, event, finish } = fixture();
  try {
    const a = event();
    reserveDevice(db, 1, a, now);
    clearDevices(db, 1, 7);
    finish(a);
    assert.equal(deviceRows(db, 1, "", 1, now + 20).total, 0);
    const b = event("b");
    reserveDevice(db, 1, b, now);
    finishDeviceRequest(
      db,
      1,
      {
        ...b,
        email: "other@example.com",
        delivered: true,
        status: 200,
        bytes: 5,
      },
      { ...b, denied: 0 },
      now + 20,
    );
    assert.equal(db.prepare("SELECT COUNT(*) n FROM device_leases").get().n, 0);
    finish(b, true, now + RESERVATION_MS + 10);
    assert.equal(deviceRows(db, 1, "", 1, now + RESERVATION_MS + 20).total, 0);
    clearDevices(db, 1);
  } finally {
    db.close();
  }
});

test("记录页设备数按当前邮箱批量去重，排除过期/其他用户与面板，预留单独计数", () => {
  const { db, now } = fixture();
  try {
    db.exec(
      "INSERT INTO subjects(panel,uid,email) VALUES(1,7,'a@example.com'),(1,8,'person7@example.com'),(2,7,'a@example.com')",
    );
    const lease = db.prepare(
      "INSERT INTO device_leases(panel,uid,email,hwid,last_success) VALUES(?,?,?,?,?)",
    );
    lease.run(1, 7, "a@example.com", "active", now - HOUR);
    lease.run(1, 7, "a@example.com", "expired", now - 24 * HOUR);
    lease.run(1, 7, "old@example.com", "old-email", now);
    lease.run(1, 8, "person7@example.com", "other-user", now);
    lease.run(2, 7, "a@example.com", "other-panel", now);
    const reserve = db.prepare(
      "INSERT INTO device_reservations(panel,event_id,uid,email,hwid,expires) VALUES(?,?,?,?,?,?)",
    );
    reserve.run(1, "same-active", 7, "a@example.com", "active", now + 1000);
    reserve.run(1, "pending-one", 7, "a@example.com", "pending", now + 1000);
    reserve.run(1, "pending-repeat", 7, "a@example.com", "pending", now + 1000);
    reserve.run(1, "expired", 7, "a@example.com", "expired-reservation", now);
    const result = deviceCountsByUsers(db, 1, [7, 7, 8, 9, NaN], now);
    assert.equal(result.size, 3);
    assert.deepEqual(result.get(7), {
      count: 2,
      pending: 1,
      enabled: true,
      hours: 24,
    });
    assert.equal(result.get(8).count, 1);
    assert.equal(result.get(9).count, 0);
    assert.ok(
      deviceRows(db, 1, "7", 1, now).rows.every((row) => row.uid === 7),
      "ID navigation never includes another account whose email contains the ID",
    );
    assert.equal(deviceCountsByUsers(db, 1, [], now).size, 0);
    clearDevices(db, 1, 7);
    assert.equal(deviceCountsByUsers(db, 1, [7, 8], now).get(7).count, 0);
    assert.equal(deviceCountsByUsers(db, 1, [7, 8], now).get(8).count, 1);
  } finally {
    db.close();
  }
});

test("真实签名审核与上报：设备额度、白名单、并发、清除与面板权限", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-devices-"));
  const app = createApp({
    dataDir: dir,
    secureCookie: false,
    background: false,
  });
  const base = await new Promise((resolve) =>
    app.admin.listen(0, "127.0.0.1", () =>
      resolve(`http://127.0.0.1:${app.admin.address().port}`),
    ),
  );
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
    const setup = await post("/api/setup", {
      username: "owner",
      password: "test-password",
      confirmPassword: "test-password",
    });
    const cookie = setup.headers.get("set-cookie").split(";")[0];
    const { id } = await (
      await post("/api/panels", { name: "Panel" }, cookie)
    ).json();
    const key = await (await post(`/api/panels/${id}/key`, {}, cookie)).json();
    const panel = app.db.prepare("SELECT * FROM panels WHERE id=?").get(id);
    const rules = {
      ...JSON.parse(panel.rules),
      uaEnabled: false,
      chinaEnabled: false,
      foreignEnabled: false,
      dcEnabled: false,
    };
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), id);
    const history = async () =>
      (
        await (
          await fetch(base + `/api/panels/${id}/events`, {
            headers: { Cookie: cookie },
          })
        ).json()
      ).rows;
    assert.equal(
      (
        await post(
          `/api/panels/${id}/devices/settings`,
          { enabled: true, hours: 24 },
          cookie,
        )
      ).status,
      200,
    );
    const signed = async (route, data) => {
      const body = JSON.stringify(data),
        ts = String(Math.floor(Date.now() / 1000));
      const response = await fetch(base + route, {
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
      const text = await response.text();
      assert.equal(response.status, 200, text);
      return JSON.parse(text);
    };
    const make = (letter, extra = {}) => ({
      schema: 1,
      event_id: randomBytes(16).toString("hex"),
      ts: Date.now(),
      user_id: 7,
      email: "a@example.com",
      ip: "8.8.8.8",
      ua: "Pa55wall/1 (Windows)",
      hwid: letter.repeat(64),
      platform: "Windows",
      identity_kind: "hwid",
      device_limit: 1,
      ...extra,
    });
    const a = make("a"),
      b = make("b");
    const responses = await Promise.all([
      signed("/api/collector/review", a),
      signed("/api/collector/review", b),
    ]);
    assert.equal(responses.filter((r) => r.allow).length, 1);
    const winner = responses[0].allow ? a : b;
    const report = {
      ...winner,
      completed_at: Date.now(),
      peer_ip: "127.0.0.1",
      ip_source: "trusted_proxy",
      flag: "",
      status: 200,
      ms: 1,
      bytes: 20,
      content_type: "text/plain",
      delivered: true,
    };
    await signed("/api/collector/events", {
      schema: 1,
      version: "4.0.24",
      mode: "request",
      events: [report],
    });
    const list = await (
      await fetch(base + `/api/panels/${id}/devices`, {
        headers: { Cookie: cookie },
      })
    ).json();
    assert.equal(list.total, 1);
    assert.equal(list.rows[0].pending, 0);
    assert.equal(
      app.db.prepare("SELECT reporting_mode FROM panels WHERE id=?").get(id)
        .reporting_mode,
      "request",
    );
    assert.equal(
      (await signed("/api/collector/review", make("c"))).codes[0],
      "device-limit",
    );
    assert.equal((await fetch(base + `/api/panels/${id}/devices`)).status, 401);
    // Turning on the quota adds a rule; it never disables other risk checks.
    app.db.prepare("UPDATE panels SET rules=? WHERE id=?").run(
      JSON.stringify({
        ...rules,
        uaEnabled: true,
        uaKeywords: ["allowed-client"],
      }),
      id,
    );
    const denied = make("e");
    const decision = await signed("/api/collector/review", denied);
    assert.ok(
      decision.codes.includes("ua") && decision.codes.includes("device-limit"),
    );
    await signed("/api/collector/events", {
      schema: 1,
      version: "4.0.24",
      mode: "request",
      events: [
        {
          ...denied,
          completed_at: Date.now(),
          peer_ip: "127.0.0.1",
          ip_source: "trusted_proxy",
          flag: "",
          status: 403,
          ms: 1,
          bytes: 10,
          content_type: "application/json",
          delivered: false,
        },
      ],
    });
    const record = app.db
      .prepare("SELECT * FROM visits WHERE panel=? AND event_id=?")
      .get(id, denied.event_id);
    assert.equal(record.review_blocked, 1);
    assert.ok(
      JSON.parse(record.review_reasons).some((r) => r.includes("上限 1")),
    );
    assert.ok(
      JSON.parse(record.review_reasons).some((r) => r.includes("非指定客户端")),
    );
    const beforeClear = await history();
    assert.equal(beforeClear.length, 2);
    assert.ok(
      beforeClear.every(
        (row) =>
          row.currentUser.devices.count === 1 &&
          row.currentUser.devices.pending === 0,
      ),
      "all historical requests show the current device count",
    );
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), id);
    assert.equal(
      (await post(`/api/panels/${id}/devices/clear`, {}, cookie)).status,
      400,
    );
    assert.equal(
      (
        await post(
          `/api/panels/${id}/devices/clear`,
          { confirm: true, uid: 7 },
          cookie,
        )
      ).status,
      200,
    );
    assert.ok(
      (await history()).every((row) => row.currentUser.devices.count === 0),
      "clearing changes current counts on old records without rewriting visits",
    );
    assert.equal(
      (await signed("/api/collector/review", make("c"))).allow,
      true,
    );
    app.db
      .prepare("UPDATE subjects SET white=1 WHERE panel=? AND uid=7")
      .run(id);
    await post(
      `/api/panels/${id}/devices/settings`,
      { enabled: false, hours: 24 },
      cookie,
    );
    clearDevices(app.db, id, 7);
    const whiteDevice = make("e", { device_limit: 1 });
    assert.equal(
      (await signed("/api/collector/review", whiteDevice)).allow,
      true,
    );
    await signed("/api/collector/events", {
      schema: 1,
      version: "4.0.25",
      mode: "request",
      events: [{ ...report, ...whiteDevice, completed_at: Date.now() }],
    });
    const whiteHistory = await history();
    assert.ok(
      whiteHistory.every(
        (row) =>
          row.currentUser.white &&
          row.currentUser.devices.count === 1 &&
          row.currentUser.devices.enabled === false,
      ),
      "whitelist requests update current counts even when enforcement is off",
    );
    assert.equal(
      (
        await signed(
          "/api/collector/review",
          make("d", { hwid: undefined, device_limit: undefined }),
        )
      ).allow,
      true,
    );
    app.db
      .prepare("UPDATE subjects SET white=0 WHERE panel=? AND uid=7")
      .run(id);
    await post(
      `/api/panels/${id}/devices/settings`,
      { enabled: false, hours: 24 },
      cookie,
    );
    assert.equal(
      (
        await signed(
          "/api/collector/review",
          make("f", { hwid: undefined, device_limit: undefined }),
        )
      ).allow,
      true,
    );
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
