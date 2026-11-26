import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import {
  initEventWindows,
  syncEventWindows,
  windowVisitsSql,
} from "../event-windows.mjs";
import { defaults, validateRules } from "../model.mjs";
import { createApp } from "../server.mjs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

test("实际接口展示合并行、原始明细并支持修改时长", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-window-"));
  const app = createApp({
    dataDir: dir,
    secureCookie: false,
    background: false,
  });
  await new Promise((r) => app.admin.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${app.admin.address().port}`;
  const post = (url, data, cookie = "") =>
    fetch(base + url, {
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
      await post("/api/panels", { name: "test" }, cookie)
    ).json();
    app.db
      .prepare("INSERT INTO subjects(panel,uid,email,verified) VALUES(?,7,?,1)")
      .run(p.id, "test@example.com");
    const put = app.db.prepare(
      "INSERT INTO visits(panel,uid,email,ts,ip,ua,status,delivered) VALUES(?,7,?,?,?,?,?,?)",
    );
    const ts = Date.now() - 6 * 3600000;
    for (const [ago, ua, status] of [
      [0, "first", 200],
      [3600000, "Clash.Meta/1.19.34 Pa55wall/1.0.30 (Windows)", 403],
      [5 * 3600000, "latest", 200],
    ])
      put.run(
        p.id,
        "test@example.com",
        ts + ago,
        "1.1.1.1",
        ua,
        status,
        status === 200 ? 1 : 0,
      );
    const route = `/api/panels/${p.id}`;
    const get = async (url) => {
      const res = await fetch(base + route + url, {
        headers: { Cookie: cookie },
      });
      assert.equal(res.status, 200, await res.clone().text());
      return res.json();
    };
    let d = await get("/event-windows");
    assert.equal(d.total, 2);
    assert.equal(d.rows[0].ua, "latest");
    assert.equal(d.rows[1].windowRequests, 2);
    assert.equal(d.rows[1].status, 403);
    const w = d.rows[1];
    d = await get(
      `/user-history?uid=7&kind=visits&windowFrom=${w.windowStarted}&windowTo=${w.windowEnded}`,
    );
    assert.equal(d.rows.length, 2);
    assert.equal(d.rows[0].ua, "Clash.Meta/1.19.34 Pa55wall/1.0.30 (Windows)");
    assert.equal((await get("/events")).total, 3);
    const rules = JSON.parse(
      app.db.prepare("SELECT rules FROM panels WHERE id=?").get(p.id).rules,
    );
    rules.historyMergeMinutes = 60;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), p.id);
    assert.equal((await get("/event-windows")).total, 3);
    assert.equal((await fetch(base + route + "/event-windows")).status, 401);
    rules.historyMergeMinutes = 0;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), p.id);
    put.run(
      p.id,
      "test@example.com",
      ts + 5 * 3600000,
      "1.1.1.1",
      "same-millisecond",
      200,
      1,
    );
    const groups = await get("/event-windows");
    const selected = groups.rows[0].id;
    const deleted = await post(
      route + "/history/bulk-delete",
      { ids: [selected], windows: true, password: "test-password" },
      cookie,
    );
    assert.equal(deleted.status, 200, await deleted.clone().text());
    assert.equal(
      (await get("/events")).total,
      3,
      "0分钟时只删除选中记录，不误删同毫秒其他请求",
    );
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("记录按用户固定时段合并，10/11点合并、15点新增，修改时长/迟到/删除后重建且不改原始数据", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(
      "CREATE TABLE visits(id INTEGER PRIMARY KEY,panel INTEGER,uid INTEGER,ts INTEGER,ua TEXT);",
    );
    initEventWindows(db);
    const put = db.prepare("INSERT INTO visits VALUES(?,?,?,?,?)");
    put.run(1, 1, 7, 10 * 3600000, "raw-a");
    put.run(2, 1, 7, 11 * 3600000, "raw-b");
    put.run(3, 1, 7, 15 * 3600000, "raw-c");
    put.run(4, 1, 8, 11 * 3600000, "other-user");
    put.run(5, 2, 7, 11 * 3600000, "other-panel");
    const rows = () =>
      db
        .prepare(
          `SELECT * FROM ${windowVisitsSql} WHERE panel=1 ORDER BY ts DESC,id DESC`,
        )
        .all();
    syncEventWindows(db, 1, 240);
    syncEventWindows(db, 1, 240);
    assert.deepEqual(
      rows().map((r) => [r.id, r.windowRequests]),
      [
        [3, 1],
        [4, 1],
        [2, 2],
      ],
    );
    assert.equal(rows()[2].ua, "raw-b");
    assert.equal(rows()[2].windowStarted, 10 * 3600000);
    syncEventWindows(db, 1, 60);
    assert.equal(rows().length, 4);
    syncEventWindows(db, 1, 0);
    assert.equal(rows().length, 4);
    syncEventWindows(db, 1, 240);
    put.run(6, 1, 7, 14 * 3600000, "exact-boundary");
    syncEventWindows(db, 1, 240);
    assert.deepEqual(
      rows()
        .filter((r) => r.uid === 7)
        .map((r) => [r.id, r.windowRequests]),
      [
        [3, 2],
        [2, 2],
      ],
    );
    db.prepare("DELETE FROM visits WHERE id IN (1,2)").run();
    syncEventWindows(db, 1, 240);
    assert.equal(rows().filter((r) => r.uid === 7).length, 1);
    db.prepare("DELETE FROM visits WHERE panel=1 AND uid=7").run();
    syncEventWindows(db, 1, 240);
    assert.equal(rows().length, 1);
    assert.equal(
      db.prepare("SELECT count(*) n FROM visits WHERE panel=2").get().n,
      1,
    );
  } finally {
    db.close();
  }
});

test("记录合并时长独立校验，默认240分钟，允许关闭和1周，不改变计次时长", () => {
  assert.equal(defaults.historyMergeMinutes, 240);
  for (const value of [0, 1, 240, 10080]) {
    const rules = validateRules({
      ...defaults,
      historyMergeMinutes: value,
      requestDedupeMinutes: 60,
    });
    assert.equal(rules.historyMergeMinutes, value);
    assert.equal(rules.requestDedupeMinutes, 60);
  }
  for (const value of [-1, 0.5, 10081, "240"])
    assert.throws(() =>
      validateRules({ ...defaults, historyMergeMinutes: value }),
    );
});
