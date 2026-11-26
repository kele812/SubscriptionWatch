import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import vm from "node:vm";
import { createApp } from "../server.mjs";
import { requestCounts } from "../request-counts.mjs";

test("网页整面板清零需登录及确认，含白名单、保留记录风险、隔离其他面板且失败回滚", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-panel-reset-"));
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
      }),
      cookie = auth.headers.get("set-cookie").split(";")[0];
    const a = await (await post("/api/panels", { name: "A" }, cookie)).json(),
      b = await (await post("/api/panels", { name: "B" }, cookie)).json();
    app.db
      .prepare(
        "INSERT INTO accounts(username,password_hash,created) SELECT 'other',password_hash,created FROM accounts LIMIT 1",
      )
      .run();
    app.db
      .prepare(
        "INSERT INTO panels(owner,name,public_id,secret,rules) SELECT (SELECT id FROM accounts WHERE username='other'),'Foreign','other','secret',rules FROM panels LIMIT 1",
      )
      .run();
    const foreign = app.db
      .prepare("SELECT id FROM panels WHERE name='Foreign'")
      .get().id;
    const url = (id) => `/api/panels/${id}/client-status/reset-all`;
    const before = Date.now() - 1000;
    for (const id of [a.id, b.id, foreign])
      for (const uid of [1, 2]) {
        app.db
          .prepare(
            "INSERT INTO subjects(panel,uid,email,verified,white) VALUES(?,?,?,1,?)",
          )
          .run(id, uid, `user${uid}@example.com`, uid === 2 ? 1 : 0);
        app.db
          .prepare(
            "INSERT INTO visits(panel,uid,email,ts,ip,ua,status,delivered) VALUES(?,?,?,?,?,?,200,1)",
          )
          .run(
            id,
            uid,
            `user${uid}@example.com`,
            before,
            "1.1.1.1",
            "Pa55wall/1.0.30 (Windows)",
          );
        app.db
          .prepare("INSERT INTO risks VALUES(?,?,1,?,?,?)")
          .run(id, uid, before, before, "[]");
      }
    assert.equal(requestCounts(app.db, a.id, 1, Date.now()).total, 1);
    assert.equal((await post(url(a.id), { confirm: true })).status, 401);
    assert.equal((await post(url(a.id), {}, cookie)).status, 400);
    assert.equal(
      (await post(url(foreign), { confirm: true }, cookie)).status,
      404,
    );
    app.db.exec(
      `CREATE TRIGGER reset_fail BEFORE UPDATE OF daily_reset_at ON subjects BEGIN SELECT RAISE(ABORT,'test rollback'); END;`,
    );
    assert.equal(
      (await post(url(a.id), { confirm: true }, cookie)).status,
      400,
    );
    assert.equal(
      app.db.prepare("SELECT count(*) n FROM risk_history").get().n,
      0,
    );
    app.db.exec("DROP TRIGGER reset_fail");
    const response = await post(
      url(a.id) + "?uid=1&page=2",
      { confirm: true },
      cookie,
    );
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.count, 2);
    assert.match(result.notice, /A/);
    const reset = app.db
      .prepare("SELECT daily_reset_at FROM subjects WHERE panel=? AND uid=1")
      .get(a.id).daily_reset_at;
    assert.equal(requestCounts(app.db, a.id, 1, Date.now(), reset).total, 0);
    assert.equal(
      app.db
        .prepare(
          "SELECT count(*) n FROM subjects WHERE panel=? AND daily_reset_at>0",
        )
        .get(a.id).n,
      2,
    );
    assert.equal(
      app.db
        .prepare("SELECT sum(daily_reset_at) n FROM subjects WHERE panel<>?")
        .get(a.id).n,
      0,
    );
    assert.equal(app.db.prepare("SELECT count(*) n FROM visits").get().n, 6);
    assert.equal(app.db.prepare("SELECT sum(active) n FROM risks").get().n, 6);
    assert.equal(
      app.db
        .prepare("SELECT count(*) n FROM risk_history WHERE panel=?")
        .get(a.id).n,
      2,
    );
    const empty = await (
      await post("/api/panels", { name: "Empty" }, cookie)
    ).json();
    assert.equal(
      (await (await post(url(empty.id), { confirm: true }, cookie)).json())
        .count,
      0,
    );
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("网页确认锁定点击时的面板，切换面板后不会清零其他面板", async () => {
  const script = readFileSync(
    new URL("../public/app.js", import.meta.url),
    "utf8",
  );
  const start = script.indexOf('$("#historyResetAll").onclick =');
  const end = script.indexOf('if ($("#historySelectPage"))', start);
  const button = {},
    requests = [];
  let pending;
  const context = vm.createContext({
    panelId: 7,
    panel: () => ({ name: "Original" }),
    $: () => button,
    ask: (title, help, fields, fn) => {
      pending = fn;
      assert.match(title, /Original/);
      assert.match(help, /不受当前搜索/);
    },
    api: (url, body) => requests.push({ url, confirm: body.confirm }),
  });
  vm.runInContext(script.slice(start, end), context);
  button.onclick();
  context.panelId = 8;
  await pending();
  assert.deepEqual(requests, [
    { url: "/api/panels/7/client-status/reset-all", confirm: true },
  ]);
});
