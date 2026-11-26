import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { initPanelOrder, savePanelOrder } from "../panel-order.mjs";
import { createApp } from "../server.mjs";

test("面板排序隔离账号，拒绝重复/缺失/外部ID，保持原默认顺序", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(
      "CREATE TABLE panels(id INTEGER PRIMARY KEY,owner INTEGER);INSERT INTO panels VALUES(1,1),(2,1),(3,2)",
    );
    initPanelOrder(db);
    initPanelOrder(db);
    const list = (owner) =>
      db
        .prepare(
          "SELECT id FROM panels WHERE owner=? ORDER BY COALESCE(sort_order,id),id",
        )
        .all(owner)
        .map((p) => p.id);
    assert.deepEqual(list(1), [1, 2]);
    savePanelOrder(db, 1, [2, 1]);
    assert.deepEqual(list(1), [2, 1]);
    for (const ids of [[2, 2], [2], [3, 1], [1, 2, 3], ["1", 2]])
      assert.throws(() => savePanelOrder(db, 1, ids));
    assert.deepEqual(list(1), [2, 1]);
    assert.deepEqual(list(2), [3]);
  } finally {
    db.close();
  }
});

test("排序接口需登录并持久保存，重启后下拉顺序一致", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-panel-order-"));
  let app;
  async function start() {
    app = createApp({ dataDir: dir, secureCookie: false, background: false });
    await new Promise((r) => app.admin.listen(0, "127.0.0.1", r));
    return `http://127.0.0.1:${app.admin.address().port}`;
  }
  let base = await start();
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
    assert.equal((await post("/api/panels/order", { ids: [] })).status, 401);
    const auth = await post("/api/setup", {
      username: "owner",
      password: "test-password",
      confirmPassword: "test-password",
    });
    let cookie = auth.headers.get("set-cookie").split(";")[0];
    const a = await (await post("/api/panels", { name: "A" }, cookie)).json();
    const b = await (await post("/api/panels", { name: "B" }, cookie)).json();
    assert.equal(
      (await post("/api/panels/order", { ids: [b.id, a.id] }, cookie)).status,
      200,
    );
    await app.close();
    base = await start();
    const login = await post("/api/login", {
      username: "owner",
      password: "test-password",
    });
    cookie = login.headers.get("set-cookie").split(";")[0];
    const result = await (
      await fetch(base + "/api/panels", { headers: { Cookie: cookie } })
    ).json();
    assert.deepEqual(
      result.rows.map((p) => p.id),
      [b.id, a.id],
    );
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
