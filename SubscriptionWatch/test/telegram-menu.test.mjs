import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createApp } from "../server.mjs";
import { requestCounts } from "../request-counts.mjs";

test("机器人菜单选择本人面板；整面板计次重置需私聊本人确认、隔离面板且不可重放", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-tg-menu-")),
    calls = [];
  const fetcher = async (url, options) => {
    const method = url.split("/").at(-1),
      data = JSON.parse(options.body);
    calls.push({ method, data });
    return Response.json({
      ok: true,
      result:
        method === "getMe"
          ? { id: 123456, is_bot: true, username: "test_bot" }
          : method === "getWebhookInfo"
            ? { url: "" }
            : method === "getChat"
              ? { id: 22, type: "private" }
              : {},
    });
  };
  const app = createApp({
    dataDir: dir,
    secureCookie: false,
    background: false,
    fetcher,
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
    const a = await (
        await post("/api/panels", { name: "Panel A" }, cookie)
      ).json(),
      b = await (await post("/api/panels", { name: "Panel B" }, cookie)).json();
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
    await app.tg.configure(a.id, "123456:abcdefghijklmnopqrstuvwxyz", "22");
    let bot = app.db.prepare("SELECT * FROM telegram WHERE panel=?").get(a.id);
    const msg = (text, who = 22, type = "private") => ({
      message: { from: { id: who }, chat: { id: who, type }, text },
    });
    const cb = (data, who = 22, type = "private") => ({
      callback_query: {
        id: "test",
        from: { id: who },
        message: { chat: { id: who, type } },
        data,
      },
    });
    const lastText = () =>
      calls.filter((c) => c.method === "sendMessage").at(-1).data;
    await app.tg.handle(bot, msg("/menu"));
    assert.ok(lastText().reply_markup.keyboard);
    assert.ok(calls.some((c) => c.method === "setMyCommands"));
    await app.tg.handle(bot, msg("选择面板"));
    assert.equal(lastText().reply_markup.inline_keyboard.length, 2);
    await app.tg.handle(bot, cb("mw:select:" + foreign));
    assert.equal(
      app.db.prepare("SELECT selected FROM telegram").get().selected,
      null,
    );
    await app.tg.handle(bot, cb("mw:select:" + b.id, 33));
    assert.equal(
      app.db.prepare("SELECT selected FROM telegram").get().selected,
      null,
    );
    await app.tg.handle(bot, cb("mw:select:" + b.id));
    assert.equal(
      app.db.prepare("SELECT selected FROM telegram").get().selected,
      b.id,
    );
    const now = Date.now() - 1000;
    for (const panel of [a.id, b.id])
      for (const uid of [1, 2]) {
        app.db
          .prepare(
            "INSERT INTO subjects(panel,uid,email,verified,white) VALUES(?,?,?,?,?)",
          )
          .run(panel, uid, `user${uid}@example.com`, 1, uid === 2 ? 1 : 0);
        app.db
          .prepare(
            "INSERT INTO visits(panel,uid,email,ts,ip,ua,status,delivered) VALUES(?,?,?,?,?,?,200,1)",
          )
          .run(
            panel,
            uid,
            `user${uid}@example.com`,
            now,
            "1.1.1.1",
            "Pa55wall/1.0.30 (Windows)",
          );
        app.db
          .prepare("INSERT INTO risks VALUES(?,?,1,?,?,?)")
          .run(panel, uid, now, now, "[]");
      }
    assert.equal(requestCounts(app.db, b.id, 1, Date.now()).total, 1);
    await app.tg.handle(bot, msg("重置当前面板所有用户次数"));
    assert.match(lastText().text, /Panel B/);
    let buttons = lastText().reply_markup.inline_keyboard[0];
    const confirm = buttons[0].callback_data;
    assert.equal(
      app.db.prepare("SELECT sum(daily_reset_at) n FROM subjects").get().n,
      0,
    );
    await app.tg.handle(bot, cb(confirm, 33));
    await app.tg.handle(bot, cb(confirm, 22, "group"));
    assert.equal(
      app.db.prepare("SELECT sum(daily_reset_at) n FROM subjects").get().n,
      0,
    );
    // Confirmation retains the named panel even if the selection is changed meanwhile.
    await app.tg.handle(bot, cb("mw:select:" + a.id));
    await app.tg.handle(bot, cb(confirm));
    assert.match(lastText().text, /Panel B.*2 位/s);
    assert.equal(
      app.db
        .prepare(
          "SELECT count(*) n FROM subjects WHERE panel=? AND daily_reset_at>0",
        )
        .get(b.id).n,
      2,
    );
    assert.equal(
      app.db
        .prepare("SELECT sum(daily_reset_at) n FROM subjects WHERE panel=?")
        .get(a.id).n,
      0,
    );
    const reset = app.db
      .prepare("SELECT daily_reset_at FROM subjects WHERE panel=? AND uid=1")
      .get(b.id).daily_reset_at;
    assert.equal(requestCounts(app.db, b.id, 1, Date.now(), reset).total, 0);
    assert.equal(app.db.prepare("SELECT count(*) n FROM visits").get().n, 4);
    assert.equal(app.db.prepare("SELECT sum(active) n FROM risks").get().n, 4);
    assert.equal(
      app.db.prepare("SELECT count(*) n FROM risk_history").get().n,
      2,
    );
    await app.tg.handle(bot, cb(confirm));
    assert.equal(
      app.db.prepare("SELECT count(*) n FROM risk_history").get().n,
      2,
    );
    await app.tg.handle(bot, msg("/reset"));
    buttons = lastText().reply_markup.inline_keyboard[0];
    await app.tg.handle(bot, cb(buttons[1].callback_data));
    await app.tg.handle(bot, cb(buttons[0].callback_data));
    assert.equal(
      app.db
        .prepare("SELECT sum(daily_reset_at) n FROM subjects WHERE panel=?")
        .get(a.id).n,
      0,
    );
    await app.tg.handle(bot, msg("/reset"));
    const expires = lastText().reply_markup.inline_keyboard[0][0].callback_data;
    app.db.prepare("UPDATE tg_menu_confirm SET until=0").run();
    await app.tg.handle(bot, cb(expires));
    assert.equal(
      app.db
        .prepare("SELECT sum(daily_reset_at) n FROM subjects WHERE panel=?")
        .get(a.id).n,
      0,
    );
    app.tg.disconnect(a.id);
    await app.tg.handle(bot, cb(confirm));
    assert.equal(
      app.db.prepare("SELECT count(*) n FROM tg_menu_confirm").get().n,
      0,
    );
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
