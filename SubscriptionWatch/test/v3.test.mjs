import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  createHmac,
  randomBytes,
  createCipheriv,
  createHash,
  scryptSync,
} from "node:crypto";
import * as tar from "tar";
import { DatabaseSync } from "node:sqlite";
import { createApp } from "../server.mjs";
import {
  defaults,
  transaction,
  simplifyAccounts,
  migratePanelBots,
} from "../model.mjs";
import { evaluate } from "../risk.mjs";
import { assess } from "../assessment.mjs";
import { GeoDatabase } from "../geo.mjs";
import { restoreBackup } from "../restore.mjs";
const password = "my-test-password-123",
  user = {
    username: "owner",
    password,
    confirmPassword: password,
    adminPath: "private123",
  };
const listen = (s) =>
  new Promise((r) =>
    s.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${s.address().port}`)),
  );
const cookie = (r) => r.headers.get("set-cookie")?.split(";")[0];
async function fixture(fn, options = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-v3-"));
  let app = createApp({
      dataDir: dir,
      secureCookie: false,
      background: false,
      ...options,
    }),
    base = await listen(app.admin);
  const c = {
    dir,
    get app() {
      return app;
    },
    get base() {
      return base;
    },
    async request(route, body, auth) {
      return fetch(base + route, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Watch-Request": "1",
          Cookie: auth || "",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    },
    async api(route, body, auth) {
      const r = await c.request(route, body, auth);
      assert.equal(r.status, 200, await r.clone().text());
      return r.json();
    },
    async restart() {
      await app.close();
      app = createApp({
        dataDir: dir,
        secureCookie: false,
        background: false,
        ...options,
      });
      base = await listen(app.admin);
    },
  };
  try {
    await fn(c);
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
}
async function setup(c) {
  const r = await c.request("/api/setup", user);
  assert.equal(r.status, 200);
  return cookie(r);
}
async function panel(c, auth, name = "test") {
  const p = await c.api("/api/panels", { name }, auth),
    k = await c.api(`/api/panels/${p.id}/key`, {}, auth);
  return { ...p, ...k };
}
const event = (b = {}) => ({
  event_id: randomBytes(16).toString("hex"),
  ts: Date.now() - 1000,
  user_id: 1,
  email: "sample@example.com",
  ip: "1.1.1.1",
  peer_ip: "127.0.0.1",
  ip_source: "trusted_proxy",
  ua: "Shadowrocket/3445",
  flag: "",
  status: 200,
  ms: 4,
  bytes: null,
  ...b,
});
async function send(c, p, events, secret = p.collectorKey) {
  const body = JSON.stringify({
      schema: 1,
      version: "3.0.0",
      metrics: { pending: 0, dropped: 0, expired: 0 },
      events,
    }),
    timestamp = String(Math.floor(Date.now() / 1000));
  return fetch(c.base + "/api/collector/events", {
    method: "POST",
    headers: {
      "X-Watch-Panel": p.publicId,
      "X-Watch-Timestamp": timestamp,
      "X-Watch-Signature": createHmac("sha256", secret)
        .update(timestamp + "\n" + body)
        .digest("hex"),
    },
    body,
  });
}

test("首次设置、强制登录、禁止注册、退出和改密使旧会话失效", () =>
  fixture(async (c) => {
    const rs = await Promise.all([
      c.request("/api/setup", user),
      c.request("/api/setup", user),
    ]);
    assert.deepEqual(rs.map((r) => r.status).sort(), [200, 409]);
    let auth = cookie(rs.find((r) => r.status === 200));
    for (const route of [
      "/api/me",
      "/api/panels",
      "/api/admin/geo",
      "/app.js",
    ]) {
      assert.equal((await c.request(route)).status, 401);
      assert.equal(
        (await c.request(route, undefined, "watch=forged")).status,
        401,
      );
    }
    const page = await c.request("/");
    assert.match(page.headers.get("cache-control"), /no-store/);
    assert.match(await page.text(), /auth.js/);
    assert.doesNotMatch(
      await (await c.request("/")).text(),
      /id="historyTable"/,
    );
    assert.match(
      await (await c.request("/", undefined, auth)).text(),
      /id="historyTable"/,
    );
    assert.equal((await c.request("/api/register", user)).status, 404);
    await c.api("/api/logout", {}, auth);
    assert.equal((await c.request("/api/me", undefined, auth)).status, 401);
    auth = cookie(await c.request("/api/login", user));
    await c.api(
      "/api/password",
      {
        currentPassword: password,
        newPassword: "changed-password-123",
        confirmPassword: "changed-password-123",
      },
      auth,
    );
    assert.equal((await c.request("/api/me", undefined, auth)).status, 401);
    assert.equal((await c.request("/api/login", user)).status, 401);
    await c.restart();
    assert.equal((await c.api("/api/setup/status")).needsSetup, false);
    assert.equal(
      (
        await c.request("/api/login", {
          username: "owner",
          password: "changed-password-123",
        })
      ).status,
      200,
    );
  }));

test("账号、面板、密钥、同名用户隔离；签名、原子性和重试去重", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      a = await panel(c, auth),
      b = await panel(c, auth, "second");
    const own = await panel(c, auth, "third");
    assert.equal((await send(c, a, [event()], own.collectorKey)).status, 401);
    assert.equal(
      (await send(c, a, [event(), event({ ip: "fake" })])).status,
      422,
    );
    assert.equal(c.app.db.prepare("SELECT count(*) n FROM visits").get().n, 0);
    const e = event();
    assert.equal((await send(c, a, [e])).status, 200);
    assert.equal((await (await send(c, a, [e])).json()).duplicates, 1);
    assert.equal(
      (await send(c, b, [{ ...e, email: "other@example.com" }])).status,
      200,
    );
    assert.equal(
      (await c.api(`/api/panels/${a.id}/events`, undefined, auth)).rows[0]
        .email,
      "sample@example.com",
    );
    assert.equal(
      (await c.api(`/api/panels/${b.id}/events`, undefined, auth)).rows[0]
        .email,
      "other@example.com",
    );
    c.app.db.exec(
      "CREATE TRIGGER fail_test BEFORE INSERT ON visits BEGIN SELECT RAISE(ABORT,'disk full'); END",
    );
    const failed = event({ user_id: 999 });
    assert.equal((await send(c, a, [failed])).status, 503);
    assert.equal(
      c.app.db.prepare("SELECT count(*) n FROM subjects WHERE uid=999").get().n,
      0,
    );
    c.app.db.exec("DROP TRIGGER fail_test");
    assert.equal((await send(c, a, [failed])).status, 200);
    assert.equal(
      (await c.api("/api/panels?all=1", undefined, auth)).rows.length,
      3,
    );
  }));

test("三条风险规则、滚动阈值、白名单和去重通知", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      now = Date.now();
    await send(
      c,
      p,
      Array.from({ length: 4 }, (_, i) =>
        event({ ip: `1.1.1.${i + 1}`, ts: now - 10000 + i }),
      ),
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      0,
    );
    await send(c, p, [event({ ip: "1.1.1.5" })]);
    let risks = (await c.api(`/api/panels/${p.id}/risks`, undefined, auth))
      .rows;
    assert.deepEqual(
      risks[0].reasons.map((r) => r.code),
      ["ip", "rate"],
    );
    const count = c.app.db.prepare("SELECT count(*) n FROM outbox").get().n;
    await send(c, p, [event()]);
    assert.equal(
      c.app.db.prepare("SELECT count(*) n FROM outbox").get().n,
      count,
    );
    await send(c, p, [event({ ua: "Mozilla/5.0" })]);
    assert.ok(
      (
        await c.api(`/api/panels/${p.id}/risks`, undefined, auth)
      ).rows[0].reasons.some((r) => r.code === "ua"),
    );
    await c.api(
      `/api/panels/${p.id}/whitelist`,
      { uid: 1, email: "sample@example.com", enabled: true },
      auth,
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      0,
    );
    await send(c, p, [event({ ua: "" })]);
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      0,
    );
    await c.api(
      `/api/panels/${p.id}/whitelist`,
      { uid: 1, enabled: false },
      auth,
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      1,
    );
  }));

test("取消后旧请求不再触发，新增异常再次触发；清空访问记录保留风险与评估历史", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    const old = event({ ua: "browser" });
    await send(c, p, [old]);
    await c.api(`/api/panels/${p.id}/resolve`, { uid: 1 }, auth);
    await send(c, p, [event({ ts: old.ts, ua: "browser" })]);
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      0,
    );
    await new Promise((r) => setTimeout(r, 5));
    await send(c, p, [event({ ts: Date.now(), ua: "browser" })]);
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      1,
    );
    const histories = c.app.db
      .prepare("SELECT count(*) n FROM risk_history")
      .get().n;
    await c.api(`/api/panels/${p.id}/history/clear`, { confirm: true }, auth);
    assert.equal(
      (await c.api(`/api/panels/${p.id}/events`, undefined, auth)).total,
      0,
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      1,
    );
    assert.equal(
      c.app.db.prepare("SELECT count(*) n FROM risk_history").get().n,
      histories,
    );
    assert.equal((await (await send(c, p, [old])).json()).discarded, 1);
    transaction(c.app.db, () =>
      evaluate(
        c.app.db,
        c.app.db.prepare("SELECT * FROM panels WHERE id=?").get(p.id),
        1,
        Date.now() + 86400001,
      ),
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      0,
    );
    assert.ok(
      c.app.db.prepare("SELECT count(*) n FROM risk_history").get().n >
        histories,
    );
    await c.api(`/api/panels/${p.id}/risk-delete`, { password, uid: 1 }, auth);
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks?all=1`, undefined, auth)).rows
        .length,
      0,
    );
    await c.api(
      `/api/panels/${p.id}/risk-history/delete`,
      { password, all: true, confirm: "删除风险评估历史" },
      auth,
    );
    assert.equal(
      c.app.db.prepare("SELECT count(*) n FROM risk_history").get().n,
      0,
    );
  }));

test("频率规则在边界到期，合法UA大小写匹配、规则修改和CSV转义", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    await c.api(
      `/api/panels/${p.id}/settings`,
      {
        name: "test",
        notify: true,
        rules: { ...defaults, uaKeywords: ["netflow"], ipEnabled: false },
      },
      auth,
    );
    const now = Date.now();
    await send(
      c,
      p,
      Array.from({ length: 5 }, () =>
        event({ ts: now - 3599000, ua: "NETFLOW/1", email: "=SUM(1)" }),
      ),
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows[0]
        .reasons[0].code,
      "rate",
    );
    evaluate(
      c.app.db,
      c.app.db.prepare("SELECT * FROM panels WHERE id=?").get(p.id),
      1,
      now + 1000,
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      0,
    );
    const csv = await (
      await c.request(`/api/panels/${p.id}/export`, undefined, auth)
    ).text();
    assert.ok(csv.includes("'=SUM(1)"));
    assert.ok(!csv.includes("客户端推测"));
    assert.equal(
      (
        await c.request(
          `/api/panels/${p.id}/settings`,
          { name: "test", notify: true, rules: { ...defaults, rateLimit: 0 } },
          auth,
        )
      ).status,
      400,
    );
  }));

test("TG只能私聊绑定账户、不能跨面板查询，取消风险需要本人确认", () =>
  fixture(
    async (c) => {
      const auth = await setup(c),
        p = await panel(c, auth);
      await c.api(
        `/api/panels/${p.id}/telegram`,
        { token: "123456:abcdefghijklmnopqrstuvwxyz" },
        auth,
      );
      const binding = await c.api(
          `/api/panels/${p.id}/telegram/bind`,
          {},
          auth,
        ),
        code = binding.command.split(" ")[1];
      let bot = c.app.db.prepare("SELECT * FROM telegram").get();
      const msg = (id, text, type = "private") => ({
        message: { chat: { id, type }, from: { id }, text },
      });
      await c.app.tg.handle(bot, msg(22, "/start " + code, "group"));
      assert.equal(
        c.app.db.prepare("SELECT chat FROM telegram").get().chat,
        null,
      );
      await c.app.tg.handle(bot, msg(22, "/start " + code));
      bot = c.app.db.prepare("SELECT * FROM telegram").get();
      assert.equal(bot.chat, "22");
      const otherPanel = { id: 999999 };
      await c.app.tg.handle(bot, msg(22, "/select " + otherPanel.id));
      assert.equal(
        c.app.db.prepare("SELECT selected FROM telegram").get().selected,
        null,
      );
      await c.app.tg.handle(bot, msg(33, "/select " + p.id));
      assert.equal(
        c.app.db.prepare("SELECT selected FROM telegram").get().selected,
        null,
      );
      await c.app.tg.handle(bot, msg(22, "/select " + p.id));
      bot = c.app.db.prepare("SELECT * FROM telegram").get();
      await send(c, p, [event({ ua: "browser" })]);
      await c.app.tg.handle(bot, msg(22, "/resolve 1"));
      assert.equal(
        c.app.db.prepare("SELECT active FROM risks").get().active,
        1,
      );
      const confirm = c.app.db.prepare("SELECT * FROM tg_confirm").get();
      await c.app.tg.handle(bot, {
        callback_query: {
          id: "c",
          from: { id: 33 },
          data: confirm.code,
          message: { chat: { id: 33, type: "private" } },
        },
      });
      assert.equal(
        c.app.db.prepare("SELECT active FROM risks").get().active,
        1,
      );
      await c.app.tg.handle(bot, {
        callback_query: {
          id: "c",
          from: { id: 22 },
          data: confirm.code,
          message: { chat: { id: 22, type: "private" } },
        },
      });
      assert.equal(
        c.app.db.prepare("SELECT active FROM risks").get().active,
        0,
      );
    },
    {
      fetcher: async (url) =>
        new Response(
          JSON.stringify({
            ok: true,
            result: url.endsWith("getMe")
              ? { id: 123456, is_bot: true, username: "test_bot" }
              : url.endsWith("getWebhookInfo")
                ? { url: "" }
                : true,
          }),
        ),
    },
  ));

test("Geo设置仅管理员可访问，内网标注，下载失败保留旧状态并清理临时目录", () =>
  fixture(
    async (c) => {
      const auth = await setup(c);
      assert.equal(c.app.geo.lookup("127.0.0.1").country, "本机");
      assert.equal(c.app.geo.lookup("192.168.1.1").country, "内网 / 保留地址");
      await c.api(
        "/api/admin/geo/credentials",
        { accountId: "123", licenseKey: "a-valid-test-key" },
        auth,
      );
      assert.ok(
        !c.app.db
          .prepare("SELECT value FROM config WHERE key='maxmind'")
          .get()
          .value.includes("a-valid-test-key"),
      );
      const r = await c.request("/api/admin/geo/install", {}, auth);
      assert.equal(r.status, 202);
      await c.app.geo.task;
      assert.ok(c.app.geo.status().phase.includes("失败"));
      assert.deepEqual(readdirSync(path.join(c.dir, "geo")), []);
    },
    { fetcher: async () => new Response("", { status: 403 }) },
  ));

test("真实MMDB格式安装、校验失败回滚、更新后清理旧库与压缩包、重启读取", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      packs = {};
    for (const name of ["GeoLite2-City", "GeoLite2-ASN"]) {
      const folder = path.join(c.dir, name + "_test");
      mkdirSync(folder);
      writeFileSync(
        path.join(folder, name + ".mmdb"),
        readFileSync(
          new URL("./fixtures/" + name + "-Test.mmdb", import.meta.url),
        ),
      );
      const chunks = [];
      for await (const chunk of tar.c({ gzip: true, cwd: c.dir }, [
        name + "_test",
      ]))
        chunks.push(chunk);
      packs[name] = Buffer.concat(chunks);
    }
    let corrupt = false;
    c.app.geo.fetcher = async (url, { method } = {}) => {
      const name = url.includes("GeoLite2-City")
          ? "GeoLite2-City"
          : "GeoLite2-ASN",
        data = packs[name];
      if (method === "HEAD")
        return new Response(null, {
          headers: { "Last-Modified": "Wed, 16 Sep 2026 00:00:00 GMT" },
        });
      if (url.endsWith(".sha256"))
        return new Response(
          corrupt
            ? "0".repeat(64)
            : createHash("sha256").update(data).digest("hex"),
        );
      return new Response(data, {
        headers: { "Last-Modified": "Wed, 16 Sep 2026 00:00:00 GMT" },
      });
    };
    await c.api(
      "/api/admin/geo/credentials",
      { accountId: "123", licenseKey: "test-license-123" },
      auth,
    );
    const check = await c.app.geo.check();
    assert.equal(check.databases[0].available, true);
    c.app.geo.install();
    await c.app.geo.task;
    assert.ok(
      c.app.geo.status().phase.includes("成功"),
      c.app.geo.status().phase,
    );
    const first = c.app.geo.current.directory;
    assert.equal(readdirSync(path.join(c.dir, "geo", first)).length, 2);
    corrupt = true;
    c.app.geo.install();
    await c.app.geo.task;
    assert.equal(c.app.geo.current.directory, first);
    assert.equal(
      readdirSync(path.join(c.dir, "geo")).filter((s) => s.startsWith("stage"))
        .length,
      0,
    );
    corrupt = false;
    c.app.geo.install();
    await c.app.geo.task;
    assert.notEqual(c.app.geo.current.directory, first);
    assert.equal(existsSync(path.join(c.dir, "geo", first)), false);
    assert.equal((await c.app.geo.check()).databases[0].available, false);
    await c.restart();
    assert.equal(c.app.geo.status().phase, "就绪");
    assert.ok(c.app.geo.readers["GeoLite2-City"]);
  }));

test("旧版数据库迁移保留管理员、访问记录、采集密钥及清空边界，重启不重复迁移", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-migrate-")),
    master = randomBytes(32),
    iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", master, iv),
    secret = "a".repeat(64),
    salt = "test-salt";
  writeFileSync(path.join(dir, "master.key"), master);
  const encrypted = Buffer.concat([
    iv,
    cipher.update(secret),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
  const db = new DatabaseSync(path.join(dir, "watch.sqlite"));
  db.exec(
    `CREATE TABLE administrator(id INTEGER,username TEXT,password_hash TEXT);CREATE TABLE secrets(name TEXT,value TEXT);CREATE TABLE users(hash TEXT,user_id INTEGER,email TEXT);CREATE TABLE events(ts INTEGER,user_id INTEGER,email TEXT,ip TEXT,ua TEXT,peer_ip TEXT,ip_source TEXT,status INTEGER,ms INTEGER,bytes INTEGER);CREATE TABLE ingest_receipts(event_id TEXT,received_at INTEGER);CREATE TABLE collector_state(id INTEGER,cleared_at INTEGER);CREATE TABLE settings(id INTEGER,value TEXT);INSERT INTO collector_state VALUES(1,123);INSERT INTO users VALUES('collector:7',7,'old@example.com');INSERT INTO events VALUES(456,7,'old@example.com','1.1.1.1','Shadowrocket','127.0.0.1','peer',200,3,NULL);`,
  );
  db.prepare("INSERT INTO administrator VALUES(1,?,?)").run(
    "legacy",
    salt + ":" + scryptSync(password, salt, 64).toString("hex"),
  );
  db.prepare("INSERT INTO secrets VALUES(?,?)").run("collector", encrypted);
  db.close();
  let app;
  try {
    app = createApp({ dataDir: dir, secureCookie: false, background: false });
    let base = await listen(app.admin);
    assert.equal(app.db.prepare("SELECT count(*) n FROM visits").get().n, 1);
    assert.equal(
      app.db.prepare("SELECT cleared_at FROM panels").get().cleared_at,
      123,
    );
    const login = await fetch(base + "/api/login", {
      method: "POST",
      headers: { "X-Watch-Request": "1" },
      body: JSON.stringify({
        username: "legacy",
        password,
        adminPath: "manage",
      }),
    });
    assert.equal(login.status, 200);
    const key = await fetch(base + "/api/panels/1/key", {
      method: "POST",
      headers: { "X-Watch-Request": "1", Cookie: cookie(login) },
      body: "{}",
    });
    assert.equal((await key.json()).collectorKey, secret);
    await app.close();
    app = createApp({ dataDir: dir, secureCookie: false, background: false });
    assert.equal(app.db.prepare("SELECT count(*) n FROM accounts").get().n, 1);
    assert.equal(app.db.prepare("SELECT count(*) n FROM visits").get().n, 1);
  } finally {
    if (app) await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("配置导入鉴权、加密保存、格式校验及401提示", () =>
  fixture(
    async (c) => {
      const content =
        "AccountID 123456\nLicenseKey testing-license-key-123\nEditionIDs GeoLite2-City GeoLite2-ASN GeoLite2-Country";
      assert.equal(
        (await c.request("/api/admin/geo/import", { content })).status,
        401,
      );
      const auth = await setup(c);
      const result = await c.api("/api/admin/geo/import", { content }, auth);
      assert.equal(result.accountId, "123456");
      assert.doesNotMatch(JSON.stringify(result), /testing-license/);
      assert.doesNotMatch(
        JSON.stringify(await c.api("/api/admin/geo", undefined, auth)),
        /testing-license/,
      );
      for (const bad of [
        "AccountID 1",
        "AccountID 1\nLicenseKey YOUR_KEY",
        content + "\nAccountID 2",
      ])
        assert.equal(
          (await c.request("/api/admin/geo/import", { content: bad }, auth))
            .status,
          400,
        );
      const failed = await c.request("/api/admin/geo/check", {}, auth);
      assert.match(await failed.text(), /401/);
    },
    { fetcher: async () => new Response("", { status: 401 }) },
  ));

test("v3.0升级保留账号密码、面板密钥和历史，停用原普通账号", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    await send(c, p, [event({ ua: "browser" })]);
    const db = c.app.db;
    const original = db
      .prepare("SELECT password_hash FROM accounts WHERE id=1")
      .get().password_hash;
    db.prepare(
      "INSERT INTO accounts(id,username,password_hash,created) VALUES(2,?,?,?)",
    ).run("olduser", original, Date.now());
    db.prepare("UPDATE panels SET owner=2 WHERE id=?").run(p.id);
    db.prepare("DELETE FROM config WHERE key='singleAccountMode'").run();
    simplifyAccounts(db);
    assert.equal(
      db.prepare("SELECT owner FROM panels WHERE id=?").get(p.id).owner,
      1,
    );
    assert.equal(
      db.prepare("SELECT disabled FROM accounts WHERE id=2").get().disabled,
      1,
    );
    assert.equal(db.prepare("SELECT count(*) n FROM visits").get().n, 1);
    assert.equal(db.prepare("SELECT count(*) n FROM risk_history").get().n, 1);
    assert.equal(
      (await c.api(`/api/panels/${p.id}/key`, {}, auth)).collectorKey,
      p.collectorKey,
    );
    assert.equal(
      (await c.request("/api/login", { username: "olduser", password })).status,
      401,
    );
    await c.restart();
    assert.equal((await c.request("/api/login", user)).status, 200);
    assert.equal(c.app.db.prepare("SELECT count(*) n FROM visits").get().n, 1);
  }));

test("两个面板机器人独立绑定、通知、查询、确认和移除", async () => {
  const calls = [];
  await fixture(
    async (c) => {
      const auth = await setup(c),
        a = await panel(c, auth, "Panel A"),
        b = await panel(c, auth, "Panel B");
      const route = (p) => `/api/panels/${p.id}/telegram`;
      assert.equal(
        (await c.request(route(a), { token: "111:abcdefghijklmnopqrstuvwxyz" }))
          .status,
        401,
      );
      await c.api(route(a), { token: "111:abcdefghijklmnopqrstuvwxyz" }, auth);
      assert.equal(
        (
          await c.request(
            route(b),
            { token: "111:abcdefghijklmnopqrstuvwxyz" },
            auth,
          )
        ).status,
        400,
      );
      await c.api(route(b), { token: "222:abcdefghijklmnopqrstuvwxyz" }, auth);
      for (const p of [a, b]) {
        const binding = await c.api(route(p) + "/bind", {}, auth);
        const bot = c.app.db
          .prepare("SELECT * FROM telegram WHERE panel=?")
          .get(p.id);
        await c.app.tg.handle(bot, {
          message: {
            chat: { id: 22, type: "private" },
            from: { id: 22 },
            text: binding.command,
          },
        });
      }
      await send(c, a, [event({ ua: "browser", email: "a@example.com" })]);
      await send(c, b, [event({ ua: "browser", email: "b@example.com" })]);
      calls.length = 0;
      await c.app.tg.tick();
      const notifications = calls.filter((x) => x.method === "sendMessage");
      assert.equal(notifications.length, 2);
      assert.match(
        notifications.find((x) => x.bot === "111").data.text,
        /Panel A/,
      );
      assert.doesNotMatch(
        notifications.find((x) => x.bot === "111").data.text,
        /b@example.com/,
      );
      assert.match(
        notifications.find((x) => x.bot === "222").data.text,
        /Panel B/,
      );
      const botA = c.app.db
          .prepare("SELECT * FROM telegram WHERE panel=?")
          .get(a.id),
        botB = c.app.db
          .prepare("SELECT * FROM telegram WHERE panel=?")
          .get(b.id);
      const msg = (text) => ({
        message: { chat: { id: 22, type: "private" }, from: { id: 22 }, text },
      });
      await c.app.tg.handle(botA, msg("/select " + b.id));
      await c.app.tg.handle(botA, msg("/user 1"));
      assert.match(calls.at(-1).data.text, /a@example.com/);
      assert.doesNotMatch(calls.at(-1).data.text, /b@example.com/);
      await c.app.tg.handle(botA, msg("/resolve 1"));
      const confirm = c.app.db
        .prepare("SELECT * FROM tg_confirm WHERE panel=?")
        .get(a.id);
      const callback = {
        callback_query: {
          id: "test",
          from: { id: 22 },
          data: confirm.code,
          message: { chat: { id: 22, type: "private" } },
        },
      };
      await c.app.tg.handle(botB, callback);
      assert.equal(
        c.app.db.prepare("SELECT active FROM risks WHERE panel=?").get(a.id)
          .active,
        1,
      );
      await c.app.tg.handle(botA, callback);
      assert.equal(
        c.app.db.prepare("SELECT active FROM risks WHERE panel=?").get(a.id)
          .active,
        0,
      );
      assert.equal(
        c.app.db.prepare("SELECT active FROM risks WHERE panel=?").get(b.id)
          .active,
        1,
      );
      await c.api(route(a) + "/remove", {}, auth);
      assert.equal((await c.api(route(b), undefined, auth)).chat, "22");
      assert.equal((await c.api(route(a), undefined, auth)).bot_name, null);
      await c.restart();
      assert.equal(
        c.app.db.prepare("SELECT count(*) n FROM telegram").get().n,
        1,
      );
    },
    {
      fetcher: async (url, options) => {
        const bot = url.match(/bot(\d+):/)[1],
          method = url.split("/").at(-1),
          data = JSON.parse(options.body);
        calls.push({ bot, method, data });
        const result =
          method === "getMe"
            ? { id: Number(bot), is_bot: true, username: "bot_" + bot }
            : method === "getWebhookInfo"
              ? { url: "" }
              : method === "getUpdates"
                ? []
                : true;
        return new Response(JSON.stringify({ ok: true, result }));
      },
    },
  );
});

test("旧机器人优先迁移到已选面板，未选择则迁移第一个，重启不重复", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      a = await panel(c, auth),
      b = await panel(c, auth, "second");
    const db = c.app.db;
    db.exec(
      "DROP TABLE telegram; ALTER TABLE telegram_legacy RENAME TO telegram",
    );
    db.prepare(
      "INSERT INTO telegram(account,token,bot_id,bot_name,chat,selected) VALUES(1,?,?,?,?,?)",
    ).run("encrypted", "111", "oldbot", "22", b.id);
    migratePanelBots(db);
    assert.equal(db.prepare("SELECT panel FROM telegram").get().panel, b.id);
    assert.equal(db.prepare("SELECT chat FROM telegram").get().chat, "22");
    db.exec(
      "DROP TABLE telegram; ALTER TABLE telegram_legacy RENAME TO telegram; UPDATE telegram SET selected=NULL",
    );
    migratePanelBots(db);
    assert.equal(db.prepare("SELECT panel FROM telegram").get().panel, a.id);
    migratePanelBots(db);
    assert.equal(db.prepare("SELECT count(*) n FROM telegram").get().n, 1);
  }));

test("TG超时或数字错误码不会中断服务及登录会话", async () => {
  for (const failure of [
    new DOMException("timeout", "TimeoutError"),
    Object.assign(new Error("numeric error"), { code: 23 }),
  ]) {
    await fixture(
      async (c) => {
        const auth = await setup(c),
          p = await panel(c, auth);
        const response = await c.request(
          `/api/panels/${p.id}/telegram`,
          { token: "111:abcdefghijklmnopqrstuvwxyz" },
          auth,
        );
        assert.equal(response.status, 400);
        assert.match((await response.json()).error, /Telegram/);
        assert.equal((await c.request("/api/me", undefined, auth)).status, 200);
        assert.equal((await c.api("/healthz")).ok, true);
      },
      {
        fetcher: async () => {
          throw failure;
        },
      },
    );
  }
});

test("白名单精确核对、只显示主动添加用户、邮箱变化撤销豁免", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    assert.equal(
      (
        await c.request(
          url + "/whitelist",
          { uid: 99, email: "fake@example.com", enabled: true },
          auth,
        )
      ).status,
      400,
    );
    await send(c, p, [event()]);
    assert.equal(
      (await c.api(url + "/subjects", undefined, auth)).rows.length,
      0,
    );
    assert.equal(
      (
        await c.request(
          url + "/whitelist",
          { uid: 1, email: "wrong@example.com", enabled: true },
          auth,
        )
      ).status,
      400,
    );
    await c.api(
      url + "/whitelist",
      { uid: 1, email: "sample@example.com", enabled: true },
      auth,
    );
    assert.equal(
      (await c.api(url + "/subjects", undefined, auth)).rows.length,
      1,
    );
    await send(c, p, [event({ email: "changed@example.com" })]);
    assert.equal(
      (await c.api(url + "/subjects", undefined, auth)).rows.length,
      0,
    );
  }));

test("三级风险、中国IP和云组织规则、IP及Cloudflare请求豁免、到期降级", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    c.app.geo.lookup = (ip) => ({
      countryCode: ip.startsWith("1.") ? "CN" : "US",
      organization: ip.startsWith("2.")
        ? "Tencent Cloud"
        : ip.startsWith("3.")
          ? "Cloudflare, Inc."
          : "ISP",
    });
    const rows = async () =>
      (await c.api(url + "/risks", undefined, auth)).rows;
    await send(c, p, [event({ ua: "browser" })]);
    assert.equal((await rows())[0].level, "low");
    await send(
      c,
      p,
      Array.from({ length: 4 }, () => event({ ip: "4.0.0.1" })),
    );
    assert.equal((await rows())[0].level, "medium");
    await send(c, p, [event({ ip: "1.1.1.2" }), event({ ip: "1.1.1.3" })]);
    assert.equal((await rows())[0].level, "high");
    await send(c, p, [
      event({ user_id: 2, ip: "2.0.0.1" }),
      event({ user_id: 2, ip: "2.0.0.2" }),
      event({ user_id: 2, ip: "2.0.0.3" }),
    ]);
    assert.equal((await rows()).find((x) => x.uid === 2).level, "medium");
    await send(c, p, [event({ user_id: 3, ip: "3.0.0.1", ua: "browser" })]);
    const rules = {
      ...defaults,
      cloudflareExempt: true,
      ipWhitelist: ["2.0.0.1", "2.0.0.2", "2.0.0.3"],
    };
    await c.api(url + "/settings", { name: "test", notify: true, rules }, auth);
    assert.deepEqual(
      (await rows()).map((x) => x.uid),
      [1],
    );
    assert.equal((await c.api(url + "/events", undefined, auth)).total, 11);
    const stored = c.app.db
      .prepare("SELECT * FROM panels WHERE id=?")
      .get(p.id);
    evaluate(c.app.db, stored, 1, Date.now() + 11 * 60000, c.app.geo);
    assert.equal((await rows())[0].level, "medium");
    await send(c, p, [event({ user_id: 3, ip: "4.0.0.1", ua: "browser" })]);
    assert.equal((await rows()).find((x) => x.uid === 3).level, "low");
  }));

test("定时清理只删到期访问记录，手动清理只需确认按钮", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    await send(c, p, [event({ ua: "browser" }), event({ user_id: 2 })]);
    c.app.db
      .prepare("UPDATE visits SET ts=? WHERE uid=2")
      .run(Date.now() - 3 * 86400000);
    await c.api(
      url + "/settings",
      { name: "test", notify: true, rules: { ...defaults, retentionDays: 1 } },
      auth,
    );
    c.app.maintenance();
    assert.equal((await c.api(url + "/events", undefined, auth)).total, 1);
    assert.equal((await c.api(url + "/risks", undefined, auth)).rows.length, 1);
    const history = (await c.api(url + "/risk-history", undefined, auth)).rows
      .length;
    assert.equal(
      (await c.request(url + "/history/clear", {}, auth)).status,
      400,
    );
    await c.api(url + "/history/clear", { confirm: true }, auth);
    assert.equal(
      (await c.api(url + "/risk-history", undefined, auth)).rows.length,
      history,
    );
    assert.equal((await c.api(url + "/events", undefined, auth)).total, 0);
  }));

test("TG Token和个人ID直接绑定，验证失败保留旧设置及会话", () =>
  fixture(
    async (c) => {
      const auth = await setup(c),
        p = await panel(c, auth),
        url = `/api/panels/${p.id}/telegram`;
      await c.api(
        url,
        { token: "111:abcdefghijklmnopqrstuvwxyz", chatId: "22" },
        auth,
      );
      assert.equal((await c.api(url, undefined, auth)).chat, "22");
      assert.equal(
        (
          await c.request(
            url,
            { token: "111:abcdefghijklmnopqrstuvwxyz", chatId: "-100123" },
            auth,
          )
        ).status,
        400,
      );
      assert.equal(
        (
          await c.request(
            url,
            { token: "111:abcdefghijklmnopqrstuvwxyz", chatId: "33" },
            auth,
          )
        ).status,
        400,
      );
      assert.equal((await c.api(url, undefined, auth)).chat, "22");
      assert.equal((await c.request("/api/me", undefined, auth)).status, 200);
    },
    {
      fetcher: async (url, opts) =>
        new Response(
          JSON.stringify({
            ok: true,
            result: url.endsWith("getMe")
              ? { id: 111, is_bot: true, username: "test" }
              : url.endsWith("getWebhookInfo")
                ? { url: "" }
                : JSON.parse(opts.body).chat_id === "22"
                  ? { id: 22, type: "private" }
                  : { id: 33, type: "group" },
          }),
        ),
    },
  ));

test("TG上游返回HTML错误页仍返回JSON错误并保留登录会话", () =>
  fixture(
    async (c) => {
      const auth = await setup(c),
        p = await panel(c, auth);
      const r = await c.request(
        `/api/panels/${p.id}/telegram`,
        { token: "111:abcdefghijklmnopqrstuvwxyz", chatId: "22" },
        auth,
      );
      assert.equal(r.status, 400);
      assert.match((await r.json()).error, /Telegram/);
      assert.equal((await c.request("/api/me", undefined, auth)).status, 200);
    },
    {
      fetcher: async () =>
        new Response("<!DOCTYPE html><h1>502</h1>", {
          status: 502,
          headers: { "Content-Type": "text/html" },
        }),
    },
  ));

async function control(c, p, extra = {}, secret = p.collectorKey) {
  const b = {
    schema: 1,
    capability: "ban-v1",
    version: "3.4.0",
    nonce: randomBytes(24).toString("hex"),
    acceptTasks: true,
    results: [],
    ...extra,
  };
  const raw = JSON.stringify(b),
    ts = String(Math.floor(Date.now() / 1000));
  const r = await fetch(c.base + "/api/collector/control", {
    method: "POST",
    headers: {
      "X-Watch-Panel": p.publicId,
      "X-Watch-Timestamp": ts,
      "X-Watch-Signature": createHmac("sha256", secret)
        .update("control-request\n" + ts + "\n" + raw)
        .digest("hex"),
    },
    body: raw,
  });
  const envelope = await r.json();
  if (!r.ok) return { status: r.status, error: envelope.error };
  assert.equal(
    envelope.signature,
    createHmac("sha256", p.collectorKey)
      .update("control-response\n" + envelope.payload)
      .digest("hex"),
  );
  const data = JSON.parse(Buffer.from(envelope.payload, "base64").toString());
  assert.equal(data.nonce, b.nonce);
  assert.equal(data.panel, p.publicId);
  return { status: r.status, ...data };
}
async function highRisk(c, p, uid = 1) {
  c.app.geo.lookup = () => ({ countryCode: "CN", organization: "ISP" });
  await send(c, p, [
    event({ user_id: uid }),
    event({ user_id: uid, ip: "1.1.1.2" }),
    event({ user_id: uid, ip: "1.1.1.3" }),
    event({ user_id: uid, ip: "1.1.1.4" }),
    event({ user_id: uid, ip: "1.1.1.5" }),
  ]);
}

test("插件控制签名、nonce防重放、未连接禁止开启、默认不开启", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}/ban`;
    await highRisk(c, p);
    assert.equal(
      (await c.request(url, { enabled: true, observeMinutes: 0 }, auth)).status,
      400,
    );
    assert.equal((await control(c, p, {}, "wrong-secret")).status, 401);
    const nonce = randomBytes(24).toString("hex");
    assert.equal((await control(c, p, { nonce })).tasks.length, 0);
    assert.equal((await control(c, p, { nonce })).status, 400);
    assert.equal((await c.api(url, undefined, auth)).connected, true);
    assert.equal((await c.api(url, undefined, auth)).enabled, false);
    await c.api(url, { enabled: true, observeMinutes: 0 }, auth);
    assert.equal((await c.api(url, undefined, auth)).enabled, true);
  }));

test("高风险任务仅下发一次、结果重传幂等、不同面板拒绝回执串用", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      a = await panel(c, auth),
      b = await panel(c, auth, "B");
    await highRisk(c, a);
    await highRisk(c, b);
    await control(c, a);
    await control(c, b);
    await c.api(
      `/api/panels/${a.id}/ban`,
      { enabled: true, observeMinutes: 0 },
      auth,
    );
    const first = await control(c, a);
    assert.equal(first.tasks.length, 1);
    const task = first.tasks[0];
    assert.equal(task.user_id, 1);
    assert.equal(task.email, "sample@example.com");
    assert.equal(task.action, "ban");
    assert.ok(task.expires > Date.now());
    assert.equal((await control(c, a)).tasks.length, 0);
    assert.equal(
      (await control(c, b, { results: [{ id: task.id, status: "banned" }] }))
        .acknowledged.length,
      0,
    );
    const receipt = { id: task.id, status: "banned" };
    assert.deepEqual(
      (await control(c, a, { results: [receipt], acceptTasks: false }))
        .acknowledged,
      [task.id],
    );
    await control(c, a, { results: [receipt] });
    const status = await c.api(`/api/panels/${a.id}/ban`, undefined, auth);
    assert.equal(status.history.length, 1);
    assert.equal(status.history[0].status, "已封禁");
    await c.restart();
    assert.equal((await control(c, a)).tasks.length, 0);
  }));

test("豁免或关闭开关不派发任务；任务过期未知不重发但接受迟到结果", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    await highRisk(c, p);
    await control(c, p);
    await c.api(url + "/ban", { enabled: true, observeMinutes: 0 }, auth);
    await c.api(
      url + "/whitelist",
      { uid: 1, email: "sample@example.com", enabled: true },
      auth,
    );
    assert.equal((await control(c, p)).tasks.length, 0);
    await c.api(url + "/whitelist", { uid: 1, enabled: false }, auth);
    await c.api(url + "/ban", { enabled: false }, auth);
    assert.equal((await control(c, p)).tasks.length, 0);
    await c.api(url + "/ban", { enabled: true, observeMinutes: 0 }, auth);
    const task = (await control(c, p)).tasks[0];
    c.app.db
      .prepare("UPDATE ban_tasks SET expires=? WHERE token=?")
      .run(Date.now() - 1, task.id);
    await c.app.bans.tick();
    assert.equal(c.app.bans.status(p.id).history[0].status, "失败或待核对");
    assert.equal((await control(c, p)).tasks.length, 0);
    await control(c, p, { results: [{ id: task.id, status: "expired" }] });
    assert.equal(c.app.bans.status(p.id).history[0].status, "已取消");
  }));

test("v3.3管理员API凭据清除，升级关闭封禁但保留旧执行历史", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    c.app.db
      .prepare(
        "INSERT INTO ban_settings(panel,enabled,base,prefix,auth) VALUES(?,1,?,?,?)",
      )
      .run(
        p.id,
        "https://example.com",
        "/api/v2/manage/user",
        "encrypted-old-secret",
      );
    c.app.db
      .prepare(
        "INSERT INTO ban_actions(panel,uid,episode,status,message,created,updated) VALUES(?,1,1,'已封禁','old',1,1)",
      )
      .run(p.id);
    c.app.db.prepare("DELETE FROM config WHERE key='pluginBansV34'").run();
    await c.restart();
    const row = c.app.db
      .prepare("SELECT * FROM ban_settings WHERE panel=?")
      .get(p.id);
    assert.equal(row.enabled, 0);
    assert.equal(row.auth, null);
    assert.equal(row.base, null);
    assert.equal(c.app.bans.status(p.id).history[0].status, "已封禁");
  }));

test("自有节点排除地域组织计数，但UA与频率照常评估；证据保留归属和UA", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    c.app.geo.lookup = () => ({
      countryCode: "CN",
      country: "中国",
      organization: "Tencent Cloud",
    });
    const ips = ["1.1.1.1", "1.1.1.2", "1.1.1.3"];
    await c.api(
      url + "/settings",
      { name: "test", notify: true, rules: { ...defaults, ownedIps: ips } },
      auth,
    );
    await send(
      c,
      p,
      ips.map((ip) => event({ ip, ua: "Browser" })),
    );
    let row = (await c.api(url + "/risks", undefined, auth)).rows[0];
    assert.equal(row.level, "low");
    assert.equal(row.reasons[0].evidence[0].owned, true);
    assert.equal(row.reasons[0].evidence[0].geo.organization, "Tencent Cloud");
    assert.equal(row.reasons[0].evidence[0].ua, "Browser");
    await send(c, p, [event(), event()]);
    assert.equal(
      (await c.api(url + "/risks", undefined, auth)).rows[0].level,
      "low",
    );
    c.app.geo.lookup = (ip) => ({
      countryCode: ip.startsWith("4.") ? "US" : "CN",
      country: "测试",
      organization: "Tencent Cloud",
    });
    await send(c, p, [event({ ip: "4.0.0.1" }), event({ ip: "4.0.0.1" })]);
    row = (await c.api(url + "/risks", undefined, auth)).rows[0];
    assert.equal(row.level, "medium");
    assert.equal(row.reasons.find((x) => x.code === "rate").threshold, 5);
    assert.equal(row.reasons.find((x) => x.code === "rate").windowMinutes, 60);
    assert.equal(
      (
        await c.request(
          url + "/settings",
          {
            name: "test",
            notify: true,
            rules: { ...defaults, ownedIps: ["*"] },
          },
          auth,
        )
      ).status,
      400,
    );
  }));

test("观察期默认30分钟，持续高风险到期才执行；降级重置，重启保留", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}/ban`;
    await highRisk(c, p);
    await control(c, p);
    assert.equal((await c.api(url, undefined, auth)).observeMinutes, 30);
    await c.api(url, { enabled: true }, auth);
    assert.equal((await control(c, p)).tasks.length, 0);
    const stored = c.app.db
      .prepare("SELECT * FROM panels WHERE id=?")
      .get(p.id);
    c.app.geo.lookup = () => ({ countryCode: "US", organization: "ISP" });
    evaluate(c.app.db, stored, 1, Date.now(), c.app.geo);
    assert.equal(
      c.app.db.prepare("SELECT count(*) n FROM risk_observation").get().n,
      0,
    );
    await highRisk(c, p);
    c.app.db
      .prepare("UPDATE risk_observation SET since=?")
      .run(Date.now() - 31 * 60000);
    c.app.db
      .prepare("UPDATE ban_settings SET since=?")
      .run(Date.now() - 31 * 60000);
    await c.restart();
    c.app.geo.lookup = () => ({ countryCode: "CN", organization: "ISP" });
    assert.equal((await control(c, p)).tasks.length, 1);
  }));

test("手动解封要求新插件、已知ID邮箱、鉴权；不依赖封禁开关且回执幂等", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}/unban`;
    await highRisk(c, p);
    await control(c, p);
    const data = { uid: 1, email: "sample@example.com" };
    assert.equal((await c.request(url, data)).status, 401);
    assert.equal((await c.request(url, data, auth)).status, 400);
    await control(c, p, { capability: "ban-v2" });
    assert.equal(
      (await c.request(url, { ...data, email: "wrong@example.com" }, auth))
        .status,
      400,
    );
    await c.api(url, data, auth);
    assert.equal((await c.request(url, data, auth)).status, 400);
    assert.equal((await control(c, p)).tasks.length, 0); // Old plugin never receives unban.
    const result = await control(c, p, { capability: "ban-v2" }),
      task = result.tasks[0];
    assert.equal(task.action, "unban");
    assert.equal(
      (await control(c, p, { capability: "ban-v2" })).tasks.length,
      0,
    );
    await control(c, p, {
      capability: "ban-v2",
      results: [{ id: task.id, status: "unbanned" }],
    });
    await control(c, p, {
      capability: "ban-v2",
      results: [{ id: task.id, status: "unbanned" }],
    });
    assert.equal(c.app.bans.status(p.id).history[0].status, "已解封");
    assert.equal(
      c.app.db
        .prepare(
          "SELECT count(*) n FROM outbox WHERE json_extract(payload,'$.kind')='action'",
        )
        .get().n,
      1,
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/risks`, undefined, auth)).rows.length,
      0,
    );
  }));

test("风险通知队列合并为最新等级，解除风险后操作结果仍通知", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    await send(c, p, [event({ ua: "Browser" })]);
    await highRisk(c, p);
    assert.equal(c.app.db.prepare("SELECT count(*) n FROM outbox").get().n, 1);
    const data = JSON.parse(
      c.app.db.prepare("SELECT payload FROM outbox").get().payload,
    );
    assert.ok(data.reasons.some((r) => r.code === "china"));
    await highRisk(c, p);
    assert.equal(c.app.db.prepare("SELECT count(*) n FROM outbox").get().n, 1);
    c.app.bans.notifyAction({
      panel: p.id,
      uid: 1,
      kind: "unban",
      status: "已解封",
      message: "done",
    });
    await c.api(`/api/panels/${p.id}/resolve`, { uid: 1 }, auth);
    assert.equal(c.app.db.prepare("SELECT count(*) n FROM outbox").get().n, 1);
    c.app.db
      .prepare(
        "INSERT INTO telegram(panel,account,token,bot_id,chat) VALUES(?,1,'test','1','22')",
      )
      .run(p.id);
    c.app.tg.decrypt = () => "test";
    const sent = [];
    c.app.tg.call = async (secret, method, body) => {
      if (method === "getUpdates") return [];
      if (method === "sendMessage") {
        sent.push(body.text);
        return { message_id: 1 };
      }
      return {};
    };
    await c.app.tg.tick();
    assert.equal(sent.length, 1);
    assert.match(sent[0], /已解封/);
  }));

test("完整备份需登录，恢复保留账号密钥面板；损坏包拒绝且原数据不变", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    await highRisk(c, p);
    await control(c, p);
    await c.api(`/api/panels/${p.id}/ban`, { enabled: true }, auth);
    const geoDir = "db-" + randomBytes(24).toString("hex");
    mkdirSync(path.join(c.dir, "geo", geoDir));
    for (const name of ["GeoLite2-City", "GeoLite2-ASN"])
      writeFileSync(
        path.join(c.dir, "geo", geoDir, name + ".mmdb"),
        readFileSync(
          new URL("./fixtures/" + name + "-Test.mmdb", import.meta.url),
        ),
      );
    c.app.geo.current = { directory: geoDir };
    writeFileSync(
      path.join(c.dir, "geo/current.json"),
      JSON.stringify(c.app.geo.current),
    );
    assert.equal((await c.request("/api/backup")).status, 401);
    const response = await c.request("/api/backup", undefined, auth);
    assert.equal(response.status, 200);
    const external = mkdtempSync(path.join(tmpdir(), "watch-restore-"));
    try {
      const archive = path.join(external, "backup.tar.gz"),
        target = path.join(external, "restored");
      writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
      mkdirSync(target);
      writeFileSync(path.join(target, "old.txt"), "preserve me");
      const previous = await restoreBackup(archive, target);
      assert.equal(
        readFileSync(path.join(previous, "old.txt"), "utf8"),
        "preserve me",
      );
      const app = createApp({
        dataDir: target,
        secureCookie: false,
        background: false,
      });
      const base = await listen(app.admin);
      try {
        const login = await fetch(base + "/api/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Watch-Request": "1",
          },
          body: JSON.stringify(user),
        });
        assert.equal(login.status, 200);
        const key = await fetch(base + `/api/panels/${p.id}/key`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Watch-Request": "1",
            Cookie: cookie(login),
          },
          body: "{}",
        });
        assert.equal((await key.json()).collectorKey, p.collectorKey);
        assert.equal(
          app.db.prepare("SELECT count(*) n FROM visits").get().n,
          5,
        );
        assert.equal(app.bans.status(p.id).enabled, false);
        assert.ok(app.geo.readers["GeoLite2-City"]);
        assert.ok(app.geo.readers["GeoLite2-ASN"]);
      } finally {
        await app.close();
      }
      const before = readFileSync(path.join(target, "master.key"));
      const unpack = path.join(external, "unpacked");
      mkdirSync(unpack);
      await tar.x({ file: archive, cwd: unpack });
      writeFileSync(path.join(unpack, "master.key"), "broken");
      const manifest = JSON.parse(
        readFileSync(path.join(unpack, "manifest.json")),
      );
      const bad = path.join(external, "bad.tar.gz");
      await tar.c({ cwd: unpack, file: bad, gzip: true }, [
        ...Object.keys(manifest.files),
        "manifest.json",
      ]);
      await assert.rejects(restoreBackup(bad, target), /校验失败/);
      assert.deepEqual(readFileSync(path.join(target, "master.key")), before);
    } finally {
      rmSync(external, { recursive: true, force: true });
    }
  }));

test("采集健康区分未连接、正常和过期，旧版失败计数不冒充零", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}/status`;
    assert.equal((await c.api(url, undefined, auth)).panel.health, "尚未上报");
    await send(c, p, []);
    assert.equal((await c.api(url, undefined, auth)).panel.health, "正常");
    assert.equal((await c.api(url, undefined, auth)).panel.failures, null);
    c.app.db
      .prepare("UPDATE panels SET last_seen=? WHERE id=?")
      .run(Date.now() - 181000, p.id);
    assert.match((await c.api(url, undefined, auth)).panel.health, /中断/);
  }));

async function importWeb(c, auth, bytes, confirmed = true) {
  return fetch(c.base + "/api/backup/import", {
    method: "POST",
    headers: {
      "Content-Type": "application/gzip",
      "X-Watch-Request": "1",
      "X-Watch-Confirm": confirmed ? "restore" : "",
      Cookie: auth || "",
    },
    body: bytes,
  });
}
test("频率统计按国内IP与完整UA去重、白名单排除，国外及未知IP逐次计算", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    await c.api(
      url + "/settings",
      {
        name: "test",
        notify: true,
        rules: {
          ...defaults,
          uaEnabled: false,
          ipEnabled: false,
          chinaEnabled: false,
          dcEnabled: false,
          ipWhitelist: ["2.2.2.2"],
        },
      },
      auth,
    );
    c.app.geo.lookup = (ip) =>
      ip.startsWith("1.")
        ? { countryCode: "CN" }
        : ip.startsWith("3.")
          ? { countryCode: "US" }
          : {};
    await send(
      c,
      p,
      Array.from({ length: 8 }, () => event({ ip: "1.1.1.1" })),
    );
    await send(
      c,
      p,
      Array.from({ length: 8 }, () => event({ ip: "2.2.2.2" })),
    );
    assert.equal((await c.api(url + "/risks", undefined, auth)).rows.length, 0);
    await send(c, p, [
      event({ ip: "3.3.3.3" }),
      event({ ip: "3.3.3.3" }),
      event({ ip: "4.4.4.4" }),
    ]);
    assert.equal((await c.api(url + "/risks", undefined, auth)).rows.length, 0);
    await send(c, p, [event({ ip: "4.4.4.4" })]);
    const reason = (await c.api(url + "/risks", undefined, auth)).rows[0]
      .reasons[0];
    assert.equal(reason.code, "rate");
    assert.equal(reason.count, 5);
    assert.equal(reason.rawCount, 12);
    await send(
      c,
      p,
      Array.from({ length: 8 }, () => event({ user_id: 2, ip: "1.1.1.1" })),
    );
    assert.equal((await c.api(url + "/risks", undefined, auth)).rows.length, 1);
    await send(c, p, [
      event({ user_id: 2, ua: "Shadowrocket/3446" }),
      event({ user_id: 2, ua: "shadowrocket/3445" }),
      event({ user_id: 2, ua: "NetFlow/1" }),
    ]);
    assert.equal((await c.api(url + "/risks", undefined, auth)).rows.length, 1);
    await send(c, p, [event({ user_id: 2, ua: "Clash/1" })]);
    const second = (await c.api(url + "/risks", undefined, auth)).rows.find(
      (r) => r.uid === 2,
    );
    assert.equal(second.reasons[0].count, 5);
    assert.equal(second.reasons[0].rawCount, 12);
  }));

test("风险页面手动封禁跳过观察期、支持旧控制插件、鉴权及白名单检查", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    await highRisk(c, p);
    await control(c, p);
    const input = { uid: 1, email: "sample@example.com", confirm: true };
    assert.equal((await c.request(url + "/ban/manual", input)).status, 401);
    assert.equal(
      (await c.request(url + "/ban/manual", { ...input, confirm: false }, auth))
        .status,
      400,
    );
    assert.equal(
      (
        await c.request(
          url + "/ban/manual",
          { ...input, email: "wrong@example.com" },
          auth,
        )
      ).status,
      400,
    );
    await c.api(url + "/ban/manual", input, auth);
    assert.equal(
      (await c.request(url + "/ban/manual", input, auth)).status,
      400,
    );
    const task = (await control(c, p)).tasks[0];
    assert.equal(task.action, "ban");
    assert.equal(c.app.bans.status(p.id).enabled, false);
    await control(c, p, { results: [{ id: task.id, status: "banned" }] });
    assert.equal(c.app.bans.status(p.id).history[0].origin, "manual");
    await c.api(url + "/ban", { enabled: true, observeMinutes: 0 }, auth);
    assert.equal((await control(c, p)).tasks.length, 0);
    await highRisk(c, p, 2);
    await c.api(url + "/ban/manual", { ...input, uid: 2 }, auth);
    await c.api(
      url + "/whitelist",
      { uid: 2, email: input.email, enabled: true },
      auth,
    );
    assert.equal((await control(c, p)).tasks.length, 0);
    assert.equal(
      (await c.request(url + "/ban/manual", { ...input, uid: 2 }, auth)).status,
      400,
    );
  }));

test("网页导入：登录与确认检查，完整替换数据后无需重启，原会话失效", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    await highRisk(c, p);
    const exported = Buffer.from(
      await (await c.request("/api/backup", undefined, auth)).arrayBuffer(),
    );
    await panel(c, auth, "will be replaced");
    assert.equal((await importWeb(c, "", exported)).status, 401);
    assert.equal((await importWeb(c, auth, exported, false)).status, 400);
    const imported = await importWeb(c, auth, exported);
    assert.equal(imported.status, 200, await imported.clone().text());
    assert.equal((await c.request("/api/me", undefined, auth)).status, 401);
    const login = await c.request("/api/login", user);
    assert.equal(login.status, 200);
    const restoredAuth = cookie(login);
    assert.equal(
      (await c.api("/api/panels", undefined, restoredAuth)).rows.length,
      1,
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/key`, {}, restoredAuth)).collectorKey,
      p.collectorKey,
    );
    assert.equal(
      (await c.api(`/api/panels/${p.id}/events`, undefined, restoredAuth))
        .total,
      5,
    );
    await send(c, p, [event()]);
    assert.equal(
      (await c.api(`/api/panels/${p.id}/events`, undefined, restoredAuth))
        .total,
      6,
    );
    assert.ok(
      readdirSync(c.dir).some((n) => n.startsWith("restore-previous-")),
    );
  }));

test("网页导入坏包及不匹配密钥均保留原运行数据和登录状态", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    const broken = await importWeb(c, auth, Buffer.from("not a valid archive"));
    assert.equal(broken.status, 400);
    assert.equal((await c.request("/api/me", undefined, auth)).status, 200);
    const archive = path.join(c.dir, "export.tar.gz");
    writeFileSync(
      archive,
      Buffer.from(
        await (await c.request("/api/backup", undefined, auth)).arrayBuffer(),
      ),
    );
    const unpack = path.join(c.dir, "tampered");
    mkdirSync(unpack);
    await tar.x({ file: archive, cwd: unpack });
    const key = randomBytes(32);
    writeFileSync(path.join(unpack, "master.key"), key);
    const manifest = JSON.parse(
      readFileSync(path.join(unpack, "manifest.json")),
    );
    manifest.files["master.key"].sha256 = createHash("sha256")
      .update(key)
      .digest("hex");
    writeFileSync(path.join(unpack, "manifest.json"), JSON.stringify(manifest));
    const bad = path.join(c.dir, "bad-key.tar.gz");
    await tar.c({ file: bad, cwd: unpack, gzip: true }, [
      "master.key",
      "watch.sqlite",
      "manifest.json",
    ]);
    const result = await importWeb(c, auth, readFileSync(bad));
    assert.equal(result.status, 400);
    assert.equal((await c.request("/api/me", undefined, auth)).status, 200);
    assert.equal(
      (await c.api(`/api/panels/${p.id}/key`, {}, auth)).collectorKey,
      p.collectorKey,
    );
    await c.api("/api/panels", { name: "still writable" }, auth);
  }));

test("v3.7 完整UA双条件、失败请求排除、预览无写入且鉴权", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    const rules = {
      ...defaults,
      uaEnabled: false,
      ipEnabled: false,
      rateEnabled: false,
      chinaEnabled: false,
      dcEnabled: false,
      countryEnabled: false,
      comboEnabled: false,
    };
    await c.api(url + "/settings", { name: "test", notify: true, rules }, auth);
    await send(c, p, [
      event({ status: 500 }),
      event({ status: 403, ip: "1.1.1.2", ua: "Shadowrocket/3446" }),
      event({ status: 404, ip: "1.1.1.3", ua: "shadowrocket/3445" }),
    ]);
    assert.equal((await c.api(url + "/risks", undefined, auth)).rows.length, 0);
    await send(c, p, [
      event(),
      event({ ip: "1.1.1.2", ua: "Shadowrocket/3446" }),
      event({ ip: "1.1.1.3", ua: "shadowrocket/3445" }),
    ]);
    let risk = (await c.api(url + "/risks", undefined, auth)).rows[0];
    assert.equal(risk.level, "high");
    assert.equal(risk.reasons[0].uaCount, 3);
    assert.equal(risk.reasons[0].evidence.length, 3);
    assert.ok(risk.reasons[0].evidence.every((e) => e.status === 200));
    const snapshot = () =>
      JSON.stringify(
        [
          "panels",
          "risks",
          "risk_history",
          "outbox",
          "risk_observation",
          "ban_actions",
          "ban_tasks",
        ].map((t) => c.app.db.prepare(`SELECT * FROM ${t}`).all()),
      );
    const before = snapshot();
    assert.equal((await c.request(url + "/preview", { rules })).status, 401);
    assert.equal(
      (
        await c.request(
          url + "/preview",
          { rules: { ...rules, multiMinutes: 0 } },
          auth,
        )
      ).status,
      400,
    );
    const preview = await c.api(
      url + "/preview",
      { rules: { ...rules, multiUaLimit: 4 } },
      auth,
    );
    assert.equal(preview.counts.high, 0);
    assert.equal(preview.counts.none, 1);
    assert.equal(snapshot(), before);
    await c.api(
      url + "/settings",
      { name: "test", notify: true, rules: { ...rules, multiMinutes: 20 } },
      auth,
    );
    const history = c.app.db
      .prepare("SELECT reasons FROM risk_history WHERE panel=? ORDER BY id")
      .all(p.id)
      .map((x) => JSON.parse(x.reasons));
    assert.equal(history[0][0].windowMinutes, 10);
    assert.equal(history.at(-1)[0].windowMinutes, 20);
    assert.equal(history[0][0].ruleSnapshot.multiMinutes, 10);
    assert.equal((await c.api(url + "/events", undefined, auth)).total, 6);
  }));

test("v3.7 跨国家排除未知及自有节点，组合不得拼接窗口外异常", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    c.app.geo.lookup = (ip) => ({
      countryCode: { 1: "CN", 2: "US", 3: "JP", 4: "DE" }[ip[0]],
    });
    const rules = {
      ...defaults,
      uaEnabled: false,
      ipEnabled: false,
      rateEnabled: false,
      chinaEnabled: false,
      dcEnabled: false,
      multiEnabled: false,
      comboEnabled: false,
      ownedIps: ["4.0.0.1"],
    };
    await c.api(
      url + "/settings",
      { name: "test", notify: false, rules },
      auth,
    );
    await send(c, p, [
      event(),
      event({ ip: "2.0.0.1" }),
      event({ ip: "4.0.0.1" }),
      event({ ip: "9.0.0.1" }),
    ]);
    assert.equal((await c.api(url + "/risks", undefined, auth)).rows.length, 0);
    await send(c, p, [event({ ip: "3.0.0.1" })]);
    const result = (await c.api(url + "/risks", undefined, auth)).rows[0];
    assert.equal(result.level, "low");
    assert.equal(result.reasons[0].count, 3);
    assert.equal(result.reasons[0].evidence.length, 3);
    const now = Date.now();
    await send(c, p, [
      ...Array.from({ length: 5 }, (_, i) =>
        event({ user_id: 2, ip: "1.0.0." + (i + 1), ts: now - 20 * 60000 }),
      ),
      event({ user_id: 2, ip: "2.0.0.2" }),
    ]);
    const candidate = {
      ...c.app.db.prepare("SELECT * FROM panels WHERE id=?").get(p.id),
      rules: JSON.stringify({
        ...defaults,
        multiEnabled: false,
        countryEnabled: false,
        chinaMinutes: 30,
      }),
    };
    const subject = c.app.db
      .prepare("SELECT * FROM subjects WHERE panel=? AND uid=2")
      .get(p.id);
    let reasons = assess(c.app.db, candidate, subject, now, c.app.geo);
    assert.ok(reasons.some((r) => r.code === "china"));
    assert.ok(reasons.some((r) => r.code === "rate"));
    assert.ok(!reasons.some((r) => r.code.startsWith("combo")));
    await send(
      c,
      p,
      Array.from({ length: 5 }, (_, i) =>
        event({ user_id: 2, ip: "1.0.0." + (i + 1), ts: now - 1000 }),
      ),
    );
    reasons = assess(c.app.db, candidate, subject, now, c.app.geo);
    const combo = reasons.find((r) => r.code === "comboChina");
    assert.ok(combo);
    assert.equal(combo.windowMinutes, 10);
    assert.ok(combo.evidence.every((e) => e.time > now - 10 * 60000));
    reasons = assess(c.app.db, candidate, subject, now + 10 * 60000, c.app.geo);
    assert.ok(!reasons.some((r) => r.code.startsWith("combo")));
  }));

test("v3.7 仅IP与UA双条件高风险也能进入自动封禁任务", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth),
      url = `/api/panels/${p.id}`;
    const rules = {
      ...defaults,
      uaEnabled: false,
      ipEnabled: false,
      rateEnabled: false,
      chinaEnabled: false,
      dcEnabled: false,
      countryEnabled: false,
      comboEnabled: false,
    };
    await c.api(
      url + "/settings",
      { name: "test", notify: false, rules },
      auth,
    );
    await send(c, p, [
      event(),
      event({ ip: "1.1.1.2", ua: "Clash/1" }),
      event({ ip: "1.1.1.3", ua: "NetFlow/1" }),
    ]);
    await control(c, p);
    await c.api(url + "/ban", { enabled: true, observeMinutes: 0 }, auth);
    const result = await control(c, p);
    assert.equal(result.tasks.length, 1);
  }));

test("v3.7 旧样本迁移保留失败状态，缺失访问记录不猜测成功", () =>
  fixture(async (c) => {
    const auth = await setup(c),
      p = await panel(c, auth);
    await send(c, p, [
      event({ user_id: 1, status: 200 }),
      event({ user_id: 2, status: 500 }),
      event({ user_id: 3, status: 200 }),
    ]);
    c.app.db.exec(
      "DELETE FROM visits WHERE uid=3; ALTER TABLE samples DROP COLUMN status;",
    );
    await c.restart();
    assert.deepEqual(
      c.app.db
        .prepare("SELECT status FROM samples ORDER BY uid")
        .all()
        .map((x) => x.status),
      [200, 500, null],
    );
    await c.restart();
    assert.equal(
      c.app.db.prepare("SELECT status FROM samples WHERE uid=2").get().status,
      500,
    );
  }));
