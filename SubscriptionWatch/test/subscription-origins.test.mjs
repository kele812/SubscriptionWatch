import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { createApp } from "../server.mjs";
import { normalizeSubscriptionOrigin } from "../subscription-origins.mjs";

test("指定订阅根地址拒绝路径、Token、凭据和非 HTTPS，支持规范化域名", () => {
  assert.equal(
    normalizeSubscriptionOrigin("https://Sub.Example.COM/"),
    "https://sub.example.com",
  );
  assert.equal(
    normalizeSubscriptionOrigin("https://sub.example.com:8443"),
    "https://sub.example.com:8443",
  );
  for (const value of [
    null,
    "sub.example.com",
    "http://sub.example.com",
    "https://a.example/subscribe",
    "https://a.example/a/..",
    "https://a.example/?token=secret",
    "https://a.example?",
    "https://a.example#",
    "https://owner:password@a.example",
    "https://a.example/\\b",
    " https://a.example",
    "https://a.example\n",
  ]) {
    assert.throws(() => normalizeSubscriptionOrigin(value), String(value));
  }
});

test("本地地址同步：保存立即确认、搜索当前链接、删除与失败补同步", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-origin-sync-"));
  let base,
    panel,
    tables = {},
    outage = false,
    badReply = false,
    pushCalls = 0;
  const app = createApp({
    dataDir: dir,
    secureCookie: false,
    background: false,
    fetcher: async (url, options) => {
      if (!url.startsWith("https://panel.example.com/"))
        throw Error("unexpected target");
      pushCalls++;
      if (outage) throw Error("simulated outage");
      const { stdout } = await promisify(execFile)(
        process.env.PHP_BIN,
        [
          "-n",
          fileURLToPath(
            new URL("./plugin-subscription-origin.php", import.meta.url),
          ),
          url.endsWith("origin-lookup") ? "lookup" : "notify",
        ],
        {
          env: {
            ...process.env,
            WATCH_TEST_BASE: base,
            WATCH_TEST_SECRET: panel.key.collectorKey,
            WATCH_TEST_PANEL: panel.key.publicId,
            WATCH_TEST_TABLES: Buffer.from(JSON.stringify(tables)).toString(
              "base64",
            ),
            WATCH_TEST_NOTIFY: Buffer.from(
              JSON.stringify({ body: options.body, headers: options.headers }),
            ).toString("base64"),
          },
        },
      );
      const result = JSON.parse(stdout);
      tables = result.tables;
      return new Response(
        badReply
          ? '{"payload":"untrusted","signature":"invalid"}'
          : result.body,
        { status: result.status },
      );
    },
  });
  await new Promise((resolve) => app.admin.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${app.admin.address().port}`;
  const post = (route, body, cookie = "") =>
    fetch(base + route, {
      method: "POST",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/json",
        "X-Watch-Request": "1",
      },
      body: JSON.stringify(body),
    });
  try {
    const password = randomBytes(24).toString("hex");
    const setup = await post("/api/setup", {
      username: "owner",
      password,
      confirmPassword: password,
    });
    const cookie = setup.headers.get("set-cookie").split(";")[0];
    const { id } = await (
      await post("/api/panels", { name: "sync" }, cookie)
    ).json();
    panel = {
      id,
      key: await (await post(`/api/panels/${id}/key`, {}, cookie)).json(),
    };
    const route = `/api/panels/${id}/subscription-origins`;
    const list = async () =>
      (await fetch(base + route, { headers: { Cookie: cookie } })).json();
    assert.equal(
      (await post(route + "/sync", { xboard_url: "https://panel.example.com" }))
        .status,
      401,
    );
    assert.equal((await post(route + "/lookup", { query: "7" })).status, 401);
    for (const value of [
      "http://panel.example.com",
      "https://panel.example.com/path",
      "https://user:pass@panel.example.com",
    ])
      assert.equal(
        (await post(route + "/sync", { xboard_url: value }, cookie)).status,
        400,
      );
    if (!process.env.PHP_BIN) return;
    const configured = await (
      await post(
        route + "/sync",
        { xboard_url: "https://panel.example.com" },
        cookie,
      )
    ).json();
    assert.equal(configured.sync.ok, true);
    assert.equal((await list()).sync.state, "已同步到 Xboard");
    const search = async (query) =>
      (await post(route + "/lookup", { query }, cookie)).json();
    const found = await search("7");
    assert.equal(found.user.id, 7);
    assert.equal(
      found.user.subscribe_url,
      "https://default.example.com/s/" + "a".repeat(32) + "?flag=clash",
    );
    assert.equal(found.setting, null);
    assert.equal((await list()).total, 0, "search never creates overrides");
    const saved = {
      uid: 7,
      email: "customer@example.com",
      origin: "https://custom.example.com",
    };
    const created = await (await post(route, saved, cookie)).json();
    assert.equal(created.sync.ok, true);
    assert.equal(
      Object.values(tables.subscription_watch_origins)[0].origin,
      saved.origin,
    );
    assert.equal((await list()).rows[0].state, "已同步到 Xboard");
    assert.equal(
      (await search(saved.email)).user.subscribe_url,
      "https://custom.example.com/s/" + "a".repeat(32) + "?flag=clash",
    );
    assert.equal((await search("999")).user, null);
    const edited = await (
      await post(route, { ...saved, origin: "https://new.example.com" }, cookie)
    ).json();
    assert.equal(edited.sync.ok, true);
    assert.equal(
      (await list()).total,
      1,
      "manual add overwrites same customer's search edit",
    );
    assert.equal((await search("7")).setting.origin, "https://new.example.com");
    const before = pushCalls;
    await list();
    await list();
    assert.equal(
      pushCalls,
      before,
      "listing configured users performs no Xboard lookup",
    );
    outage = true;
    const pending = await (
      await post(
        route,
        { ...saved, origin: "https://pending.example.com" },
        cookie,
      )
    ).json();
    assert.equal(pending.sync.ok, false);
    assert.equal((await list()).sync.state, "待同步到 Xboard");
    assert.equal(
      tables.subscription_watch_origins[0].origin,
      "https://new.example.com",
      "outage retains local snapshot",
    );
    outage = false;
    const retried = await (
      await post(
        route + "/sync",
        { xboard_url: "https://panel.example.com" },
        cookie,
      )
    ).json();
    assert.equal(retried.sync.ok, true);
    assert.equal(
      tables.subscription_watch_origins[0].origin,
      "https://pending.example.com",
    );
    badReply = true;
    assert.equal(
      (await post(route + "/lookup", { query: "7" }, cookie)).status,
      502,
    );
    const untrusted = await (
      await post(
        route,
        { ...saved, origin: "https://unconfirmed.example.com" },
        cookie,
      )
    ).json();
    assert.equal(
      untrusted.sync.ok,
      false,
      "untrusted acknowledgement cannot mark success",
    );
    assert.equal((await list()).sync.state, "待同步到 Xboard");
    badReply = false;
    const current = (await list()).rows[0];
    const deleted = await (
      await post(
        route + "/delete",
        { uid: current.uid, email: current.email, revision: current.revision },
        cookie,
      )
    ).json();
    assert.equal(deleted.sync.ok, true);
    assert.equal((await list()).total, 0);
    assert.equal(tables.subscription_watch_origins.length, 0);
    assert.equal(
      (await search("7")).user.subscribe_url,
      found.user.subscribe_url,
    );
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("客户指定地址：鉴权、隔离、变更、删除恢复默认及备选保留", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-origins-"));
  let app = createApp({ dataDir: dir, secureCookie: false, background: false });
  let base;
  const listen = async () => {
    await new Promise((resolve) => app.admin.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${app.admin.address().port}`;
  };
  await listen();
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
    const password = randomBytes(24).toString("hex");
    const setup = await post("/api/setup", {
      username: "owner",
      password,
      confirmPassword: password,
    });
    assert.equal(setup.status, 200);
    let cookie = setup.headers.get("set-cookie").split(";")[0];
    const createPanel = async (name) => {
      const { id } = await (await post("/api/panels", { name }, cookie)).json();
      const key = await (
        await post(`/api/panels/${id}/key`, {}, cookie)
      ).json();
      return { id, key, route: `/api/panels/${id}/subscription-origins` };
    };
    const p = await createPanel("First"),
      other = await createPanel("Second");
    const saved = {
      uid: 7,
      email: "customer@example.com",
      origin: "https://sub.example.com/",
    };
    const pluginUrl = async (
      email = saved.email,
      mode = "live",
      route = "api/v2/admin/user/fetch",
    ) => {
      if (!process.env.PHP_BIN) return null;
      const { stdout } = await promisify(execFile)(
        process.env.PHP_BIN,
        [
          "-n",
          fileURLToPath(
            new URL("./plugin-subscription-origin.php", import.meta.url),
          ),
          mode,
        ],
        {
          env: {
            ...process.env,
            WATCH_TEST_BASE: base,
            WATCH_TEST_SECRET: p.key.collectorKey,
            WATCH_TEST_PANEL: p.key.publicId,
            WATCH_TEST_EMAIL: email,
            WATCH_TEST_ROUTE: route,
          },
        },
      );
      return stdout;
    };
    assert.equal((await post(p.route, saved)).status, 401);
    assert.equal(
      (
        await fetch(base + p.route, {
          method: "POST",
          headers: { Cookie: cookie, "Content-Type": "application/json" },
          body: JSON.stringify(saved),
        })
      ).status,
      403,
    );
    assert.equal(
      (await post("/api/panels/999999/subscription-origins", saved, cookie))
        .status,
      404,
    );
    const created = await post(p.route, saved, cookie);
    assert.equal(created.status, 200);
    let revision = (await created.json()).revision;
    const list = async (panel = p, q = "") =>
      (
        await fetch(base + panel.route + "?q=" + encodeURIComponent(q), {
          headers: { Cookie: cookie },
        })
      ).json();
    assert.equal((await list()).rows[0].origin, "https://sub.example.com");
    assert.equal((await list()).rows[0].state, "待同步到 Xboard");
    const optionsRoute = p.route + "/options";
    const getOptions = async (panel = p) =>
      (
        await fetch(base + panel.route + "/options", {
          headers: { Cookie: cookie },
        })
      ).json();
    assert.equal((await fetch(base + optionsRoute)).status, 401);
    assert.equal((await post(optionsRoute, { origins: [] })).status, 401);
    assert.deepEqual((await getOptions()).origins, ["https://sub.example.com"]);
    assert.deepEqual((await getOptions(other)).origins, []);
    for (const origins of [
      null,
      [7],
      Array(21).fill("https://one.example.com"),
      ["https://one.example.com/path"],
      ["http://one.example.com"],
    ])
      assert.equal((await post(optionsRoute, { origins }, cookie)).status, 400);
    const optionData = await (
      await post(
        optionsRoute,
        {
          origins: [
            "https://Choice-One.example.com/",
            "https://choice-one.example.com",
            "https://choice-two.example.com",
          ],
        },
        cookie,
      )
    ).json();
    assert.deepEqual(optionData.origins, [
      "https://choice-one.example.com",
      "https://choice-two.example.com",
    ]);
    assert.deepEqual((await getOptions()).origins, optionData.origins);
    assert.equal(
      (await post(optionsRoute, { origins: [], revision: null }, cookie))
        .status,
      409,
    );
    assert.equal((await list()).rows[0].origin, "https://sub.example.com");
    const clearedOptions = await (
      await post(
        optionsRoute,
        { origins: [], revision: optionData.revision },
        cookie,
      )
    ).json();
    assert.deepEqual((await getOptions()).origins, []);
    assert.equal((await list()).rows[0].origin, "https://sub.example.com");
    assert.equal(
      (
        await post(
          optionsRoute,
          { origins: optionData.origins, revision: clearedOptions.revision },
          cookie,
        )
      ).status,
      200,
    );
    assert.equal((await list(other)).total, 0);
    assert.equal((await list(p, "sub.example")).total, 1);
    assert.equal((await list(p, "not-present")).total, 0);
    const resolve = async (
      panel = p,
      change = {},
      bad = false,
      stale = false,
    ) => {
      const event = {
        schema: 1,
        nonce: randomBytes(24).toString("hex"),
        user_id: 7,
        email: saved.email,
        ...change,
      };
      const body = JSON.stringify(event),
        timestamp = String(Math.floor(Date.now() / 1000) - (stale ? 600 : 0));
      const signature = createHmac("sha256", panel.key.collectorKey)
        .update("subscription-origin-request\n" + timestamp + "\n" + body)
        .digest("hex");
      const response = await fetch(
        base + "/api/collector/subscription-origin",
        {
          method: "POST",
          headers: {
            "X-Watch-Panel": panel.key.publicId,
            "X-Watch-Timestamp": timestamp,
            "X-Watch-Signature": bad ? "0".repeat(64) : signature,
          },
          body,
        },
      );
      const envelope = await response.json();
      if (response.status !== 200) return { status: response.status };
      assert.equal(
        envelope.signature,
        createHmac("sha256", panel.key.collectorKey)
          .update("subscription-origin-response\n" + envelope.payload)
          .digest("hex"),
      );
      const result = JSON.parse(Buffer.from(envelope.payload, "base64"));
      assert.equal(result.nonce, event.nonce);
      assert.equal(result.panel, panel.key.publicId);
      assert.equal(result.user_id, event.user_id);
      assert.equal(result.email, event.email);
      assert.ok(result.expires > Date.now());
      assert.ok(!JSON.stringify(result).includes("token"));
      return { status: 200, ...result };
    };
    assert.equal((await resolve(p, {}, true)).status, 401);
    assert.equal((await resolve(p, {}, false, true)).status, 401);
    assert.equal((await resolve(p, { token: "not-allowed" })).status, 422);
    assert.equal((await resolve()).origin, "https://sub.example.com");
    assert.equal((await resolve()).lookup_status, "configured");
    if (process.env.PHP_BIN) {
      for (const route of [
        "api/v2/admin/user/fetch",
        "api/v1/user/getSubscribe",
      ]) {
        const result = JSON.parse(
          await pluginUrl(saved.email, "live-response", route),
        );
        assert.equal(
          result.data.rows[0].subscribe_url,
          "https://sub.example.com/s/" + "a".repeat(32) + "?flag=clash",
        );
      }
    }
    if (process.env.PHP_BIN)
      assert.equal(
        await pluginUrl(),
        "https://sub.example.com/s/" + "a".repeat(32) + "?flag=clash",
      );
    assert.equal(
      (await list()).rows[0].state,
      process.env.PHP_BIN ? "已同步到 Xboard" : "待同步到 Xboard",
    );
    assert.equal((await resolve(other)).origin, null);
    assert.equal(
      (await resolve(p, { email: "different@example.com" })).origin,
      null,
    );
    assert.equal(
      (await list()).rows[0].state,
      process.env.PHP_BIN ? "已同步到 Xboard" : "待同步到 Xboard",
    );
    assert.equal(
      (await resolve(p, { email: "different@example.com" })).lookup_status,
      "email-mismatch",
    );
    assert.equal((await resolve(p, { user_id: 8 })).origin, null);
    // Known, verified identities must not silently inherit someone else's settings.
    app.db
      .prepare("INSERT INTO subjects(panel,uid,email,verified) VALUES(?,?,?,1)")
      .run(p.id, 7, "changed@example.com");
    assert.equal((await resolve()).origin, null);
    assert.equal((await list()).rows[0].state, "邮箱不匹配，已暂停");
    assert.equal(
      (await post(p.route, { ...saved, revision }, cookie)).status,
      400,
    );
    const edited = await post(
      p.route,
      {
        ...saved,
        email: "changed@example.com",
        origin: "https://last.example.com",
        revision,
      },
      cookie,
    );
    assert.equal(edited.status, 200);
    const previousRevision = revision;
    revision = (await edited.json()).revision;
    const lastSaved = await post(
      p.route,
      {
        ...saved,
        email: "changed@example.com",
        origin: "https://last.example.com",
        revision: previousRevision,
      },
      cookie,
    );
    assert.equal(lastSaved.status, 200);
    revision = (await lastSaved.json()).revision;
    assert.equal((await list()).total, 1);
    assert.equal(
      (await resolve(p, { email: "changed@example.com" })).origin,
      "https://last.example.com",
    );
    if (process.env.PHP_BIN)
      assert.ok(
        (await pluginUrl("changed@example.com")).startsWith(
          "https://last.example.com/",
        ),
      );
    const deleteData = { uid: 7, email: "changed@example.com", revision };
    const deleteRoute = p.route + "/delete";
    assert.equal((await post(deleteRoute, deleteData)).status, 401);
    assert.equal(
      (await post(other.route + "/delete", deleteData, cookie)).status,
      404,
    );
    assert.equal(
      (
        await post(
          deleteRoute,
          { ...deleteData, email: "wrong@example.com" },
          cookie,
        )
      ).status,
      409,
    );
    assert.equal(
      (
        await post(
          deleteRoute,
          { ...deleteData, revision: previousRevision },
          cookie,
        )
      ).status,
      409,
    );
    const optionsBeforeDelete = (await getOptions()).origins;
    const restored = await post(deleteRoute, deleteData, cookie);
    assert.equal(restored.status, 200);
    assert.equal((await restored.json()).ok, true);
    revision = null;
    assert.equal(
      (await resolve(p, { email: "changed@example.com" })).origin,
      null,
    );
    if (process.env.PHP_BIN)
      assert.ok(
        (await pluginUrl("changed@example.com")).startsWith(
          "https://default.example.com/",
        ),
      );
    assert.equal((await list()).total, 0);
    assert.deepEqual((await getOptions()).origins, optionsBeforeDelete);
    assert.equal(
      app.db
        .prepare("SELECT email FROM subjects WHERE panel=? AND uid=?")
        .get(p.id, 7).email,
      "changed@example.com",
    );
    assert.equal((await post(deleteRoute, deleteData, cookie)).status, 404);
    assert.equal(
      (
        await post(
          p.route,
          {
            uid: 7,
            email: "changed@example.com",
            origin: "https://again.example.com",
            revision,
          },
          cookie,
        )
      ).status,
      200,
    );
    const currentSetting = (await list()).rows[0];
    assert.equal(
      (await post(deleteRoute, deleteData, cookie)).status,
      409,
      "stale delete must not remove a recreated override",
    );
    assert.equal(
      (
        await post(
          p.route,
          {
            uid: 7,
            email: currentSetting.email,
            origin: null,
            revision: currentSetting.revision,
          },
          cookie,
        )
      ).status,
      200,
    );
    assert.equal(
      (await list()).total,
      0,
      "legacy restore-default request also removes the override",
    );
    assert.equal(
      (
        await post(
          p.route,
          {
            uid: 7,
            email: "changed@example.com",
            origin: "https://again.example.com",
          },
          cookie,
        )
      ).status,
      200,
    );
    await app.close();
    // Simulate the 4.0.17 table shape before starting the upgraded service.
    const oldDb = new DatabaseSync(path.join(dir, "watch.sqlite"));
    oldDb.exec("ALTER TABLE subscription_origins DROP COLUMN last_status");
    oldDb.close();
    app = createApp({ dataDir: dir, secureCookie: false, background: false });
    await listen();
    const login = await post("/api/login", { username: "owner", password });
    assert.equal(login.status, 200);
    cookie = login.headers.get("set-cookie").split(";")[0];
    assert.deepEqual((await getOptions()).origins, [
      "https://choice-one.example.com",
      "https://choice-two.example.com",
    ]);
    assert.equal(
      (await resolve(p, { email: "changed@example.com" })).origin,
      "https://again.example.com",
    );
    assert.equal((await list()).total, 1);
    for (let uid = 100; uid < 151; uid++) {
      assert.equal(
        (
          await post(
            p.route,
            {
              uid,
              email: `page-${uid}@example.com`,
              origin: "https://pages.example.com",
            },
            cookie,
          )
        ).status,
        200,
      );
    }
    const firstPage = await list();
    const secondPage = await (
      await fetch(base + p.route + "?page=2", { headers: { Cookie: cookie } })
    ).json();
    assert.equal(firstPage.total, 52);
    assert.equal(firstPage.rows.length, 50);
    assert.equal(secondPage.rows.length, 2);
    assert.equal(
      new Set([...firstPage.rows, ...secondPage.rows].map((row) => row.uid))
        .size,
      52,
    );
    assert.equal((await list(other)).total, 0);
    // A complete snapshot is paginated independently from the admin list, and never includes subscription tokens.
    const insert = app.db.prepare(
      "INSERT INTO subscription_origins(panel,uid,email,origin,revision,updated) VALUES(?,?,?,?,?,?)",
    );
    for (let uid = 200; uid < 650; uid++)
      insert.run(
        p.id,
        uid,
        `sync-${uid}@example.com`,
        "https://pages.example.com",
        randomBytes(16).toString("hex"),
        Date.now(),
      );
    const syncPage = async (panel, change = {}, bad = false) => {
      const event = {
        schema: 1,
        nonce: randomBytes(24).toString("hex"),
        revision: null,
        cursor: 0,
        ...change,
      };
      const body = JSON.stringify(event),
        timestamp = String(Math.floor(Date.now() / 1000));
      const response = await fetch(
        base + "/api/collector/subscription-origin-sync",
        {
          method: "POST",
          headers: {
            "X-Watch-Panel": panel.key.publicId,
            "X-Watch-Timestamp": timestamp,
            "X-Watch-Signature": bad
              ? "0".repeat(64)
              : createHmac("sha256", panel.key.collectorKey)
                  .update(
                    "subscription-origin-sync-request\n" +
                      timestamp +
                      "\n" +
                      body,
                  )
                  .digest("hex"),
          },
          body,
        },
      );
      if (response.status !== 200) return { status: response.status };
      const envelope = await response.json();
      assert.equal(
        envelope.signature,
        createHmac("sha256", panel.key.collectorKey)
          .update("subscription-origin-sync-response\n" + envelope.payload)
          .digest("hex"),
      );
      const data = JSON.parse(Buffer.from(envelope.payload, "base64"));
      assert.equal(data.panel, panel.key.publicId);
      assert.equal(data.nonce, event.nonce);
      assert.ok(!JSON.stringify(data).includes("token"));
      return data;
    };
    assert.equal((await syncPage(p, {}, true)).status, 401);
    assert.equal((await syncPage(p, { cursor: -1 })).status, 422);
    assert.equal((await syncPage(p, { token: "forbidden" })).status, 422);
    const firstSync = await syncPage(p);
    assert.equal(firstSync.users.length, 500);
    assert.ok(firstSync.next > 0);
    const secondSync = await syncPage(p, {
      revision: firstSync.revision,
      cursor: firstSync.next,
    });
    assert.equal(secondSync.next, null);
    assert.equal(
      new Set(
        [...firstSync.users, ...secondSync.users].map((row) => row.user_id),
      ).size,
      502,
    );
    const unchanged = await syncPage(p, { revision: firstSync.revision });
    assert.equal(unchanged.unchanged, true);
    assert.deepEqual(unchanged.users, []);
    assert.equal((await syncPage(other)).users.length, 0);
    app.db
      .prepare("DELETE FROM subscription_origins WHERE panel=? AND uid=?")
      .run(p.id, 200);
    assert.equal(
      (
        await syncPage(p, {
          revision: firstSync.revision,
          cursor: firstSync.next,
        })
      ).restart,
      true,
    );
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
