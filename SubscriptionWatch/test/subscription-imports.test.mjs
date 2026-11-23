import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { createApp } from "../server.mjs";
import {
  embeddedBrowser,
  shadowrocketUrl,
  subscriptionImportUrl,
} from "../subscription-imports.mjs";

test("Shadowrocket 使用标准Base64，保留订阅参数；识别微信/QQ但不误拦独立QQ浏览器", () => {
  const url =
    "http://sub.example.com:8080/custom/abc?flag=shadowrocket&name=%E6%B5%8B%E8%AF%95#remark";
  const grant = "b".repeat(64),
    target = subscriptionImportUrl(url, grant);
  assert.equal(
    target,
    url.replace("#remark", "&watch_import=" + grant + "#remark"),
  );
  const encoded = shadowrocketUrl(target)
    .split("shadowrocket://add/sub://")[1]
    .split("?remark=")[0];
  assert.equal(encoded, Buffer.from(target).toString("base64"));
  assert.equal(Buffer.from(encoded, "base64").toString(), target);
  assert.equal(
    new URL(subscriptionImportUrl(target, "c".repeat(64))).searchParams.getAll(
      "watch_import",
    ).length,
    1,
  );
  for (const bad of [
    "javascript:alert(1)",
    "ftp://x.example",
    "https://user:pass@x.example",
  ])
    assert.throws(() => shadowrocketUrl(bad));
  assert.equal(
    embeddedBrowser("Mozilla/5.0 iPhone MicroMessenger/8.0"),
    "微信",
  );
  assert.equal(embeddedBrowser("Mozilla/5.0 QQ/9.0.1"), "QQ");
  assert.equal(embeddedBrowser("Mozilla/5.0 V1_IPH_SQ_9.0_1_APP_A"), "QQ");
  assert.equal(embeddedBrowser("Mozilla/5.0 V1_AND_SQ_9.0_1_APP_A"), "QQ");
  assert.equal(
    embeddedBrowser("Mozilla/5.0 MQQBrowser/14.2 QQBrowser/14.2"),
    null,
  );
  assert.equal(
    embeddedBrowser("Mozilla/5.0 iPhone Version/18 Mobile Safari/604.1"),
    null,
  );
});

async function setup(t) {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-imports-"));
  const w = {
    dir,
    password: randomBytes(24).toString("hex"),
    keys: new Map(),
    calls: 0,
    outage: false,
    badSignature: false,
    hold: null,
    users: new Map([
      [
        7,
        {
          id: 7,
          email: "customer@example.com",
          subscribe_url:
            "https://sub.example.com/s/" +
            "a".repeat(32) +
            "?flag=shadowrocket",
        },
      ],
      [
        8,
        {
          id: 8,
          email: "other@example.com",
          subscribe_url: "https://sub.example.com/s/" + "b".repeat(32),
        },
      ],
    ]),
  };
  const start = async () => {
    w.app = createApp({
      dataDir: dir,
      secureCookie: false,
      background: false,
      fetcher: async (url, options) => {
        assert.ok(url.endsWith("/origin-lookup"));
        w.calls++;
        if (w.outage) throw Error("test outage");
        if (w.hold) await w.hold();
        const event = JSON.parse(options.body),
          key = w.keys.get(options.headers["X-Watch-Panel"]);
        assert.equal(
          options.headers["X-Watch-Signature"],
          createHmac("sha256", key.collectorKey)
            .update(
              "subscription-origin-lookup-request\n" +
                options.headers["X-Watch-Timestamp"] +
                "\n" +
                options.body,
            )
            .digest("hex"),
        );
        const user =
          w.users.get(Number(event.query)) ||
          [...w.users.values()].find((user) => user.email === event.query) ||
          null;
        const payload = Buffer.from(
          JSON.stringify({
            schema: 1,
            nonce: event.nonce,
            query: event.query,
            panel: key.publicId,
            expires: Date.now() + 30000,
            user,
          }),
        ).toString("base64");
        return new Response(
          JSON.stringify({
            payload,
            signature: w.badSignature
              ? "0".repeat(64)
              : createHmac("sha256", key.collectorKey)
                  .update("subscription-origin-lookup-response\n" + payload)
                  .digest("hex"),
          }),
        );
      },
    });
    await new Promise((resolve) => w.app.admin.listen(0, "127.0.0.1", resolve));
    w.base = `http://127.0.0.1:${w.app.admin.address().port}`;
  };
  await start();
  t.after(async () => {
    await w.app.close();
    rmSync(dir, { recursive: true, force: true });
  });
  w.post = (route, data, cookie = w.cookie || "") =>
    fetch(w.base + route, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Watch-Request": "1",
        Cookie: cookie,
      },
      body: JSON.stringify(data),
    });
  const auth = await w.post("/api/setup", {
    username: "owner",
    password: w.password,
    confirmPassword: w.password,
  });
  w.cookie = auth.headers.get("set-cookie").split(";")[0];
  w.panel = async (name) => {
    const { id } = await (await w.post("/api/panels", { name })).json();
    const key = await (await w.post(`/api/panels/${id}/key`, {})).json();
    w.keys.set(key.publicId, key);
    w.app.db
      .prepare(
        "INSERT INTO subscription_origin_push(panel,xboard_url) VALUES(?,?)",
      )
      .run(id, "https://panel.example.com");
    return {
      id,
      key,
      route: `/api/panels/${id}/subscription-origins/import-link`,
    };
  };
  w.p = await w.panel("First");
  w.other = await w.panel("Second");
  w.create = async (panel = w.p, uid = 7) => {
    const user = w.users.get(uid);
    const r = await w.post(panel.route, { uid, email: user.email });
    assert.equal(r.status, 200);
    return r.json();
  };
  w.get = (route, ua = "Mozilla/5.0 iPhone Version/18 Safari/604.1") =>
    fetch(w.base + route, { headers: { "User-Agent": ua } });
  w.signed = async (route, data, panel = w.p) => {
    const raw = JSON.stringify(data),
      ts = String(Math.floor(Date.now() / 1000));
    return fetch(w.base + route, {
      method: "POST",
      headers: {
        "X-Watch-Panel": panel.key.publicId,
        "X-Watch-Timestamp": ts,
        "X-Watch-Signature": createHmac("sha256", panel.key.collectorKey)
          .update(ts + "\n" + raw)
          .digest("hex"),
      },
      body: raw,
    });
  };
  w.review = async (change = {}, panel = w.p) => {
    const event = {
      schema: 1,
      event_id: randomBytes(16).toString("hex"),
      ts: Date.now(),
      user_id: 7,
      email: "customer@example.com",
      ip: "8.8.8.8",
      ua: "blocked-client",
      ...change,
    };
    const response = await w.signed("/api/collector/review", event, panel),
      raw = await response.text();
    assert.equal(response.status, 200);
    assert.equal(
      response.headers.get("x-watch-decision-signature"),
      createHmac("sha256", panel.key.collectorKey).update(raw).digest("hex"),
    );
    return { event, ...JSON.parse(raw) };
  };
  w.restart = async () => {
    await w.app.close();
    await start();
    const login = await w.post("/api/login", {
      username: "owner",
      password: w.password,
    });
    w.cookie = login.headers.get("set-cookie").split(";")[0];
  };
  return w;
}

function importedUrl(html) {
  const href = /id="shadowrocket-import" href="([^"]+)"/.exec(html)?.[1];
  assert.ok(href, "import button exists");
  return Buffer.from(
    href.split("shadowrocket://add/sub://")[1].split("?remark=")[0],
    "base64",
  ).toString();
}

test("分享页：鉴权、长期复用、最新地址、微信QQ提示、撤销与重启保留", async (t) => {
  const w = await setup(t),
    data = { uid: 7, email: "customer@example.com" };
  assert.equal((await w.post(w.p.route, data, "")).status, 401);
  assert.equal(
    (await w.post(w.p.route, { ...data, email: "wrong@example.com" })).status,
    409,
  );
  const link = await w.create(),
    cap = link.path.split("/").at(-1);
  assert.equal((await w.create()).path, link.path);
  const stored = JSON.stringify(
    w.app.db.prepare("SELECT * FROM subscription_imports").all(),
  );
  assert.ok(!stored.includes(cap));
  assert.ok(!stored.includes("a".repeat(32)));
  assert.ok(!stored.includes("sub.example.com"));
  const response = await w.get(link.path),
    html = await response.text();
  assert.equal(response.status, 200);
  const target = new URL(importedUrl(html));
  assert.equal(target.searchParams.get("watch_import"), cap);
  assert.equal(target.searchParams.get("flag"), "shadowrocket");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.match(
    response.headers.get("content-security-policy"),
    /frame-ancestors 'none'/,
  );
  const before = w.calls;
  for (const ua of [
    "MicroMessenger/8.0",
    "Mozilla QQ/9.1",
    "V1_IPH_SQ_9_0_APP_A",
  ]) {
    const page = await w.get(link.path, ua),
      body = await page.text();
    assert.match(body, /请用其他浏览器打开/);
    assert.ok(!body.includes("shadowrocket://"));
    assert.ok(!body.includes("a".repeat(32)));
    assert.ok(!body.includes("watch_import="));
  }
  assert.equal(
    w.calls,
    before,
    "embedded browser never fetches subscription information",
  );
  assert.match(
    await (await w.get(link.path, "MQQBrowser/14 QQBrowser/14")).text(),
    /id="shadowrocket-import"/,
  );
  w.users.get(7).subscribe_url =
    "http://new.example.com:8080/custom/" + "c".repeat(32) + "?x=1";
  assert.ok(
    importedUrl(await (await w.get(link.path)).text()).startsWith(
      w.users.get(7).subscribe_url + "&watch_import=",
    ),
  );
  w.app.db
    .prepare("UPDATE subscription_imports SET created=?")
    .run(Date.now() - 400 * 86400000);
  await w.restart();
  assert.equal(
    (await w.get(link.path)).status,
    200,
    "link has no automatic expiration",
  );
  assert.equal((await w.create()).path, link.path);
  assert.equal(
    (
      await w.post(w.other.route + "/revoke", {
        ...data,
        revision: link.revision,
      })
    ).status,
    404,
  );
  assert.equal(
    (await w.post(w.p.route + "/revoke", { ...data, revision: "stale" }))
      .status,
    409,
  );
  assert.equal(
    (await w.post(w.p.route + "/revoke", { ...data, revision: link.revision }))
      .status,
    200,
  );
  assert.equal((await w.get(link.path)).status, 410);
  const newLink = await w.create();
  assert.notEqual(newLink.path, link.path);
  assert.equal(
    (await w.post(w.p.route + "/revoke", { ...data, revision: link.revision }))
      .status,
    409,
  );
  assert.equal((await w.get(newLink.path)).status, 200);
  assert.equal((await w.get("/sr-import/invalid")).status, 404);
  const asset = await w.get("/shadowrocket-import.js");
  assert.equal(asset.status, 200);
  assert.equal((await w.get("/app.js")).status, 401);
});

test("专用凭证只豁免匹配面板和客户的请求，普通地址不豁免，撤销立即失效", async (t) => {
  const w = await setup(t),
    link = await w.create(),
    cap = link.path.split("/").at(-1);
  const fingerprint = createHash("sha256").update(cap).digest("hex");
  for (const p of [w.p, w.other]) {
    const r = JSON.parse(
      w.app.db.prepare("SELECT rules FROM panels WHERE id=?").get(p.id).rules,
    );
    Object.assign(r, {
      mainlandOnly: true,
      uaEnabled: true,
      uaKeywords: ["allowed-client"],
      dailyLimit: 1,
      dcEnabled: true,
      dcKeywords: ["Cloud"],
      blockSuspiciousUsers: true,
      foreignEnabled: true,
      foreignShortLimit: 1,
      foreignLongLimit: 1,
    });
    w.app.db
      .prepare("UPDATE panels SET rules=?,notify=0 WHERE id=?")
      .run(JSON.stringify(r), p.id);
  }
  w.app.geo.lookup = () => ({ countryCode: "US", organization: "Cloud Host" });
  const existingReasons = JSON.stringify([
    { code: "foreign60", label: "已有测试风险" },
  ]);
  w.app.db
    .prepare(
      "INSERT INTO risks(panel,uid,active,started,updated,reasons) VALUES(?,7,1,?,?,?)",
    )
    .run(w.p.id, Date.now(), Date.now(), existingReasons);
  const allowed = await w.review({ import_fingerprint: fingerprint });
  assert.equal(allowed.allow, true);
  assert.equal(
    w.app.db
      .prepare("SELECT reasons FROM risks WHERE panel=? AND uid=7")
      .get(w.p.id).reasons,
    existingReasons,
    "request grant preserves existing risk",
  );
  const phpReview = async (grant) => {
    const { stdout } = await promisify(execFile)(
      process.env.PHP_BIN,
      [
        "-n",
        fileURLToPath(new URL("./plugin-import-grant.php", import.meta.url)),
      ],
      {
        env: {
          ...process.env,
          WATCH_TEST_BASE: w.base,
          WATCH_TEST_SECRET: w.p.key.collectorKey,
          WATCH_TEST_PANEL: w.p.key.publicId,
          WATCH_TEST_GRANT: grant,
        },
      },
    );
    return JSON.parse(stdout);
  };
  if (process.env.PHP_BIN) {
    assert.equal(
      (await phpReview(cap)).allow,
      true,
      "actual PHP collector submits bound fingerprint",
    );
    assert.equal(
      (await phpReview("")).allow,
      false,
      "ordinary PHP request has no exemption",
    );
  }
  assert.equal(
    w.app.db
      .prepare("SELECT white FROM subjects WHERE panel=? AND uid=7")
      .get(w.p.id).white,
    0,
  );
  assert.equal(
    w.app.db
      .prepare(
        "SELECT import_whitelisted FROM review_decisions WHERE panel=? AND event_id=?",
      )
      .get(w.p.id, allowed.event.event_id).import_whitelisted,
    1,
  );
  const ordinary = await w.review({ ip: "9.9.9.9" });
  assert.equal(ordinary.allow, false);
  assert.ok(
    !ordinary.codes.includes("foreign60"),
    "granted review history excluded from multi-IP risk",
  );
  for (const code of ["ua", "mainland-only", "daily-limit", "cloud"])
    assert.ok(ordinary.codes.includes(code));
  assert.equal(
    (await w.review({ import_fingerprint: "f".repeat(64) })).allow,
    false,
  );
  assert.equal(
    (
      await w.review({
        import_fingerprint: fingerprint,
        user_id: 8,
        email: "other@example.com",
      })
    ).allow,
    false,
  );
  assert.equal(
    (
      await w.review({
        import_fingerprint: fingerprint,
        email: "changed@example.com",
      })
    ).allow,
    false,
  );
  assert.equal(
    (await w.review({ import_fingerprint: fingerprint }, w.other)).allow,
    false,
  );
  assert.equal(
    (await w.review({ import_fingerprint: fingerprint })).allow,
    true,
    "whitelist skips daily and all enabled rules",
  );
  const event = {
    ...allowed.event,
    flag: "",
    peer_ip: allowed.event.ip,
    ip_source: "peer",
    status: 200,
    ms: 1,
    bytes: 100,
    delivered: true,
  };
  delete event.schema;
  delete event.import_fingerprint;
  const batch = await w.signed("/api/collector/events", {
    schema: 1,
    version: "4.0.22",
    metrics: { pending: 0, dropped: 0, expired: 0 },
    events: [event],
  });
  assert.equal(batch.status, 200);
  assert.equal(
    w.app.db
      .prepare(
        "SELECT import_whitelisted FROM visits WHERE panel=? AND event_id=?",
      )
      .get(w.p.id, event.event_id).import_whitelisted,
    1,
  );
  assert.equal(
    w.app.db
      .prepare("SELECT COUNT(*) n FROM samples WHERE panel=? AND uid=7")
      .get(w.p.id).n,
    0,
    "granted request is not an evaluation sample",
  );
  const rawDecisions = JSON.stringify(
    w.app.db.prepare("SELECT * FROM review_decisions").all(),
  );
  assert.ok(!rawDecisions.includes(cap));
  assert.ok(!rawDecisions.includes(fingerprint));
  await w.post(w.p.route + "/revoke", {
    uid: 7,
    email: "customer@example.com",
    revision: link.revision,
  });
  assert.equal(
    (await w.review({ import_fingerprint: fingerprint })).allow,
    false,
  );
  if (process.env.PHP_BIN)
    assert.equal(
      (await phpReview(cap)).allow,
      false,
      "revoked grant is denied through PHP collector",
    );
  const replay = await w.review({
    ...allowed.event,
    import_fingerprint: fingerprint,
  });
  assert.equal(replay.allow, false);
  assert.ok(replay.codes.includes("import-link-invalid"));
});

test("撤销竞态、身份变化和上游故障不返回旧地址或导入按钮", async (t) => {
  const w = await setup(t),
    link = await w.create();
  let release, entered;
  const seen = new Promise((resolve) => {
    entered = resolve;
  });
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  w.hold = async () => {
    entered();
    await gate;
  };
  const request = w.get(link.path);
  await seen;
  await w.post(w.p.route + "/revoke", {
    uid: 7,
    email: "customer@example.com",
    revision: link.revision,
  });
  release();
  const revoked = await request;
  assert.equal(revoked.status, 410);
  assert.ok(!(await revoked.text()).includes("shadowrocket://"));
  w.hold = null;
  const active = await w.create();
  w.badSignature = true;
  const unavailable = await w.get(active.path);
  assert.equal(unavailable.status, 503);
  assert.ok(!(await unavailable.text()).includes("a".repeat(32)));
  w.badSignature = false;
  w.users.get(7).email = "new-owner@example.com";
  assert.equal((await w.get(active.path)).status, 410);
});
