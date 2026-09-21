import {
  initDestinations,
  cleanDestinations,
  createDestinationNode,
  setDestinationUser,
  destinationStatus,
  destinationRows,
  receiveDestinations,
} from "./destinations.mjs";
import { migrate371 } from "./migrate371.mjs";
import { assess } from "./assessment.mjs";
import http from "node:http";
import { DatabaseSync } from "node:sqlite";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  statfsSync,
} from "node:fs";
import {
  randomBytes,
  scrypt,
  timingSafeEqual,
  createCipheriv,
  createDecipheriv,
} from "node:crypto";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  initialize,
  simplifyAccounts,
  migratePanelBots,
  migrateRiskV33,
  defaults,
  token,
  getConfig,
  setConfig,
  transaction,
  validateRules,
} from "./model.mjs";
import { receiveBatch, MAX_AGE } from "./ingest.mjs";
import { evaluate, resolveRisk, riskRows, riskLevel } from "./risk.mjs";
import { GeoDatabase, parseGeoConfig } from "./geo.mjs";
import { AccountBan } from "./ban.mjs";
import { Telegram } from "./telegram.mjs";
import { exportBackup } from "./backup.mjs";
import { restoreBackup } from "./restore.mjs";
import { mkdtemp, open, rm } from "node:fs/promises";
const root = path.dirname(fileURLToPath(import.meta.url)),
  derive = promisify(scrypt);
async function hash(password) {
  const salt = randomBytes(16).toString("hex");
  return salt + ":" + (await derive(password, salt, 64)).toString("hex");
}
async function verify(password, stored) {
  if (typeof password !== "string" || password.length > 256) return false;
  const [salt, h] = stored.split(":");
  const actual = await derive(password, salt, 64),
    expected = Buffer.from(h, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
function password(p, confirm) {
  if (typeof p !== "string" || p.length < 1 || p.length > 256)
    throw Error("密码不能为空，最多256位");
  if (p !== confirm) throw Error("两次密码不一致");
}
const fail = (status, message) => {
  throw Object.assign(Error(message), { status });
};
export function createApp({
  dataDir = process.env.DATA_DIR || path.join(root, "data"),
  secureCookie = process.env.COOKIE_SECURE !== "false",
  fetcher = fetch,
  background = true,
} = {}) {
  mkdirSync(dataDir, { recursive: true });
  const master = path.join(dataDir, "master.key");
  if (!existsSync(master))
    writeFileSync(master, randomBytes(32), { mode: 0o600 });
  let key = readFileSync(master);
  const encrypt = (t) => {
    const iv = randomBytes(12),
      c = createCipheriv("aes-256-gcm", key, iv);
    return Buffer.concat([iv, c.update(t), c.final(), c.getAuthTag()]).toString(
      "base64",
    );
  };
  const decrypt = (t) => {
    const b = Buffer.from(t, "base64"),
      c = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12));
    c.setAuthTag(b.subarray(-16));
    return Buffer.concat([c.update(b.subarray(12, -16)), c.final()]).toString();
  };
  let db, geo, tg, bans;
  const loadState = (validate = false) => {
    key = readFileSync(master);
    db = new DatabaseSync(path.join(dataDir, "watch.sqlite"));
    try {
      initialize(db, encrypt);
      simplifyAccounts(db);
      migratePanelBots(db);
      migrateRiskV33(db);
      geo = new GeoDatabase({ db, dataDir, encrypt, decrypt, fetcher });
      tg = new Telegram({ db, encrypt, decrypt, geo, fetcher });
      bans = new AccountBan({ db, encrypt, decrypt, geo, fetcher });
      migrate371(db);
      initDestinations(db);
      // Verify restored encrypted credentials before accepting the replacement.
      if (validate) {
        try {
          for (const row of db
            .prepare(
              "SELECT secret value FROM panels UNION ALL SELECT token value FROM telegram WHERE token IS NOT NULL UNION ALL SELECT secret value FROM destination_nodes",
            )
            .all())
            decrypt(row.value);
          const storedGeo = getConfig(db, "maxmind");
          if (storedGeo) decrypt(storedGeo);
        } catch {
          throw Error("备份密钥与数据库中的凭据不匹配，已取消导入");
        }
        if (
          geo.current &&
          (!geo.readers["GeoLite2-City"] || !geo.readers["GeoLite2-ASN"])
        )
          throw Error("备份中的IP数据库无法读取");
      }
    } catch (e) {
      db.close();
      throw e;
    }
  };
  loadState();
  const sessions = new Map(),
    attempts = new Map();
  const initialized = () =>
    !!db.prepare("SELECT id FROM accounts WHERE admin=1").get();
  let backupBusy = false;
  let restoring = false,
    importBusy = false,
    activeRequests = 0;
  const json = (res, status, data) => {
    res.writeHead(status, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    res.end(JSON.stringify(data));
  };
  const body = async (req) => {
    let n = 0;
    const chunks = [];
    for await (const c of req) {
      n += c.length;
      if (n > 65536) fail(413, "请求过大");
      chunks.push(c);
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString() || "{}");
    } catch {
      fail(400, "JSON格式错误");
    }
  };
  function throttle(key, limit = 20) {
    const now = Date.now(),
      a = attempts.get(key) || { n: 0, until: now + 900000 };
    if (a.until <= now) {
      a.n = 0;
      a.until = now + 900000;
    }
    if (a.n >= limit) fail(429, "尝试过多，请15分钟后重试");
    a.n++;
    attempts.set(key, a);
  }
  function makeSession(res, account) {
    const sid = token();
    sessions.set(sid, { account, until: Date.now() + 28800000 });
    res.setHeader(
      "Set-Cookie",
      `watch=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secureCookie ? "; Secure" : ""}`,
    );
  }
  const visible = (p) => ({
    id: p.id,
    owner: p.owner,
    owner_name: p.owner_name,
    name: p.name,
    public_id: p.public_id,
    rules: { ...defaults, ...JSON.parse(p.rules) },
    commonUaKeywords: defaults.uaKeywords,
    notify: !!p.notify,
    last_seen: p.last_seen,
    pending: p.pending,
    dropped: p.dropped,
    expired: p.expired,
    version: p.version,
    failures: p.failures ?? null,
    health: !p.last_seen
      ? "尚未上报"
      : Date.now() - p.last_seen > 180000
        ? "上报中断（超过3分钟）"
        : p.pending >= 100
          ? "已连接，有积压"
          : "正常",
  });
  const maintenance = () => {
    if (restoring) return;
    const now = Date.now();
    cleanDestinations(db, now);
    for (const [k, v] of sessions) if (v.until < now) sessions.delete(k);
    for (const [k, v] of attempts) if (v.until < now) attempts.delete(k);
    transaction(db, () => {
      db.prepare("DELETE FROM receipts WHERE ts<?").run(now - MAX_AGE - 600000);
      db.prepare("DELETE FROM samples WHERE ts<?").run(now - 604800000);
      db.prepare("DELETE FROM tg_confirm WHERE until<?").run(now);
      db.prepare("DELETE FROM outbox WHERE created<?").run(now - 604800000);
      const rows = db
        .prepare(
          "SELECT DISTINCT panel,uid FROM samples UNION SELECT panel,uid FROM risks WHERE active=1",
        )
        .all();
      const panels = new Map(
        db
          .prepare("SELECT * FROM panels")
          .all()
          .map((p) => [p.id, p]),
      );
      for (const p of panels.values()) {
        const days = JSON.parse(p.rules).retentionDays || 0;
        if (days)
          db.prepare("DELETE FROM visits WHERE panel=? AND ts<?").run(
            p.id,
            now - days * 86400000,
          );
      }
      for (const r of rows) {
        const p = panels.get(r.panel);
        if (p) evaluate(db, p, r.uid, now, geo);
      }
    });
  };
  const timers = background
    ? [
        setInterval(() => {
          try {
            maintenance();
          } catch {
            console.error("maintenance failed");
          }
        }, 60000),
        setInterval(() => {
          if (restoring) return;
          tg.tick().catch(() => {});
          bans.tick().catch(() => {});
        }, 3000),
      ]
    : [];
  timers.forEach((t) => t.unref());
  const admin = http.createServer(async (req, res) => {
    activeRequests++;
    try {
      const u = new URL(req.url, "http://localhost"),
        route = u.pathname,
        method = req.method;
      res.setHeader("Cache-Control", "private, no-store, max-age=0");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Vary", "Cookie");
      res.setHeader("X-Content-Type-Options", "nosniff");
      if (restoring) {
        if (route === "/healthz" && method === "GET")
          return json(res, 200, { ok: true, restoring: true });
        fail(503, "正在导入备份，请稍后重新登录");
      }
      const sid = (req.headers.cookie || "")
        .split(";")
        .map((s) => s.trim())
        .find((s) => s.startsWith("watch="))
        ?.slice(6);
      const session = sessions.get(sid);
      const owner = db
        .prepare("SELECT * FROM accounts WHERE admin=1 ORDER BY id LIMIT 1")
        .get();
      const account =
        session &&
        owner &&
        session.account === owner.id &&
        !owner.disabled &&
        session.until > Date.now()
          ? owner
          : null;
      if (method === "GET" && route === "/healthz")
        return json(res, 200, { ok: true });
      if (method === "GET" && route === "/api/setup/status")
        return json(res, 200, {
          needsSetup: !initialized(),
        });
      if (
        method === "GET" &&
        ["/", "/app.js", "/auth.js", "/style.css"].includes(route)
      ) {
        if (route === "/app.js" && !account) fail(401, "请先登录");
        const file =
          route === "/"
            ? account
              ? "index.html"
              : "login.html"
            : route.slice(1);
        res.setHeader(
          "Content-Type",
          file.endsWith(".js")
            ? "text/javascript"
            : file.endsWith(".css")
              ? "text/css"
              : "text/html; charset=utf-8",
        );
        res.setHeader(
          "Content-Security-Policy",
          "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        );
        return res.end(readFileSync(path.join(root, "public", file)));
      }
      if (method === "GET" && !route.startsWith("/api/")) {
        res.writeHead(302, { Location: "/" });
        return res.end();
      }
      if (
        method === "POST" &&
        ["/api/node-access/policy", "/api/node-access/events"].includes(route)
      )
        return await receiveDestinations(req, res, {
          db,
          decrypt,
          route,
          freeBytes: () => {
            const s = statfsSync(dataDir);
            return s.bavail * s.bsize;
          },
        });
      if (method === "POST" && route === "/api/collector/control")
        return await bans.receive(req, res);
      if (method === "POST" && route === "/api/collector/events")
        return await receiveBatch(req, res, { db, decrypt, geo });
      if (method !== "GET" && req.headers["x-watch-request"] !== "1")
        fail(403, "请求校验失败");
      if (method === "POST" && ["/api/setup", "/api/login"].includes(route)) {
        const b = await body(req);
        throttle("auth:" + req.socket.remoteAddress, 500);
        throttle("user:" + String(b.username).toLowerCase(), 15);
        let a;
        if (route === "/api/login") {
          a =
            typeof b.username === "string" &&
            db
              .prepare(
                "SELECT * FROM accounts WHERE username=? AND admin=1 ORDER BY id LIMIT 1",
              )
              .get(b.username);
          if (!a || a.disabled || !(await verify(b.password, a.password_hash)))
            fail(401, "账号或密码错误");
          const fresh = db
            .prepare("SELECT * FROM accounts WHERE id=?")
            .get(a.id);
          if (fresh.disabled || fresh.password_hash !== a.password_hash)
            fail(401, "账号状态已改变，请重新登录");
        } else {
          const setup = true;
          if (setup && initialized()) fail(409, "已经初始化");

          if (
            typeof b.username !== "string" ||
            !/^[A-Za-z0-9_@.\-]{3,64}$/.test(b.username)
          )
            fail(400, "账号须为3～64位字母、数字或 _ @ . -");
          password(b.password, b.confirmPassword);

          const hashed = await hash(b.password);
          a = transaction(db, () => {
            if (setup && initialized()) fail(409, "已经初始化");

            if (
              db
                .prepare("SELECT id FROM accounts WHERE username=?")
                .get(b.username)
            )
              fail(409, "账号已存在");
            const id = Number(
              db
                .prepare(
                  "INSERT INTO accounts(username,password_hash,admin,created) VALUES(?,?,?,?)",
                )
                .run(b.username, hashed, Number(setup), Date.now())
                .lastInsertRowid,
            );

            return { id, admin: Number(setup) };
          });
        }
        attempts.delete("user:" + String(b.username).toLowerCase());
        const attemptsAtAddress = attempts.get(
          "auth:" + req.socket.remoteAddress,
        );
        if (attemptsAtAddress)
          attemptsAtAddress.n = Math.max(0, attemptsAtAddress.n - 1);
        makeSession(res, a.id);
        return json(res, 200, {
          ok: true,
        });
      }
      if (route === "/api/register") fail(404, "注册功能已关闭");
      if (!account) fail(401, "请先登录");
      if (route === "/api/backup/import" && method === "POST") {
        if (!account.admin) fail(403, "无权导入");
        if (req.headers["x-watch-confirm"] !== "restore")
          fail(400, "请确认覆盖当前数据");
        if (backupBusy || importBusy || geo.busy)
          fail(409, "正在备份、导入或安装IP库，请稍后重试");
        if (Number(req.headers["content-length"]) > 2 * 1024 ** 3)
          fail(413, "备份压缩包最多2GB");
        importBusy = true;
        let upload;
        let databaseClosed = false;
        try {
          upload = await mkdtemp(path.join(dataDir, ".upload-"));
          const file = path.join(upload, "backup.tar.gz"),
            handle = await open(file, "wx", 0o600);
          let size = 0;
          try {
            for await (const chunk of req) {
              size += chunk.length;
              if (size > 2 * 1024 ** 3)
                fail(413, "备份压缩包最多2GB；更大的备份请使用VPS恢复工具");
              await handle.writeFile(chunk);
            }
          } finally {
            await handle.close();
          }
          if (!size) fail(400, "请选择备份文件");
          await restoreBackup(file, dataDir, {
            internalArchive: true,
            keep: [path.basename(upload)],
            beforeReplace: async () => {
              if (sessions.get(sid) !== session || session.until <= Date.now())
                fail(401, "登录已失效，请重新登录后导入");
              restoring = true;
              tg.stopped = true;
              bans.stopped = true;
              const deadline = Date.now() + 60000;
              while (
                activeRequests > 1 ||
                tg.running ||
                bans.running ||
                geo.busy
              ) {
                if (Date.now() > deadline)
                  throw Error("仍有请求正在处理，请稍后重试导入");
                await new Promise((r) => setTimeout(r, 25));
              }
              if (sessions.get(sid) !== session || session.until <= Date.now())
                fail(401, "登录已失效，请重新登录后导入");
              db.close();
              databaseClosed = true;
            },
            afterReplace: () => {
              loadState(true);
              databaseClosed = false;
            },
            afterRollback: () => {
              loadState();
              databaseClosed = false;
            },
          });
          sessions.clear();
          attempts.clear();
          res.setHeader(
            "Set-Cookie",
            "watch=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
          );
          return json(res, 200, {
            ok: true,
            message: "导入成功，请使用备份中的账号密码登录",
          });
        } finally {
          if (databaseClosed) {
            loadState();
            databaseClosed = false;
          }
          tg.stopped = false;
          bans.stopped = false;
          restoring = false;
          importBusy = false;
          if (upload) await rm(upload, { recursive: true, force: true });
        }
      }
      if (route === "/api/backup" && method === "GET") {
        if (!account.admin) fail(403, "无权备份");
        if (backupBusy || importBusy || geo.busy)
          fail(409, "正在备份或安装IP数据库，请稍后重试");
        backupBusy = true;
        try {
          await exportBackup(db, dataDir, geo, res);
        } finally {
          backupBusy = false;
        }
        return;
      }
      if (route === "/api/me" && method === "GET")
        return json(res, 200, {
          id: account.id,
          username: account.username,
        });
      if (route === "/api/logout" && method === "POST") {
        sessions.delete(sid);
        res.setHeader(
          "Set-Cookie",
          "watch=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        );
        return json(res, 200, { ok: true });
      }
      if (route === "/api/password" && method === "POST") {
        throttle("password:" + account.id);
        const b = await body(req);
        if (!(await verify(b.currentPassword, account.password_hash)))
          fail(400, "当前密码错误");
        password(b.newPassword, b.confirmPassword);
        const hashed = await hash(b.newPassword);
        if (
          !db
            .prepare(
              "UPDATE accounts SET password_hash=? WHERE id=? AND password_hash=?",
            )
            .run(hashed, account.id, account.password_hash).changes
        )
          fail(409, "密码已改变");
        for (const [k, v] of sessions)
          if (v.account === account.id) sessions.delete(k);
        return json(res, 200, { ok: true });
      }
      if (route.startsWith("/api/admin/")) {
        if ((backupBusy || importBusy) && method === "POST")
          fail(409, "正在备份，请稍后修改IP数据库");
        const b = method === "POST" ? await body(req) : {};
        if (route === "/api/admin/geo" && method === "GET")
          return json(res, 200, geo.status());
        if (route === "/api/admin/geo/credentials" && method === "POST") {
          geo.configure(b.accountId, b.licenseKey);
          return json(res, 200, { ok: true });
        }
        if (route === "/api/admin/geo/import" && method === "POST") {
          const config = parseGeoConfig(b.content);
          geo.configure(config.account, config.license);
          return json(res, 200, {
            ok: true,
            accountId: config.account,
            editions: config.editions,
          });
        }
        if (route === "/api/admin/geo/check" && method === "POST")
          return json(res, 200, await geo.check());
        if (route === "/api/admin/geo/install" && method === "POST") {
          geo.install();
          return json(res, 202, { ok: true });
        }
      }
      if (route === "/api/panels" && method === "GET") {
        const all = u.searchParams.get("all") === "1";

        return json(res, 200, {
          rows: db
            .prepare(
              `SELECT p.*,a.username owner_name FROM panels p JOIN accounts a ON a.id=p.owner ${all ? "" : "WHERE p.owner=?"} ORDER BY p.id`,
            )
            .all(...(all ? [] : [account.id]))
            .map(visible),
        });
      }
      if (route === "/api/panels" && method === "POST") {
        const b = await body(req);
        if (typeof b.name !== "string" || !b.name.trim() || b.name.length > 80)
          fail(400, "面板名称须为1～80字");
        if (
          db
            .prepare("SELECT count(*) n FROM panels WHERE owner=?")
            .get(account.id).n >= 100
        )
          fail(400, "每个账号最多100个面板");
        const id = Number(
          db
            .prepare(
              "INSERT INTO panels(owner,name,public_id,secret,rules) VALUES(?,?,?,?,?)",
            )
            .run(
              account.id,
              b.name.trim(),
              token(),
              encrypt(token()),
              JSON.stringify(defaults),
            ).lastInsertRowid,
        );
        return json(res, 200, { id });
      }
      const match = route.match(/^\/api\/panels\/(\d+)(?:\/(.*))?$/);
      if (match) {
        const id = Number(match[1]),
          action = match[2] || "",
          panel = db.prepare("SELECT * FROM panels WHERE id=?").get(id);
        if (!panel || panel.owner !== account.id) fail(404, "面板不存在");
        const b = method === "POST" ? await body(req) : {};
        if (action === "unban" && method === "POST") {
          bans.unban(id, b.uid, b.email);
          return json(res, 200, { ok: true });
        }
        if (action === "ban/manual" && method === "POST") {
          if (b.confirm !== true) fail(400, "请确认封禁账号");
          bans.manualBan(id, b.uid, b.email);
          return json(res, 200, { ok: true });
        }
        if (action === "ban" && method === "GET")
          return json(res, 200, bans.status(id));
        if (action === "ban" && method === "POST") {
          bans.configure(id, b);
          return json(res, 200, { ok: true });
        }
        if (action === "telegram" && method === "GET")
          return json(res, 200, tg.status(id));
        if (action === "telegram" && method === "POST") {
          await tg.configure(id, b.token, b.chatId);
          return json(res, 200, { ok: true });
        }
        if (action === "telegram/bind" && method === "POST")
          return json(res, 200, tg.bindCode(id));
        if (action === "telegram/remove" && method === "POST") {
          tg.disconnect(id);
          return json(res, 200, { ok: true });
        }

        const confirm = async () => {
          throttle("sensitive:" + account.id);
          if (!(await verify(b.password, account.password_hash)))
            fail(400, "当前账号密码错误");
        };
        if (action === "destinations" && method === "GET")
          return json(res, 200, destinationRows(db, id, u.searchParams));
        if (action === "destinations/settings" && method === "GET")
          return json(res, 200, destinationStatus(db, id));
        if (action === "destinations/user" && method === "POST") {
          setDestinationUser(db, id, b);
          return json(res, 200, { ok: true });
        }
        if (action === "destinations/node" && method === "POST")
          return json(res, 200, createDestinationNode(db, id, b.name, encrypt));
        if (action === "destinations/node/remove" && method === "POST") {
          await confirm();
          db.prepare(
            "DELETE FROM destination_nodes WHERE panel=? AND id=?",
          ).run(id, Number(b.id) || 0);
          return json(res, 200, { ok: true });
        }
        if (action === "destinations/clear" && method === "POST") {
          await confirm();
          transaction(db, () => {
            db.prepare("DELETE FROM destinations WHERE panel=?").run(id);
            db.prepare(
              "UPDATE destination_users SET since=? WHERE panel=?",
            ).run(Date.now(), id);
          });
          return json(res, 200, { ok: true });
        }
        if (action === "key" && method === "POST")
          return json(res, 200, {
            publicId: panel.public_id,
            collectorKey: decrypt(panel.secret),
          });
        if (action === "preview" && method === "POST") {
          const rules = validateRules(b.rules),
            candidate = { ...panel, rules: JSON.stringify(rules) };
          const counts = { suspicious: 0, none: 0 },
            now = Date.now();
          for (const subject of db
            .prepare("SELECT * FROM subjects WHERE panel=?")
            .all(id))
            counts[riskLevel(assess(db, candidate, subject, now, geo))]++;
          return json(res, 200, {
            counts,
            at: now,
            note: "地域规则按保留样本预览；UA和云服务器仅预览已有触发证据，新请求才会新增标记。已保留的旧标记不会因预览解除。不发通知、不封禁。",
          });
        }
        if (action === "settings" && method === "POST") {
          if (
            typeof b.name !== "string" ||
            !b.name.trim() ||
            b.name.length > 80 ||
            typeof b.notify !== "boolean"
          )
            fail(400, "面板设置格式错误");
          const rules = validateRules(b.rules);
          transaction(db, () => {
            db.prepare(
              "UPDATE panels SET name=?,notify=?,rules=? WHERE id=?",
            ).run(b.name.trim(), Number(b.notify), JSON.stringify(rules), id);
            const changed = {
              ...panel,
              name: b.name.trim(),
              notify: Number(b.notify),
              rules: JSON.stringify(rules),
            };
            for (const s of db
              .prepare("SELECT uid FROM subjects WHERE panel=?")
              .all(id))
              evaluate(db, changed, s.uid, Date.now(), geo);
          });
          return json(res, 200, { ok: true });
        }
        if (action === "delete" && method === "POST") {
          await confirm();

          db.prepare("DELETE FROM panels WHERE id=?").run(id);
          return json(res, 200, { ok: true });
        }
        if (action === "status" && method === "GET") {
          const storage = statfsSync(dataDir);
          return json(res, 200, {
            panel: visible(panel),
            events: db
              .prepare("SELECT count(*) n FROM visits WHERE panel=?")
              .get(id).n,
            today: db
              .prepare("SELECT count(*) n FROM visits WHERE panel=? AND ts>?")
              .get(id, Date.now() - 86400000).n,
            risks: db
              .prepare(
                "SELECT count(*) n FROM risks WHERE panel=? AND active=1",
              )
              .get(id).n,
            freeBytes: Number(storage.bavail) * Number(storage.bsize),
          });
        }
        const page = Math.max(
            1,
            Math.min(1000000, parseInt(u.searchParams.get("page")) || 1),
          ),
          offset = (page - 1) * 50;
        if (["events", "export"].includes(action) && method === "GET") {
          const conditions = ["panel=?"],
            params = [id];
          for (const f of ["uid", "ip"])
            if (u.searchParams.get(f)) {
              conditions.push(f + "=?");
              params.push(u.searchParams.get(f));
            }
          for (const f of ["email", "ua"])
            if (u.searchParams.get(f)) {
              conditions.push(f + " LIKE ?");
              params.push("%" + u.searchParams.get(f).slice(0, 200) + "%");
            }
          for (const [f, op] of [
            ["from", ">="],
            ["to", "<="],
          ])
            if (u.searchParams.get(f)) {
              const ts = Date.parse(u.searchParams.get(f));
              if (!Number.isFinite(ts)) fail(400, "日期错误");
              conditions.push("ts" + op + "?");
              params.push(ts);
            }
          const where = conditions.join(" AND ");
          const rows = db
            .prepare(
              "SELECT * FROM visits WHERE " +
                where +
                " ORDER BY ts DESC,id DESC LIMIT ? OFFSET ?",
            )
            .all(
              ...params,
              action === "export" ? 50000 : 50,
              action === "export" ? 0 : offset,
            )
            .map((r) => ({ ...r, geo: geo.lookup(r.ip) }));
          if (action === "export") {
            const escape = (x) =>
              '"' +
              String(x ?? "")
                .replace(/^[=+@\-\t\r]/, "'$&")
                .replaceAll('"', '""') +
              '"';
            res.writeHead(200, {
              "Content-Type": "text/csv; charset=utf-8",
              "Content-Disposition":
                'attachment; filename="subscription-history.csv"',
              "Cache-Control": "no-store",
            });
            res.write(
              "\ufeff时间,用户ID,邮箱,IP,国家,地区,城市,网络组织,原始UA,状态码\r\n",
            );
            for (const r of rows)
              res.write(
                [
                  new Date(r.ts).toISOString(),
                  r.uid,
                  r.email,
                  r.ip,
                  r.geo.country,
                  r.geo.region,
                  r.geo.city,
                  r.geo.organization,
                  r.ua,
                  r.status,
                ]
                  .map(escape)
                  .join(",") + "\r\n",
              );
            return res.end();
          }
          return json(res, 200, {
            rows,
            page,
            total: db
              .prepare("SELECT count(*) n FROM visits WHERE " + where)
              .get(...params).n,
          });
        }
        const enrich = (reasons) =>
          reasons.map((r) => ({
            ...r,
            locations: (r.ips || [r.ip])
              .filter(Boolean)
              .map((ip) => ({ ip, ...geo.lookup(ip) })),
          }));
        if (action === "risks" && method === "GET")
          return json(res, 200, {
            rows: riskRows(db, id, {
              all: u.searchParams.get("all") === "1",
              limit: 50,
              offset,
            }).map((r) => ({ ...r, reasons: enrich(r.reasons) })),
            page,
          });
        if (action === "risk-history" && method === "GET")
          return json(res, 200, {
            rows: db
              .prepare(
                "SELECT * FROM risk_history WHERE panel=? ORDER BY id DESC LIMIT 50 OFFSET ?",
              )
              .all(id, offset)
              .map((r) => ({ ...r, reasons: enrich(JSON.parse(r.reasons)) })),
            page,
          });
        if (action === "subjects" && method === "GET") {
          const q = (u.searchParams.get("q") || "").slice(0, 254);
          return json(res, 200, {
            rows: db
              .prepare(
                "SELECT * FROM subjects WHERE panel=? AND white=1 AND (CAST(uid AS TEXT)=? OR email LIKE ?) ORDER BY uid LIMIT 50 OFFSET ?",
              )
              .all(id, q, "%" + q + "%", offset),
          });
        }
        if (action === "whitelist" && method === "POST") {
          const uid = Number(b.uid);
          if (
            !Number.isSafeInteger(uid) ||
            uid < 1 ||
            typeof b.enabled !== "boolean"
          )
            fail(400, "用户ID或白名单状态错误");
          transaction(db, () => {
            const existing = db
              .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
              .get(id, uid);
            if (!existing || !existing.verified)
              fail(400, "此用户尚无已采集记录，请先让用户获取一次订阅");
            if (
              b.enabled &&
              (typeof b.email !== "string" || b.email.trim() !== existing.email)
            )
              fail(400, "用户ID与已采集邮箱不对应");
            db.prepare(
              "UPDATE subjects SET white=? WHERE panel=? AND uid=?",
            ).run(Number(b.enabled), id, uid);
            evaluate(db, panel, uid, Date.now(), geo);
          });
          return json(res, 200, { ok: true });
        }
        if (["resolve", "risk-delete"].includes(action) && method === "POST") {
          if (action === "risk-delete") await confirm();
          transaction(db, () =>
            resolveRisk(db, id, Number(b.uid), {
              remove: action === "risk-delete",
            }),
          );
          return json(res, 200, { ok: true });
        }
        if (action === "risk-history/delete" && method === "POST") {
          await confirm();
          if (b.all === true) {
            db.prepare("DELETE FROM risk_history WHERE panel=?").run(id);
          } else
            db.prepare("DELETE FROM risk_history WHERE panel=? AND id=?").run(
              id,
              Number(b.id) || 0,
            );
          return json(res, 200, { ok: true });
        }
        if (action === "history/clear" && method === "POST") {
          await confirm();
          transaction(db, () => {
            db.prepare("DELETE FROM visits WHERE panel=?").run(id);
            db.prepare("UPDATE panels SET cleared_at=? WHERE id=?").run(
              Date.now(),
              id,
            );
          });
          return json(res, 200, { ok: true });
        }
      }
      fail(404, "未找到接口");
    } catch (e) {
      if (!res.headersSent)
        json(
          res,
          Number.isInteger(e.status) && e.status >= 400 && e.status <= 599
            ? e.status
            : 400,
          {
            error:
              typeof e.code === "string" && e.code.startsWith("ERR_SQLITE")
                ? "数据库操作失败"
                : e.message,
          },
        );
      else res.end();
    } finally {
      activeRequests--;
    }
  });
  admin.requestTimeout = 15 * 60000;
  admin.headersTimeout = 10000;
  admin.maxHeadersCount = 50;
  return {
    admin,
    get db() {
      return db;
    },
    get geo() {
      return geo;
    },
    get tg() {
      return tg;
    },
    maintenance,
    get bans() {
      return bans;
    },
    close: async () => {
      timers.forEach(clearInterval);
      bans.stopped = true;
      while (bans.running) await new Promise((r) => setTimeout(r, 20));
      tg.stopped = true;
      await new Promise((r) => admin.close(r));
      while (tg.running) await new Promise((r) => setTimeout(r, 20));
      if (geo.task) await geo.task;
      db.close();
    },
  };
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const app = createApp();
  app.admin.listen(Number(process.env.ADMIN_PORT || 8080), "0.0.0.0");
  console.log("Subscription Watch v3.8.1 ready");
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () => app.close().then(() => process.exit(0)));
}
