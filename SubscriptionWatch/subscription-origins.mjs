import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { transaction } from "./model.mjs";

export function initSubscriptionOrigins(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS subscription_origin_sync(
    panel INTEGER PRIMARY KEY REFERENCES panels(id) ON DELETE CASCADE,
    applied_revision TEXT,last_contact INTEGER NOT NULL);`);
  db.exec(`CREATE TABLE IF NOT EXISTS subscription_origin_push(
    panel INTEGER PRIMARY KEY REFERENCES panels(id) ON DELETE CASCADE,
    xboard_url TEXT NOT NULL,last_error TEXT);`);
  db.exec(`CREATE TABLE IF NOT EXISTS subscription_origins(
    panel INTEGER NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    uid INTEGER NOT NULL,email TEXT NOT NULL,origin TEXT,
    revision TEXT NOT NULL,updated INTEGER NOT NULL,
    last_checked INTEGER,last_revision TEXT,
    PRIMARY KEY(panel,uid));`);
  db.exec(`CREATE TABLE IF NOT EXISTS subscription_origin_options(
    panel INTEGER PRIMARY KEY REFERENCES panels(id) ON DELETE CASCADE,
    origins TEXT NOT NULL,revision TEXT NOT NULL);`);
  if (
    !db
      .prepare("PRAGMA table_info(subscription_origins)")
      .all()
      .some((column) => column.name === "last_status")
  )
    db.exec("ALTER TABLE subscription_origins ADD COLUMN last_status TEXT");
}

export function subscriptionOriginOptions(db, panel) {
  const row = db
    .prepare(
      "SELECT origins,revision FROM subscription_origin_options WHERE panel=?",
    )
    .get(panel);
  const origins = row
    ? JSON.parse(row.origins)
    : db
        .prepare(
          `SELECT origin FROM subscription_origins
    WHERE panel=? AND origin IS NOT NULL GROUP BY origin ORDER BY MAX(updated) DESC,origin LIMIT 20`,
        )
        .all(panel)
        .map((item) => item.origin);
  return { origins, revision: row?.revision || null };
}

export function saveSubscriptionOriginOptions(db, panel, data) {
  if (
    !Array.isArray(data.origins) ||
    data.origins.length > 20 ||
    data.origins.some((value) => typeof value !== "string")
  )
    throw Error("最多保存20个备选订阅地址，每行一个 HTTP 或 HTTPS 根地址");
  const origins = [
    ...new Set(
      data.origins.map((value) => normalizeSubscriptionOrigin(value.trim())),
    ),
  ];
  return transaction(db, () => {
    const previous = subscriptionOriginOptions(db, panel);
    if (previous.revision !== (data.revision ?? null))
      throw Object.assign(Error("备选地址已变化，请刷新后再保存"), {
        status: 409,
      });
    const revision = randomBytes(16).toString("hex");
    db.prepare(
      `INSERT INTO subscription_origin_options(panel,origins,revision) VALUES(?,?,?)
      ON CONFLICT(panel) DO UPDATE SET origins=excluded.origins,revision=excluded.revision`,
    ).run(panel, JSON.stringify(origins), revision);
    return { origins, revision };
  });
}

export function normalizeSubscriptionOrigin(value, httpsOnly = false) {
  const protocols = httpsOnly ? "HTTPS" : "HTTP 或 HTTPS";
  if (typeof value !== "string" || value.length > 255 || /[\s\\]/u.test(value))
    throw Error(`请填写 ${protocols} 根地址，不含路径、Token 或空格`);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw Error(`请填写完整 ${protocols} 地址，例如 https://sub.example.com`);
  }
  if (
    !/^https?:\/\/[^/?#]+\/?$/.test(value) ||
    !(httpsOnly ? ["https:"] : ["http:", "https:"]).includes(url.protocol) ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    value.includes("?") ||
    value.includes("#")
  )
    throw Error(`只允许 ${protocols} 根地址，不含账号、路径、查询参数或 Token`);
  return url.origin;
}

function identity(uid, email) {
  if (
    !Number.isSafeInteger(uid) ||
    uid < 1 ||
    typeof email !== "string" ||
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+$/u.test(email)
  )
    throw Error("请填写有效的客户 ID 和邮箱");
}

export function saveSubscriptionOrigin(db, panel, data) {
  identity(data.uid, data.email);
  // Older dashboards used null to restore defaults. Preserve that effect by deleting the override.
  if (data.origin === null) return deleteSubscriptionOrigin(db, panel, data);
  const origin = normalizeSubscriptionOrigin(data.origin);
  return transaction(db, () => {
    // Search/edit and manual add share one mapping. The last explicit save wins.
    const known = db
      .prepare("SELECT email,verified FROM subjects WHERE panel=? AND uid=?")
      .get(panel, data.uid);
    if (origin && known?.verified && known.email !== data.email)
      throw Error("客户 ID 与已采集邮箱不匹配，请核对后再设置");
    const revision = randomBytes(16).toString("hex"),
      updated = Date.now();
    db.prepare(
      `INSERT INTO subscription_origins(panel,uid,email,origin,revision,updated)
      VALUES(?,?,?,?,?,?) ON CONFLICT(panel,uid) DO UPDATE SET
      email=excluded.email,origin=excluded.origin,revision=excluded.revision,updated=excluded.updated`,
    ).run(panel, data.uid, data.email, origin, revision, updated);
    return { ok: true, revision };
  });
}

export function deleteSubscriptionOrigin(db, panel, data) {
  identity(data.uid, data.email);
  return transaction(db, () => {
    const current = db
      .prepare(
        "SELECT email,revision FROM subscription_origins WHERE panel=? AND uid=?",
      )
      .get(panel, data.uid);
    if (!current)
      throw Object.assign(Error("此指定订阅设置已不存在，请刷新列表"), {
        status: 404,
      });
    if (current.email !== data.email || current.revision !== data.revision)
      throw Object.assign(Error("此客户设置已变化，请刷新后再删除"), {
        status: 409,
      });
    db.prepare(
      "DELETE FROM subscription_origins WHERE panel=? AND uid=? AND revision=? AND email=?",
    ).run(panel, data.uid, data.revision, data.email);
    return { ok: true };
  });
}

export function subscriptionOriginRows(db, panel, query, page) {
  const snapshot = originSnapshot(db, panel);
  const sync = db
    .prepare("SELECT * FROM subscription_origin_sync WHERE panel=?")
    .get(panel);
  const synced = sync?.applied_revision === snapshot.revision;
  const push = db
    .prepare("SELECT * FROM subscription_origin_push WHERE panel=?")
    .get(panel);
  const q = String(query || "")
    .trim()
    .slice(0, 254);
  const where =
    "o.panel=? AND (?='' OR CAST(o.uid AS TEXT)=? OR instr(lower(o.email),lower(?))>0 OR instr(lower(COALESCE(o.origin,'')),lower(?))>0)";
  const params = [panel, q, q, q, q];
  return {
    sync: {
      state: synced ? "已同步到 Xboard" : "待同步到 Xboard",
      last_contact: sync?.last_contact || null,
      xboard_url: push?.xboard_url || "",
      error: push?.last_error || null,
    },
    total: db
      .prepare(`SELECT COUNT(*) n FROM subscription_origins o WHERE ${where}`)
      .get(...params).n,
    rows: db
      .prepare(
        `SELECT o.*,s.email AS current_email,s.verified FROM subscription_origins o
      LEFT JOIN subjects s ON s.panel=o.panel AND s.uid=o.uid WHERE ${where}
      ORDER BY o.updated DESC,o.uid LIMIT 50 OFFSET ?`,
      )
      .all(...params, (page - 1) * 50)
      .map((row) => ({
        ...row,
        state: !row.origin
          ? "已恢复默认"
          : row.verified && row.current_email !== row.email
            ? "邮箱不匹配，已暂停"
            : synced
              ? "已同步到 Xboard"
              : "待同步到 Xboard",
      })),
  };
}

function originSnapshot(db, panel) {
  const rows = db
    .prepare(
      `SELECT o.uid AS user_id,o.email,o.origin,o.revision FROM subscription_origins o
    LEFT JOIN subjects s ON s.panel=o.panel AND s.uid=o.uid
    WHERE o.panel=? AND o.origin IS NOT NULL AND (s.verified IS NULL OR s.verified=0 OR s.email=o.email)
    ORDER BY o.uid`,
    )
    .all(panel);
  return {
    rows,
    revision: createHash("sha256").update(JSON.stringify(rows)).digest("hex"),
  };
}

function reply(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(data));
}

export async function receiveSubscriptionOrigin(
  req,
  res,
  { db, decrypt },
  sync = false,
) {
  const timestamp = req.headers["x-watch-timestamp"],
    signature = req.headers["x-watch-signature"];
  const panelId = req.headers["x-watch-panel"];
  if (
    typeof timestamp !== "string" ||
    !/^\d{10}$/.test(timestamp) ||
    Math.abs(Date.now() / 1000 - Number(timestamp)) > 300 ||
    typeof signature !== "string" ||
    !/^[a-f0-9]{64}$/.test(signature) ||
    typeof panelId !== "string" ||
    !/^[a-f0-9]{48}$/.test(panelId)
  )
    return reply(res, 401, { error: "invalid signature or panel" });
  const panel = db
    .prepare("SELECT * FROM panels WHERE public_id=?")
    .get(panelId);
  if (!panel) return reply(res, 401, { error: "invalid signature or panel" });
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 4096) return reply(res, 413, { error: "request too large" });
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks),
    secret = decrypt(panel.secret);
  const expected = createHmac("sha256", secret)
    .update(
      (sync
        ? "subscription-origin-sync-request\n"
        : "subscription-origin-request\n") +
        timestamp +
        "\n",
    )
    .update(raw)
    .digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, "hex")))
    return reply(res, 401, { error: "invalid signature" });
  let event;
  try {
    event = JSON.parse(raw);
    if (!sync) identity(event.user_id, event.email);
    if (
      event.schema !== 1 ||
      typeof event.nonce !== "string" ||
      !/^[a-f0-9]{48}$/.test(event.nonce) ||
      Object.keys(event).some(
        (key) =>
          !(
            sync
              ? ["schema", "revision", "cursor", "nonce"]
              : ["schema", "user_id", "email", "nonce"]
          ).includes(key),
      )
    )
      throw Error();
    if (
      sync &&
      ((event.revision !== null &&
        (typeof event.revision !== "string" ||
          !/^[a-f0-9]{64}$/.test(event.revision))) ||
        !Number.isSafeInteger(event.cursor) ||
        event.cursor < 0)
    )
      throw Error();
  } catch {
    return reply(res, 422, { error: "invalid request" });
  }
  if (sync) {
    const snapshot = originSnapshot(db, panel.id);
    if (event.cursor === 0)
      db.prepare(
        `INSERT INTO subscription_origin_sync(panel,applied_revision,last_contact) VALUES(?,?,?)
      ON CONFLICT(panel) DO UPDATE SET applied_revision=excluded.applied_revision,last_contact=excluded.last_contact`,
      ).run(panel.id, event.revision, Date.now());
    const restart = event.cursor > 0 && event.revision !== snapshot.revision;
    const unchanged =
      event.cursor === 0 && event.revision === snapshot.revision;
    const rows =
      restart || unchanged
        ? []
        : snapshot.rows
            .filter((row) => row.user_id > event.cursor)
            .slice(0, 500);
    const last = rows.at(-1)?.user_id || 0;
    const next =
      rows.length === 500 && snapshot.rows.some((row) => row.user_id > last)
        ? last
        : null;
    const payload = Buffer.from(
      JSON.stringify({
        schema: 1,
        panel: panelId,
        nonce: event.nonce,
        expires: Date.now() + 30000,
        revision: snapshot.revision,
        restart,
        unchanged,
        next,
        users: rows.map(({ user_id, email, origin }) => ({
          user_id,
          email,
          origin,
        })),
      }),
    ).toString("base64");
    return reply(res, 200, {
      payload,
      signature: createHmac("sha256", secret)
        .update("subscription-origin-sync-response\n" + payload)
        .digest("hex"),
    });
  }
  const row = db
    .prepare("SELECT * FROM subscription_origins WHERE panel=? AND uid=?")
    .get(panel.id, event.user_id);
  const known = db
    .prepare("SELECT email,verified FROM subjects WHERE panel=? AND uid=?")
    .get(panel.id, event.user_id);
  const matches =
    row?.email === event.email &&
    (!known?.verified || known.email === event.email);
  const origin = matches ? row.origin : null;
  const status = !row
    ? "not-configured"
    : !matches
      ? "email-mismatch"
      : row.origin
        ? "configured"
        : "default";
  // No subscription token is sent to or stored by the watch service.
  const payload = Buffer.from(
    JSON.stringify({
      schema: 1,
      panel: panelId,
      nonce: event.nonce,
      user_id: event.user_id,
      email: event.email,
      origin,
      lookup_status: status,
      expires: Date.now() + 30000,
    }),
  ).toString("base64");
  if (row)
    db.prepare(
      "UPDATE subscription_origins SET last_checked=?,last_revision=?,last_status=? WHERE panel=? AND uid=?",
    ).run(Date.now(), row.revision, status, panel.id, event.user_id);
  return reply(res, 200, {
    payload,
    signature: createHmac("sha256", secret)
      .update("subscription-origin-response\n" + payload)
      .digest("hex"),
  });
}

export function receiveSubscriptionOriginSync(req, res, context) {
  return receiveSubscriptionOrigin(req, res, context, true);
}

export function saveSubscriptionOriginPush(db, panel, value) {
  const origin = value === "" ? "" : normalizeSubscriptionOrigin(value, true);
  db.prepare(
    `INSERT INTO subscription_origin_push(panel,xboard_url) VALUES(?,?)
    ON CONFLICT(panel) DO UPDATE SET xboard_url=excluded.xboard_url,last_error=NULL`,
  ).run(panel, origin);
}

export async function lookupSubscriptionOrigin(
  { db, decrypt, fetcher },
  panel,
  query,
) {
  if (
    typeof query !== "string" ||
    query.length > 254 ||
    !/^(?:[1-9][0-9]{0,14}|[^\s@]+@[^\s@]+)$/u.test(query)
  )
    throw Error("请输入完整客户 ID 或邮箱进行精确查询");
  const target = db
    .prepare("SELECT xboard_url FROM subscription_origin_push WHERE panel=?")
    .get(panel.id)?.xboard_url;
  if (!target) throw Error("请先配置当前面板的 Xboard 地址");
  const secret = decrypt(panel.secret),
    nonce = randomBytes(24).toString("hex"),
    timestamp = String(Math.floor(Date.now() / 1000));
  const body = JSON.stringify({ schema: 1, nonce, query });
  try {
    const response = await fetcher(
      target + "/api/v1/guest/subscription-watch/origin-lookup",
      {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(10000),
        headers: {
          "Content-Type": "application/json",
          "X-Watch-Panel": panel.public_id,
          "X-Watch-Timestamp": timestamp,
          "X-Watch-Signature": createHmac("sha256", secret)
            .update(
              "subscription-origin-lookup-request\n" + timestamp + "\n" + body,
            )
            .digest("hex"),
        },
        body,
      },
    );
    if (!response.ok) throw Error();
    const raw = await response.text();
    if (raw.length > 16384) throw Error();
    const envelope = JSON.parse(raw);
    if (
      typeof envelope.payload !== "string" ||
      typeof envelope.signature !== "string" ||
      !/^[a-f0-9]{64}$/.test(envelope.signature) ||
      !timingSafeEqual(
        createHmac("sha256", secret)
          .update("subscription-origin-lookup-response\n" + envelope.payload)
          .digest(),
        Buffer.from(envelope.signature, "hex"),
      )
    )
      throw Error();
    const result = JSON.parse(Buffer.from(envelope.payload, "base64"));
    if (
      result.schema !== 1 ||
      result.panel !== panel.public_id ||
      result.nonce !== nonce ||
      result.query !== query ||
      !Number.isSafeInteger(result.expires) ||
      result.expires < Date.now() ||
      result.expires > Date.now() + 60000
    )
      throw Error();
    if (result.user !== null) {
      identity(result.user.id, result.user.email);
      if (
        typeof result.user.subscribe_url !== "string" ||
        result.user.subscribe_url.length > 4096
      )
        throw Error();
      const url = new URL(result.user.subscribe_url);
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password
      )
        throw Error();
    }
    const setting = result.user
      ? db
          .prepare("SELECT * FROM subscription_origins WHERE panel=? AND uid=?")
          .get(panel.id, result.user.id)
      : null;
    return { user: result.user, setting: setting || null };
  } catch {
    throw Object.assign(
      Error(
        "无法确认 Xboard 当前订阅地址，请检查面板地址、插件版本和连接后重试",
      ),
      { status: 502 },
    );
  }
}

export async function pushSubscriptionOrigins({ db, decrypt, fetcher }, panel) {
  const target = db
    .prepare("SELECT xboard_url FROM subscription_origin_push WHERE panel=?")
    .get(panel.id)?.xboard_url;
  if (!target)
    return { ok: false, message: "未配置 Xboard 地址，等待定时同步" };
  const secret = decrypt(panel.secret),
    nonce = randomBytes(24).toString("hex"),
    timestamp = String(Math.floor(Date.now() / 1000));
  const body = JSON.stringify({ schema: 1, nonce });
  try {
    const response = await fetcher(
      target + "/api/v1/guest/subscription-watch/origin-sync",
      {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(20000),
        headers: {
          "Content-Type": "application/json",
          "X-Watch-Panel": panel.public_id,
          "X-Watch-Timestamp": timestamp,
          "X-Watch-Signature": createHmac("sha256", secret)
            .update(
              "subscription-origin-notify-request\n" + timestamp + "\n" + body,
            )
            .digest("hex"),
        },
        body,
      },
    );
    if (!response.ok) throw Error();
    const raw = await response.text();
    if (raw.length > 8192) throw Error();
    const envelope = JSON.parse(raw);
    if (
      typeof envelope.payload !== "string" ||
      typeof envelope.signature !== "string" ||
      !/^[a-f0-9]{64}$/.test(envelope.signature) ||
      !timingSafeEqual(
        createHmac("sha256", secret)
          .update("subscription-origin-notify-response\n" + envelope.payload)
          .digest(),
        Buffer.from(envelope.signature, "hex"),
      )
    )
      throw Error();
    const result = JSON.parse(Buffer.from(envelope.payload, "base64"));
    if (
      result.schema !== 1 ||
      result.panel !== panel.public_id ||
      result.nonce !== nonce ||
      !Number.isSafeInteger(result.expires) ||
      result.expires < Date.now() ||
      result.expires > Date.now() + 60000 ||
      result.revision !== originSnapshot(db, panel.id).revision
    )
      throw Error();
    db.prepare(
      `INSERT INTO subscription_origin_sync(panel,applied_revision,last_contact) VALUES(?,?,?)
      ON CONFLICT(panel) DO UPDATE SET applied_revision=excluded.applied_revision,last_contact=excluded.last_contact`,
    ).run(panel.id, result.revision, Date.now());
    db.prepare(
      "UPDATE subscription_origin_push SET last_error=NULL WHERE panel=?",
    ).run(panel.id);
    return { ok: true, message: "已同步到 Xboard，刷新订阅信息后使用新地址" };
  } catch {
    const message =
      "主动同步未确认成功，请检查 Xboard 地址、插件版本及连接；设置已保留，将定时重试";
    db.prepare(
      "UPDATE subscription_origin_push SET last_error=? WHERE panel=?",
    ).run(message, panel.id);
    return { ok: false, message };
  }
}
