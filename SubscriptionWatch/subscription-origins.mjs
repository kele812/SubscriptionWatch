import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { transaction } from "./model.mjs";

export function initSubscriptionOrigins(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS subscription_origins(
    panel INTEGER NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    uid INTEGER NOT NULL,email TEXT NOT NULL,origin TEXT,
    revision TEXT NOT NULL,updated INTEGER NOT NULL,
    last_checked INTEGER,last_revision TEXT,
    PRIMARY KEY(panel,uid));`);
}

export function normalizeSubscriptionOrigin(value) {
  if (typeof value !== "string" || value.length > 255 || /[\s\\]/u.test(value))
    throw Error("请填写 HTTPS 订阅根地址，不含路径、Token 或空格");
  let url;
  try {
    url = new URL(value);
  } catch {
    throw Error("请填写完整 HTTPS 地址，例如 https://sub.example.com");
  }
  if (
    !/^https:\/\/[^/?#]+\/?$/.test(value) ||
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    value.includes("?") ||
    value.includes("#")
  )
    throw Error("只允许 HTTPS 根地址，不含账号、路径、查询参数或 Token");
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
  // null means restore the default, and retains the row in the modified-user list.
  const origin =
    data.origin === null ? null : normalizeSubscriptionOrigin(data.origin);
  return transaction(db, () => {
    const previous = db
      .prepare("SELECT * FROM subscription_origins WHERE panel=? AND uid=?")
      .get(panel, data.uid);
    if ((previous?.revision || null) !== (data.revision ?? null))
      throw Object.assign(Error("此客户设置已变化，请刷新列表后编辑"), {
        status: 409,
      });
    if (!previous && origin === null) throw Error("此客户尚未设置指定订阅地址");
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

export function subscriptionOriginRows(db, panel, query, page) {
  const q = String(query || "")
    .trim()
    .slice(0, 254);
  const where =
    "o.panel=? AND (?='' OR CAST(o.uid AS TEXT)=? OR instr(lower(o.email),lower(?))>0 OR instr(lower(COALESCE(o.origin,'')),lower(?))>0)";
  const params = [panel, q, q, q, q];
  return {
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
            : row.last_revision === row.revision
              ? "插件已查询"
              : "待客户刷新订阅信息",
      })),
  };
}

function reply(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(data));
}

export async function receiveSubscriptionOrigin(req, res, { db, decrypt }) {
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
    .update("subscription-origin-request\n" + timestamp + "\n")
    .update(raw)
    .digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, "hex")))
    return reply(res, 401, { error: "invalid signature" });
  let event;
  try {
    event = JSON.parse(raw);
    identity(event.user_id, event.email);
    if (
      event.schema !== 1 ||
      typeof event.nonce !== "string" ||
      !/^[a-f0-9]{48}$/.test(event.nonce) ||
      Object.keys(event).some(
        (key) => !["schema", "user_id", "email", "nonce"].includes(key),
      )
    )
      throw Error();
  } catch {
    return reply(res, 422, { error: "invalid request" });
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
  // No subscription token is sent to or stored by the watch service.
  const payload = Buffer.from(
    JSON.stringify({
      schema: 1,
      panel: panelId,
      nonce: event.nonce,
      user_id: event.user_id,
      email: event.email,
      origin,
      expires: Date.now() + 30000,
    }),
  ).toString("base64");
  if (matches)
    db.prepare(
      "UPDATE subscription_origins SET last_checked=?,last_revision=? WHERE panel=? AND uid=?",
    ).run(Date.now(), row.revision, panel.id, event.user_id);
  return reply(res, 200, {
    payload,
    signature: createHmac("sha256", secret)
      .update("subscription-origin-response\n" + payload)
      .digest("hex"),
  });
}
