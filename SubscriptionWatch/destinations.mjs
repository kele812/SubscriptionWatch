import { createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { token, transaction } from "./model.mjs";

export const DESTINATION_DAYS = 3;
export function initDestinations(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS destination_users(panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,email TEXT NOT NULL,since INTEGER NOT NULL,PRIMARY KEY(panel,uid));
    CREATE TABLE IF NOT EXISTS destination_nodes(id INTEGER PRIMARY KEY,panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,name TEXT NOT NULL,public_id TEXT UNIQUE NOT NULL,secret TEXT NOT NULL,last_seen INTEGER,pending INTEGER DEFAULT 0,dropped INTEGER DEFAULT 0,failures INTEGER DEFAULT 0,rejected INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS destinations(id INTEGER PRIMARY KEY,panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,node INTEGER REFERENCES destination_nodes(id) ON DELETE CASCADE,event_id TEXT NOT NULL,uid INTEGER NOT NULL,email TEXT NOT NULL,ts INTEGER NOT NULL,source TEXT NOT NULL,host TEXT NOT NULL,port INTEGER NOT NULL,network TEXT NOT NULL,UNIQUE(node,event_id));
    CREATE INDEX IF NOT EXISTS destination_time ON destinations(ts);
    CREATE INDEX IF NOT EXISTS destination_panel_time ON destinations(panel,id DESC);
    CREATE INDEX IF NOT EXISTS destination_host_time ON destinations(panel,host,id DESC);
    CREATE INDEX IF NOT EXISTS destination_node_time ON destinations(panel,node,id DESC);
    CREATE INDEX IF NOT EXISTS destination_user_time ON destinations(panel,uid,id DESC);`);
}
export function cleanDestinations(db, now = Date.now()) {
  // Bounded deletions keep each maintenance pass short on a small VPS.
  db.prepare(
    "DELETE FROM destinations WHERE id IN (SELECT id FROM destinations WHERE ts<? LIMIT 10000)",
  ).run(now - DESTINATION_DAYS * 86400000);
}
export function createDestinationNode(db, panel, name, encrypt) {
  if (typeof name !== "string" || !name.trim() || name.length > 80)
    throw Error("请填写节点名称（最多80字）");
  if (
    db
      .prepare("SELECT COUNT(*) n FROM destination_nodes WHERE panel=?")
      .get(panel).n >= 200
  )
    throw Error("每个面板最多200个采集节点");
  const publicId = token(),
    secret = token();
  const id = Number(
    db
      .prepare(
        "INSERT INTO destination_nodes(panel,name,public_id,secret) VALUES(?,?,?,?)",
      )
      .run(panel, name.trim(), publicId, encrypt(secret)).lastInsertRowid,
  );
  return { id, publicId, secret };
}
export function setDestinationUser(db, panel, b) {
  if (
    !Number.isSafeInteger(b.uid) ||
    b.uid < 1 ||
    typeof b.enabled !== "boolean"
  )
    throw Error("用户设置格式错误");
  if (!b.enabled) {
    db.prepare("DELETE FROM destination_users WHERE panel=? AND uid=?").run(
      panel,
      b.uid,
    );
    return;
  }
  const user = db
    .prepare("SELECT * FROM subjects WHERE panel=? AND uid=? AND verified=1")
    .get(panel, b.uid);
  if (!user || user.email !== b.email)
    throw Error("ID与邮箱必须匹配已采集的用户记录");
  const previous = db
    .prepare("SELECT * FROM destination_users WHERE panel=? AND uid=?")
    .get(panel, b.uid);
  if (previous?.email === b.email) return;
  if (
    db
      .prepare("SELECT COUNT(*) n FROM destination_users WHERE panel=?")
      .get(panel).n >= 100
  )
    throw Error("每个面板最多同时采集100名指定用户");
  db.prepare(
    "INSERT INTO destination_users VALUES(?,?,?,?) ON CONFLICT(panel,uid) DO UPDATE SET email=excluded.email,since=excluded.since",
  ).run(panel, b.uid, b.email, Date.now());
}
export function destinationStatus(db, panel) {
  return {
    retentionDays: DESTINATION_DAYS,
    users: db
      .prepare(
        "SELECT d.*,s.email current_email FROM destination_users d LEFT JOIN subjects s ON s.panel=d.panel AND s.uid=d.uid WHERE d.panel=? ORDER BY d.uid",
      )
      .all(panel),
    nodes: db
      .prepare(
        "SELECT id,name,public_id,last_seen,pending,dropped,failures,rejected FROM destination_nodes WHERE panel=? ORDER BY id",
      )
      .all(panel),
  };
}
export function destinationRows(db, panel, q) {
  const args = [panel, Date.now() - DESTINATION_DAYS * 86400000];
  let where = "d.panel=? AND d.ts>=?";
  for (const k of ["uid", "node"])
    if (q.get(k)) {
      const n = Number(q.get(k));
      if (!Number.isSafeInteger(n) || n < 1) throw Error("用户或节点ID无效");
      where += ` AND d.${k}=?`;
      args.push(n);
    }
  if (q.get("host")) {
    where += " AND d.host=?";
    args.push(q.get("host").slice(0, 253).toLowerCase());
  }
  if (q.get("before")) {
    const n = Number(q.get("before"));
    if (!Number.isSafeInteger(n) || n < 1) throw Error("分页参数错误");
    where += " AND d.id<?";
    args.push(n);
  }
  const rows = db
    .prepare(
      `SELECT d.*,n.name node_name FROM destinations d JOIN destination_nodes n ON n.id=d.node WHERE ${where} ORDER BY d.id DESC LIMIT 101`,
    )
    .all(...args);
  const more = rows.length > 100;
  if (more) rows.pop();
  return { rows, next: more ? rows.at(-1).id : null };
}
export async function receiveDestinations(
  req,
  res,
  { db, decrypt, route, freeBytes },
) {
  const reply = (status, data) => {
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    });
    res.end(JSON.stringify(data));
  };
  const node = db
    .prepare(
      "SELECT n.* FROM destination_nodes n JOIN panels p ON p.id=n.panel JOIN accounts a ON a.id=p.owner WHERE n.public_id=? AND a.disabled=0",
    )
    .get(String(req.headers["x-watch-node"] || ""));
  const stamp = String(req.headers["x-watch-timestamp"] || ""),
    sig = String(req.headers["x-watch-signature"] || "");
  if (
    !node ||
    !/^\d{10}$/.test(stamp) ||
    Math.abs(Date.now() / 1000 - Number(stamp)) > 90 ||
    !/^[a-f0-9]{64}$/.test(sig)
  )
    return reply(401, { error: "invalid signature" });
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > 262144) return reply(413, { error: "batch too large" });
    chunks.push(c);
  }
  const raw = Buffer.concat(chunks),
    expected = createHmac("sha256", decrypt(node.secret))
      .update(route + "\n" + stamp + "\n")
      .update(raw)
      .digest();
  if (!timingSafeEqual(expected, Buffer.from(sig, "hex")))
    return reply(401, { error: "invalid signature" });
  if (
    !db
      .prepare("SELECT id FROM destination_nodes WHERE id=? AND public_id=?")
      .get(node.id, node.public_id)
  )
    return reply(401, { error: "node revoked" });
  let b;
  try {
    b = JSON.parse(raw);
  } catch {
    return reply(400, { error: "invalid JSON" });
  }
  if (b?.schema !== 1) return reply(422, { error: "invalid schema" });
  const now = Date.now();
  const selected = db
    .prepare(
      "SELECT d.* FROM destination_users d JOIN subjects s ON s.panel=d.panel AND s.uid=d.uid AND s.email=d.email AND s.verified=1 WHERE d.panel=?",
    )
    .all(node.panel);
  if (route.endsWith("/policy"))
    return reply(200, {
      users: selected.map((s) => ({ uid: s.uid, since: s.since })),
      ttlSeconds: 90,
      retentionDays: 3,
    });
  const integer = (x) => Number.isSafeInteger(x) && x >= 0;
  if (
    !Array.isArray(b.events) ||
    b.events.length > 100 ||
    !b.metrics ||
    !["pending", "dropped", "failures"].every((k) => integer(b.metrics[k]))
  )
    return reply(422, { error: "invalid batch" });
  for (const e of b.events) {
    if (
      !e ||
      typeof e.id !== "string" ||
      !/^[a-zA-Z0-9-]{1,96}$/.test(e.id) ||
      !integer(e.uid) ||
      e.uid < 1 ||
      !integer(e.ts) ||
      e.ts > now + 30000 ||
      !integer(e.since) ||
      !isIP(e.source) ||
      typeof e.host !== "string" ||
      e.host.length > 253 ||
      !e.host ||
      (!isIP(e.host) &&
        (!domainToASCII(e.host) || !/^[a-zA-Z0-9_.-]+$/.test(e.host))) ||
      !Number.isInteger(e.port) ||
      e.port < 1 ||
      e.port > 65535 ||
      !["tcp", "udp"].includes(e.network)
    )
      return reply(422, { error: "invalid event" });
  }
  // This feed is optional; disk protection must take priority over diagnostic retention.
  if (freeBytes() < 512 * 1024 * 1024)
    return reply(507, { error: "insufficient disk space" });
  const allowed = new Map(selected.map((s) => [s.uid, s]));
  let inserted = 0,
    rejected = 0,
    duplicates = 0;
  transaction(db, () => {
    const put = db.prepare(
      "INSERT OR IGNORE INTO destinations(panel,node,event_id,uid,email,ts,source,host,port,network) VALUES(?,?,?,?,?,?,?,?,?,?)",
    );
    for (const e of b.events) {
      const s = allowed.get(e.uid);
      if (!s || s.since !== e.since || e.ts < s.since || e.ts < now - 600000) {
        rejected++;
        continue;
      }
      const n = put.run(
        node.panel,
        node.id,
        e.id,
        e.uid,
        s.email,
        e.ts,
        e.source,
        e.host.toLowerCase(),
        e.port,
        e.network,
      ).changes;
      if (n) inserted++;
      else duplicates++;
    }
    db.prepare(
      "UPDATE destination_nodes SET last_seen=?,pending=?,dropped=?,failures=?,rejected=rejected+? WHERE id=?",
    ).run(
      now,
      b.metrics.pending,
      b.metrics.dropped,
      b.metrics.failures,
      rejected,
      node.id,
    );
  });
  return reply(200, { inserted, duplicates, rejected });
}
