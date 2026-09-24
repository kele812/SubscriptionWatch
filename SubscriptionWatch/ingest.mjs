import { createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { transaction } from "./model.mjs";
import { evaluate } from "./risk.mjs";
export const MAX_AGE = 86400000;
export async function receiveBatch(req, res, { db, decrypt, geo }) {
  const reply = (status, b) => {
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    });
    res.end(JSON.stringify(b));
  };
  const publicId = String(req.headers["x-watch-panel"] || "");
  const panel = publicId
    ? db
        .prepare(
          "SELECT p.* FROM panels p JOIN accounts a ON a.id=p.owner WHERE p.public_id=? AND a.disabled=0",
        )
        .get(publicId)
    : db
        .prepare(
          "SELECT p.* FROM panels p JOIN accounts a ON a.id=p.owner WHERE p.legacy=1 AND a.disabled=0",
        )
        .get();
  const timestamp = String(req.headers["x-watch-timestamp"] || ""),
    signature = String(req.headers["x-watch-signature"] || "");
  if (
    !panel ||
    !/^\d{10}$/.test(timestamp) ||
    Math.abs(Date.now() / 1000 - Number(timestamp)) > 300 ||
    !/^[a-f0-9]{64}$/.test(signature)
  )
    return reply(401, { error: "invalid signature or panel" });
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > 524288) return reply(413, { error: "batch too large" });
    chunks.push(c);
  }
  const raw = Buffer.concat(chunks),
    expected = createHmac("sha256", decrypt(panel.secret))
      .update(timestamp + "\n")
      .update(raw)
      .digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, "hex")))
    return reply(401, { error: "invalid signature" });
  let batch;
  try {
    batch = JSON.parse(raw);
  } catch {
    return reply(400, { error: "invalid JSON" });
  }
  const now = Date.now(),
    str = (v, max) => typeof v === "string" && v.length <= max,
    n = (v) => Number.isSafeInteger(v) && v >= 0;
  if (
    batch?.schema !== 1 ||
    !Array.isArray(batch.events) ||
    batch.events.length > 100 ||
    !str(batch.version, 32) ||
    !batch.metrics ||
    !["pending", "dropped", "expired"].every((k) => n(batch.metrics[k])) ||
    (batch.metrics.failures !== undefined && !n(batch.metrics.failures))
  )
    return reply(422, { error: "invalid batch" });
  for (const e of batch.events)
    if (
      !e ||
      typeof e.event_id !== "string" ||
      !/^[a-f0-9]{32}$/.test(e.event_id) ||
      !n(e.ts) ||
      e.ts < now - MAX_AGE ||
      e.ts > now + 300000 ||
      !n(e.user_id) ||
      e.user_id < 1 ||
      !str(e.email, 254) ||
      !e.email ||
      !str(e.ua, 1024) ||
      !str(e.flag, 128) ||
      !isIP(e.ip) ||
      !isIP(e.peer_ip) ||
      !["peer", "trusted_proxy"].includes(e.ip_source) ||
      !Number.isInteger(e.status) ||
      e.status < 100 ||
      e.status > 599 ||
      !n(e.ms) ||
      e.ms > 3600000 ||
      !(e.bytes === null || n(e.bytes)) ||
      (e.token_fingerprint !== undefined &&
        !/^[a-f0-9]{64}$/.test(e.token_fingerprint)) ||
      (e.content_type !== undefined && !str(e.content_type, 128)) ||
      (e.delivered !== undefined && typeof e.delivered !== "boolean") ||
      (e.delivered === true &&
        (e.status < 200 || e.status >= 300 || e.bytes === 0))
    )
      return reply(422, { error: "invalid event fields" });
  let inserted = 0,
    duplicates = 0,
    discarded = 0;
  try {
    transaction(db, () => {
      const touched = new Map();
      const receipt = db.prepare(
        "INSERT OR IGNORE INTO receipts VALUES(?,?,?)",
      );
      const subject = db.prepare(
        "INSERT INTO subjects(panel,uid,email,verified) VALUES(?,?,?,1) ON CONFLICT(panel,uid) DO UPDATE SET white=CASE WHEN subjects.email=excluded.email THEN subjects.white ELSE 0 END,email=excluded.email,verified=1",
      );
      const visit = db.prepare(
        "INSERT INTO visits(panel,ts,uid,email,ip,ua,peer_ip,ip_source,status,ms,bytes,event_id,token_fingerprint,content_type,delivered) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      );
      const sample = db.prepare(
        "INSERT INTO samples(panel,uid,ts,ip,ua,status,delivered) VALUES(?,?,?,?,?,?,?)",
      );
      for (const e of batch.events) {
        if (e.ts <= panel.cleared_at) {
          discarded++;
          continue;
        }
        if (!receipt.run(panel.id, e.event_id, now).changes) {
          duplicates++;
          continue;
        }
        const address =
          isIP(e.ip) === 6
            ? new URL(`http://[${e.ip}]/`).hostname.slice(1, -1)
            : e.ip;
        subject.run(panel.id, e.user_id, e.email);
        visit.run(
          panel.id,
          e.ts,
          e.user_id,
          e.email,
          address,
          e.ua,
          e.peer_ip,
          e.ip_source,
          e.status,
          e.ms,
          e.bytes,
          e.event_id,
          e.token_fingerprint ?? null,
          e.content_type ?? null,
          e.delivered === undefined ? null : Number(e.delivered),
        );
        sample.run(
          panel.id,
          e.user_id,
          e.ts,
          address,
          e.ua,
          e.status,
          e.delivered === undefined ? null : Number(e.delivered),
        );
        if (!touched.has(e.user_id)) touched.set(e.user_id, []);
        touched
          .get(e.user_id)
          .push({
            ts: e.ts,
            ip: address,
            ua: e.ua,
            status: e.status,
            delivered: e.delivered === undefined ? null : Number(e.delivered),
          });
        inserted++;
      }
      db.prepare(
        "UPDATE panels SET last_seen=?,pending=?,dropped=?,expired=?,version=?,failures=? WHERE id=?",
      ).run(
        now,
        batch.metrics.pending,
        batch.metrics.dropped,
        batch.metrics.expired,
        batch.version,
        batch.metrics.failures ?? null,
        panel.id,
      );
      for (const [uid, fresh] of touched)
        evaluate(db, panel, uid, now, geo, fresh);
    });
  } catch {
    return reply(503, { error: "storage unavailable" });
  }
  return reply(200, {
    ok: true,
    accepted: batch.events.length,
    inserted,
    duplicates,
    discarded,
  });
}
