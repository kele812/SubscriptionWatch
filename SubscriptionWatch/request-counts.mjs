import { defaults } from "./model.mjs";

const DAY = 86400000;
const geography = new WeakMap();
const eligible =
  "(delivered=1 OR enforced=1 OR (delivered IS NULL AND enforced IS NULL))";
const legacy =
  "(v.delivered=1 OR v.status IN (302,403)) AND (v.event_id IS NULL OR NOT EXISTS (SELECT 1 FROM review_decisions d WHERE d.panel=v.panel AND d.event_id=v.event_id))";

export function initRequestCounts(db, geo) {
  geography.set(db, geo);
  for (const table of ["review_decisions", "visits"]) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    for (const [name, type] of [
      ["count_bucket", "TEXT"],
      ["count_key", "TEXT"],
      ["count_started", "INTEGER"],
    ])
      if (!columns.some((c) => c.name === name))
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
    db.exec(`CREATE INDEX IF NOT EXISTS ${table}_count_bucket ON ${table}(panel,uid,count_bucket) WHERE count_bucket IS NOT NULL;
      CREATE INDEX IF NOT EXISTS ${table}_count_time ON ${table}(panel,uid,count_started) WHERE count_started IS NOT NULL;`);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS request_count_state(
    panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,policy TEXT NOT NULL,PRIMARY KEY(panel,uid));
    CREATE TABLE IF NOT EXISTS request_count_windows(
    panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,count_key TEXT,bucket TEXT NOT NULL,started INTEGER NOT NULL,
    PRIMARY KEY(panel,uid,count_key));`);
}

export function dedupeMinutes(db, panel) {
  const row = db.prepare("SELECT rules FROM panels WHERE id=?").get(panel);
  return (
    JSON.parse(row?.rules || "{}").requestDedupeMinutes ??
    defaults.requestDedupeMinutes
  );
}

function sourceKey(db, ip, previous) {
  const place = geography.get(db)?.lookup(ip);
  if (
    /\bcloudflare\b/i.test(place?.organization || "") ||
    (!place?.organization && previous === "cf")
  )
    return "cf";
  const address = ip.includes(":")
    ? new URL(`http://[${ip}]/`).hostname.slice(1, -1)
    : ip;
  return "ip:" + address;
}

function rows(db, panel, uid, now, resetAt, onlyMissing = false) {
  const since = Math.max(now - DAY, resetAt);
  const missing = onlyMissing ? " AND count_bucket IS NULL" : "";
  return db
    .prepare(
      `SELECT 'r' src,event_id id,ts,ip,count_key FROM review_decisions
    WHERE panel=? AND uid=? AND ts>? AND ts<=? AND ${eligible}${missing}
    UNION ALL SELECT 'v' src,v.id,v.ts,v.ip,v.count_key FROM visits v
    WHERE v.panel=? AND v.uid=? AND v.ts>? AND v.ts<=? AND ${legacy}${onlyMissing ? " AND v.count_bucket IS NULL" : ""}
    ORDER BY ts,src,id${onlyMissing ? " LIMIT 1" : ""}`,
    )
    .all(panel, uid, since, now, panel, uid, since, now);
}

function ensureScope(db, panel, uid, now, resetAt, minutes) {
  const policy = `${minutes}:${resetAt}`;
  const state = db
    .prepare("SELECT policy FROM request_count_state WHERE panel=? AND uid=?")
    .get(panel, uid);
  if (
    state?.policy === policy &&
    !rows(db, panel, uid, now, resetAt, true).length
  )
    return;
  db.exec("SAVEPOINT request_count_rebuild");
  try {
    const windows = new Map();
    const updateReview = db.prepare(
      "UPDATE review_decisions SET count_key=?,count_bucket=?,count_started=? WHERE panel=? AND event_id=?",
    );
    const updateVisit = db.prepare(
      "UPDATE visits SET count_key=?,count_bucket=?,count_started=? WHERE panel=? AND id=?",
    );
    for (const row of rows(db, panel, uid, now, resetAt)) {
      const key = sourceKey(db, row.ip, row.count_key);
      let window = windows.get(key);
      if (!minutes || !window || row.ts - window.started >= minutes * 60000) {
        window = { bucket: row.src + ":" + row.id, started: row.ts };
        windows.set(key, window);
      }
      (row.src === "r" ? updateReview : updateVisit).run(
        key,
        window.bucket,
        window.started,
        panel,
        row.id,
      );
    }
    db.prepare("DELETE FROM request_count_windows WHERE panel=? AND uid=?").run(
      panel,
      uid,
    );
    const insert = db.prepare(
      "INSERT INTO request_count_windows(panel,uid,count_key,bucket,started) VALUES(?,?,?,?,?)",
    );
    for (const [key, window] of windows)
      insert.run(panel, uid, key, window.bucket, window.started);
    db.prepare(
      "INSERT INTO request_count_state(panel,uid,policy) VALUES(?,?,?) ON CONFLICT(panel,uid) DO UPDATE SET policy=excluded.policy",
    ).run(panel, uid, policy);
    db.exec("RELEASE request_count_rebuild");
  } catch (error) {
    db.exec("ROLLBACK TO request_count_rebuild; RELEASE request_count_rebuild");
    throw error;
  }
}

function groupExists(db, panel, uid, bucket, authorized = false) {
  const review = db
    .prepare(
      `SELECT 1 FROM review_decisions WHERE panel=? AND uid=? AND count_bucket=? AND ${eligible}
    ${authorized ? "AND NOT EXISTS (SELECT 1 FROM json_each(codes) WHERE value='daily-limit')" : ""} LIMIT 1`,
    )
    .get(panel, uid, bucket);
  if (review) return true;
  return !!db
    .prepare(
      `SELECT 1 FROM visits v WHERE v.panel=? AND v.uid=? AND v.count_bucket=? AND ${legacy}
    ${authorized ? "AND v.delivered=1 AND v.status BETWEEN 200 AND 299" : ""} LIMIT 1`,
    )
    .get(panel, uid, bucket);
}

export function prepareRequestCount(db, panel, event, now, resetAt = 0) {
  const minutes = dedupeMinutes(db, panel);
  ensureScope(db, panel, event.user_id, now, resetAt, minutes);
  const key = sourceKey(db, event.ip);
  const previous = db
    .prepare(
      "SELECT bucket,started FROM request_count_windows WHERE panel=? AND uid=? AND count_key=?",
    )
    .get(panel, event.user_id, key);
  const reuse = !!(
    minutes &&
    previous &&
    previous.started > resetAt &&
    now >= previous.started &&
    now - previous.started < minutes * 60000 &&
    groupExists(db, panel, event.user_id, previous.bucket)
  );
  const bucket = reuse ? previous.bucket : "r:" + event.event_id;
  const started = reuse ? previous.started : now;
  if (!reuse)
    db.prepare(
      "INSERT INTO request_count_windows(panel,uid,count_key,bucket,started) VALUES(?,?,?,?,?) ON CONFLICT(panel,uid,count_key) DO UPDATE SET bucket=excluded.bucket,started=excluded.started",
    ).run(panel, event.user_id, key, bucket, started);
  return {
    key,
    bucket,
    started,
    reuse,
    authorized: reuse && groupExists(db, panel, event.user_id, bucket, true),
  };
}

export function requestCounts(db, panel, uid, now, resetAt = 0) {
  ensureScope(db, panel, uid, now, resetAt, dedupeMinutes(db, panel));
  const since = Math.max(now - DAY, resetAt);
  const result = db
    .prepare(
      `WITH entries AS (
    SELECT count_bucket bucket,count_key,ip_whitelisted=1 white,ip_whitelisted IS NULL unknown FROM review_decisions
    WHERE panel=? AND uid=? AND count_started>? AND count_started<=? AND ts<=? AND ${eligible}
    UNION ALL SELECT v.count_bucket,v.count_key,0 white,1 unknown FROM visits v
    WHERE v.panel=? AND v.uid=? AND v.count_started>? AND v.count_started<=? AND v.ts<=? AND ${legacy}
  ), grouped AS (SELECT bucket,MAX(count_key='cf') cf,MAX(white) white,MAX(unknown) unknown FROM entries GROUP BY bucket)
  SELECT COUNT(*) total,COALESCE(SUM(cf),0) cfCount,COALESCE(SUM(1-cf),0) normalCount,
    COALESCE(SUM(white),0) ipWhitelist,COALESCE(SUM(CASE WHEN white=1 THEN 0 ELSE unknown END),0) unclassified FROM grouped`,
    )
    .get(panel, uid, since, now, now, panel, uid, since, now, now);
  return result;
}

export function requestCount(db, panel, uid, now, resetAt = 0) {
  return requestCounts(db, panel, uid, now, resetAt).total;
}

export function cleanRequestCounts(db, now) {
  db.prepare("DELETE FROM request_count_windows WHERE started<=?").run(
    now - DAY,
  );
}
