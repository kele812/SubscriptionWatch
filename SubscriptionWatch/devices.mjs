// The panel signs device metadata. Raw HWIDs never leave Xboard.
const HOUR = 3600000;
export const RESERVATION_MS = 300000;

export function initDevices(db) {
  if (
    !db
      .prepare("PRAGMA table_info(panels)")
      .all()
      .some((c) => c.name === "reporting_mode")
  )
    db.exec(
      "ALTER TABLE panels ADD COLUMN reporting_mode TEXT NOT NULL DEFAULT 'periodic'",
    );
  db.exec(`CREATE TABLE IF NOT EXISTS device_settings(
    panel INTEGER PRIMARY KEY REFERENCES panels(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 0, hours INTEGER NOT NULL DEFAULT 24);
    CREATE TABLE IF NOT EXISTS device_leases(
      panel INTEGER REFERENCES panels(id) ON DELETE CASCADE, uid INTEGER, email TEXT,
      hwid TEXT, platform TEXT, identity_kind TEXT NOT NULL DEFAULT 'hwid', last_success INTEGER, device_limit INTEGER,
      PRIMARY KEY(panel,uid,email,hwid));
    CREATE TABLE IF NOT EXISTS device_reservations(
      panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,event_id TEXT,uid INTEGER,
      email TEXT,hwid TEXT,platform TEXT,identity_kind TEXT NOT NULL DEFAULT 'hwid',created INTEGER,expires INTEGER,device_limit INTEGER,
      PRIMARY KEY(panel,event_id));
    CREATE INDEX IF NOT EXISTS device_reservations_user ON device_reservations(panel,uid,email,expires);
    CREATE INDEX IF NOT EXISTS device_leases_user ON device_leases(panel,uid,email,last_success);`);
}

export function deviceSettings(db, panel) {
  const row = db
    .prepare("SELECT enabled,hours FROM device_settings WHERE panel=?")
    .get(panel);
  return { enabled: !!row?.enabled, hours: row?.hours ?? 24 };
}

// One local query for all users on the history page; count the same active
// identities as deviceRows, bound to each subject's current email.
export function deviceCountsByUsers(db, panel, uids, now = Date.now()) {
  const ids = [
    ...new Set(uids.filter((id) => Number.isSafeInteger(id) && id > 0)),
  ];
  if (!ids.length) return new Map();
  const settings = deviceSettings(db, panel);
  const marks = ids.map(() => "?").join(",");
  const rows = db
    .prepare(
      `WITH active AS (
    SELECT uid,email,hwid,0 pending FROM device_leases WHERE panel=? AND uid IN (${marks}) AND last_success>?
    UNION ALL SELECT uid,email,hwid,1 pending FROM device_reservations WHERE panel=? AND uid IN (${marks}) AND expires>?
  ), grouped AS (SELECT uid,email,hwid,MIN(pending) pending FROM active GROUP BY uid,email,hwid)
  SELECT g.uid,COUNT(*) count,SUM(g.pending) pending FROM grouped g
  JOIN subjects s ON s.panel=? AND s.uid=g.uid AND s.email=g.email GROUP BY g.uid`,
    )
    .all(panel, ...ids, now - settings.hours * HOUR, panel, ...ids, now, panel);
  const counts = new Map(rows.map((row) => [row.uid, row]));
  return new Map(
    ids.map((uid) => [
      uid,
      {
        count: counts.get(uid)?.count ?? 0,
        pending: counts.get(uid)?.pending ?? 0,
        ...settings,
      },
    ]),
  );
}

export function saveDeviceSettings(db, panel, value) {
  if (
    typeof value.enabled !== "boolean" ||
    !Number.isInteger(value.hours) ||
    value.hours < 1 ||
    value.hours > 8760
  )
    throw Error("设备占用时长须为 1～8760 个整小时");
  const previous = deviceSettings(db, panel);
  db.prepare("DELETE FROM device_leases WHERE panel=? AND last_success<=?").run(
    panel,
    Date.now() - previous.hours * HOUR,
  );
  db.prepare(
    "INSERT INTO device_settings(panel,enabled,hours) VALUES(?,?,?) ON CONFLICT(panel) DO UPDATE SET enabled=excluded.enabled,hours=excluded.hours",
  ).run(panel, Number(value.enabled), value.hours);
  return deviceSettings(db, panel);
}

// Called inside the same transaction as the risk decision: concurrent requests
// cannot both claim the final place. Existing devices always share one place.
export function reserveDevice(db, panel, event, now, claim = true) {
  const settings = deviceSettings(db, panel);
  const white = db
    .prepare("SELECT white FROM subjects WHERE panel=? AND uid=? AND email=?")
    .get(panel, event.user_id, event.email);
  const exempt = !!white?.white;
  if (!settings.enabled && !exempt) return {};
  const validLimit =
    Number.isSafeInteger(event.device_limit) && event.device_limit >= 0;
  if (!validLimit && !exempt) return { code: "device-metadata" };
  if (!event.hwid)
    return exempt
      ? {}
      : { code: "device-id-required", limit: event.device_limit };
  const cutoff = now - settings.hours * HOUR;
  db.prepare("DELETE FROM device_leases WHERE panel=? AND last_success<=?").run(
    panel,
    cutoff,
  );
  db.prepare(
    "DELETE FROM device_reservations WHERE panel=? AND expires<=?",
  ).run(panel, now);
  if (!exempt) {
    const active = db
      .prepare(
        `SELECT hwid FROM device_leases WHERE panel=? AND uid=? AND email=? AND last_success>?
    UNION SELECT hwid FROM device_reservations WHERE panel=? AND uid=? AND email=? AND expires>?`,
      )
      .all(
        panel,
        event.user_id,
        event.email,
        cutoff,
        panel,
        event.user_id,
        event.email,
        now,
      );
    if (
      event.device_limit > 0 &&
      !active.some((r) => r.hwid === event.hwid) &&
      active.length >= event.device_limit
    )
      return {
        code: "device-limit",
        limit: event.device_limit,
        count: active.length,
      };
  }
  if (!claim) return {};
  db.prepare(
    `INSERT INTO device_reservations(panel,event_id,uid,email,hwid,platform,identity_kind,created,expires,device_limit)
    VALUES(?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    panel,
    event.event_id,
    event.user_id,
    event.email,
    event.hwid,
    event.platform || "未知",
    event.identity_kind || "hwid",
    now,
    now + RESERVATION_MS,
    validLimit ? event.device_limit : null,
  );
  return {};
}

export function finishDeviceRequest(db, panel, event, reviewed, now) {
  const pending = db
    .prepare("SELECT * FROM device_reservations WHERE panel=? AND event_id=?")
    .get(panel, event.event_id);
  if (
    !pending ||
    !reviewed ||
    reviewed.denied ||
    pending.uid !== event.user_id ||
    pending.email !== event.email ||
    reviewed.ip !== event.ip ||
    reviewed.ua !== event.ua
  )
    return;
  db.prepare(
    "DELETE FROM device_reservations WHERE panel=? AND event_id=?",
  ).run(panel, event.event_id);
  const completed = event.completed_at ?? event.ts;
  const statsAllowed =
    deviceSettings(db, panel).enabled ||
    !!db
      .prepare("SELECT white FROM subjects WHERE panel=? AND uid=? AND email=?")
      .get(panel, event.user_id, event.email)?.white;
  if (
    !statsAllowed ||
    pending.expires <= now ||
    event.delivered !== true ||
    event.status < 200 ||
    event.status >= 300 ||
    event.bytes === 0 ||
    /text\/html/i.test(event.content_type || "") ||
    completed < pending.created - 300000 ||
    completed > now + 300000
  )
    return;
  db.prepare(
    `INSERT INTO device_leases(panel,uid,email,hwid,platform,identity_kind,last_success,device_limit) VALUES(?,?,?,?,?,?,?,?)
    ON CONFLICT(panel,uid,email,hwid) DO UPDATE SET platform=excluded.platform,last_success=MAX(device_leases.last_success,excluded.last_success),device_limit=excluded.device_limit`,
  ).run(
    panel,
    pending.uid,
    pending.email,
    pending.hwid,
    pending.platform,
    pending.identity_kind,
    Math.min(now, completed),
    pending.device_limit,
  );
}

export function clearDevices(db, panel, uid = null) {
  // Removing reservations is essential: late successful reports cannot undo a clear.
  for (const table of ["device_leases", "device_reservations"])
    if (uid === null)
      db.prepare(`DELETE FROM ${table} WHERE panel=?`).run(panel);
    else
      db.prepare(`DELETE FROM ${table} WHERE panel=? AND uid=?`).run(
        panel,
        uid,
      );
}

export function cleanDevices(db, now) {
  db.prepare("DELETE FROM device_reservations WHERE expires<=?").run(now);
  db.prepare(
    `DELETE FROM device_leases WHERE last_success<=? - COALESCE((SELECT hours FROM device_settings WHERE device_settings.panel=device_leases.panel),24)*${HOUR}`,
  ).run(now);
}

export function deviceRows(db, panel, query = "", page = 1, now = Date.now()) {
  const settings = deviceSettings(db, panel);
  const cutoff = now - settings.hours * HOUR;
  const filter = query.trim();
  const args = [panel, cutoff, panel, now];
  const cte = `WITH active AS (
    SELECT uid,email,hwid,platform,identity_kind,last_success,last_success+${settings.hours * HOUR} expires,device_limit,0 pending FROM device_leases WHERE panel=? AND last_success>?
    UNION ALL SELECT uid,email,hwid,platform,identity_kind,NULL last_success,expires,device_limit,1 pending FROM device_reservations WHERE panel=? AND expires>?
  ), grouped AS (SELECT uid,email,hwid,MAX(platform) platform,MAX(identity_kind) identity_kind,MAX(last_success) last_success,MAX(expires) expires,MAX(device_limit) device_limit,MIN(pending) pending FROM active GROUP BY uid,email,hwid)
  `;
  const byId = /^\d+$/.test(filter);
  const where = filter ? (byId ? " WHERE uid=?" : " WHERE email LIKE ?") : "";
  if (filter) args.push(byId ? filter : `%${filter}%`);
  return {
    settings,
    total: db
      .prepare(cte + "SELECT COUNT(*) total FROM grouped" + where)
      .get(...args).total,
    rows: db
      .prepare(
        cte +
          "SELECT * FROM grouped" +
          where +
          " ORDER BY uid,email,hwid LIMIT 50 OFFSET ?",
      )
      .all(...args, (page - 1) * 50),
  };
}
