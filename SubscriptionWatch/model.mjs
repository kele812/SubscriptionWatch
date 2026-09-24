import { randomBytes } from "node:crypto";
import { isIP } from "node:net";

export const defaults = {
  schema: 371,
  uaEnabled: true,
  chinaEnabled: true,
  foreignEnabled: true,
  cnShortMinutes: 60,
  cnShortLimit: 3,
  cnLongMinutes: 720,
  cnLongLimit: 10,
  foreignShortMinutes: 60,
  foreignShortLimit: 3,
  foreignLongMinutes: 720,
  foreignLongLimit: 10,
  dcEnabled: true,
  uaKeywords: [
    "shadowrocket",
    "NetFlow",
    "clash",
    "mihomo",
    "v2rayn",
    "v2rayng",
    "sing-box",
    "hiddify",
    "stash",
    "surge",
    "quantumult",
    "loon",
    "karing",
    "nekobox",
    "v2box",
  ],
  dcKeywords: [
    "tencent",
    "alibaba",
    "aliyun",
    "huawei",
    "amazon",
    "google",
    "microsoft",
    "腾讯",
    "阿里",
    "华为",
  ],
  cloudflareExempt: false,
  ipWhitelist: [],
  retentionDays: 0,
};
export function migrateRiskV33(db) {
  if (
    !db
      .prepare("PRAGMA table_info(samples)")
      .all()
      .some((c) => c.name === "status")
  ) {
    transaction(db, () => {
      db.exec("ALTER TABLE samples ADD COLUMN status INTEGER");
      // No guessed success for old samples whose corresponding visit has been cleared.
      db.exec(
        "UPDATE samples SET status=(SELECT MAX(v.status) FROM visits v WHERE v.panel=samples.panel AND v.uid=samples.uid AND v.ts=samples.ts AND v.ip=samples.ip AND v.ua=samples.ua)",
      );
    });
  }

  if (
    !db
      .prepare("PRAGMA table_info(subjects)")
      .all()
      .some((c) => c.name === "verified")
  ) {
    db.exec(`ALTER TABLE subjects ADD COLUMN verified INTEGER DEFAULT 0;
      UPDATE subjects SET verified=1 WHERE EXISTS(SELECT 1 FROM visits v WHERE v.panel=subjects.panel AND v.uid=subjects.uid AND v.email=subjects.email);
      UPDATE subjects SET white=0 WHERE verified=0;`);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS ban_settings(panel INTEGER PRIMARY KEY REFERENCES panels(id) ON DELETE CASCADE,enabled INTEGER DEFAULT 0,base TEXT,prefix TEXT,auth TEXT,since INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS ban_actions(id INTEGER PRIMARY KEY,panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,episode INTEGER,status TEXT,message TEXT,created INTEGER,updated INTEGER,UNIQUE(panel,uid,episode));`);
}
export function migrateRequestEvidence(db) {
  for (const [table, columns] of [
    [
      "visits",
      [
        ["event_id", "TEXT"],
        ["token_fingerprint", "TEXT"],
        ["content_type", "TEXT"],
        ["delivered", "INTEGER"],
      ],
    ],
    ["samples", [["delivered", "INTEGER"]]],
  ]) {
    const existing = new Set(
      db
        .prepare(`PRAGMA table_info(${table})`)
        .all()
        .map((c) => c.name),
    );
    for (const [name, type] of columns)
      if (!existing.has(name))
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  }
  db.exec("CREATE INDEX IF NOT EXISTS visit_source_time ON visits(ip,ts DESC)");
}
export const token = () => randomBytes(24).toString("hex");
export function migratePanelBots(db) {
  if (
    db
      .prepare("PRAGMA table_info(telegram)")
      .all()
      .some((c) => c.name === "panel")
  )
    return;
  transaction(db, () => {
    db.exec(`ALTER TABLE telegram RENAME TO telegram_legacy;
      CREATE TABLE telegram(panel INTEGER PRIMARY KEY REFERENCES panels(id) ON DELETE CASCADE,account INTEGER NOT NULL REFERENCES accounts(id),token TEXT,bot_id TEXT UNIQUE,bot_name TEXT,chat TEXT,bind_hash TEXT,bind_until INTEGER,offset INTEGER DEFAULT 0,selected INTEGER,error TEXT);`);
    for (const bot of db.prepare("SELECT * FROM telegram_legacy").all()) {
      const panel = db
        .prepare(
          "SELECT id,owner FROM panels WHERE owner=? ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END,id LIMIT 1",
        )
        .get(bot.account, bot.selected || 0);
      if (!panel) continue;
      db.prepare(
        "INSERT INTO telegram(panel,account,token,bot_id,bot_name,chat,offset) VALUES(?,?,?,?,?,?,?)",
      ).run(
        panel.id,
        panel.owner,
        bot.token,
        bot.bot_id,
        bot.bot_name,
        bot.chat,
        bot.offset,
      );
      db.prepare("DELETE FROM outbox WHERE account=? AND panel<>?").run(
        bot.account,
        panel.id,
      );
    }
    db.exec("DELETE FROM tg_confirm");
  });
}
export function simplifyAccounts(db) {
  if (getConfig(db, "singleAccountMode")) return;
  transaction(db, () => {
    const owner = db
      .prepare("SELECT id FROM accounts WHERE admin=1 ORDER BY id LIMIT 1")
      .get();
    if (owner) {
      setConfig(
        db,
        "previousPanelOwners",
        db.prepare("SELECT id,owner FROM panels").all(),
      );
      db.prepare("UPDATE panels SET owner=?").run(owner.id);
      db.prepare("UPDATE accounts SET disabled=1,admin=0 WHERE id<>?").run(
        owner.id,
      );
      db.prepare("DELETE FROM outbox WHERE account<>?").run(owner.id);
    }
    setConfig(db, "registration", false);
    db.prepare(
      "DELETE FROM config WHERE key IN ('adminPath','upgradeEntryRequired')",
    ).run();
    setConfig(db, "singleAccountMode", true);
  });
}
export function transaction(db, fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}
export function initialize(db, encrypt) {
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY,username TEXT UNIQUE COLLATE NOCASE NOT NULL,password_hash TEXT NOT NULL,admin INTEGER DEFAULT 0,disabled INTEGER DEFAULT 0,created INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS panels(id INTEGER PRIMARY KEY,owner INTEGER NOT NULL REFERENCES accounts(id),name TEXT NOT NULL,public_id TEXT UNIQUE NOT NULL,secret TEXT NOT NULL,rules TEXT NOT NULL,notify INTEGER DEFAULT 1,cleared_at INTEGER DEFAULT 0,last_seen INTEGER,pending INTEGER DEFAULT 0,dropped INTEGER DEFAULT 0,expired INTEGER DEFAULT 0,version TEXT,legacy INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS subjects(panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,email TEXT NOT NULL,white INTEGER DEFAULT 0,dismissed INTEGER DEFAULT 0,PRIMARY KEY(panel,uid));
    CREATE TABLE IF NOT EXISTS visits(id INTEGER PRIMARY KEY,panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,ts INTEGER,uid INTEGER,email TEXT,ip TEXT,ua TEXT,peer_ip TEXT,ip_source TEXT,status INTEGER,ms INTEGER,bytes INTEGER);
    CREATE INDEX IF NOT EXISTS visit_subject ON visits(panel,uid,ts);
    CREATE INDEX IF NOT EXISTS visit_time ON visits(panel,ts);
    CREATE TABLE IF NOT EXISTS receipts(panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,event_id TEXT,ts INTEGER,PRIMARY KEY(panel,event_id));
    CREATE INDEX IF NOT EXISTS receipt_ts_v3 ON receipts(ts);
    CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY,panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,ts INTEGER,ip TEXT,ua TEXT);
    CREATE INDEX IF NOT EXISTS sample_subject ON samples(panel,uid,ts);
    CREATE INDEX IF NOT EXISTS sample_time ON samples(ts);
    CREATE TABLE IF NOT EXISTS ip_blacklist(ip TEXT PRIMARY KEY,source_panel INTEGER,source_name TEXT NOT NULL,source_uid INTEGER NOT NULL,source_ts INTEGER NOT NULL,added INTEGER NOT NULL,expires INTEGER NOT NULL,removed_at INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS ip_blacklist_expiry ON ip_blacklist(expires);
    CREATE TABLE IF NOT EXISTS risks(panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,active INTEGER,started INTEGER,updated INTEGER,reasons TEXT NOT NULL,PRIMARY KEY(panel,uid));
    CREATE TABLE IF NOT EXISTS risk_history(id INTEGER PRIMARY KEY,panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,email TEXT,ts INTEGER,action TEXT,reasons TEXT);
    CREATE INDEX IF NOT EXISTS risk_history_panel ON risk_history(panel,id);
    CREATE TABLE IF NOT EXISTS telegram(account INTEGER PRIMARY KEY REFERENCES accounts(id),token TEXT,bot_id TEXT UNIQUE,bot_name TEXT,chat TEXT,bind_hash TEXT,bind_until INTEGER,offset INTEGER DEFAULT 0,selected INTEGER,error TEXT);
    CREATE TABLE IF NOT EXISTS tg_confirm(code TEXT PRIMARY KEY,account INTEGER,panel INTEGER,uid INTEGER,until INTEGER);
    CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,account INTEGER REFERENCES accounts(id),panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,payload TEXT,created INTEGER,tries INTEGER DEFAULT 0,next_try INTEGER DEFAULT 0);`);
  // One transaction makes a interrupted legacy migration safe to retry.
  if (!getConfig(db, "migrated"))
    transaction(db, () => {
      const legacy = db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='administrator'",
        )
        .get();
      const old =
        legacy && db.prepare("SELECT * FROM administrator WHERE id=1").get();
      if (old) {
        db.prepare(
          "INSERT INTO accounts(id,username,password_hash,admin,created) VALUES(1,?,?,1,?)",
        ).run(old.username, old.password_hash, Date.now());
        const secret =
          db.prepare("SELECT value FROM secrets WHERE name='collector'").get()
            ?.value || encrypt(token());
        db.prepare(
          "INSERT INTO panels(id,owner,name,public_id,secret,rules,legacy) VALUES(1,1,?,?,?,?,1)",
        ).run("原有 Xboard", token(), secret, JSON.stringify(defaults));
        db.exec(`INSERT OR IGNORE INTO subjects(panel,uid,email) SELECT 1,user_id,email FROM users;
        INSERT INTO visits(panel,ts,uid,email,ip,ua,peer_ip,ip_source,status,ms,bytes) SELECT 1,ts,user_id,email,ip,ua,peer_ip,ip_source,status,ms,bytes FROM events;
        INSERT INTO receipts SELECT 1,event_id,received_at FROM ingest_receipts;
        UPDATE panels SET cleared_at=(SELECT cleared_at FROM collector_state WHERE id=1) WHERE id=1;
        DROP TABLE events; DROP TABLE users; DROP TABLE administrator; DROP TABLE ingest_receipts; DROP TABLE collector_state; DROP TABLE secrets; DROP TABLE settings;`);
        setConfig(db, "adminPath", "manage");
        setConfig(db, "upgradeEntryRequired", true);
      }
      setConfig(db, "registration", false);
      setConfig(db, "migrated", true);
    });
}
export const getConfig = (db, key, fallback = null) => {
  const r = db.prepare("SELECT value FROM config WHERE key=?").get(key);
  return r ? JSON.parse(r.value) : fallback;
};
export const setConfig = (db, key, value) =>
  db
    .prepare(
      "INSERT INTO config VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
    )
    .run(key, JSON.stringify(value));
export function validateRules(b) {
  b = { ...defaults, ...b };
  const r = {};
  for (const prefix of ["cn", "foreign"])
    for (const w of ["Short", "Long"])
      for (const [end, max] of [
        ["Minutes", 10080],
        ["Limit", 1000],
      ]) {
        const k = prefix + w + end;
        if (!Number.isInteger(b[k]) || b[k] < 1 || b[k] > max)
          throw Error(k + " 超出允许范围");
        r[k] = b[k];
      }
  for (const k of [
    "uaEnabled",
    "chinaEnabled",
    "foreignEnabled",
    "dcEnabled",
    "cloudflareExempt",
  ]) {
    if (typeof b[k] !== "boolean") throw Error("规则开关格式错误");
    r[k] = b[k];
  }
  if (
    !Array.isArray(b.uaKeywords) ||
    b.uaKeywords.length > 100 ||
    b.uaKeywords.some(
      (s) => typeof s !== "string" || !s.trim() || s.length > 100,
    )
  )
    throw Error("UA 关键词每项1～100字，最多100项");
  r.uaKeywords = [...new Set(b.uaKeywords.map((s) => s.trim().toLowerCase()))];
  if (r.uaEnabled && !r.uaKeywords.length)
    throw Error("启用 UA 规则前至少填写一个允许关键词");
  if (
    !Number.isInteger(b.retentionDays) ||
    b.retentionDays < 0 ||
    b.retentionDays > 3650
  )
    throw Error("保留天数须为0～3650，0为不自动清理");
  r.retentionDays = b.retentionDays;
  if (
    !Array.isArray(b.ipWhitelist) ||
    b.ipWhitelist.length > 1000 ||
    b.ipWhitelist.some((ip) => typeof ip !== "string" || !isIP(ip.trim()))
  )
    throw Error("IP白名单须为有效IPv4或IPv6地址，每行一个，最多1000个");
  r.ipWhitelist = [
    ...new Set(
      b.ipWhitelist.map((ip) =>
        isIP(ip.trim()) === 6
          ? new URL(`http://[${ip.trim()}]/`).hostname.slice(1, -1)
          : ip.trim(),
      ),
    ),
  ];
  if (
    !Array.isArray(b.dcKeywords) ||
    b.dcKeywords.length > 100 ||
    b.dcKeywords.some(
      (k) => typeof k !== "string" || !k.trim() || k.length > 100,
    )
  )
    throw Error("数据中心关键词最多100项，每项1～100字");
  r.dcKeywords = [...new Set(b.dcKeywords.map((k) => k.trim().toLowerCase()))];
  if (r.dcEnabled && !r.dcKeywords.length)
    throw Error("启用数据中心规则需要至少一个关键词");
  return { ...r, schema: 371 };
}
