import { assess } from "./assessment.mjs";
export const riskLevel = (reasons) =>
  reasons.some(
    (r) =>
      ["ua", "multi", "comboChina", "comboCloud"].includes(r.code) ||
      (r.ruleVersion !== "3.7" && ["china", "datacenter"].includes(r.code)),
  )
    ? "high"
    : reasons.some((r) =>
          ["ip", "rate", "china", "datacenter"].includes(r.code),
        )
      ? "medium"
      : reasons.length
        ? "low"
        : "none";
export const levelLabel = (level) =>
  ({ high: "高风险", medium: "中风险", low: "低风险", none: "已解除" })[level];
export function evaluate(db, panel, uid, now = Date.now(), geo) {
  const subject = db
    .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
    .get(panel.id, uid);
  if (!subject) return;
  const old = db
    .prepare("SELECT * FROM risks WHERE panel=? AND uid=?")
    .get(panel.id, uid);
  const current = assess(db, panel, subject, now, geo);
  // Keep triggered reasons until explicit handling; expiry only affects live checks.
  const saved = old?.active && !subject.white ? JSON.parse(old.reasons) : [];
  const reasons = [
    ...current,
    ...saved.filter((r) => !current.some((x) => x.code === r.code)),
  ];
  const active = Number(reasons.length > 0),
    previous = old ? JSON.parse(old.reasons) : [],
    changed =
      previous.map((r) => r.code).join() !==
        reasons.map((r) => r.code).join() ||
      JSON.stringify(previous[0]?.ruleSnapshot) !==
        JSON.stringify(reasons[0]?.ruleSnapshot);
  if (!active && !old) return;
  if (!active && old && !old.active) return;
  const high = riskLevel(current) === "high";
  if (
    db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='risk_observation'",
      )
      .get()
  ) {
    if (
      high &&
      (!old?.active ||
        Math.max(
          0,
          ...previous
            .filter((x) => riskLevel([x]) === "high")
            .map((x) => x.expires || 0),
        ) <= now)
    )
      db.prepare("DELETE FROM risk_observation WHERE panel=? AND uid=?").run(
        panel.id,
        uid,
      );
    if (!high)
      db.prepare("DELETE FROM risk_observation WHERE panel=? AND uid=?").run(
        panel.id,
        uid,
      );
    else
      db.prepare(
        "INSERT OR IGNORE INTO risk_observation(panel,uid,since) VALUES(?,?,?)",
      ).run(panel.id, uid, now);
  }
  db.prepare(
    "INSERT INTO risks VALUES(?,?,?,?,?,?) ON CONFLICT(panel,uid) DO UPDATE SET active=excluded.active,started=excluded.started,updated=excluded.updated,reasons=excluded.reasons",
  ).run(
    panel.id,
    uid,
    active,
    active && !old?.active ? now : old?.started || now,
    now,
    JSON.stringify(reasons),
  );
  if (changed || active !== old?.active) {
    const action = active
      ? old?.active
        ? "风险原因变化"
        : "标记风险"
      : subject.white
        ? "白名单解除"
        : "自动解除";
    db.prepare(
      "INSERT INTO risk_history(panel,uid,email,ts,action,reasons) VALUES(?,?,?,?,?,?)",
    ).run(
      panel.id,
      uid,
      subject.email,
      now,
      action,
      JSON.stringify(active ? reasons : previous),
    );
    if (
      active &&
      panel.notify &&
      (!old?.active ||
        db
          .prepare(
            "SELECT 1 FROM outbox WHERE panel=? AND uid=? AND COALESCE(json_extract(payload,'$.kind'),'risk')='risk'",
          )
          .get(panel.id, uid) ||
        { none: 0, low: 1, medium: 2, high: 3 }[riskLevel(reasons)] >
          { none: 0, low: 1, medium: 2, high: 3 }[riskLevel(previous)])
    ) {
      db.prepare(
        "DELETE FROM outbox WHERE panel=? AND uid=? AND COALESCE(json_extract(payload,'$.kind'),'risk')='risk'",
      ).run(panel.id, uid);
      db.prepare(
        "INSERT INTO outbox(account,panel,uid,payload,created) VALUES(?,?,?,?,?)",
      ).run(
        panel.owner,
        panel.id,
        uid,
        JSON.stringify({
          panel: panel.name,
          uid,
          email: subject.email,
          reasons,
        }),
        now,
      );
    }
  }
}
export function resolveRisk(
  db,
  panel,
  uid,
  { remove = false, now = Date.now() } = {},
) {
  const s = db
    .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
    .get(panel, uid);
  if (!s) throw Error("用户不存在");
  // Remove processed evaluation samples, including requests whose source clock
  // was ahead. Original visits/history remain; receipts prevent replay.
  db.prepare("DELETE FROM samples WHERE panel=? AND uid=?").run(panel, uid);
  db.prepare("DELETE FROM risk_observation WHERE panel=? AND uid=?").run(
    panel,
    uid,
  );
  db.prepare("UPDATE subjects SET dismissed=? WHERE panel=? AND uid=?").run(
    now,
    panel,
    uid,
  );
  const risk = db
    .prepare("SELECT * FROM risks WHERE panel=? AND uid=?")
    .get(panel, uid);
  if (risk && !remove)
    db.prepare(
      "INSERT INTO risk_history(panel,uid,email,ts,action,reasons) VALUES(?,?,?,?,?,?)",
    ).run(panel, uid, s.email, now, "手动取消", risk.reasons);
  if (remove)
    db.prepare("DELETE FROM risks WHERE panel=? AND uid=?").run(panel, uid);
  else
    db.prepare(
      "UPDATE risks SET active=0,updated=?,reasons='[]' WHERE panel=? AND uid=?",
    ).run(now, panel, uid);
  db.prepare(
    "DELETE FROM outbox WHERE panel=? AND uid=? AND COALESCE(json_extract(payload,'$.kind'),'risk')='risk'",
  ).run(panel, uid);
}
export function riskRows(
  db,
  panel,
  { all = false, limit = 100, offset = 0 } = {},
) {
  return db
    .prepare(
      `SELECT r.*,s.email,s.white FROM risks r JOIN subjects s ON s.panel=r.panel AND s.uid=r.uid WHERE r.panel=? ${all ? "" : "AND r.active=1"} ORDER BY r.active DESC,r.updated DESC LIMIT ? OFFSET ?`,
    )
    .all(panel, limit, offset)
    .map((r) => ({
      ...r,
      level: r.active ? riskLevel(JSON.parse(r.reasons)) : "none",
      reasons: JSON.parse(r.reasons),
      accountAction:
        db
          .prepare(
            "SELECT kind,origin,status FROM ban_actions WHERE panel=? AND uid=? ORDER BY id DESC LIMIT 1",
          )
          .get(panel, r.uid) || null,
    }));
}
