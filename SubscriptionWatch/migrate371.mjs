import { defaults, getConfig, setConfig, transaction } from "./model.mjs";
export function migrate371(db) {
  if (getConfig(db, "rules371")) return;
  transaction(db, () => {
    const now = Date.now();
    for (const panel of db.prepare("SELECT * FROM panels").all()) {
      const old = JSON.parse(panel.rules),
        rules = { ...defaults };
      for (const key of [
        "uaEnabled",
        "uaKeywords",
        "dcKeywords",
        "ipWhitelist",
        "cloudflareExempt",
        "retentionDays",
      ])
        if (old[key] !== undefined) rules[key] = old[key];
      db.prepare("UPDATE panels SET rules=? WHERE id=?").run(
        JSON.stringify(rules),
        panel.id,
      );
    }
    for (const row of db
      .prepare(
        "SELECT r.*,s.email FROM risks r JOIN subjects s ON s.panel=r.panel AND s.uid=r.uid WHERE r.active=1",
      )
      .all()) {
      const previous = JSON.parse(row.reasons),
        kept = previous.filter((r) => r.code === "ua");
      db.prepare(
        "INSERT INTO risk_history(panel,uid,email,ts,action,reasons) VALUES(?,?,?,?,?,?)",
      ).run(
        row.panel,
        row.uid,
        row.email,
        now,
        kept.length
          ? "3.7.1迁移：保留UA可疑标记"
          : "3.7.1迁移：取消已删除规则标记",
        row.reasons,
      );
      db.prepare(
        "UPDATE risks SET active=?,reasons=?,updated=? WHERE panel=? AND uid=?",
      ).run(
        Number(kept.length > 0),
        JSON.stringify(kept.map((r) => ({ ...r, expires: null }))),
        now,
        row.panel,
        row.uid,
      );
    }
    // Old samples must not immediately recreate retired-rule flags; original visits/history are retained.
    db.exec(
      "DELETE FROM samples; DELETE FROM risk_observation; UPDATE ban_settings SET enabled=0; DELETE FROM outbox WHERE COALESCE(json_extract(payload,'$.kind'),'risk')='risk'; UPDATE ban_actions SET status='已取消',message='3.7.1规则升级，自动任务已取消' WHERE origin='auto' AND status='待领取';",
    );
    setConfig(db, "rules371", true);
  });
}
