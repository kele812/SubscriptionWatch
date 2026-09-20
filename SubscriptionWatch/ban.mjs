import { assess } from "./assessment.mjs";
import { createHmac, timingSafeEqual } from "node:crypto";
import { riskLevel, evaluate, resolveRisk } from "./risk.mjs";
import { transaction, token, getConfig, setConfig } from "./model.mjs";
const results = {
  banned: ["已封禁", "插件已执行封禁并清理登录会话"],
  already_banned: ["已封禁", "Xboard原本已封禁，未重复修改"],
  unbanned: ["已解封", "插件已解除账号封禁；未修改套餐、流量或到期时间"],
  already_unbanned: ["已解封", "Xboard账号原本未封禁，未重复修改"],
  rejected: ["已拒绝", "用户不存在、ID邮箱不符或属于管理员/员工"],
  expired: ["已取消", "任务已过期，插件未执行"],
  failed: ["失败或待核对", "插件执行异常，请在Xboard核对；不自动重试"],
};
export class AccountBan {
  constructor({ db, decrypt, geo }) {
    Object.assign(this, { db, decrypt, geo });
    this.running = false;
    this.stopped = false;
    db.exec(`CREATE TABLE IF NOT EXISTS ban_tasks(token TEXT PRIMARY KEY,action INTEGER UNIQUE REFERENCES ban_actions(id) ON DELETE CASCADE,panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,expires INTEGER,result TEXT);
      CREATE TABLE IF NOT EXISTS control_clients(panel INTEGER PRIMARY KEY REFERENCES panels(id) ON DELETE CASCADE,seen INTEGER,version TEXT);
      CREATE TABLE IF NOT EXISTS control_nonces(panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,nonce TEXT,created INTEGER,PRIMARY KEY(panel,nonce));`);
    for (const [table, column, spec] of [
      ["ban_settings", "observe_minutes", "INTEGER DEFAULT 0"],
      ["ban_actions", "kind", "TEXT DEFAULT 'ban'"],
      ["ban_actions", "email", "TEXT"],
      ["ban_actions", "origin", "TEXT DEFAULT 'auto'"],
      ["control_clients", "capability", "TEXT DEFAULT 'ban-v1'"],
      ["panels", "failures", "INTEGER"],
    ]) {
      if (
        !db
          .prepare(`PRAGMA table_info(${table})`)
          .all()
          .some((c) => c.name === column)
      )
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${spec}`);
    }
    db.exec(
      "CREATE TABLE IF NOT EXISTS risk_observation(panel INTEGER REFERENCES panels(id) ON DELETE CASCADE,uid INTEGER,since INTEGER,PRIMARY KEY(panel,uid));",
    );
    db.exec(
      "CREATE INDEX IF NOT EXISTS ban_action_user ON ban_actions(panel,uid,id DESC)",
    );
    if (!getConfig(db, "pluginBansV34"))
      transaction(db, () => {
        db.exec(
          "UPDATE ban_settings SET enabled=0,base=NULL,prefix=NULL,auth=NULL; UPDATE ban_actions SET status='失败或待核对',message='旧API任务已停用，请到Xboard核对' WHERE status='处理中'",
        );
        setConfig(db, "pluginBansV34", true);
      });
  }
  status(panel) {
    const client = this.db
      .prepare("SELECT * FROM control_clients WHERE panel=?")
      .get(panel);
    return {
      enabled: !!this.db
        .prepare("SELECT enabled FROM ban_settings WHERE panel=?")
        .get(panel)?.enabled,
      connected: !!client && client.seen > Date.now() - 180000,
      version: client?.version || null,
      lastSeen: client?.seen || null,
      canUnban:
        client?.capability === "ban-v2" && client.seen > Date.now() - 180000,
      history: this.db
        .prepare(
          "SELECT id,uid,kind,origin,status,message,created,updated FROM ban_actions WHERE panel=? ORDER BY id DESC LIMIT 30",
        )
        .all(panel),
    };
  }
  configure(panel, b) {
    if (typeof b.enabled !== "boolean") throw Error("封禁开关格式错误");
    if (b.enabled && !this.status(panel).connected)
      throw Error("请先更新并启用v3.4采集插件，等待插件连接后再开启封禁");
    this.db
      .prepare(
        "INSERT INTO ban_settings(panel,enabled,since,observe_minutes) VALUES(?,?,?,?) ON CONFLICT(panel) DO UPDATE SET enabled=excluded.enabled,since=excluded.since,observe_minutes=excluded.observe_minutes,base=NULL,prefix=NULL,auth=NULL",
      )
      .run(panel, Number(b.enabled), Date.now(), 0);
    this.db.prepare("DELETE FROM risk_observation WHERE panel=?").run(panel);
  }
  unban(panel, uid, email) {
    if (!Number.isSafeInteger(uid) || uid < 1 || typeof email !== "string")
      throw Error("请输入有效用户ID和邮箱");
    if (!this.status(panel).canUnban)
      throw Error("请更新v3.5插件并等待控制通道连接");
    const subject = this.db
      .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
      .get(panel, uid);
    if (!subject?.verified || subject.email !== email)
      throw Error("ID与邮箱必须和已采集用户精确匹配");
    if (
      this.db
        .prepare(
          "SELECT 1 FROM ban_actions a LEFT JOIN ban_tasks t ON t.action=a.id WHERE a.panel=? AND a.uid=? AND (a.status='待领取' OR (a.status='已下发' AND t.expires>?))",
        )
        .get(panel, uid, Date.now())
    )
      throw Error("该用户还有待执行任务，请等待结果或任务过期");
    transaction(this.db, () => {
      this.db
        .prepare(
          "INSERT INTO ban_actions(panel,uid,episode,status,message,created,updated,kind,email) VALUES(?,?,?,'待领取','手动解封，等待插件领取',?,?,'unban',?)",
        )
        .run(panel, uid, -Date.now(), Date.now(), Date.now(), email);
      resolveRisk(this.db, panel, uid);
    });
  }
  notifyAction(action) {
    const p = this.db
      .prepare("SELECT * FROM panels WHERE id=?")
      .get(action.panel);
    if (!p?.notify) return;
    this.db
      .prepare(
        "INSERT INTO outbox(account,panel,uid,payload,created) VALUES(?,?,?,?,?)",
      )
      .run(
        p.owner,
        p.id,
        action.uid,
        JSON.stringify({
          kind: "action",
          text: `${p.name} · ${action.kind === "unban" ? "手动解封" : action.origin === "manual" ? "手动封禁" : "自动封禁"}\n用户ID：${action.uid}\n${action.status}\n${action.message}`,
        }),
        Date.now(),
      );
  }
  manualBan(panel, uid, email) {
    if (!Number.isSafeInteger(uid) || uid < 1 || typeof email !== "string")
      throw Error("用户ID或邮箱格式错误");
    if (!this.status(panel).connected) throw Error("插件未连接，暂不能封禁");
    const subject = this.db
      .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
      .get(panel, uid);
    if (!subject?.verified || subject.email !== email)
      throw Error("ID与邮箱必须匹配已采集用户");
    if (subject.white) throw Error("请先将该用户移出白名单");
    if (
      !this.db
        .prepare("SELECT 1 FROM risks WHERE panel=? AND uid=? AND active=1")
        .get(panel, uid)
    )
      throw Error("该用户当前不是风险用户，请刷新列表");
    if (
      this.db
        .prepare(
          "SELECT 1 FROM ban_actions a LEFT JOIN ban_tasks t ON t.action=a.id WHERE a.panel=? AND a.uid=? AND (a.status='待领取' OR (a.status='已下发' AND t.expires>?))",
        )
        .get(panel, uid, Date.now())
    )
      throw Error("已有待执行任务，请等待结果");
    const now = Date.now();
    this.db
      .prepare(
        "INSERT INTO ban_actions(panel,uid,episode,status,message,created,updated,kind,email,origin) VALUES(?,?,?,'待领取','手动封禁，插件下次领取执行',?,?,'ban',?,'manual')",
      )
      .run(panel, uid, -now, now, now, email);
  }
  eligible(p, uid, now = Date.now()) {
    evaluate(this.db, p, uid, now, this.geo);
    const risk = this.db
        .prepare("SELECT * FROM risks WHERE panel=? AND uid=?")
        .get(p.id, uid),
      subject = this.db
        .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
        .get(p.id, uid);
    return risk?.active &&
      subject &&
      riskLevel(assess(this.db, p, subject, now, this.geo)) === "suspicious" &&
      subject?.verified &&
      !subject.white
      ? { risk, subject }
      : null;
  }
  async tick() {
    const now = Date.now();
    const expired = this.db
      .prepare(
        "SELECT * FROM ban_actions WHERE (status='已下发' AND id IN(SELECT action FROM ban_tasks WHERE expires<? AND result IS NULL)) OR (status='待领取' AND created<?)",
      )
      .all(now, now - 600000);
    this.db
      .prepare(
        "UPDATE ban_actions SET status='失败或待核对',message='任务未在期限内回传结果，请在Xboard核对；不重复下发',updated=? WHERE status='已下发' AND id IN(SELECT action FROM ban_tasks WHERE expires<? AND result IS NULL)",
      )
      .run(now, now);
    this.db
      .prepare(
        "UPDATE ban_actions SET status='已取消',message='十分钟内未领取，请重新提交',updated=? WHERE status='待领取' AND created<?",
      )
      .run(now, now - 600000);
    for (const a of expired)
      this.notifyAction(
        this.db.prepare("SELECT * FROM ban_actions WHERE id=?").get(a.id),
      );
    this.db
      .prepare("DELETE FROM control_nonces WHERE created<?")
      .run(now - 600000);
  }
  exchange(panel, b) {
    return transaction(this.db, () => {
      const now = Date.now();
      if (
        !this.db
          .prepare("INSERT OR IGNORE INTO control_nonces VALUES(?,?,?)")
          .run(panel.id, b.nonce, now).changes
      )
        throw Error("请求已处理，请使用新nonce重试");
      this.db
        .prepare(
          "INSERT INTO control_clients(panel,seen,version,capability) VALUES(?,?,?,?) ON CONFLICT(panel) DO UPDATE SET seen=excluded.seen,version=excluded.version,capability=excluded.capability",
        )
        .run(panel.id, now, b.version, b.capability);
      const acknowledged = [];
      for (const r of b.results) {
        const task = this.db
          .prepare("SELECT * FROM ban_tasks WHERE token=? AND panel=?")
          .get(r.id, panel.id);
        if (!task) continue;
        const a = this.db
          .prepare("SELECT * FROM ban_actions WHERE id=?")
          .get(task.action);
        if (
          (a.kind === "ban" &&
            ["unbanned", "already_unbanned"].includes(r.status)) ||
          (a.kind === "unban" &&
            ["banned", "already_banned"].includes(r.status))
        )
          continue;
        acknowledged.push(r.id);
        if (task.result) continue;
        this.db
          .prepare("UPDATE ban_tasks SET result=? WHERE token=?")
          .run(r.status, r.id);
        this.db
          .prepare(
            "UPDATE ban_actions SET status=?,message=?,updated=? WHERE id=?",
          )
          .run(...results[r.status], now, task.action);
        if (
          a.kind === "unban" &&
          ["unbanned", "already_unbanned"].includes(r.status)
        )
          resolveRisk(this.db, panel.id, a.uid);
        this.notifyAction(
          this.db
            .prepare("SELECT * FROM ban_actions WHERE id=?")
            .get(task.action),
        );
      }
      const tasks = [];
      if (b.acceptTasks) {
        for (const a of this.db
          .prepare(
            "SELECT * FROM ban_actions WHERE panel=? AND (kind='ban' OR ?='ban-v2') AND status='待领取' AND created>? ORDER BY id LIMIT 3",
          )
          .all(panel.id, b.capability, now - 600000)) {
          const subject = this.db
            .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
            .get(panel.id, a.uid);
          if (
            !subject?.verified ||
            subject.email !== a.email ||
            (a.kind === "ban" && subject.white)
          ) {
            this.db
              .prepare(
                "UPDATE ban_actions SET status='已取消',message='身份信息变化或已加入白名单',updated=? WHERE id=?",
              )
              .run(now, a.id);
            this.notifyAction(
              this.db.prepare("SELECT * FROM ban_actions WHERE id=?").get(a.id),
            );
            continue;
          }
          const id = token(),
            expires = now + 30000;
          this.db
            .prepare(
              "INSERT INTO ban_tasks(token,action,panel,expires) VALUES(?,?,?,?)",
            )
            .run(id, a.id, panel.id, expires);
          this.db
            .prepare(
              "UPDATE ban_actions SET status='已下发',updated=? WHERE id=?",
            )
            .run(now, a.id);
          tasks.push({
            id,
            action: a.kind,
            user_id: a.uid,
            email: a.email,
            expires,
          });
        }
      }
      if (
        b.acceptTasks &&
        this.db
          .prepare("SELECT enabled FROM ban_settings WHERE panel=?")
          .get(panel.id)?.enabled
      ) {
        const rows = this.db
          .prepare(
            "SELECT r.* FROM risks r WHERE r.panel=? AND r.active=1 AND EXISTS(SELECT 1 FROM json_each(r.reasons) j WHERE json_extract(j.value,'$.code') IN ('ua','cloud','cn60','cn720','foreign60','foreign720')) AND NOT EXISTS(SELECT 1 FROM ban_actions a WHERE a.panel=r.panel AND a.uid=r.uid AND (a.episode=r.started OR (a.origin='manual' AND a.created>=r.started) OR (a.kind='unban' AND a.status IN ('待领取','已下发','失败或待核对')))) ORDER BY r.updated LIMIT 30",
          )
          .all(panel.id);
        for (const r of rows) {
          if (tasks.length >= 3) break;
          const current = this.eligible(panel, r.uid, now);
          if (!current) continue;
          const id = token(),
            expires = now + 30000;
          const action = Number(
            this.db
              .prepare(
                "INSERT INTO ban_actions(panel,uid,episode,status,message,created,updated) VALUES(?,?,?,'已下发','等待插件执行，任务不重复下发',?,?)",
              )
              .run(panel.id, r.uid, r.started, now, now).lastInsertRowid,
          );
          this.db
            .prepare(
              "INSERT INTO ban_tasks(token,action,panel,expires) VALUES(?,?,?,?)",
            )
            .run(id, action, panel.id, expires);
          tasks.push({
            id,
            action: "ban",
            user_id: r.uid,
            email: current.subject.email,
            expires,
          });
        }
      }
      return {
        schema: 1,
        panel: panel.public_id,
        nonce: b.nonce,
        expires: now + 30000,
        acknowledged,
        tasks,
      };
    });
  }
  async receive(req, res) {
    const reply = (status, data) => {
      res.writeHead(status, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(data));
    };
    try {
      const panel = this.db
        .prepare(
          "SELECT p.* FROM panels p JOIN accounts a ON a.id=p.owner WHERE p.public_id=? AND a.disabled=0",
        )
        .get(String(req.headers["x-watch-panel"] || ""));
      const ts = String(req.headers["x-watch-timestamp"] || ""),
        sig = String(req.headers["x-watch-signature"] || "");
      if (
        !panel ||
        !/^\d{10}$/.test(ts) ||
        Math.abs(Date.now() / 1000 - Number(ts)) > 300 ||
        !/^[a-f0-9]{64}$/.test(sig)
      )
        return reply(401, { error: "invalid signature" });
      let size = 0;
      const chunks = [];
      for await (const c of req) {
        size += c.length;
        if (size > 16384) return reply(413, { error: "too large" });
        chunks.push(c);
      }
      const raw = Buffer.concat(chunks),
        secret = this.decrypt(panel.secret);
      const expected = createHmac("sha256", secret)
        .update("control-request\n" + ts + "\n")
        .update(raw)
        .digest();
      if (!timingSafeEqual(expected, Buffer.from(sig, "hex")))
        return reply(401, { error: "invalid signature" });
      const b = JSON.parse(raw);
      if (
        !b ||
        b.schema !== 1 ||
        !["ban-v1", "ban-v2"].includes(b.capability) ||
        typeof b.version !== "string" ||
        b.version.length > 32 ||
        typeof b.nonce !== "string" ||
        !/^[a-f0-9]{48}$/.test(b.nonce) ||
        typeof b.acceptTasks !== "boolean" ||
        !Array.isArray(b.results) ||
        b.results.length > 10 ||
        b.results.some(
          (r) =>
            !r ||
            typeof r.id !== "string" ||
            !/^[a-f0-9]{48}$/.test(r.id) ||
            typeof r.status !== "string" ||
            !Object.hasOwn(results, r.status),
        )
      )
        return reply(422, { error: "invalid control message" });
      const payload = Buffer.from(
        JSON.stringify(this.exchange(panel, b)),
      ).toString("base64");
      return reply(200, {
        payload,
        signature: createHmac("sha256", secret)
          .update("control-response\n" + payload)
          .digest("hex"),
      });
    } catch {
      return reply(400, { error: "control request rejected" });
    }
  }
}
