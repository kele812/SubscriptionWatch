import { createHash } from "node:crypto";
import { token, transaction } from "./model.mjs";
import { riskRows, resolveRisk, riskLevel, levelLabel } from "./risk.mjs";
const digest = (s) => createHash("sha256").update(s).digest("hex");
export class Telegram {
  constructor({ db, encrypt, decrypt, geo, fetcher = fetch }) {
    Object.assign(this, { db, encrypt, decrypt, geo, fetcher });
    this.running = false;
    this.stopped = false;
    this.cursor = 0;
  }
  status(panel) {
    const r = this.db
      .prepare("SELECT bot_name,chat,error FROM telegram WHERE panel=?")
      .get(panel);
    return r || { bot_name: null, chat: null, error: null };
  }
  async call(secret, method, data) {
    try {
      const response = await this.fetcher(
        `https://api.telegram.org/bot${secret}/${method}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data),
          signal: AbortSignal.timeout(8000),
        },
      );
      const b = await response.json();
      if (!response.ok || !b.ok)
        throw Error("Telegram 请求失败，请检查 Token、机器人私聊状态或网络");
      return b.result;
    } catch (error) {
      if (error?.name === "TimeoutError" || error?.name === "AbortError")
        throw Error(
          "Telegram 连接超时，请检查风控机能否连接 api.telegram.org，登录状态不受影响",
        );
      throw Error(
        "Telegram 请求失败，请检查 Token、机器人私聊状态或风控机网络",
      );
    }
  }
  async configure(panel, secret, chatId) {
    if (typeof secret === "string") secret = secret.trim();
    if (
      chatId !== undefined &&
      (typeof chatId !== "string" || !/^[1-9]\d{0,15}$/.test(chatId.trim()))
    )
      throw Error("请输入个人数字ID，不是用户名或群组ID");
    if (typeof secret !== "string" || !/^\d+:[A-Za-z0-9_-]{20,}$/.test(secret))
      throw Error("Bot Token 格式错误");
    const me = await this.call(secret, "getMe", {});
    if (!me.is_bot) throw Error("不是有效机器人");
    const existing = this.db
      .prepare("SELECT panel FROM telegram WHERE bot_id=?")
      .get(String(me.id));
    if (existing && existing.panel !== panel)
      throw Error("该机器人已被其他面板使用");
    const info = await this.call(secret, "getWebhookInfo", {});
    if (info.url)
      throw Error(
        "这个机器人已设置 Webhook，请使用独立机器人或先移除原 Webhook",
      );
    if (chatId !== undefined) {
      chatId = chatId.trim();
      const chat = await this.call(secret, "getChat", { chat_id: chatId });
      if (chat?.type !== "private" || String(chat.id) !== chatId)
        throw Error(
          "无法确认个人私聊，请先用该账号给机器人发送 /start，并检查个人数字ID",
        );
    }
    this.db
      .prepare(
        "INSERT INTO telegram(panel,account,token,bot_id,bot_name) VALUES(?,(SELECT owner FROM panels WHERE id=?),?,?,?) ON CONFLICT(panel) DO UPDATE SET token=excluded.token,bot_id=excluded.bot_id,bot_name=excluded.bot_name,chat=NULL,bind_hash=NULL,bind_until=0,offset=0,selected=NULL,error=NULL",
      )
      .run(panel, panel, this.encrypt(secret), String(me.id), me.username);
    this.db.prepare("DELETE FROM outbox WHERE panel=?").run(panel);
    this.db.prepare("DELETE FROM tg_confirm WHERE panel=?").run(panel);
    if (chatId !== undefined)
      this.db
        .prepare("UPDATE telegram SET chat=? WHERE panel=?")
        .run(chatId, panel);
  }
  bindCode(panel) {
    const code = token();
    if (
      !this.db
        .prepare("UPDATE telegram SET bind_hash=?,bind_until=? WHERE panel=?")
        .run(digest(code), Date.now() + 600000, panel).changes
    )
      throw Error("请先保存机器人 Token");
    return { command: "/start " + code, expiresMinutes: 10 };
  }
  disconnect(panel) {
    this.db.prepare("DELETE FROM telegram WHERE panel=?").run(panel);
    this.db.prepare("DELETE FROM outbox WHERE panel=?").run(panel);
    this.db.prepare("DELETE FROM tg_confirm WHERE panel=?").run(panel);
  }
  async handle(bot, update) {
    const message = update.message || update.callback_query?.message,
      from = update.message?.from || update.callback_query?.from;
    if (
      !message ||
      message.chat?.type !== "private" ||
      !from ||
      String(message.chat.id) !== String(from.id)
    )
      return;
    const secret = this.decrypt(bot.token),
      say = (text, extra = {}) =>
        this.call(secret, "sendMessage", {
          chat_id: message.chat.id,
          text: text.slice(0, 3900),
          ...extra,
        });
    const args = (message.text || "").trim().split(/\s+/),
      cmd = args[0]?.split("@")[0];
    if (
      !update.callback_query &&
      cmd === "/start" &&
      args[1] &&
      bot.bind_hash &&
      bot.bind_until > Date.now() &&
      digest(args[1]) === bot.bind_hash
    ) {
      const changed = this.db
        .prepare(
          "UPDATE telegram SET chat=?,bind_hash=NULL,bind_until=0 WHERE panel=? AND bind_hash=?",
        )
        .run(String(from.id), bot.panel, bot.bind_hash);
      if (changed.changes)
        await say(
          "绑定成功。此机器人仅管理当前配置的面板，发送 /help 查看指令。",
        );
      return;
    }
    if (String(from.id) !== bot.chat) return;
    if (update.callback_query) {
      const code = String(update.callback_query.data || "");
      const confirm = this.db
        .prepare(
          "SELECT * FROM tg_confirm WHERE code=? AND panel=? AND until>?",
        )
        .get(code, bot.panel, Date.now());
      if (confirm) {
        const p = this.db
          .prepare("SELECT id FROM panels WHERE id=? AND owner=?")
          .get(confirm.panel, bot.account);
        if (p)
          transaction(this.db, () => {
            resolveRisk(this.db, p.id, confirm.uid);
            this.db.prepare("DELETE FROM tg_confirm WHERE code=?").run(code);
          });
        await this.call(secret, "answerCallbackQuery", {
          callback_query_id: update.callback_query.id,
          text: p ? "已取消风险，旧记录不再触发" : "面板已不存在",
        });
      } else
        await this.call(secret, "answerCallbackQuery", {
          callback_query_id: update.callback_query.id,
          text: "确认已失效，请重新发送指令",
        });
      return;
    }
    const p = this.db
      .prepare("SELECT * FROM panels WHERE id=? AND owner=?")
      .get(bot.panel, bot.account);
    if (!p) return;
    if (["/panels", "/select", "/help", "/start"].includes(cmd)) {
      await say(
        "当前面板：" +
          p.name +
          "\n此机器人仅管理这个面板，无需切换。\n/risk 查看当前风险\n/user 用户ID 查看近期访问\n/resolve 用户ID 取消风险（按钮确认）",
      );
      return;
    }
    if (cmd === "/risk") {
      const rows = riskRows(this.db, p.id, { limit: 15 });
      await say(
        p.name +
          "\n" +
          (rows
            .map(
              (r) =>
                `${levelLabel(r.level)} · ID ${r.uid} ${r.email}\n${r.reasons.map((x) => x.label + "：" + x.count).join("；")}`,
            )
            .join("\n\n") || "当前无风险用户"),
      );
      return;
    }
    const uid = Number(args[1]);
    if (!Number.isSafeInteger(uid) || uid < 1) {
      await say("发送 /help 查看指令。");
      return;
    }
    const subject = this.db
      .prepare("SELECT * FROM subjects WHERE panel=? AND uid=?")
      .get(p.id, uid);
    if (!subject) {
      await say("该面板尚无此用户记录。");
      return;
    }
    if (cmd === "/resolve") {
      const code = token();
      this.db
        .prepare("INSERT INTO tg_confirm VALUES(?,?,?,?,?)")
        .run(code, bot.account, p.id, uid, Date.now() + 300000);
      await say(`确认取消 ${p.name} 用户 ${uid} 的风险？旧记录将视为已处理。`, {
        reply_markup: {
          inline_keyboard: [[{ text: "确认取消风险", callback_data: code }]],
        },
      });
      return;
    }
    if (cmd === "/user") {
      const stats = this.db
        .prepare(
          "SELECT count(*) total,count(DISTINCT ip) ips FROM visits WHERE panel=? AND uid=? AND ts>?",
        )
        .get(p.id, uid, Date.now() - 86400000);
      const last = this.db
        .prepare(
          "SELECT ip,ua FROM visits WHERE panel=? AND uid=? ORDER BY ts DESC LIMIT 1",
        )
        .get(p.id, uid);
      const risk = this.db
        .prepare("SELECT active,reasons FROM risks WHERE panel=? AND uid=?")
        .get(p.id, uid);
      await say(
        `${p.name}\nID ${uid} · ${subject.email}\n白名单：${subject.white ? "是" : "否"}\n24小时 ${stats.total}次 / ${stats.ips}个IP\n风险：${
          risk?.active
            ? JSON.parse(risk.reasons)
                .map((r) => r.label)
                .join("；")
            : "无"
        }\n最近IP：${last?.ip || "无"} ${last ? Object.values(this.geo.lookup(last.ip)).filter(Boolean).join(" / ") : ""}\n原始UA：${last?.ua || "无"}`,
      );
    }
  }
  async tick() {
    if (this.running || this.stopped) return;
    this.running = true;
    try {
      let bots = this.db
        .prepare(
          "SELECT t.* FROM telegram t JOIN accounts a ON a.id=t.account JOIN panels p ON p.id=t.panel WHERE a.disabled=0 AND p.owner=t.account AND t.panel>? ORDER BY t.panel LIMIT 3",
        )
        .all(this.cursor);
      if (!bots.length) {
        this.cursor = 0;
        return;
      }
      await Promise.allSettled(
        bots.map(async (bot) => {
          try {
            const secret = this.decrypt(bot.token),
              updates = await this.call(secret, "getUpdates", {
                offset: bot.offset,
                timeout: 0,
                limit: 20,
                allowed_updates: ["message", "callback_query"],
              });
            for (const update of updates) {
              if (this.stopped) return;
              const current = this.db
                .prepare("SELECT * FROM telegram WHERE panel=?")
                .get(bot.panel);
              if (!current || current.token !== bot.token) return;
              await this.handle(current, update);
              this.db
                .prepare(
                  "UPDATE telegram SET offset=? WHERE panel=? AND token=?",
                )
                .run(update.update_id + 1, bot.panel, bot.token);
            }
            const current = this.db
              .prepare("SELECT * FROM telegram WHERE panel=?")
              .get(bot.panel);
            if (!current || current.token !== bot.token || this.stopped) return;
            for (const item of this.db
              .prepare(
                "SELECT * FROM outbox WHERE panel=? AND next_try<=? ORDER BY id LIMIT 5",
              )
              .all(bot.panel, Date.now())) {
              const p = this.db
                  .prepare("SELECT notify FROM panels WHERE id=? AND owner=?")
                  .get(item.panel, bot.account),
                risk = this.db
                  .prepare(
                    "SELECT active,reasons FROM risks WHERE panel=? AND uid=?",
                  )
                  .get(item.panel, item.uid);
              const payload = JSON.parse(item.payload);
              if (
                !p?.notify ||
                (payload.kind !== "action" && !risk?.active) ||
                !current.chat
              ) {
                this.db.prepare("DELETE FROM outbox WHERE id=?").run(item.id);
                continue;
              }
              try {
                if (payload.kind === "action") {
                  await this.call(secret, "sendMessage", {
                    chat_id: current.chat,
                    text: payload.text.slice(0, 3900),
                  });
                  this.db.prepare("DELETE FROM outbox WHERE id=?").run(item.id);
                  continue;
                }
                const data = JSON.parse(item.payload);
                data.reasons = JSON.parse(risk.reasons);
                const ips = [
                  ...new Set(
                    data.reasons
                      .flatMap((r) => r.ips || [r.ip])
                      .filter(Boolean),
                  ),
                ].slice(0, 5);
                await this.call(secret, "sendMessage", {
                  chat_id: current.chat,
                  text: `${levelLabel(riskLevel(data.reasons))} · ${data.panel}\n用户ID：${data.uid}\n邮箱：${data.email}\n${data.reasons.map((r) => r.label + "（" + r.count + "）").join("\n")}\n${ips.map((ip) => ip + " · " + Object.values(this.geo.lookup(ip)).filter(Boolean).join(" / ")).join("\n")}\n${new Date(item.created).toISOString()}`.slice(
                    0,
                    3900,
                  ),
                });
                this.db.prepare("DELETE FROM outbox WHERE id=?").run(item.id);
              } catch {
                this.db
                  .prepare(
                    "UPDATE outbox SET tries=tries+1,next_try=? WHERE id=?",
                  )
                  .run(
                    Date.now() +
                      Math.min(3600000, 30000 * 2 ** Math.min(item.tries, 7)),
                    item.id,
                  );
                throw Error("通知发送失败，稍后重试");
              }
            }
            this.db
              .prepare(
                "UPDATE telegram SET error=NULL WHERE panel=? AND token=?",
              )
              .run(bot.panel, bot.token);
          } catch {
            if (!this.stopped)
              this.db
                .prepare(
                  "UPDATE telegram SET error=? WHERE panel=? AND token=?",
                )
                .run(
                  "连接或发送失败，请检查 Token、私聊绑定和风控机网络",
                  bot.panel,
                  bot.token,
                );
          }
        }),
      );
      this.cursor = bots.at(-1).panel;
    } finally {
      this.running = false;
    }
  }
}
