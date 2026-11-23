import { createHash, randomBytes } from "node:crypto";
import { transaction } from "./model.mjs";
import { lookupSubscriptionOrigin } from "./subscription-origins.mjs";

export function initSubscriptionImports(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS subscription_imports(
    panel INTEGER NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    uid INTEGER NOT NULL,email TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL,revision TEXT NOT NULL,created INTEGER NOT NULL,revoked INTEGER,
    PRIMARY KEY(panel,uid));`);
  for (const table of ["review_decisions", "visits"])
    if (
      !db
        .prepare(`PRAGMA table_info(${table})`)
        .all()
        .some((column) => column.name === "import_whitelisted")
    )
      db.exec(
        `ALTER TABLE ${table} ADD COLUMN import_whitelisted INTEGER${table === "review_decisions" ? " NOT NULL DEFAULT 0" : ""}`,
      );
}
function customer(data) {
  if (
    !data ||
    !Number.isSafeInteger(data.uid) ||
    data.uid < 1 ||
    typeof data.email !== "string" ||
    data.email.length > 254 ||
    !/^[^\s@]+@[^\s@]+$/u.test(data.email)
  )
    throw Error("请核对客户 ID 和邮箱");
}
const digest = (value) => createHash("sha256").update(value).digest("hex");
export async function createSubscriptionImport(context, panel, data) {
  customer(data);
  const current = await lookupSubscriptionOrigin(
    context,
    panel,
    String(data.uid),
  );
  if (current.user?.id !== data.uid || current.user.email !== data.email)
    throw Object.assign(Error("客户资料已变化，请重新搜索后生成导入页"), {
      status: 409,
    });
  return transaction(context.db, () => {
    let row = context.db
      .prepare("SELECT * FROM subscription_imports WHERE panel=? AND uid=?")
      .get(panel.id, data.uid);
    let token;
    if (row && row.revoked === null && row.email === data.email)
      token = context.decrypt(row.secret);
    else {
      token = randomBytes(32).toString("hex");
      row = {
        uid: data.uid,
        email: data.email,
        revision: randomBytes(16).toString("hex"),
        created: Date.now(),
      };
      context.db
        .prepare(
          `INSERT INTO subscription_imports(panel,uid,email,token_hash,secret,revision,created,revoked)
        VALUES(?,?,?,?,?,?,?,NULL) ON CONFLICT(panel,uid) DO UPDATE SET email=excluded.email,
        token_hash=excluded.token_hash,secret=excluded.secret,revision=excluded.revision,created=excluded.created,revoked=NULL`,
        )
        .run(
          panel.id,
          data.uid,
          data.email,
          digest(token),
          context.encrypt(token),
          row.revision,
          row.created,
        );
    }
    return {
      uid: row.uid,
      email: row.email,
      path: "/sr-import/" + token,
      revision: row.revision,
      created: row.created,
    };
  });
}
export function revokeSubscriptionImport(db, panel, data) {
  customer(data);
  const row = db
    .prepare("SELECT * FROM subscription_imports WHERE panel=? AND uid=?")
    .get(panel.id, data.uid);
  if (!row || row.revoked !== null)
    throw Object.assign(Error("此客户没有有效导入页"), { status: 404 });
  if (row.email !== data.email || row.revision !== data.revision)
    throw Object.assign(Error("导入页设置已变化，请重新打开后撤销"), {
      status: 409,
    });
  db.prepare(
    "UPDATE subscription_imports SET revoked=?,revision=? WHERE panel=? AND uid=? AND revision=?",
  ).run(
    Date.now(),
    randomBytes(16).toString("hex"),
    panel.id,
    data.uid,
    row.revision,
  );
  return {
    ok: true,
    notice: "导入页及专用白名单已撤销，后续订阅请求恢复普通风控检查",
  };
}
export function isSubscriptionImportWhitelisted(
  db,
  panel,
  uid,
  email,
  fingerprint,
) {
  return (
    typeof fingerprint === "string" &&
    /^[a-f0-9]{64}$/.test(fingerprint) &&
    !!db
      .prepare(
        "SELECT 1 FROM subscription_imports WHERE panel=? AND uid=? AND email=? AND token_hash=? AND revoked IS NULL",
      )
      .get(panel, uid, email, fingerprint)
  );
}
export function subscriptionImportUrl(url, token) {
  const parsed = new URL(url);
  if (parsed.searchParams.has("watch_import")) {
    parsed.searchParams.set("watch_import", token);
    return parsed.href;
  }
  const index = url.indexOf("#"),
    head = index < 0 ? url : url.slice(0, index),
    fragment = index < 0 ? "" : url.slice(index);
  return (
    head + (head.includes("?") ? "&" : "?") + "watch_import=" + token + fragment
  );
}
export function embeddedBrowser(ua) {
  if (/MicroMessenger/i.test(String(ua))) return "微信";
  if (/(?:^|[\s;(])(?:QQ|TIM)\/[\d.]|V1_(?:IPH|AND)_SQ_/i.test(String(ua)))
    return "QQ";
  return null;
}
export function shadowrocketUrl(url) {
  const parsed = new URL(url);
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password
  )
    throw Error("Invalid subscription URL");
  return (
    "shadowrocket://add/sub://" +
    Buffer.from(url, "utf8").toString("base64") +
    "?remark=" +
    encodeURIComponent("我的订阅")
  );
}
const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (value) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        value
      ],
  );
function layout(title, content) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex,nofollow,noarchive"><meta name="referrer" content="no-referrer"><title>${escape(title)} · 订阅导入</title><style>
    :root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0b1118;color:#eaf2f5}*{box-sizing:border-box}body{margin:0;padding:40px 20px;min-height:100svh;display:grid;place-items:center}main{width:100%;max-width:440px}header{display:flex;align-items:center;gap:12px;margin-bottom:42px;color:#a8bac5;font-size:14px}.mark{display:grid;place-items:center;width:38px;height:38px;border:1px solid #3a7166;border-radius:12px;color:#8eebc6;font-weight:700}.eyebrow{color:#8eebc6;font-size:13px;letter-spacing:.08em}h1{font-size:32px;letter-spacing:-.035em;line-height:1.3;margin:14px 0 18px}p{font-size:15px;line-height:1.8;color:#a8bac5}.card{background:#111c26;border:1px solid #273b49;border-radius:22px;padding:28px 24px}.primary,button{display:block;text-align:center;width:100%;padding:16px;border-radius:12px;font-size:16px;font-weight:600;text-decoration:none;cursor:pointer}.primary{background:#8eebc6;color:#09241d;border:0;margin:28px 0 12px}button{background:transparent;color:#d9e8ed;border:1px solid #3b5261;margin-top:12px}.steps{margin:26px 0;padding-top:20px;border-top:1px solid #273b49;font-size:14px}input{width:100%;padding:12px;border:1px solid #3b5261;border-radius:10px;background:#0b1118;color:#d9e8ed;font-size:12px}details{margin-top:24px;color:#a8bac5;font-size:13px}summary{cursor:pointer;margin-bottom:14px}footer{margin-top:28px;font-size:12px;color:#6e8797;line-height:1.8}#message{min-height:24px;color:#8eebc6}#message[data-error="true"]{color:#ff9aac}a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #8eebc6;outline-offset:4px}@media(max-width:380px){body{padding:24px 14px}.card{padding:24px 18px}h1{font-size:28px}}
    </style></head><body><main><header><span class="mark" aria-hidden="true">↗</span><span>订阅导入</span></header><section class="card">${content}<p id="message" role="status"></p></section><footer>请妥善保管此链接，仅提供给对应订阅的使用者。</footer></main><script src="/shadowrocket-import.js" defer></script></body></html>`;
}
function unavailable(
  status,
  title = "链接已失效",
  message = "此导入页已撤销或不存在，请联系服务方重新获取链接。",
) {
  return {
    status,
    html: layout(
      title,
      `<span class="eyebrow">订阅导入</span><h1>${escape(title)}</h1><p>${escape(message)}</p>`,
    ),
  };
}
export async function subscriptionImportPage(
  context,
  token,
  ua,
  allow = () => {},
) {
  if (!/^[a-f0-9]{64}$/.test(token)) return unavailable(404);
  const tokenHash = digest(token);
  const row = context.db
    .prepare("SELECT * FROM subscription_imports WHERE token_hash=?")
    .get(tokenHash);
  if (!row) return unavailable(404);
  if (row.revoked !== null) return unavailable(410);
  const browser = embeddedBrowser(ua);
  if (browser)
    return {
      status: 200,
      html: layout(
        "请用其他浏览器打开",
        `<span class="eyebrow">当前在${browser}内打开</span><h1>请用其他浏览器打开</h1><p>${browser}内置浏览器可能无法唤起 Shadowrocket。请使用 Safari 或其他系统浏览器打开此链接。</p><p class="steps">点击右上角“…”菜单，选择“在浏览器打开”；也可以复制链接，粘贴到 Safari 地址栏。</p><button data-copy="page">复制此页链接</button>`,
      ),
    };
  try {
    allow(tokenHash);
    const panel = context.db
      .prepare(
        "SELECT p.* FROM panels p JOIN accounts a ON a.id=p.owner WHERE p.id=? AND a.disabled=0",
      )
      .get(row.panel);
    if (!panel) return unavailable(410);
    const result = await lookupSubscriptionOrigin(
      context,
      panel,
      String(row.uid),
    );
    const active = context.db
      .prepare(
        "SELECT revision,revoked FROM subscription_imports WHERE token_hash=?",
      )
      .get(tokenHash);
    if (!active || active.revoked !== null || active.revision !== row.revision)
      return unavailable(410);
    if (result.user?.id !== row.uid || result.user.email !== row.email)
      return unavailable(410);
    const url = subscriptionImportUrl(result.user.subscribe_url, token);
    return {
      status: 200,
      html: layout(
        "导入到 Shadowrocket",
        `<span class="eyebrow">iOS · SHADOWROCKET</span><h1>将订阅导入<br>Shadowrocket</h1><p>请先在 iPhone 或 iPad 上安装 Shadowrocket，再点击下方按钮。系统可能会提示确认打开应用。</p><a class="primary" id="shadowrocket-import" href="${escape(shadowrocketUrl(url))}">导入到 Shadowrocket</a><p class="steps">未能打开？请确认已安装 Shadowrocket，并在 Safari 中重新打开此页。</p>`,
      ),
    };
  } catch (error) {
    return unavailable(
      error.status === 429 ? 429 : 503,
      "暂时无法获取订阅",
      "请稍后重新打开此页；如果仍无法使用，请联系服务方。",
    );
  }
}
