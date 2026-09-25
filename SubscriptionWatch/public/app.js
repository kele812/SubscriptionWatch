const $ = (s) => document.querySelector(s);
let destinationBefore = null,
  destinationNext = null,
  sourceIpQuery = "";
let blacklistPage = 1,
  blacklistSettingsLoaded = false;
const batchSelected = {
    history: new Set(),
    risk: new Set(),
    blacklist: new Set(),
  },
  batchVisible = { history: [], risk: [], blacklist: [] },
  batchScope = { history: "", risk: "", blacklist: "" };
let me,
  panels = [],
  panelId = 0,
  tab = "history",
  page = 1,
  pendingAction,
  toastTimer,
  refreshBusy = false,
  refreshPending = false;
function requestStatusText(value) {
  const code = Number(value);
  const meanings = {
    100: "继续请求",
    101: "切换协议",
    102: "处理中",
    103: "预先提示",
    200: "请求成功",
    201: "创建成功",
    202: "已接受，待处理",
    204: "请求成功，无返回内容",
    206: "部分内容返回",
    300: "有多个可选地址",
    301: "永久跳转",
    302: "临时跳转",
    303: "跳转到其他地址",
    304: "内容未修改，使用缓存",
    307: "临时跳转，保留请求方式",
    308: "永久跳转，保留请求方式",
    400: "请求有误",
    401: "未通过身份验证",
    403: "拒绝访问",
    404: "地址不存在",
    405: "请求方式不允许",
    406: "不支持请求的内容格式",
    408: "请求超时",
    409: "请求冲突",
    410: "资源已移除",
    413: "请求内容过大",
    414: "请求地址过长",
    415: "不支持的内容类型",
    422: "请求参数无法处理",
    429: "请求过于频繁",
    451: "因法律原因不可用",
    499: "客户端提前断开",
    500: "服务器内部错误",
    501: "服务器不支持此功能",
    502: "上游服务响应异常",
    503: "服务暂时不可用",
    504: "上游服务响应超时",
    505: "不支持的协议版本",
    520: "上游返回未知错误",
    521: "源站拒绝连接",
    522: "连接源站超时",
    523: "无法连接源站",
    524: "源站响应超时",
    525: "源站加密握手失败",
    526: "源站证书无效",
  };
  if (!Number.isInteger(code) || code < 100 || code > 599) return "状态未知";
  return (
    meanings[code] ||
    (code < 200
      ? "请求处理中"
      : code < 300
        ? "请求成功"
        : code < 400
          ? "重定向响应"
          : code < 500
            ? "请求未被接受"
            : "服务器处理异常")
  );
}
function toast(text) {
  $("#toast").textContent = text;
  $("#toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("#toast").hidden = true), 6500);
}
async function api(url, data) {
  const r = await fetch(url, {
    method: data === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json", "X-Watch-Request": "1" },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  const text = await r.text();
  let b;
  try {
    b = JSON.parse(text);
  } catch {
    throw Error(
      `服务器返回了非 JSON 响应（HTTP ${r.status}），请检查反向代理和服务日志。`,
    );
  }
  if (!r.ok) {
    if (r.status === 401) {
      document.body.hidden = true;
      location.replace("/");
    }
    throw Error(b.error || "请求失败");
  }
  return b;
}
const run = (fn) => async (e) => {
  e?.preventDefault();
  try {
    await fn(e);
  } catch (e) {
    toast(e.message);
  }
};
const panel = () => panels.find((p) => p.id === panelId),
  endpoint = (action) => `/api/panels/${panelId}/${action}`;
const format = (t) => (t ? new Date(t).toLocaleString() : "—"),
  geoText = (g) =>
    [g.country, g.region, g.city, g.organization]
      .filter((x) => x && x !== "未知")
      .join(" / ") || "未知";
function button(label, fn) {
  const b = document.createElement("button");
  b.type = "button";
  b.textContent = label;
  b.onclick = run(fn);
  return b;
}
function riskCollectionAction(id, user, collecting) {
  return button(collecting ? "取消采集" : "开启采集", () =>
    ask(
      collecting ? "取消用户访问采集" : "开启用户访问采集",
      `用户 ${user.uid} / ${user.email}。` +
        (collecting
          ? "取消后不再接收该用户的新访问记录，已有记录继续按3天保留规则处理。"
          : "将加入当前面板的指定用户采集。需已接入采集节点，只记录开启后新连接的目标域名或IP，记录保留3天。"),
      [],
      () =>
        api(`/api/panels/${id}/destinations/user`, {
          uid: user.uid,
          email: user.email,
          enabled: !collecting,
        }),
    ),
  );
}
function riskDetail(r) {
  return {
    用户ID: r.uid,
    邮箱: r.email,
    时间: format(r.updated || r.ts),
    风险原因: r.reasons.map((x) => ({
      规则: x.label,
      代码: x.code,
      统计: x.accounting,
      规则版本: x.ruleVersion || "旧版",
      附加条件: x.uaThreshold
        ? `不同UA ${x.uaCount}种 / 阈值 ${x.uaThreshold}种`
        : x.requestThreshold
          ? `有效请求 ${x.requestCount}次 / 阈值 ${x.requestThreshold}次`
          : "",
      实际数量: x.count,
      阈值: x.threshold ?? "旧记录未保存",
      计数说明: x.counting || "",
      合并前请求数: x.rawCount,
      窗口分钟:
        x.windowMinutes === null ? null : (x.windowMinutes ?? "旧记录未保存"),
      窗口开始: format(x.windowStart),
      窗口结束: format(x.windowEnd),
      预计条件到期: format(x.expires),
      证据说明: x.evidenceLimited
        ? "最多展示100组IP和原始UA证据，未完整展示"
        : "每组IP和原始UA展示最近一次获取",
      访问证据: (x.evidence || []).map((e) => ({
        时间: format(e.time),
        IP: e.ip,
        归属地: geoText(e.geo || {}),
        原始UA: e.ua,
        自有节点: e.owned ? "是" : "否",
        计入: e.included,
        排除原因: e.exclusion,
        地址提示: e.anomaly,
        参与统计: e.components,
        黑名单来源面板: e.blacklistSourcePanel,
        黑名单来源用户: e.blacklistSourceUser,
        黑名单加入时间: e.blacklistAdded ? format(e.blacklistAdded) : undefined,
        黑名单到期时间:
          e.blacklistExpires === Number.MAX_SAFE_INTEGER
            ? "永久保留"
            : e.blacklistExpires
              ? format(e.blacklistExpires)
              : undefined,
      })),
    })),
  };
}
function evidenceHint(code) {
  if (code === "ua")
    return "核查提示：UA 可修改。这条记录只说明请求使用了未列入允许名单的 UA，不能据此认定账号本人操作。";
  if (code === "cloud")
    return "核查提示：云厂商依据 IP 数据库的组织名匹配。建议打开对应访问记录，对照直连 IP 和反代日志。";
  if (code === "blacklist")
    return "核查提示：此 IP 来自跨面板共享名单。先核对名单来源面板与加入时间，再决定是否处置。";
  return "核查提示：多个不同 IP 已成功请求同一账号订阅；这说明订阅被多处使用，不能单独证明是谁操作。";
}
function sourceTraceDetail(r) {
  return {
    时间: format(r.ts),
    用户ID: r.uid,
    邮箱: r.email,
    来源IP: r.ip,
    直接连接IP: r.peer_ip,
    IP取值依据: r.ip_source,
    原始UA: r.ua,
    状态: requestStatusText(r.status),
    确认返回订阅:
      r.delivered === 1 ? "是" : r.delivered === 0 ? "否" : "旧版未核实",
    请求编号: r.event_id,
    订阅指纹: r.token_fingerprint,
    内容类型: r.content_type,
    耗时毫秒: r.ms,
  };
}
function table(target, head, rows) {
  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  const t = document.createElement("table"),
    thead = document.createElement("thead"),
    tr = document.createElement("tr");
  for (const h of head) {
    const th = document.createElement("th");
    th.textContent = h;
    tr.append(th);
  }
  thead.append(tr);
  t.append(thead);
  const body = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const value of row) {
      const td = document.createElement("td");
      if (value instanceof Node) td.append(value);
      else td.textContent = value ?? "—";
      tr.append(td);
    }
    body.append(tr);
  }
  t.append(body);
  wrap.append(t);
  if (!rows.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "暂无记录";
    wrap.append(p);
  }
  $(target).replaceChildren(wrap);
}
function updateBatch(kind) {
  const labels = { history: "条", risk: "人", blacklist: "个 IP" };
  const selected = batchSelected[kind],
    visible = batchVisible[kind],
    prefix = kind === "blacklist" ? "blacklist" : kind;
  $(`#${prefix}SelectedCount`).textContent =
    `已选 ${selected.size} ${labels[kind]}（仅当前页）`;
  $(`#${prefix}SelectPage`).textContent =
    visible.length && visible.every((key) => selected.has(key))
      ? "取消本页选择"
      : "全选本页";
  $(`#${prefix}SelectPage`).disabled = !visible.length;
  const actions = {
    history: ["historyBulkDelete"],
    risk: ["riskBulkResolve", "riskBulkCollectOn", "riskBulkCollectOff"],
    blacklist: ["blacklistBulkRemove"],
  };
  for (const id of actions[kind]) $(`#${id}`).disabled = !selected.size;
}
function batchRows(kind, scope, keys) {
  if (batchScope[kind] !== scope) batchSelected[kind].clear();
  batchScope[kind] = scope;
  batchVisible[kind] = keys;
  for (const key of batchSelected[kind])
    if (!keys.includes(key)) batchSelected[kind].delete(key);
  updateBatch(kind);
}
function batchCheck(kind, key, label, disabled = false) {
  const input = document.createElement("input");
  input.type = "checkbox";
  input.className = "batch-check";
  input.dataset.batch = kind;
  input.dataset.key = key;
  input.setAttribute("aria-label", label);
  input.checked = batchSelected[kind].has(key);
  input.disabled = disabled;
  input.onchange = () => {
    if (input.checked) batchSelected[kind].add(key);
    else batchSelected[kind].delete(key);
    updateBatch(kind);
  };
  return input;
}
function toggleBatchPage(kind, target) {
  const selected = batchSelected[kind],
    keys = batchVisible[kind];
  if (keys.every((key) => selected.has(key)))
    for (const key of keys) selected.delete(key);
  else for (const key of keys) selected.add(key);
  for (const input of document.querySelectorAll(
    `${target} input[data-batch="${kind}"]`,
  ))
    input.checked = selected.has(
      kind === "blacklist" ? input.dataset.key : Number(input.dataset.key),
    );
  updateBatch(kind);
}
function resetBatch() {
  for (const kind of Object.keys(batchSelected)) {
    batchSelected[kind].clear();
    batchScope[kind] = "";
  }
}
function actions(...items) {
  const div = document.createElement("div");
  div.className = "row-actions";
  div.append(...items);
  return div;
}
function detail(data) {
  const evidence = $("#detailEvidence");
  evidence.replaceChildren();
  const line = (parent, value, className = "") => {
    const p = document.createElement("p");
    p.textContent = value;
    if (className) p.className = className;
    parent.append(p);
  };
  const risk = Array.isArray(data.风险原因);
  const visit = !risk && "来源IP" in data;
  $("#detailText").hidden = risk || visit;
  if (Array.isArray(data.风险原因)) {
    line(evidence, `用户 ${data.用户ID} · ${data.邮箱} · 更新于 ${data.时间}`);
    const title = document.createElement("h3");
    title.textContent = data.风险原因.length
      ? `触发 ${data.风险原因.length} 条规则`
      : "当前没有触发中的规则";
    evidence.append(title);
    for (const reason of data.风险原因) {
      const card = document.createElement("section");
      card.className = "evidence-card";
      const heading = document.createElement("h3");
      heading.textContent = reason.规则;
      card.append(heading);
      const stats = reason.统计;
      const duration =
        typeof reason.窗口分钟 === "number"
          ? reason.窗口分钟 % 60 === 0
            ? `${reason.窗口分钟 / 60} 小时`
            : `${reason.窗口分钟} 分钟`
          : null;
      const count = stats
        ? reason.窗口分钟 === null
          ? `${stats.includedIps} 个 IP · ${stats.includedRequests} 次请求`
          : `${reason.实际数量} 个不同 IP`
        : `实际 ${reason.实际数量}`;
      line(
        card,
        `${duration ? `最近 ${duration} · ` : ""}${count} · 阈值 ${reason.阈值}${stats?.unit || ""}${reason.附加条件 ? ` · ${reason.附加条件}` : ""}`,
        "evidence-summary",
      );
      line(card, evidenceHint(reason.代码), "evidence-hint");
      for (const hit of reason.访问证据) {
        const entry = document.createElement("div");
        entry.className = "evidence-hit";
        if (hit.计入 === false) entry.className += " evidence-exempt";
        const status =
          hit.计入 === false
            ? `不计入：${hit.排除原因 || "未参与触发"}`
            : hit.计入 === true
              ? "参与触发"
              : "历史证据，计入状态未知";
        line(
          entry,
          `${hit.时间} · ${hit.IP} · ${status}${hit.自有节点 === "是" ? " · 自有节点" : ""}`,
          hit.计入 === true && reason.代码 !== "ua" ? "evidence-trigger" : "",
        );
        if (hit.归属地) line(entry, hit.归属地);
        line(
          entry,
          `UA：${hit.原始UA || "（空）"}`,
          hit.计入 === true && reason.代码 === "ua" ? "evidence-trigger" : "",
        );
        for (const text of [
          hit.地址提示,
          hit.参与统计?.join("、"),
          hit.黑名单来源面板
            ? `黑名单来源：${hit.黑名单来源面板} · 用户 ${hit.黑名单来源用户} · 加入 ${hit.黑名单加入时间} · 到期 ${hit.黑名单到期时间}`
            : "",
        ]) {
          if (!text) continue;
          line(entry, text);
        }
        card.append(entry);
      }
      if (!reason.访问证据.length) {
        line(card, "旧记录未保存详细证据");
      }
      const extra = document.createElement("details");
      extra.className = "evidence-more";
      const toggle = document.createElement("summary");
      toggle.textContent = "判定详情";
      extra.append(toggle);
      line(extra, `规则版本：${reason.规则版本}`);
      if (reason.窗口开始 && reason.窗口结束)
        line(extra, `评估时间：${reason.窗口开始} 至 ${reason.窗口结束}`);
      if (duration) line(extra, `统计窗口：${duration}`);
      else if (reason.窗口分钟 === null) line(extra, "逐次检查，不按时间累计");
      if (reason.预计条件到期 && reason.预计条件到期 !== "—")
        line(
          extra,
          `原条件预计到期：${reason.预计条件到期}（风险不会自动解除）`,
        );
      if (stats) {
        line(
          extra,
          `全部请求：${stats.totalIps} 个 IP、${stats.totalRequests} 次；计入：${stats.includedIps} 个 IP、${stats.includedRequests} 次`,
        );
        for (const group of stats.exclusions || [])
          line(
            extra,
            `不计入：${group.reason} · ${group.ipCount} 个 IP、${group.requests} 次${group.ips?.length ? ` · ${group.ips.join("、")}` : ""}`,
            "evidence-exempt",
          );
        if (stats.mergedRequests)
          line(extra, `重复请求合并：${stats.mergedRequests} 次`);
        line(extra, "按触发时的配置保存，历史结果不随当前设置变化。");
      } else {
        line(extra, "旧记录未保存完整统计和排除明细。");
      }
      if (reason.计数说明)
        line(extra, `${reason.计数说明}；合并前 ${reason.合并前请求数} 次`);
      if (reason.证据说明) line(extra, reason.证据说明);
      card.append(extra);
      evidence.append(card);
    }
  } else if (visit) {
    line(evidence, `用户 ${data.用户ID} · ${data.邮箱}`);
    const card = document.createElement("section");
    card.className = "evidence-card";
    line(card, `${data.时间} · ${data.来源IP}`, "evidence-summary");
    if (data.归属地) line(card, geoText(data.归属地));
    line(card, `状态：${data.状态}`);
    if (data.确认返回订阅) line(card, `订阅内容：${data.确认返回订阅}`);
    line(card, `UA：${data.原始UA || "（空）"}`);
    const extra = document.createElement("details");
    extra.className = "evidence-more";
    const toggle = document.createElement("summary");
    toggle.textContent = "连接详情";
    extra.append(toggle);
    line(extra, `直接连接 IP：${data.直接连接IP || "未知"}`);
    line(
      extra,
      `来源 IP 取值：${data.IP取值依据 === "trusted_proxy" ? "可信代理转发" : data.IP取值依据 === "peer" ? "直接连接" : "旧版未知"}`,
    );
    line(
      extra,
      "来源 IP 是服务器记录的请求来源，不能单独证明账号本人发起。需结合上游反代日志核查。",
    );
    line(extra, `耗时：${data.耗时毫秒 ?? "未知"} 毫秒`);
    if (data.请求编号) line(extra, `请求编号：${data.请求编号}`);
    if (data.订阅指纹) line(extra, `订阅指纹：${data.订阅指纹}`);
    if (data.内容类型) line(extra, `内容类型：${data.内容类型}`);
    card.append(extra);
    evidence.append(card);
  }
  $("#detailText").textContent = JSON.stringify(data, null, 2);
  $("#detail").showModal();
  const title = $("#detail").querySelector("h2");
  title.tabIndex = -1;
  title.focus({ preventScroll: true });
  $("#detail").scrollTop = 0;
}
function grade(level) {
  const span = document.createElement("span");
  span.className = "badge risk-" + level;
  span.textContent =
    { suspicious: "可疑用户", none: "已解除" }[level] || "未知";
  return span;
}
function ask(title, help, fields, fn) {
  $("#actionError").textContent = "";
  $("#actionTitle").textContent = title;
  $("#actionHelp").textContent = help;
  $("#actionFields").replaceChildren();
  for (const f of fields) {
    const label = document.createElement("label");
    label.textContent = f.label;
    const input = document.createElement("input");
    Object.assign(input, {
      name: f.name,
      type: f.type || "text",
      required: true,
      value: f.value || "",
    });
    label.append(input);
    $("#actionFields").append(label);
  }
  pendingAction = fn;
  $("#actionDialog").showModal();
}
const pwd = { name: "password", label: "当前登录账号的密码", type: "password" };
$("#actionForm").onsubmit = run(async () => {
  const fn = pendingAction;
  const submit = $("#actionForm").querySelector('button[type="submit"]');
  if (submit.disabled) return;
  submit.disabled = true;
  try {
    await fn(Object.fromEntries(new FormData($("#actionForm"))));
  } catch (e) {
    $("#actionError").textContent = e.message;
    return;
  } finally {
    submit.disabled = false;
  }
  $("#actionDialog").close();
  $("#actionForm").reset();
  toast("操作完成");
  await refresh();
});
$("#cancelAction").onclick = () => $("#actionDialog").close();
$("#closeDetail").onclick = () => $("#detail").close();
$("#importBackupForm").onsubmit = run(async () => {
  const file = $("#backupFile").files[0];
  if (!file) throw Error("请选择完整备份文件");
  if (file.size > 2 * 1024 ** 3)
    throw Error("网页导入最大2GB，请使用VPS恢复工具导入更大的备份");
  ask(
    "确认导入备份并覆盖当前数据",
    `文件：${file.name}。将替换当前账号、全部面板及记录，原数据保留。完成后使用备份中的账号密码重新登录。`,
    [],
    async () => {
      const control = $("#importBackupButton");
      control.disabled = true;
      $("#importBackupStatus").textContent =
        "正在上传、校验并恢复，请保持页面打开。校验通过后会短暂暂停采集处理。";
      $("#actionHelp").textContent = $("#importBackupStatus").textContent;
      try {
        const response = await fetch("/api/backup/import", {
          method: "POST",
          headers: {
            "Content-Type": "application/gzip",
            "X-Watch-Request": "1",
            "X-Watch-Confirm": "restore",
          },
          body: file,
        });
        let result;
        try {
          result = await response.json();
        } catch {
          throw Error(
            `导入返回HTTP ${response.status}，请检查宝塔/Cloudflare的上传大小和超时限制。`,
          );
        }
        if (!response.ok) throw Error(result.error || "导入失败");
        $("#importBackupStatus").textContent =
          "导入成功，正在返回登录页。请使用备份中的账号密码。";
        location.replace("/");
      } catch (e) {
        $("#importBackupStatus").textContent = e.message;
        $("#actionHelp").textContent = "导入未完成，请查看下面的提示。";
        throw e;
      } finally {
        control.disabled = false;
      }
    },
  );
});
async function loadPanels() {
  panels = (await api("/api/panels")).rows;
  if (!panels.some((p) => p.id === panelId)) panelId = panels[0]?.id || 0;
  $("#panelSelect").replaceChildren(
    ...panels.map((p) => {
      const o = document.createElement("option");
      o.value = p.id;
      o.textContent = p.name;
      return o;
    }),
  );
  $("#panelSelect").value = panelId;
  $("#noPanel").hidden = !!panelId;
  $("#metrics").hidden = !panelId;
  $("#tgForm").reset();
  $("#tgCode").textContent = "";
  fillRules();
}
function fillRules() {
  const p = panel();
  $("#collectorKey").value = "";
  $("#collectorKey").hidden = true;
  if (!p) return;
  $("#collectorUrl").value = location.origin;
  $("#publicId").value = p.public_id;
  const f = $("#rulesForm");
  for (const [k, v] of Object.entries({
    ...p.rules,
    name: p.name,
    notify: p.notify,
  })) {
    const el = f.elements[k] || $("#panelForm").elements[k];
    if (!el) continue;
    if (el.type === "checkbox") el.checked = !!v;
    else el.value = Array.isArray(v) ? v.join("\n") : v;
  }
  updateRuleConditions(false);
}
async function enter() {
  me = await api("/api/me");
  sourceIpQuery = "";
  tab = "history";
  page = 1;
  for (const v of document.querySelectorAll("[data-view]"))
    v.hidden = v.id !== "history";
  for (const b of document.querySelectorAll("[data-tab]"))
    b.classList.toggle("active", b.dataset.tab === "history");
  $("#pageTitle").textContent = "访问记录";

  $("#app").hidden = false;
  $("#identity").textContent = me.username;
  await loadPanels();
  await refresh();
}
$("#logout").onclick = run(async () => {
  await api("/api/logout", {});
  location.reload();
});
$("#addPanel").onclick = () =>
  ask(
    "添加 Xboard 面板",
    "添加后到面板设置复制接入信息。",
    [{ name: "name", label: "面板名称" }],
    async (b) => {
      const r = await api("/api/panels", b);
      panelId = r.id;
      await loadPanels();
      showTab("panelSettings");
    },
  );
$("#panelSelect").onchange = run(async () => {
  panelId = Number($("#panelSelect").value);
  resetBatch();
  destinationBefore = null;
  $("#destinationUserForm").reset();
  $("#destinationFilters").reset();
  $("#destinationNodeConfig").hidden = true;
  $("#destinationNodeConfig").textContent = "";
  $("#tgForm").reset();
  $("#tgCode").textContent = "";
  $("#tgStatus").textContent = "正在读取当前面板机器人…";
  page = 1;
  fillRules();
  await refresh();
});
function showTab(name) {
  tab = name;
  page = 1;
  resetBatch();
  for (const section of document.querySelectorAll("[data-view]"))
    section.hidden = section.id !== name;
  for (const b of document.querySelectorAll("[data-tab]"))
    b.classList.toggle("active", b.dataset.tab === name);
  $("#pageTitle").textContent = document.querySelector(
    `[data-tab="${name}"]`,
  ).textContent;
  refresh().catch((e) => toast(e.message));
}
for (const b of document.querySelectorAll("[data-tab]"))
  b.onclick = () => showTab(b.dataset.tab);
function query() {
  const q = new URLSearchParams({ page });
  if (tab === "history")
    for (const [k, v] of new FormData($("#filters")))
      if (v)
        q.set(k, ["from", "to"].includes(k) ? new Date(v).toISOString() : v);
  return q;
}
async function refresh() {
  if (refreshBusy) {
    refreshPending = true;
    return;
  }
  refreshBusy = true;
  const context = [panelId, tab, page].join(":");
  const read = async (url, body) => {
    const data = await api(url, body);
    if (context !== [panelId, tab, page].join(":")) throw Error("STALE_VIEW");
    return data;
  };
  try {
    for (const v of document.querySelectorAll("[data-view]"))
      v.hidden =
        v.id !== tab ||
        (!panelId &&
          [
            "destinations",
            "history",
            "risk",
            "riskHistory",
            "whitelist",
            "panelSettings",
            "telegram",
          ].includes(tab));
    const pageable = ["history", "risk", "riskHistory", "whitelist"].includes(
      tab,
    );
    $("#pagination").hidden = !pageable || !panelId;
    if (panelId) {
      const s = await read(endpoint("status"));
      $("#metricEvents").textContent = s.events;
      $("#metricToday").textContent = s.today;
      $("#metricRisks").textContent = s.risks;
      $("#metricDisk").textContent =
        (s.freeBytes / 1024 ** 3).toFixed(1) + " GB";
      $("#heartbeat").textContent =
        `采集状态：${s.panel.health} · 最近上报：${format(s.panel.last_seen)} · 待发送 ${s.panel.pending} · 丢弃 ${s.panel.dropped} · 过期 ${s.panel.expired} · 上报失败 ${s.panel.failures ?? "旧插件未提供"} · 插件 ${s.panel.version || "未连接"}（计数为最近一次上报快照，离线期间未知；Redis计数可能过期归零）`;
    }
    let rows = [];
    if (tab === "sourceIp") {
      if (sourceIpQuery) {
        const d = await read(
          "/api/admin/source-ip?ip=" + encodeURIComponent(sourceIpQuery),
        );
        const s = d.summary;
        $("#sourceIpSummary").textContent =
          `${sourceIpQuery} · ${geoText(d.geo || {})} ｜ 确认返回订阅 ${s.confirmed || 0} 次 · 跳转 ${s.redirects || 0} 次 · 失败 ${s.rejected || 0} 次 ｜ 涉及 ${s.panels} 个面板、${s.users} 个用户（共 ${s.requests} 次请求；显示最近 100 条）`;
        table(
          "#sourceIpResults",
          ["时间", "面板", "用户", "请求结果", "核查"],
          d.rows.map((r) => [
            format(r.ts),
            r.panel_name,
            `${r.uid} / ${r.email}`,
            r.delivered === 1
              ? "已确认返回订阅"
              : r.delivered === 0
                ? requestStatusText(r.status)
                : "旧版未核实",
            button("核查链路", () => detail(sourceTraceDetail(r))),
          ]),
        );
      } else {
        $("#sourceIpSummary").textContent = "请输入来源 IP 后查询。";
        $("#sourceIpResults").replaceChildren();
      }
    }
    if (tab === "ipBlacklist") {
      const q = new URLSearchParams(new FormData($("#blacklistFilters")));
      q.set("page", blacklistPage);
      const removed = q.get("state") === "removed";
      const data = await read("/api/admin/ip-blacklist?" + q);
      if (!blacklistSettingsLoaded) {
        const f = $("#blacklistSettings");
        f.elements.enabled.checked = data.settings.enabled;
        f.elements.recording.checked = data.settings.recording;
        f.elements.days.value = data.settings.days;
        blacklistSettingsLoaded = true;
      }
      batchRows(
        "blacklist",
        q.toString(),
        data.rows.filter((r) => !r.removed_at).map((r) => r.ip),
      );
      table(
        "#blacklistTable",
        [
          "选择",
          "IP",
          "来源面板",
          "触发用户ID",
          "来源访问",
          "复核状态",
          "有效期",
          "操作",
        ],
        data.rows.map((r) => [
          batchCheck(
            "blacklist",
            r.ip,
            `选择黑名单 IP ${r.ip}`,
            !!r.removed_at,
          ),
          r.ip,
          `${r.source_name}（ID ${r.source_panel}）`,
          r.source_uid,
          format(r.source_ts),
          r.removed_at
            ? `已移除 · ${format(r.removed_at)}`
            : r.reviewed_at
              ? `已复核 · ${r.reviewed_by}\n${format(r.reviewed_at)}`
              : "自动收集 · 待复核",
          r.removed_at
            ? "已停止生效"
            : r.expires === Number.MAX_SAFE_INTEGER
              ? "永久保留"
              : format(r.expires),
          actions(
            ...(r.removed_at || r.reviewed_at
              ? []
              : [
                  button("标为已复核", () =>
                    ask(
                      "确认已核查此 IP",
                      "仅记录人工复核状态；不会改变黑名单命中规则，也不会自动解除用户风险。",
                      [],
                      () => api("/api/admin/ip-blacklist/review", { ip: r.ip }),
                    ),
                  ),
                ]),
            ...(r.removed_at
              ? []
              : [
                  button("移除", () =>
                    ask(
                      "移除共享黑名单 IP",
                      `${r.ip} 将对所有面板停止生效。旧证据不会重复加入，新异常证据仍可重新加入；不会解除已有可疑标记。`,
                      [pwd],
                      (b) =>
                        api("/api/admin/ip-blacklist/remove", {
                          ...b,
                          ip: r.ip,
                        }),
                    ),
                  ),
                ]),
          ),
        ]),
      );
      $("#blacklistPageInfo").textContent =
        `共 ${data.total} 个${removed ? "已移除" : "生效中"} IP · 第 ${blacklistPage} 页`;
      $("#blacklistPrevious").disabled = blacklistPage <= 1;
      $("#blacklistNext").disabled = blacklistPage * 100 >= data.total;
    }
    if (panelId && tab === "destinations") {
      const state = await read(endpoint("destinations/settings"));
      table(
        "#destinationUsers",
        ["用户ID", "邮箱", "开始时间", "操作"],
        state.users.map((x) => [
          x.uid,
          x.email +
            (x.email !== x.current_email ? "（用户资料已变化，采集暂停）" : ""),
          format(x.since),
          button("停止采集", async () => {
            await api(endpoint("destinations/user"), {
              uid: x.uid,
              email: x.current_email || x.email,
              enabled: false,
            });
            await refresh();
          }),
        ]),
      );
      table(
        "#destinationNodes",
        [
          "节点ID / 名称",
          "最近上报",
          "队列积压",
          "节点丢弃",
          "失败次数",
          "拒收记录",
          "操作",
        ],
        state.nodes.map((x) => [
          x.id + " / " + x.name,
          format(x.last_seen),
          x.pending,
          x.dropped,
          x.failures,
          x.rejected,
          button("移除", () =>
            ask(
              "移除采集节点",
              "该节点将不能再上报，已有用户访问记录也会删除。",
              [pwd],
              async (b) => {
                await api(endpoint("destinations/node/remove"), {
                  ...b,
                  id: x.id,
                });
                await refresh();
              },
            ),
          ),
        ]),
      );
      const q = new URLSearchParams(new FormData($("#destinationFilters")));
      if (destinationBefore) q.set("before", destinationBefore);
      const d = await read(endpoint("destinations") + "?" + q);
      destinationNext = d.next;
      $("#destinationNext").disabled = !d.next;
      table(
        "#destinationTable",
        [
          "时间",
          "用户ID / 邮箱",
          "节点",
          "目标域名或IP",
          "端口",
          "协议",
          "来源IP",
        ],
        d.rows.map((x) => [
          format(x.ts),
          x.uid + " / " + x.email,
          x.node_name,
          x.host,
          x.port,
          x.network,
          x.source,
        ]),
      );
    }
    if (panelId && tab === "history") {
      const d = await read(endpoint("events") + "?" + query());
      rows = d.rows;
      batchRows(
        "history",
        `${panelId}:${query()}`,
        rows.map((r) => r.id),
      );
      table(
        "#historyTable",
        [
          "选择",
          "时间",
          "用户ID / 邮箱",
          "来源IP / 归属地",
          "原始UA",
          "状态",
          "详情",
        ],
        rows.map((r) => [
          batchCheck("history", r.id, `选择访问记录 ${r.id}`),
          format(r.ts),
          r.uid + " / " + r.email,
          r.ip + "\n" + geoText(r.geo),
          r.ua || "（空）",
          `${requestStatusText(r.status)}${r.delivered === 0 ? " · 未确认返回订阅" : ""}`,
          button("查看", () =>
            detail({
              时间: format(r.ts),
              用户ID: r.uid,
              邮箱: r.email,
              来源IP: r.ip,
              归属地: r.geo,
              原始UA: r.ua,

              直接连接IP: r.peer_ip,
              IP取值依据: r.ip_source,
              状态: requestStatusText(r.status),
              耗时毫秒: r.ms,
              请求编号: r.event_id,
              订阅指纹: r.token_fingerprint,
              内容类型: r.content_type,
              确认返回订阅:
                r.delivered === 1
                  ? "是"
                  : r.delivered === 0
                    ? "否"
                    : "旧版未核实",
            }),
          ),
        ]),
      );
      $("#pageInfo").textContent = `共 ${d.total} 条 · 第 ${page} 页`;
    }
    if (panelId && tab === "risk") {
      const collection = await read(endpoint("destinations/settings"));
      const collectingUsers = new Map(collection.users.map((u) => [u.uid, u]));
      rows = (
        await read(
          endpoint("risks") +
            `?page=${page}&all=${$("#showResolved").checked ? 1 : 0}`,
        )
      ).rows;
      const id = panelId;
      batchRows(
        "risk",
        `${id}:${page}:${$("#showResolved").checked}`,
        rows.filter((r) => r.active).map((r) => r.uid),
      );
      table(
        "#riskTable",
        [
          "选择",
          "用户",
          "风险等级",
          "风险原因",
          "最近账号操作",
          "更新时间",
          "访问采集",
          "操作",
        ],
        rows.map((r) => [
          batchCheck("risk", r.uid, `选择可疑用户 ${r.uid}`, !r.active),
          r.uid + " / " + r.email,
          grade(r.level),
          r.reasons.map((x) => x.label + "：" + x.count).join("\n") || "—",
          r.accountAction
            ? `${r.accountAction.kind === "unban" ? "解封" : r.accountAction.origin === "manual" ? "手动封禁" : "自动封禁"} / ${r.accountAction.status}`
            : "—",
          format(r.updated),
          collectingUsers.has(r.uid)
            ? collectingUsers.get(r.uid).email ===
              collectingUsers.get(r.uid).current_email
              ? "采集中"
              : "已暂停（用户资料变化）"
            : "未开启",
          actions(
            button("详情", () => detail(riskDetail(r))),
            riskCollectionAction(id, r, collectingUsers.has(r.uid)),
            button("取消风险", () =>
              ask("取消风险", "旧记录不重复触发，新增异常仍可标记。", [], () =>
                api(`/api/panels/${id}/resolve`, { uid: r.uid }),
              ),
            ),
            ...(r.active
              ? [
                  button("封禁账号", () =>
                    ask(
                      "确认封禁整个Xboard账号",
                      `用户 ${r.uid} / ${r.email}。插件下次轮询执行。账号封禁会影响客户使用；管理员、员工及白名单用户不会封禁。`,
                      [],
                      async () => {
                        await api(`/api/panels/${id}/ban/manual`, {
                          uid: r.uid,
                          email: r.email,
                          confirm: true,
                        });
                        toast("封禁任务已提交，结果可在面板设置中查看");
                      },
                    ),
                  ),
                ]
              : []),
            button("删除记录", () =>
              ask(
                "删除可疑用户记录",
                "保留访问历史和评估历史，旧记录视为已处理。",
                [pwd],
                (b) =>
                  api(`/api/panels/${id}/risk-delete`, { ...b, uid: r.uid }),
              ),
            ),
          ),
        ]),
      );
    }
    if (panelId && tab === "riskHistory") {
      rows = (await read(endpoint("risk-history") + "?page=" + page)).rows;
      const id = panelId;
      table(
        "#riskHistoryTable",
        ["时间", "用户", "处理结果", "原因", "操作"],
        rows.map((r) => [
          format(r.ts),
          r.uid + " / " + r.email,
          r.action,
          r.reasons.map((x) => x.label + "：" + x.count).join("\n"),
          actions(
            button("详情", () => detail(riskDetail(r))),
            button("删除", () =>
              ask("删除这条评估历史", "不影响当前风险状态。", [pwd], (b) =>
                api(`/api/panels/${id}/risk-history/delete`, {
                  ...b,
                  id: r.id,
                }),
              ),
            ),
          ),
        ]),
      );
    }
    if (panelId && tab === "whitelist") {
      rows = (
        await read(
          endpoint("subjects") +
            "?" +
            new URLSearchParams({
              q: $("#subjectSearch").elements.q.value,
              page,
            }),
        )
      ).rows;
      const id = panelId;
      table(
        "#subjectTable",
        ["用户ID", "邮箱", "操作"],
        rows.map((r) => [
          r.uid,
          r.email,
          button("移出白名单", async () => {
            await read(`/api/panels/${id}/whitelist`, {
              uid: r.uid,
              enabled: false,
            });
            await refreshAfter();
          }),
        ]),
      );
    }
    if (pageable) {
      if (tab !== "history") $("#pageInfo").textContent = "第 " + page + " 页";
      $("#prev").disabled = page === 1;
      $("#next").disabled = rows.length < 50;
    }
    if (panelId && tab === "telegram") {
      const t = await read(endpoint("telegram"));
      $("#tgForm").elements.chatId.value = t.chat || "";
      $("#tgStatus").textContent = t.bot_name
        ? `机器人 @${t.bot_name} · ${t.chat ? "已绑定私聊 " + t.chat : "尚未绑定"}${t.error ? " · " + t.error : ""}`
        : "尚未配置机器人";
    }
    if (panelId && tab === "panelSettings") {
      const config = await read(endpoint("ban"));
      const f = $("#banForm");
      f.elements.enabled.checked = config.enabled;
      $("#banStatus").textContent =
        (config.connected ? "插件控制通道已连接" : "等待采集插件连接") +
        " · 最近连接：" +
        format(config.lastSeen) +
        " · 自动封禁：" +
        (config.enabled ? "开启" : "关闭") +
        (config.canUnban ? " · 支持手动解封" : " · 手动解封需v3.5插件") +
        "。自动封禁仅依据新版插件确认返回内容的请求：最近24小时内须有至少4个不同IP触发地域规则，或至少2个不同IP并命中2类规则；单次异常UA或云IP只标记可疑，不自动封禁。";
      table(
        "#banHistory",
        ["用户ID", "操作", "状态", "说明", "时间"],
        config.history.map((x) => [
          x.uid,
          x.kind === "unban"
            ? "手动解封"
            : x.origin === "manual"
              ? "手动封禁"
              : "自动封禁",
          x.status,
          x.message,
          format(x.updated),
        ]),
      );
    }
    if (tab === "site") await geoStatus();
  } catch (e) {
    if (e.message !== "STALE_VIEW") throw e;
  } finally {
    refreshBusy = false;
    if (refreshPending) {
      refreshPending = false;
      queueMicrotask(() => refresh().catch((e) => toast(e.message)));
    }
  }
}
async function refreshAfter() {
  refreshBusy = false;
  await refresh();
}
async function geoStatus() {
  const g = await api("/api/admin/geo");
  const lines = [
    `下载凭据：${g.configured ? "已设置" : "未设置"}`,
    `状态：${g.phase}（${g.progress}%）`,
  ];
  if (g.downloadedBytes)
    lines.push(`本次下载：${(g.downloadedBytes / 1024 ** 2).toFixed(1)} MB`);
  if (g.current) {
    lines.push(`最近安装：${format(g.current.installedAt)}`);
    for (const [name, d] of Object.entries(g.current.databases))
      lines.push(
        `${name}：${(d.bytes / 1024 ** 2).toFixed(1)} MB · 版本 ${format(d.buildEpoch)}`,
      );
  }
  if (g.check) {
    lines.push(`最近检查：${format(g.check.checkedAt)}`);
    for (const d of g.check.databases)
      lines.push(
        `${d.name}：${d.available === true ? "有更新 / 尚未安装" : d.available === false ? "已是最新" : "版本信息不足，可手动重新安装"} · 发布 ${format(d.modified)}`,
      );
  }
  $("#geoStatus").textContent = lines.join("\n");
  $("#geoCheck").disabled = g.busy;
  $("#geoInstall").disabled = g.busy;
}
$("#destinationUserForm").onsubmit = run(async () => {
  const b = Object.fromEntries(new FormData($("#destinationUserForm")));
  await api(endpoint("destinations/user"), {
    uid: Number(b.uid),
    email: b.email.trim(),
    enabled: true,
  });
  toast("已开启，节点通常在30秒内同步");
  await refresh();
});
$("#addDestinationNode").onclick = () =>
  ask(
    "添加采集节点",
    "每台采集节点使用独立密钥。",
    [{ name: "name", label: "节点名称" }],
    async (b) => {
      const n = await api(endpoint("destinations/node"), b);
      const box = $("#destinationNodeConfig");
      box.hidden = false;
      box.textContent =
        "密钥仅显示一次，请保存到该节点config.yml的顶层：\nwatch_access:\n  url: " +
        JSON.stringify(location.origin) +
        "\n  node: " +
        JSON.stringify(n.publicId) +
        "\n  secret: " +
        JSON.stringify(n.secret) +
        "\n";
      await refresh();
    },
  );
$("#destinationFilters").onsubmit = run(async () => {
  destinationBefore = null;
  await refresh();
});
$("#destinationFirst").onclick = run(async () => {
  destinationBefore = null;
  await refresh();
});
$("#destinationNext").onclick = run(async () => {
  destinationBefore = destinationNext;
  await refresh();
});
$("#clearDestinations").onclick = () =>
  ask(
    "清空用户访问记录",
    "只删除当前面板的用户访问记录，不删除订阅记录和风险评估。",
    [pwd],
    async (b) => {
      await api(endpoint("destinations/clear"), b);
      destinationBefore = null;
      await refresh();
    },
  );
$("#blacklistSettings").onsubmit = run(async () => {
  const f = $("#blacklistSettings");
  await api("/api/admin/ip-blacklist/settings", {
    enabled: f.elements.enabled.checked,
    recording: f.elements.recording.checked,
    days: Number(f.elements.days.value),
  });
  blacklistSettingsLoaded = false;
  await refresh();
  toast("共享黑名单设置已保存，对所有面板生效");
});
$("#blacklistFilters").onsubmit = run(async () => {
  blacklistPage = 1;
  await refresh();
});
$("#blacklistPrevious").onclick = run(async () => {
  blacklistPage = Math.max(1, blacklistPage - 1);
  await refresh();
});
$("#blacklistNext").onclick = run(async () => {
  blacklistPage++;
  await refresh();
});
$("#blacklistSelectPage").onclick = () =>
  toggleBatchPage("blacklist", "#blacklistTable");
$("#blacklistBulkRemove").onclick = () => {
  const ips = [...batchSelected.blacklist];
  if (!ips.length) return;
  ask(
    `移除所选 ${ips.length} 个黑名单 IP`,
    "这些 IP 将对所有面板停止生效；已有可疑标记不会自动解除。",
    [pwd],
    async (b) => {
      await api("/api/admin/ip-blacklist/bulk-remove", { ...b, ips });
      batchSelected.blacklist.clear();
    },
  );
};
$("#historySelectPage").onclick = () =>
  toggleBatchPage("history", "#historyTable");
$("#historyBulkDelete").onclick = () => {
  const ids = [...batchSelected.history];
  if (!ids.length) return;
  ask(
    `删除所选 ${ids.length} 条访问记录`,
    "只删除当前面板的所选访问记录，保留可疑用户及评估历史。",
    [pwd],
    async (b) => {
      await api(endpoint("history/bulk-delete"), { ...b, ids });
      batchSelected.history.clear();
    },
  );
};
$("#riskSelectPage").onclick = () => toggleBatchPage("risk", "#riskTable");
$("#riskBulkResolve").onclick = () => {
  const uids = [...batchSelected.risk];
  if (!uids.length) return;
  ask(
    `取消所选 ${uids.length} 人的风险标记`,
    "旧记录不再触发，后续新增异常仍会重新标记；不会自动解封已封禁账号。",
    [],
    async () => {
      await api(endpoint("risks/bulk-resolve"), { uids });
      batchSelected.risk.clear();
    },
  );
};
for (const [id, enabled, verb] of [
  ["riskBulkCollectOn", true, "开启"],
  ["riskBulkCollectOff", false, "取消"],
])
  $(`#${id}`).onclick = () => {
    const uids = [...batchSelected.risk];
    if (!uids.length) return;
    ask(
      `${verb}所选 ${uids.length} 人的用户访问采集`,
      enabled
        ? "仅采集开启后新建立的连接；每个面板最多同时采集 100 人。"
        : "停止接收新连接记录，已有记录按保留规则清理。",
      [],
      async () => {
        await api(endpoint("risks/bulk-collection"), { uids, enabled });
        batchSelected.risk.clear();
      },
    );
  };
$("#importBlacklist").onclick = () =>
  ask(
    "导入历史触发 IP",
    "从所有面板现存中国大陆规则证据收集有效IP，只对导入后的新请求判断，不重新标记旧访问。",
    [],
    async () => {
      const control = $("#importBlacklist");
      if (control.disabled) throw Error("正在导入，请稍候");
      control.disabled = true;
      let before = 0,
        changed = 0,
        scanned = 0,
        limited = 0;
      try {
        do {
          const result = await api("/api/admin/ip-blacklist/import", {
            before,
          });
          changed += result.changed;
          scanned += result.scanned;
          limited += result.limited;
          before = result.next;
          $("#blacklistImportStatus").textContent =
            `已扫描 ${scanned} 条历史，新增或更新 ${changed} 次IP条目${limited ? `；${limited} 条证据已截断，只导入现存部分` : ""}`;
        } while (before);
        blacklistPage = 1;
      } finally {
        control.disabled = false;
      }
    },
  );
$("#refresh").onclick = run(refresh);
$("#filters").onsubmit = run(async () => {
  page = 1;
  await refresh();
});
$("#sourceIpForm").onsubmit = run(async () => {
  sourceIpQuery = $("#sourceIpForm").elements.ip.value.trim();
  await refresh();
});
$("#filters").onreset = () =>
  setTimeout(() => {
    page = 1;
    refresh().catch((e) => toast(e.message));
  }, 0);
$("#subjectSearch").onsubmit = run(async () => {
  page = 1;
  await refresh();
});
$("#showResolved").onchange = run(async () => {
  page = 1;
  await refresh();
});
$("#prev").onclick = run(async () => {
  page--;
  await refresh();
});
$("#next").onclick = run(async () => {
  page++;
  await refresh();
});
$("#export").onclick = () => {
  if (panelId) location.href = endpoint("export") + "?" + query();
};
$("#addCommonUa").onclick = run(() => {
  const field = $("#rulesForm").elements.uaKeywords;
  const current = field.value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  const seen = new Set(current.map((s) => s.toLowerCase()));
  for (const word of panel().commonUaKeywords || []) {
    if (!seen.has(word.toLowerCase())) current.push(word);
    seen.add(word.toLowerCase());
  }
  field.value = current.join("\n");
  updateRuleConditions(true);
  toast("已补充常见关键词，请保存风险规则后生效");
});
$("#panelForm").onsubmit = run(async () => {
  if (!panelId) throw Error("请先添加面板");
  const f = $("#panelForm");
  await api(endpoint("settings"), {
    name: f.elements.name.value,
    notify: f.elements.notify.checked,
    rules: {
      ...panel().rules,
      retentionDays: Number(f.elements.retentionDays.value),
    },
  });
  await loadPanels();
  toast("面板设置已保存");
});
function readRuleForm() {
  if (!panelId) throw Error("请先添加面板");
  const f = $("#rulesForm"),
    rules = {};
  for (const k of [
    "uaEnabled",
    "chinaEnabled",
    "foreignEnabled",
    "dcEnabled",
    "cloudflareExempt",
  ])
    rules[k] = f.elements[k].checked;
  for (const k of ["uaKeywords", "dcKeywords", "ipWhitelist"])
    rules[k] = f.elements[k].value
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean);
  for (const prefix of ["cn", "foreign"])
    for (const w of ["Short", "Long"])
      for (const end of ["Minutes", "Limit"]) {
        const k = prefix + w + end;
        rules[k] = Number(f.elements[k].value);
      }
  return { ...rules, retentionDays: panel().rules.retentionDays };
}
$("#rulesForm").onsubmit = run(async () => {
  const rules = readRuleForm();
  await api(endpoint("settings"), {
    name: panel().name,
    notify: panel().notify,
    rules: { ...rules, retentionDays: panel().rules.retentionDays },
  });
  await loadPanels();
  toast("风险规则已保存");
});
$("#showKey").onclick = run(async () => {
  if (!panelId) throw Error("请先添加面板");
  const r = await api(endpoint("key"), {});
  $("#collectorKey").value = r.collectorKey;
  $("#collectorKey").hidden = false;
});
$("#addWhite").onclick = () => {
  const id = panelId;
  if (!id) return;
  ask(
    "添加白名单",
    "填写此面板已采集到的用户ID和对应邮箱，未知用户不能添加。",
    [
      { name: "uid", label: "用户ID", type: "number" },
      { name: "email", label: "邮箱", type: "email" },
    ],
    (b) =>
      api(`/api/panels/${id}/whitelist`, {
        uid: Number(b.uid),
        email: b.email,
        enabled: true,
      }),
  );
};
$("#clearVisits").onclick = () => {
  if (!panelId) return;
  const url = endpoint("history/clear");
  ask(
    "清空访问历史",
    "确认清空此面板全部访问历史？不删除可疑用户和评估历史。",
    [pwd],
    (b) => api(url, b),
  );
};
$("#clearRiskHistory").onclick = () => {
  if (!panelId) return;
  const url = endpoint("risk-history/delete");
  ask(
    "删除全部风险评估历史",
    "不改变当前风险状态。请输入当前登录密码确认删除。",
    [pwd],
    (b) => api(url, { ...b, all: true }),
  );
};
$("#deletePanel").onclick = () => {
  if (!panelId) return;
  const url = endpoint("delete");
  ask(
    "删除整个面板",
    "将删除该面板的所有数据、风险和配置。请输入当前登录密码确认删除。",
    [pwd],
    async (b) => {
      await api(url, b);
      await loadPanels();
    },
  );
};
$("#passwordForm").onsubmit = run(async () => {
  await api(
    "/api/password",
    Object.fromEntries(new FormData($("#passwordForm"))),
  );
  location.reload();
});
$("#tgForm").onsubmit = run(async () => {
  await api(
    endpoint("telegram"),
    Object.fromEntries(new FormData($("#tgForm"))),
  );
  $("#tgForm").reset();
  $("#tgCode").textContent = "";
  await refresh();
  toast("机器人与个人ID已保存，仅管理当前面板");
});
$("#tgRemove").onclick = () => {
  const url = endpoint("telegram/remove");
  ask("移除机器人", "停止当前面板的机器人通知和指令。", [], async () => {
    await api(url, {});
    $("#tgCode").textContent = "";
  });
};
$("#banForm").onsubmit = run(async () => {
  const f = $("#banForm"),
    data = Object.fromEntries(new FormData(f));
  data.enabled = f.elements.enabled.checked;
  await api(endpoint("ban"), data);
  await refresh();
  toast("封禁设置已保存");
});
$("#unbanForm").onsubmit = run(async () => {
  const f = $("#unbanForm"),
    id = panelId,
    uid = Number(f.elements.uid.value),
    email = f.elements.email.value.trim();
  ask(
    "确认解封整个Xboard账号",
    `用户 ${uid} / ${email}。会取消旧风险；新异常仍可触发。`,
    [],
    async () => {
      await api(`/api/panels/${id}/unban`, { uid, email });
      await refreshAfter();
      toast("解封任务已提交，请查看执行历史");
    },
  );
});
$("#geoForm").onsubmit = run(async () => {
  await api(
    "/api/admin/geo/credentials",
    Object.fromEntries(new FormData($("#geoForm"))),
  );
  $("#geoForm").reset();
  await geoStatus();
  toast("下载凭据已保存");
});
$("#geoCheck").onclick = run(async () => {
  await api("/api/admin/geo/check", {});
  await geoStatus();
});
$("#geoImportForm").onsubmit = run(async () => {
  const file = $("#geoImportForm").elements.configFile.files[0];
  if (!file || file.size > 32768)
    throw Error("请选择32KB以内的 GeoIP.conf 文件");
  const result = await api("/api/admin/geo/import", {
    content: await file.text(),
  });
  $("#geoImportForm").reset();
  await geoStatus();
  toast("配置已导入。账号ID：" + result.accountId + "；请点击检查更新。");
});
$("#geoInstall").onclick = run(async () => {
  await api("/api/admin/geo/install", {});
  await geoStatus();
});
setInterval(() => {
  if (!$("#app").hidden && tab === "site") geoStatus().catch(() => {});
}, 3000);
enter().catch((e) => toast(e.message));
// A restored page must revalidate the session before any old data is shown.
addEventListener("pagehide", () => {
  document.body.hidden = true;
});
addEventListener("pageshow", (e) => {
  if (e.persisted) location.reload();
});
document.addEventListener("visibilitychange", async () => {
  if (document.visibilityState === "visible") {
    document.body.hidden = true;
    try {
      await api("/api/me");
      document.body.hidden = false;
    } catch {
      location.replace("/");
    }
  }
});
setInterval(() => api("/api/me").catch(() => {}), 30000);

function updateRuleConditions(dirty = true) {
  const f = $("#rulesForm"),
    v = (n) => f.elements[n].value,
    on = (n) => f.elements[n].checked;
  const items = [
    ["uaEnabled", "新请求的UA为空或不匹配允许关键词，标记为可疑用户"],
    [
      "chinaEnabled",
      `${v("cnShortMinutes")}分钟超过${v("cnShortLimit")}个或${v("cnLongMinutes")}分钟超过${v("cnLongLimit")}个不同中国大陆IP成功拉取，标记为可疑用户`,
    ],
    ["dcEnabled", "云厂商组织名匹配关键词且成功拉取一次，标记为可疑用户"],
    [
      "foreignEnabled",
      `${v("foreignShortMinutes")}分钟超过${v("foreignShortLimit")}个或${v("foreignLongMinutes")}分钟超过${v("foreignLongLimit")}个不同非中国大陆IP成功拉取，标记为可疑用户`,
    ],
  ];
  for (const [key, text] of items) {
    const card = f.elements[key].closest("fieldset");
    let p = card.querySelector(".trigger-condition");
    if (!p) {
      p = document.createElement("p");
      p.className = "trigger-condition";
      card.querySelector("legend").after(p);
    }
    p.textContent = on(key)
      ? "触发条件：同一用户" + text
      : "已关闭，不参与风险判断";
  }
  $("#rulesDirty").textContent = dirty
    ? "修改尚未保存；保存后才生效"
    : "规则已保存";
  $("#previewResult").textContent = "";
  $("#previewExamples").replaceChildren();
}
$("#rulesForm").addEventListener("input", () => updateRuleConditions());
$("#previewRules").onclick = run(async () => {
  if (!$("#rulesForm").reportValidity()) return;
  const button = $("#previewRules");
  button.disabled = true;
  try {
    const target = panelId,
      rules = readRuleForm();
    const r = await api(endpoint("preview"), { rules });
    if (
      panelId !== target ||
      JSON.stringify(readRuleForm()) !== JSON.stringify(rules)
    ) {
      $("#previewResult").textContent = "设置已变化，请重新预览";
      return;
    }
    $("#previewResult").textContent =
      `试运行：新增命中 ${r.changes.new} 人 · 仍匹配 ${r.changes.unchanged} 人 · 当前标记但不再匹配 ${r.changes.noLongerMatched} 人。${r.note}`;
    table(
      "#previewExamples",
      ["用户", "结果", "命中规则"],
      r.examples.map((x) => [
        `${x.uid} / ${x.email}`,
        x.kind === "new" ? "新增命中" : "当前标记不再匹配",
        x.reasons.join("、") || "—",
      ]),
    );
  } finally {
    button.disabled = false;
  }
});

$("#exportBlacklist").onclick = run(async () => {
  const r = await fetch("/api/admin/ip-blacklist/export", {
    headers: { "X-Watch-Request": "1" },
  });
  if (!r.ok) {
    if (r.status === 401) {
      document.body.hidden = true;
      location.replace("/");
    }
    throw Error("导出失败，请确认登录状态后重试（HTTP " + r.status + "）");
  }
  if (!(r.headers.get("content-type") || "").startsWith("text/plain"))
    throw Error("导出失败：服务器返回了异常内容");
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = "ip-blacklist.txt";
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  toast("黑名单已导出，每行一个 IP");
});
