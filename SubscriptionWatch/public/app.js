const $ = (s) => document.querySelector(s);
let me,
  panels = [],
  panelId = 0,
  tab = "history",
  page = 1,
  pendingAction,
  toastTimer,
  refreshBusy = false,
  refreshPending = false;
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
      })),
    })),
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
function actions(...items) {
  const div = document.createElement("div");
  div.className = "row-actions";
  div.append(...items);
  return div;
}
function detail(data) {
  const evidence = $("#detailEvidence");
  evidence.replaceChildren();
  $("#detailText").hidden = Array.isArray(data.风险原因);
  if (Array.isArray(data.风险原因)) {
    const identity = document.createElement("p");
    identity.textContent = `用户 ${data.用户ID} · ${data.邮箱} · ${data.时间}`;
    evidence.append(identity);
    const title = document.createElement("h3");
    title.textContent = "风险原因与访问详情";
    evidence.append(title);
    for (const reason of data.风险原因) {
      const card = document.createElement("section");
      card.className = "evidence-card";
      const heading = document.createElement("h3");
      heading.textContent = reason.规则;
      card.append(heading);
      const stats = reason.统计;
      if (stats) {
        const summary = document.createElement("p");
        const duration =
          reason.窗口分钟 % 60 === 0
            ? `${reason.窗口分钟 / 60} 小时`
            : `${reason.窗口分钟} 分钟`;
        summary.textContent = `${reason.窗口分钟 === null ? "本次新请求上报" : "在最近 " + duration + "内"}（${reason.窗口开始} 至 ${reason.窗口结束}），共有 ${stats.totalIps} 个不同 IP 请求同一订阅，共请求 ${stats.totalRequests} 次。最终计入 ${reason.实际数量} ${stats.unit}，达到 ${reason.阈值} ${stats.unit}的触发阈值。`;
        card.append(summary);
        for (const group of stats.exclusions) {
          const line = document.createElement("p");
          line.textContent = `不计入：${group.reason}，涉及 ${group.ipCount} 个 IP、${group.requests} 次请求。IP：${group.ips.join("、")}${group.ipCount > group.ips.length ? "（仅展示前100个）" : ""}`;
          line.className = "evidence-exempt";
          card.append(line);
        }
        const note = document.createElement("p");
        note.textContent = `计入请求涉及 ${stats.includedIps} 个不同 IP、${stats.includedRequests} 次请求。${stats.mergedRequests ? `同一中国大陆 IP 且完整 UA 相同的重复请求合并，减少 ${stats.mergedRequests} 次计数。` : ""}${stats.exclusions.length ? "同一 IP 可能有计入和排除的不同请求，各项 IP 数不能直接相减。" : "没有被排除的请求。"} 按评估时配置记录，历史结论不随当前设置改写。`;
        card.append(note);
      } else {
        const legacy = document.createElement("p");
        legacy.textContent =
          "历史评估：按当时配置判断，未保存排除明细，不能按当前白名单推测。";
        card.append(legacy);
      }
      for (const text of [
        `规则版本：${reason.规则版本} ${reason.附加条件}`,
        `实际 ${reason.实际数量} / 阈值 ${reason.阈值} · ${reason.窗口分钟 === null ? "逐次检查，无时间窗口" : "窗口 " + reason.窗口分钟 + " 分钟"}`,
        `${reason.窗口开始} 至 ${reason.窗口结束}`,
        `原触发条件预计到期（不自动解除风险）：${reason.预计条件到期} · ${reason.证据说明}`,
      ]) {
        const line = document.createElement("p");
        line.textContent = text;
        card.append(line);
      }
      if (reason.计数说明) {
        const note = document.createElement("p");
        note.textContent = `${reason.计数说明}；合并前请求 ${reason.合并前请求数} 次`;
        card.append(note);
      }
      for (const hit of reason.访问证据) {
        const line = document.createElement("div");
        line.className = "evidence-hit";
        if (hit.计入 === false) line.className += " evidence-exempt";
        for (const text of [
          `${hit.时间} · ${hit.IP} · ${hit.计入 === true ? "参与触发" : hit.计入 === false ? "不计入：" + hit.排除原因 : "历史证据（未保存计入状态）"}${hit.自有节点 === "是" ? " · 自有节点" : ""}`,
          hit.归属地,
          `UA：${hit.原始UA || "（空）"}`,
        ]) {
          const p = document.createElement("p");
          p.textContent = text;
          if (
            hit.计入 === true &&
            (reason.代码 === "ua"
              ? text.startsWith("UA：")
              : text.startsWith(hit.时间))
          )
            p.className = "evidence-trigger";
          line.append(p);
        }
        for (const text of [hit.地址提示, hit.参与统计?.join("、")]) {
          if (!text) continue;
          const note = document.createElement("p");
          note.textContent = text;
          line.append(note);
        }
        card.append(line);
      }
      if (!reason.访问证据.length) {
        const p = document.createElement("p");
        p.textContent = "旧记录未保存详细证据";
        card.append(p);
      }
      evidence.append(card);
    }
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
    if (panelId && tab === "history") {
      const d = await read(endpoint("events") + "?" + query());
      rows = d.rows;
      table(
        "#historyTable",
        ["时间", "用户ID / 邮箱", "来源IP / 归属地", "原始UA", "状态", "详情"],
        rows.map((r) => [
          format(r.ts),
          r.uid + " / " + r.email,
          r.ip + "\n" + geoText(r.geo),
          r.ua || "（空）",
          r.status,
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
              状态: r.status,
              耗时毫秒: r.ms,
            }),
          ),
        ]),
      );
      $("#pageInfo").textContent = `共 ${d.total} 条 · 第 ${page} 页`;
    }
    if (panelId && tab === "risk") {
      rows = (
        await read(
          endpoint("risks") +
            `?page=${page}&all=${$("#showResolved").checked ? 1 : 0}`,
        )
      ).rows;
      const id = panelId;
      table(
        "#riskTable",
        ["用户", "风险等级", "风险原因", "最近账号操作", "更新时间", "操作"],
        rows.map((r) => [
          r.uid + " / " + r.email,
          grade(r.level),
          r.reasons.map((x) => x.label + "：" + x.count).join("\n") || "—",
          r.accountAction
            ? `${r.accountAction.kind === "unban" ? "解封" : r.accountAction.origin === "manual" ? "手动封禁" : "自动封禁"} / ${r.accountAction.status}`
            : "—",
          format(r.updated),
          actions(
            button("详情", () => detail(riskDetail(r))),
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
                      `用户 ${r.uid} / ${r.email}。不等待观察期，插件下次轮询执行。账号封禁会影响客户使用；管理员、员工及白名单用户不会封禁。`,
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
      f.elements.observeMinutes.value = config.observeMinutes;
      table(
        "#observations",
        ["观察中的用户", "持续可疑用户起点", "观察期结束（非保证执行）"],
        config.observing.map((x) => [
          `${x.uid} / ${x.email}`,
          format(x.since),
          config.enabled
            ? format(x.since + config.observeMinutes * 60000)
            : "自动封禁关闭",
        ]),
      );
      $("#banStatus").textContent =
        (config.connected ? "插件控制通道已连接" : "等待采集插件连接") +
        " · 最近连接：" +
        format(config.lastSeen) +
        " · 自动封禁：" +
        (config.enabled ? "开启" : "关闭") +
        (config.canUnban ? " · 支持手动解封" : " · 手动解封需v3.5插件");
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
$("#refresh").onclick = run(refresh);
$("#filters").onsubmit = run(async () => {
  page = 1;
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
    [],
    () => api(url, { confirm: true }),
  );
};
$("#clearRiskHistory").onclick = () => {
  if (!panelId) return;
  const url = endpoint("risk-history/delete");
  ask(
    "删除全部风险评估历史",
    "不改变当前风险状态。请输入：删除风险评估历史",
    [{ name: "confirm", label: "确认文字" }, pwd],
    (b) => api(url, { ...b, all: true }),
  );
};
$("#deletePanel").onclick = () => {
  if (!panelId) return;
  const url = endpoint("delete");
  ask(
    "删除整个面板",
    "将删除该面板的所有数据、风险和配置。请输入面板名称：" + panel().name,
    [{ name: "confirm", label: "面板名称" }, pwd],
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
  data.observeMinutes = Number(f.elements.observeMinutes.value);
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
      "按当前条件预计可疑用户 " + r.counts.suspicious + " 人；" + r.note;
  } finally {
    button.disabled = false;
  }
});
