import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

test("详情不重复展示；IP规则只标红参与IP，UA规则只标红异常UA", () => {
  class Element {
    children = [];
    textContent = "";
    className = "";
    append(...items) {
      this.children.push(...items);
    }
    replaceChildren() {
      this.children = [];
    }
    showModal() {}
    focus() {}
    querySelector() {
      return new Element();
    }
  }
  const nodes = Object.fromEntries(
    ["#detailEvidence", "#detailText", "#detail"].map((k) => [
      k,
      new Element(),
    ]),
  );
  const code = readFileSync(
    new URL("../public/app.js", import.meta.url),
    "utf8",
  );
  const context = vm.createContext({
    document: { createElement: () => new Element() },
    $: (k) => nodes[k],
    geoText: () => "示例地区",
  });
  vm.runInContext(
    code.slice(
      code.indexOf("function detail(data)"),
      code.indexOf("function grade(level)"),
    ),
    context,
  );
  const row = {
    时间: "2026/9/17 12:00",
    IP: "192.0.2.1",
    归属地: "示例",
    原始UA: "NetFlow/windows",
    计入: true,
  };
  const reason = {
    规则: "多个 IP 获取同一订阅",
    代码: "ip",
    访问证据: [
      row,
      { ...row, IP: "192.0.2.2", 计入: false, 排除原因: "自有节点" },
    ],
    统计: {
      totalIps: 2,
      totalRequests: 3,
      includedIps: 1,
      includedRequests: 2,
      exclusions: [
        { reason: "自有节点", ips: ["192.0.2.2"], ipCount: 1, requests: 1 },
      ],
    },
    窗口分钟: 1440,
  };
  const flatten = (el) => [el, ...el.children.flatMap(flatten)];
  context.input = { 风险原因: [reason] };
  vm.runInContext("detail(input)", context);
  let elements = flatten(nodes["#detailEvidence"]);
  assert.equal(
    elements.filter((e) => e.className.includes("evidence-hit")).length,
    2,
  );
  let red = elements.filter((e) => e.className === "evidence-trigger");
  assert.equal(red.length, 1);
  assert.ok(
    elements.some(
      (e) =>
        e.className.includes("evidence-exempt") &&
        e.children.some((p) => p.textContent.includes("不计入：自有节点")),
    ),
  );
  assert.ok(red[0].textContent.includes("192.0.2.1"));
  assert.ok(elements.some((e) => e.textContent.includes("最近 24 小时")));
  reason.代码 = "ua";
  vm.runInContext("detail(input)", context);
  red = flatten(nodes["#detailEvidence"]).filter(
    (e) => e.className === "evidence-trigger",
  );
  assert.equal(red.length, 1);
  assert.ok(red[0].textContent.startsWith("UA："));
  assert.ok(elements.some((e) => e.textContent === "触发 1 条规则"));
  const cloud = {
    ...reason,
    规则: "云服务器 IP 获取订阅",
    代码: "cloud",
    窗口分钟: null,
    实际数量: 1,
    阈值: 1,
    统计: { ...reason.统计, includedIps: 1, includedRequests: 1, unit: "次" },
    访问证据: [row],
  };
  context.input = { 风险原因: [reason, cloud] };
  vm.runInContext("detail(input)", context);
  elements = flatten(nodes["#detailEvidence"]);
  assert.ok(elements.some((e) => e.textContent === "触发 2 条规则"));
  assert.equal(
    elements.filter((e) => e.className === "evidence-card").length,
    2,
  );
  assert.ok(elements.some((e) => e.textContent.includes("1 个 IP · 1 次请求")));
  assert.equal(
    elements.filter((e) => e.className === "evidence-more").length,
    2,
  );

  context.input = {
    用户ID: 1,
    邮箱: "example@example.com",
    时间: "2026/9/17 12:00",
    来源IP: "192.0.2.1",
    归属地: {},
    状态: "临时跳转",
    原始UA: "NetFlow/windows",
    直接连接IP: "127.0.0.1",
    IP取值依据: "trusted_proxy",
    耗时毫秒: 12,
  };
  vm.runInContext("detail(input)", context);
  elements = flatten(nodes["#detailEvidence"]);
  assert.equal(nodes["#detailText"].hidden, true);
  assert.ok(elements.some((e) => e.textContent === "状态：临时跳转"));
  assert.ok(elements.some((e) => e.textContent === "连接详情"));
});
