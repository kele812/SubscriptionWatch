import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

test("首页直接显示403设备拒绝的全部原因，并区分未知失败", () => {
  class Element {
    children = [];
    textContent = "";
    append(...items) {
      this.children.push(...items);
    }
  }
  const code = readFileSync(
    new URL("../public/app.js", import.meta.url),
    "utf8",
  );
  const context = vm.createContext({
    document: { createElement: () => new Element() },
  });
  vm.runInContext(
    code.slice(
      code.indexOf("function requestStatusText(value)"),
      code.indexOf("function currentStatusLabels(user)"),
    ),
    context,
  );
  const reasons = [
    "设备数量已达 Xboard 套餐上限（已占用 3 / 上限 3）",
    "非指定客户端获取订阅",
  ];
  const cell = context.visitResultCell({
    status: 403,
    delivered: 0,
    review_blocked: 1,
    review_reasons: JSON.stringify(reasons),
  });
  assert.deepEqual(
    cell.children.slice(1).map((c) => c.textContent),
    reasons.map((r) => "拦截原因：" + r),
  );
  assert.equal(cell.children[0].textContent, "规则拒绝");
  const failure = context.visitOutcomeReasons({
    status: 503,
    delivered: 0,
    review_blocked: 0,
  });
  assert.match(failure[0], /失败原因/);
  assert.match(failure[0], /未上报更具体的原因/);
  assert.doesNotMatch(failure[0], /设备/);
});
