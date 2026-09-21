import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

test("可疑用户采集操作确认后提交，锁定原面板与用户，支持开启和取消", async () => {
  const code = readFileSync(
    new URL("../public/app.js", import.meta.url),
    "utf8",
  );
  for (const collecting of [false, true]) {
    let confirmation;
    const requests = [];
    const context = vm.createContext({
      button: (label, click) => ({ label, click }),
      ask: (title, help, fields, submit) => {
        confirmation = { title, help, fields, submit };
      },
      api: async (url, data) => requests.push({ url, ...data }),
      panelId: 7,
    });
    vm.runInContext(
      code.slice(
        code.indexOf("function riskCollectionAction("),
        code.indexOf("function riskDetail("),
      ),
      context,
    );
    const control = context.riskCollectionAction(
      7,
      { uid: 12, email: "user@example.com" },
      collecting,
    );
    assert.equal(control.label, collecting ? "取消采集" : "开启采集");
    control.click();
    assert.equal(requests.length, 0, "确认前不能开始或停止采集");
    context.panelId = 99;
    await confirmation.submit();
    assert.deepEqual(requests, [
      {
        url: "/api/panels/7/destinations/user",
        uid: 12,
        email: "user@example.com",
        enabled: !collecting,
      },
    ]);
  }
});
