import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

test("Pa55wall复合UA统一显示，其他客户端与Shadowrocket原始身份不改变", () => {
  const code = readFileSync(
    new URL("../public/app.js", import.meta.url),
    "utf8",
  );
  const context = vm.createContext({});
  vm.runInContext(
    code.slice(
      code.indexOf("function displayClientUa("),
      code.indexOf("function currentDeviceText("),
    ),
    context,
  );
  const ua = "Pa55wall/1.0.30 (Windows)",
    raw = "Clash.Meta/1.19.34 " + ua;
  assert.equal(context.displayClientUa(raw), ua);
  assert.equal(context.displayClientUa(ua), ua);
  assert.equal(context.displayClientUa("Mihomo/1.19.34 " + ua), ua);
  for (const other of [
    "Clash.Meta/1.19.34",
    "Clash.Meta/1.19.34 UnknownClient/2",
    "Shadowrocket/2.2.70 (iPhone; iOS 18.0)",
  ])
    assert.equal(context.displayClientUa(other), other);
  assert.equal(raw, "Clash.Meta/1.19.34 Pa55wall/1.0.30 (Windows)");
});
