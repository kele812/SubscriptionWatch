import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("后台、登录页、静态资源和采集插件使用同一版本号", () => {
  const version = JSON.parse(read("../package.json")).version;
  const lock = JSON.parse(read("../package-lock.json"));
  assert.equal(lock.version, version);
  assert.equal(lock.packages[""].version, version);
  assert.equal(JSON.parse(read("../../SubscriptionWatchCollector/config.json")).version, version);

  const login = read("../public/login.html");
  const dashboard = read("../public/index.html");
  assert.ok(login.includes(`订阅观察 / v${version}`));
  assert.ok(dashboard.includes(`v${version} · 独立采集`));
  for (const html of [login, dashboard]) {
    for (const match of html.matchAll(/[?&]v=([0-9]+\.[0-9]+\.[0-9]+)/g)) {
      assert.equal(match[1], version);
    }
  }

  assert.ok(read("../server.mjs").includes(`Subscription Watch v${version} ready`));
  assert.ok(read("../../SubscriptionWatchCollector/Services/Collector.php").includes(`'version' => '${version}'`));
  assert.ok(read("../../SubscriptionWatchCollector/Services/Control.php").includes(`'version' => '${version}'`));
});
