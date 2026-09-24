import test from "node:test";
import assert from "node:assert/strict";
import { assess } from "../assessment.mjs";
import { defaults, validateRules } from "../model.mjs";
import { riskLevel } from "../risk.mjs";
const now = Date.now(),
  row = (ip, ts = now - 1000, status = 200, ua = "NetFlow") => ({
    ip,
    ts,
    status,
    ua,
  });
function check(rows, fresh = [], rules = {}) {
  const db = { prepare: () => ({ all: () => rows, get: () => undefined }) };
  const geo = {
    lookup: (ip) => ({
      countryCode: ip.startsWith("1.")
        ? "CN"
        : ip.startsWith("2.")
          ? "HK"
          : ip.startsWith("3.")
            ? "US"
            : undefined,
      organization: ip.endsWith(".99")
        ? "Cloudflare, Inc."
        : ip.endsWith(".88")
          ? "Amazon Inc."
          : "ISP",
    }),
  };
  return assess(
    db,
    { id: 1, rules: JSON.stringify({ ...defaults, ...rules }) },
    { uid: 1, dismissed: 0 },
    now,
    geo,
    fresh,
  );
}
test("3.7.1地域规则严格超过3/10；重复IP不区分UA，CN与非CN独立", () => {
  for (const [prefix, code] of [
    ["1", "cn"],
    ["2", "foreign"],
  ]) {
    const rows = [1, 2, 3].map((n) => row(`${prefix}.0.0.${n}`));
    assert.equal(check(rows).length, 0);
    rows.push(row(`${prefix}.0.0.1`, now - 1000, 200, "OtherUA"));
    assert.equal(check(rows).length, 0);
    rows.push(row(`${prefix}.0.0.4`));
    assert.equal(check(rows).find((r) => r.code === code + "60").count, 4);
    const long = Array.from({ length: 10 }, (_, n) =>
      row(`${prefix}.0.1.${n + 1}`, now - 120 * 60000),
    );
    assert.equal(check(long).length, 0);
    long.push(row(`${prefix}.0.1.11`, now - 120 * 60000));
    assert.equal(check(long).find((r) => r.code === code + "720").count, 11);
  }
  assert.equal(
    check([row("1.0.0.1"), row("1.0.0.2"), row("2.0.0.1"), row("2.0.0.2")])
      .length,
    0,
  );
});
test("3.7.1失败请求、边界、未知归属、白名单和CF排除", () => {
  const rows = [1, 2, 3].map((n) => row(`1.0.0.${n}`));
  for (const extra of [
    row("1.0.0.4", now - 60 * 60000),
    row("1.0.0.4", now - 1000, 500),
    row("9.0.0.4"),
  ])
    assert.ok(!check([...rows, extra]).some((r) => r.code === "cn60"));
  assert.equal(
    check([...rows, row("1.0.0.99")], [], { cloudflareExempt: true }).length,
    0,
  );
  assert.equal(
    check([...rows, row("1.0.0.4")], [], { ipWhitelist: ["1.0.0.4"] }).length,
    0,
  );
  assert.equal(
    check([...rows, row("1.0.0.99")]).find((r) => r.code === "cn60").count,
    4,
  );
});
test("3.7.1 UA与云规则仅处理新请求；无时间窗口、成功状态和豁免", () => {
  const bad = row("3.0.0.1", now - 1000, 500, "");
  assert.equal(check([bad]).length, 0);
  assert.equal(check([], [bad]).length, 0);
  assert.equal(
    check([], [row("3.0.0.1", now - 1000, 302, "Browser")]).length,
    0,
  );
  assert.equal(
    check([], [row("3.0.0.1", now - 1000, 200, "Browser")])[0].code,
    "ua",
  );
  assert.equal(
    check([], [row("3.0.0.1", now - 1000, 200, "Browser")])[0].windowMinutes,
    null,
  );
  assert.equal(check([], [row("3.0.0.88")])[0].code, "cloud");
  assert.equal(check([], [row("3.0.0.88", now - 1000, 500)]).length, 0);
  assert.equal(check([], [bad], { ipWhitelist: [bad.ip] }).length, 0);
  assert.equal(
    check([], [row("3.0.0.99", now - 1000, 200, "bad")], {
      cloudflareExempt: true,
    }).length,
    0,
  );
  assert.equal(riskLevel([{ code: "cloud" }]), "suspicious");
  assert.equal(
    validateRules({ ...defaults, ownedIps: ["1.1.1.1"], uaHours: 1 }).ownedIps,
    undefined,
  );
  assert.equal(defaults.uaHours, undefined);
});
