import test from "node:test";
import assert from "node:assert/strict";
import { assess } from "../assessment.mjs";
import { defaults } from "../model.mjs";

test("自有节点排除且保存所有排除证据；同IP不同UA只计一个IP", () => {
  const now = Date.now();
  const rows = ["1", "2", "3", "4", "5", "6", "7"].map((n) => ({
    ts: now - 1000,
    ip: `192.0.2.${n}`,
    ua: "NetFlow/android",
    status: 200,
  }));
  rows.push({ ...rows[0], ua: "NetFlow/windows" });
  const db = { prepare: () => ({ all: () => rows }) };
  const rules = {
    ...defaults,
    ownedIps: ["192.0.2.6"],
    ipWhitelist: ["192.0.2.7"],
    ipLimit: 5,
  };
  const panel = { id: 1, rules: JSON.stringify(rules) };
  const subject = { uid: 1, dismissed: 0 };
  const geo = { lookup: () => ({ countryCode: "CN" }) };
  const result = assess(db, panel, subject, now, geo).find(
    (r) => r.code === "ip",
  );
  assert.equal(result.count, 5);
  assert.equal(result.accounting.totalIps, 7);
  assert.equal(result.accounting.totalRequests, 8);
  assert.equal(result.accounting.includedIps, 5);
  assert.equal(
    result.evidence.find((e) => e.ip === "192.0.2.6").exclusion,
    "自有节点",
  );
  assert.equal(
    result.evidence.find((e) => e.ip === "192.0.2.7").included,
    false,
  );
  panel.rules = JSON.stringify({
    ...rules,
    ownedIps: ["192.0.2.5", "192.0.2.6"],
  });
  assert.ok(!assess(db, panel, subject, now, geo).some((r) => r.code === "ip"));
  assert.equal(result.count, 5, "原评估快照保持原样");
  const rate = assess(db, panel, subject, now, geo).find(
    (r) => r.code === "rate",
  );
  assert.equal(rate.accounting.mergedRequests, 0, "完整UA不同不合并");
});
