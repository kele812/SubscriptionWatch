import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createApp } from "../server.mjs";
import { migrateRequestEvidence } from "../model.mjs";

test("旧访问记录保持反代核验状态未知", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(`CREATE TABLE visits(id INTEGER PRIMARY KEY,ip TEXT,ts INTEGER,proxy_ip TEXT,proxy_name TEXT);
      CREATE TABLE samples(id INTEGER PRIMARY KEY,proxy_ip TEXT,proxy_name TEXT);
      CREATE TABLE ip_blacklist(ip TEXT PRIMARY KEY);
      INSERT INTO visits(ip,ts,proxy_ip,proxy_name) VALUES('1.1.1.1',1,'198.51.100.10','旧标识');`);
    migrateRequestEvidence(db);
    assert.equal(db.prepare("SELECT proxy_verified FROM visits WHERE id=1").get().proxy_verified, null);
    assert.ok(db.prepare("PRAGMA table_info(samples)").all().some((c) => c.name === "proxy_verified"));
  } finally {
    db.close();
  }
});

test("新插件核验状态单独保存，未核验记录不能声明反代", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-proxy-state-"));
  const app = createApp({ dataDir: dir, secureCookie: false, background: false });
  const base = await new Promise((resolve) =>
    app.admin.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${app.admin.address().port}`)),
  );
  try {
    const password = randomBytes(16).toString("hex");
    const setup = await fetch(base + "/api/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Watch-Request": "1" },
      body: JSON.stringify({ username: "owner", password, confirmPassword: password }),
    });
    assert.equal(setup.status, 200);
    const cookie = setup.headers.get("set-cookie").split(";")[0];
    const api = async (route, body) => {
      const response = await fetch(base + route, {
        method: body === undefined ? "GET" : "POST",
        headers: { "Content-Type": "application/json", "X-Watch-Request": "1", Cookie: cookie },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      assert.equal(response.status, 200, await response.clone().text());
      return response.json();
    };
    const panel = await api("/api/panels", { name: "test" });
    const key = await api(`/api/panels/${panel.id}/key`, {});
    const send = async (event) => {
      const version = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
      const body = JSON.stringify({ schema: 1, version, metrics: { pending: 0, dropped: 0, expired: 0 }, events: [event] });
      const timestamp = String(Math.floor(Date.now() / 1000));
      return fetch(base + "/api/collector/events", {
        method: "POST",
        headers: {
          "X-Watch-Panel": key.publicId,
          "X-Watch-Timestamp": timestamp,
          "X-Watch-Signature": createHmac("sha256", key.collectorKey).update(timestamp + "\n" + body).digest("hex"),
        },
        body,
      });
    };
    const event = (fields = {}) => ({
      event_id: randomBytes(16).toString("hex"), ts: Date.now() - 1000,
      user_id: 1, email: "sample@example.com", ip: "1.1.1.1", peer_ip: "127.0.0.1",
      ip_source: "trusted_proxy", ua: "TestClient/1", flag: "", status: 200, ms: 1, bytes: null,
      ...fields,
    });
    assert.equal((await send(event({ proxy_ip: "198.51.100.10", proxy_name: "旧标识" }))).status, 200);
    assert.equal((await send(event({ proxy_ip: "198.51.100.10", proxy_name: "已核验", proxy_verified: true }))).status, 200);
    assert.equal((await send(event({ proxy_ip: null, proxy_name: null, proxy_verified: false }))).status, 200);
    assert.equal((await send(event({ proxy_ip: "198.51.100.10", proxy_name: "错误标识", proxy_verified: false }))).status, 422);
    const rows = (await api(`/api/panels/${panel.id}/events?uid=1`)).rows;
    assert.deepEqual(rows.map((row) => row.proxy_verified).sort(), [null, 0, 1].sort());
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
