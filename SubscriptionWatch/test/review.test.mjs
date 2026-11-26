import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createApp } from "../server.mjs";
import { validateRules } from "../model.mjs";
import { refreshDomain } from "../whitelist.mjs";
import { resolveRisk } from "../risk.mjs";
import { requestCounts } from "../review.mjs";
import { collectBlacklistedIPs, configureBlacklist } from "../blacklist.mjs";

test("非指定UA只拦截不标记；地域、云服务器及黑名单仍按规则标记", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "watch-review-"));
  const app = createApp({
    dataDir: dir,
    secureCookie: false,
    background: false,
  });
  const base = await new Promise((resolve) =>
    app.admin.listen(0, "127.0.0.1", () =>
      resolve(`http://127.0.0.1:${app.admin.address().port}`),
    ),
  );
  const post = (route, data, cookie = "") =>
    fetch(base + route, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Watch-Request": "1",
        Cookie: cookie,
      },
      body: JSON.stringify(data),
    });
  try {
    const setup = await post("/api/setup", {
      username: "owner",
      password: "test-password",
      confirmPassword: "test-password",
    });
    assert.equal(setup.status, 200);
    const cookie = setup.headers.get("set-cookie").split(";")[0];
    const created = await (
      await post("/api/panels", { name: "Panel" }, cookie)
    ).json();
    const key = await (
      await post(`/api/panels/${created.id}/key`, {}, cookie)
    ).json();
    const id = created.id;
    const panel = app.db.prepare("SELECT * FROM panels WHERE id=?").get(id);
    const rules = JSON.parse(panel.rules);
    // Preserve the original per-request quota cases; enabled dedupe has its own integration coverage.
    rules.requestDedupeMinutes = 0;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), id);
    const review = async (data, valid = true) => {
      const body = JSON.stringify({
        schema: 1,
        event_id: randomBytes(16).toString("hex"),
        ts: Date.now(),
        user_id: 42,
        email: "user@example.com",
        ip: "8.8.8.8",
        ua: "browser",
        ...data,
      });
      const timestamp = String(Math.floor(Date.now() / 1000));
      const signature = createHmac("sha256", key.collectorKey)
        .update(timestamp + "\n" + body)
        .digest("hex");
      const response = await fetch(base + "/api/collector/review", {
        method: "POST",
        headers: {
          "X-Watch-Panel": key.publicId,
          "X-Watch-Timestamp": timestamp,
          "X-Watch-Signature": valid ? signature : "0".repeat(64),
        },
        body,
      });
      const raw = await response.text();
      if (response.status === 200)
        assert.equal(
          response.headers.get("x-watch-decision-signature"),
          createHmac("sha256", key.collectorKey).update(raw).digest("hex"),
        );
      return { response, result: JSON.parse(raw) };
    };
    const reportDenial = async (eventId, status = 403, event = {}) => {
      const body = JSON.stringify({
        schema: 1,
        version: "4.0.1",
        metrics: { pending: 0, dropped: 0, expired: 0 },
        events: [
          {
            event_id: eventId,
            ts: Date.now(),
            user_id: 42,
            email: "user@example.com",
            ip: "8.8.8.8",
            peer_ip: "127.0.0.1",
            ip_source: "trusted_proxy",
            ua: "browser",
            flag: "",
            status,
            ms: 1,
            bytes: status === 200 ? 10 : 0,
            delivered: status === 200,
            ...event,
          },
        ],
      });
      const timestamp = String(Math.floor(Date.now() / 1000));
      const response = await fetch(base + "/api/collector/events", {
        method: "POST",
        headers: {
          "X-Watch-Panel": key.publicId,
          "X-Watch-Timestamp": timestamp,
          "X-Watch-Signature": createHmac("sha256", key.collectorKey)
            .update(timestamp + "\n" + body)
            .digest("hex"),
        },
        body,
      });
      assert.equal(response.status, 200, await response.text());
    };
    assert.equal((await review({}, false)).response.status, 401);
    const firstId = randomBytes(16).toString("hex");
    assert.deepEqual((await review({ event_id: firstId })).result.codes, [
      "ua",
    ]);
    assert.deepEqual((await review({ event_id: firstId })).result.codes, [
      "ua",
    ]);
    const second = (await review({})).result;
    assert.equal(second.allow, false);
    assert.equal(
      app.db
        .prepare("SELECT active FROM risks WHERE panel=? AND uid=42")
        .get(id),
      undefined,
    );
    const third = (await review({})).result;
    assert.equal(third.allow, false);
    await reportDenial(firstId, 302);
    const savedVisit = app.db
      .prepare("SELECT review_reasons FROM visits WHERE panel=? AND event_id=?")
      .get(id, firstId);
    assert.deepEqual(JSON.parse(savedVisit.review_reasons), [
      "非指定客户端获取订阅",
    ]);
    const accessRows = await (
      await fetch(base + `/api/panels/${id}/events?uid=42`, {
        headers: { Cookie: cookie },
      })
    ).json();
    assert.equal(accessRows.rows[0].review_blocked, 1);
    assert.equal(accessRows.rows[0].currentUser.suspicious, false);
    assert.ok(accessRows.rows[0].currentUser.dailyCount >= 1);
    await reportDenial(second.event_id, 503);
    assert.equal(
      app.db
        .prepare("SELECT active FROM risks WHERE panel=? AND uid=42")
        .get(id),
      undefined,
    );
    await reportDenial(second.event_id);
    await reportDenial(third.event_id);
    const fourth = (await review({})).result;
    await reportDenial(fourth.event_id);
    assert.equal(
      app.db
        .prepare("SELECT active FROM risks WHERE panel=? AND uid=42")
        .get(id),
      undefined,
    );
    assert.equal(
      app.db
        .prepare("SELECT COUNT(*) n FROM subjects WHERE panel=? AND uid=42")
        .get(id).n,
      1,
    );
    assert.equal(
      app.db
        .prepare(
          "SELECT COUNT(*) n FROM review_decisions WHERE panel=? AND denied=1",
        )
        .get(id).n,
      4,
    );
    assert.equal((await review({ ua: "Shadowrocket/1" })).result.allow, true);
    app.db
      .prepare("INSERT INTO subjects(panel,uid,email,white) VALUES(?,?,?,1)")
      .run(id, 99, "white@example.com");
    assert.equal(
      (await review({ user_id: 99, email: "white@example.com" })).result.allow,
      true,
    );
    app.geo.lookup = (ip) => ({
      countryCode: ip.startsWith("1.") ? "CN" : "US",
      organization: "ISP",
    });
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), id);
    for (const ip of ["1.0.0.1", "1.0.0.2", "1.0.0.3"])
      app.db
        .prepare(
          "INSERT INTO samples(panel,uid,ts,ip,ua,status,delivered) VALUES(?,?,?,?,?,200,1)",
        )
        .run(id, 88, Date.now(), ip, "Shadowrocket");
    assert.equal(
      (await review({ user_id: 88, ip: "1.0.0.3", ua: "Shadowrocket" })).result
        .allow,
      true,
    );
    assert.deepEqual(
      (await review({ user_id: 88, ip: "1.0.0.4", ua: "Shadowrocket" })).result
        .codes,
      ["cn60"],
    );
    for (const ip of ["1.0.0.1", "1.0.0.2", "1.0.0.3"])
      assert.equal(
        (await review({ user_id: 77, ip, ua: "Shadowrocket" })).result.allow,
        true,
      );
    assert.deepEqual(
      (await review({ user_id: 77, ip: "1.0.0.4", ua: "Shadowrocket" })).result
        .codes,
      ["cn60"],
    );
    rules.ipWhitelist = ["1.0.0.5"];
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), id);
    const activeReview = (
      await review({ user_id: 88, ip: "1.0.0.5", ua: "Shadowrocket" })
    ).result;
    assert.deepEqual(activeReview.codes, []);
    await reportDenial(activeReview.event_id, 200, {
      user_id: 88,
      ip: "1.0.0.5",
      ua: "Shadowrocket",
    });
    assert.equal(
      app.db
        .prepare(
          "SELECT ip_whitelisted FROM visits WHERE panel=? AND event_id=?",
        )
        .get(id, activeReview.event_id).ip_whitelisted,
      1,
    );
    const whitelistedVisits = await (
      await fetch(base + `/api/panels/${id}/events?uid=88`, {
        headers: { Cookie: cookie },
      })
    ).json();
    assert.equal(whitelistedVisits.rows[0].ip_whitelisted, 1);
    assert.equal(
      app.db
        .prepare(
          "SELECT reason_labels FROM review_decisions WHERE panel=? AND event_id=?",
        )
        .get(id, activeReview.event_id).reason_labels,
      "[]",
    );
    app.geo.lookup = (ip) => ({
      countryCode: ip.startsWith("1.") ? "CN" : "US",
      organization: ip.startsWith("3.") ? "Amazon Inc." : "ISP",
    });
    for (let n = 1; n <= 2; n++) {
      const cloud = (
        await review({ user_id: 90, ip: "3.0.0.88", ua: "Shadowrocket/1" })
      ).result;
      assert.deepEqual(cloud.codes, ["cloud"]);
      assert.equal(
        app.db
          .prepare("SELECT active FROM risks WHERE panel=? AND uid=90")
          .get(id),
        undefined,
      );
    }
    const thirdCloud = (
      await review({ user_id: 90, ip: "3.0.0.88", ua: "Shadowrocket/1" })
    ).result;
    assert.deepEqual(thirdCloud.codes, ["cloud"]);
    const cloudReason = JSON.parse(
      app.db
        .prepare("SELECT reasons FROM risks WHERE panel=? AND uid=90")
        .get(id).reasons,
    ).find((entry) => entry.code === "cloudShort");
    assert.equal(cloudReason.count, 3);
    assert.equal(cloudReason.evidence.length, 3);
    for (const ip of ["8.0.0.1", "8.0.0.2", "8.0.0.3"])
      assert.equal(
        (await review({ user_id: 93, ip, ua: "Shadowrocket/1" })).result.allow,
        true,
      );
    assert.deepEqual(
      (await review({ user_id: 93, ip: "8.0.0.4", ua: "Shadowrocket/1" }))
        .result.codes,
      ["foreign60"],
    );
    app.db
      .prepare(
        "INSERT INTO ip_blacklist(ip,source_panel,source_name,source_uid,source_email,source_ts,added,expires,removed_at) VALUES(?,?,?,?,?,?,?,?,0)",
      )
      .run(
        "5.0.0.1",
        id,
        "Panel",
        88,
        "source@example.com",
        Date.now(),
        Date.now(),
        Date.now() + 86400000,
      );
    assert.equal(
      (await review({ user_id: 94, ip: "5.0.0.1", ua: "Shadowrocket/1" }))
        .result.allow,
      true,
    );
    rules.reviewBlockBlacklist = true;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), id);
    assert.deepEqual(
      (await review({ user_id: 94, ip: "5.0.0.1", ua: "Shadowrocket/1" }))
        .result.codes,
      ["blacklist"],
    );
    rules.dailyLimit = 2;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(rules), id);
    assert.equal(
      (await review({ user_id: 91, ua: "Shadowrocket/1" })).result.allow,
      true,
    );
    assert.equal(
      (await review({ user_id: 91, ua: "Shadowrocket/1" })).result.allow,
      true,
    );
    assert.deepEqual(
      (await review({ user_id: 91, ua: "Shadowrocket/1" })).result.codes,
      ["daily-limit"],
    );
    assert.equal(
      app.db
        .prepare("SELECT active FROM risks WHERE panel=? AND uid=91")
        .get(id),
      undefined,
    );
    app.db
      .prepare(
        "INSERT INTO risks(panel,uid,active,started,updated,reasons) VALUES(?,?,1,?,?,?)",
      )
      .run(
        id,
        91,
        Date.now(),
        Date.now(),
        JSON.stringify([
          { code: "cloudShort", label: "云服务器 IP 频繁获取订阅" },
        ]),
      );
    const previousRequests = app.db
      .prepare(
        "SELECT COUNT(*) n FROM review_decisions WHERE panel=? AND uid=91",
      )
      .get(id).n;
    resolveRisk(app.db, id, 91, { resetDaily: true });
    assert.ok(
      app.db
        .prepare("SELECT daily_reset_at FROM subjects WHERE panel=? AND uid=91")
        .get(id).daily_reset_at > 0,
    );
    assert.equal(
      app.db
        .prepare(
          "SELECT COUNT(*) n FROM review_decisions WHERE panel=? AND uid=91",
        )
        .get(id).n,
      previousRequests,
    );
    assert.equal(
      (await review({ user_id: 91, ua: "Shadowrocket/1" })).result.allow,
      true,
    );
    assert.equal(
      (await review({ user_id: 91, ua: "Shadowrocket/1" })).result.allow,
      true,
    );
    assert.deepEqual(
      (await review({ user_id: 91, ua: "Shadowrocket/1" })).result.codes,
      ["daily-limit"],
    );
    assert.equal(
      (
        await review({
          user_id: 92,
          email: "normal@example.com",
          ua: "Shadowrocket/1",
        })
      ).result.allow,
      true,
    );
    const normalStatus = await (
      await fetch(base + `/api/panels/${id}/client-status?q=92`, {
        headers: { Cookie: cookie },
      })
    ).json();
    assert.equal(normalStatus.rows[0].suspicious, false);
    assert.equal(normalStatus.rows[0].dailyCount, 1);
    assert.equal(normalStatus.rows[0].nextRequestNumber, 2);
    const statusRoute = `/api/panels/${id}/client-status?q=91`;
    const beforeReset = await (
      await fetch(base + statusRoute, { headers: { Cookie: cookie } })
    ).json();
    assert.equal(beforeReset.rows[0].dailyCount, 3);
    assert.equal(beforeReset.rows[0].dailyLimitReached, true);
    assert.equal(beforeReset.rows[0].nextRequestNumber, 4);
    const oldDecisions = app.db
      .prepare(
        "SELECT COUNT(*) n FROM review_decisions WHERE panel=? AND uid=91",
      )
      .get(id).n;
    assert.equal(
      (
        await post(
          `/api/panels/${id}/client-status/reset`,
          {
            uid: 91,
            email: "wrong@example.com",
            confirm: true,
          },
          cookie,
        )
      ).status,
      400,
    );
    assert.equal(
      (
        await post(
          `/api/panels/${id}/client-status/reset`,
          {
            uid: 91,
            email: "user@example.com",
            confirm: true,
          },
          cookie,
        )
      ).status,
      200,
    );
    const afterReset = await (
      await fetch(base + statusRoute, { headers: { Cookie: cookie } })
    ).json();
    assert.equal(afterReset.rows[0].dailyCount, 0);
    assert.equal(afterReset.rows[0].nextRequestNumber, 1);
    assert.equal(afterReset.rows[0].dailyLimitReached, false);
    assert.equal(
      app.db
        .prepare(
          "SELECT COUNT(*) n FROM review_decisions WHERE panel=? AND uid=91",
        )
        .get(id).n,
      oldDecisions,
    );
    assert.equal(
      (await review({ user_id: 91, ua: "Shadowrocket/1" })).result.allow,
      true,
    );
    app.db
      .prepare(
        "INSERT INTO risks(panel,uid,active,started,updated,reasons) VALUES(?,?,1,?,?,?) ON CONFLICT(panel,uid) DO UPDATE SET active=1,reasons=excluded.reasons",
      )
      .run(
        id,
        91,
        Date.now(),
        Date.now(),
        JSON.stringify([
          { code: "cloudShort", label: "云服务器 IP 频繁获取订阅" },
        ]),
      );
    assert.equal(
      (
        await post(
          `/api/panels/${id}/client-status/reset`,
          {
            uid: 91,
            email: "user@example.com",
            confirm: true,
          },
          cookie,
        )
      ).status,
      200,
    );
    const stillSuspicious = await (
      await fetch(base + statusRoute, { headers: { Cookie: cookie } })
    ).json();
    assert.equal(stillSuspicious.rows[0].suspicious, true);
    assert.equal(stillSuspicious.rows[0].dailyCount, 0);
    const validated = validateRules({
      ...rules,
      mainlandOnly: true,
      dailyLimit: 30,
      ipWhitelist: ["8.0.0.8", "Exit.Example"],
      ipWhitelistNotes: { "Exit.Example": "海外备用出口" },
    });
    assert.deepEqual(validated.ipWhitelist, ["8.0.0.8", "exit.example"]);
    assert.equal(validated.ipWhitelistNotes["exit.example"], "海外备用出口");
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    app.geo.lookup = (ip) => ({
      countryCode: ip.startsWith("1.")
        ? "CN"
        : ip.startsWith("6.")
          ? null
          : "US",
      organization:
        ip === "7.0.0.7"
          ? "Cloudflare"
          : ip.startsWith("3.")
            ? "Alibaba"
            : "ISP",
    });
    assert.deepEqual(
      (await review({ user_id: 100, ip: "8.0.0.1", ua: "Shadowrocket" })).result
        .codes,
      ["mainland-only"],
    );
    const foreignBrowser = (
      await review({ user_id: 106, ip: "8.0.0.1", ua: "Chrome" })
    ).result;
    assert.equal(foreignBrowser.allow, false);
    assert.deepEqual(foreignBrowser.codes, ["mainland-only", "ua"]);
    const unknownRegion = (
      await review({ user_id: 107, ip: "6.0.0.1", ua: "Shadowrocket" })
    ).result;
    assert.equal(unknownRegion.allow, false);
    assert.deepEqual(unknownRegion.codes, ["mainland-only"]);
    app.db
      .prepare(
        "INSERT INTO risks(panel,uid,active,started,updated,reasons) VALUES(?,?,1,?,?,?)",
      )
      .run(
        id,
        108,
        Date.now(),
        Date.now(),
        JSON.stringify([{ code: "cn60", label: "多个中国大陆 IP 获取订阅" }]),
      );
    const multipleReasons = (
      await review({ user_id: 108, ip: "3.0.0.8", ua: "Chrome" })
    ).result;
    assert.deepEqual(multipleReasons.codes, [
      "mainland-only",
      "active-risk",
      "ua",
      "cloud",
    ]);
    assert.deepEqual(
      JSON.parse(
        app.db
          .prepare(
            "SELECT reason_labels FROM review_decisions WHERE panel=? AND event_id=?",
          )
          .get(id, multipleReasons.event_id).reason_labels,
      ),
      [
        "来源 IP 不在中国大陆或白名单",
        "已有可疑标记（原触发：多个中国大陆 IP 获取订阅）",
        "非指定客户端获取订阅",
        "云服务器 IP 获取订阅",
      ],
    );
    validated.blockSuspiciousUsers = false;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    const suspiciousButAllowed = (
      await review({ user_id: 108, ip: "1.0.0.9", ua: "Shadowrocket" })
    ).result;
    assert.equal(suspiciousButAllowed.allow, true);
    assert.deepEqual(suspiciousButAllowed.codes, []);
    const suspiciousWithOtherRules = (
      await review({ user_id: 108, ip: "3.0.0.8", ua: "Chrome" })
    ).result;
    assert.equal(suspiciousWithOtherRules.allow, false);
    assert.deepEqual(suspiciousWithOtherRules.codes, [
      "mainland-only",
      "ua",
      "cloud",
    ]);
    validated.blockSuspiciousUsers = true;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    assert.deepEqual(
      (await review({ user_id: 108, ip: "1.0.0.9", ua: "Shadowrocket" })).result
        .codes,
      ["active-risk"],
    );
    assert.equal(
      (await review({ user_id: 100, ip: "1.0.0.9", ua: "Shadowrocket" })).result
        .allow,
      true,
    );
    assert.deepEqual(
      (await review({ user_id: 101, ip: "1.0.0.9", ua: "Chrome" })).result
        .codes,
      ["ua"],
    );
    assert.deepEqual(
      (await review({ user_id: 99, email: "white@example.com", ip: "8.0.0.2" }))
        .result.codes,
      [],
    );
    validated.cloudflareExempt = true;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    assert.deepEqual(
      (await review({ user_id: 102, ip: "7.0.0.7", ua: "Shadowrocket" })).result
        .codes,
      [],
    );
    assert.deepEqual(
      (await review({ user_id: 109, ip: "7.0.0.7", ua: "Chrome" })).result
        .codes,
      ["ua"],
    );
    // CF skips other rules while preserving UA enforcement and request accounting.
    validated.dcKeywords = [...validated.dcKeywords, "cloudflare"];
    validated.reviewBlockBlacklist = true;
    validated.dailyLimit = 2;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    configureBlacklist(app.db, { enabled: true, recording: true, days: 7 });
    collectBlacklistedIPs(
      app.db,
      panel,
      111,
      [{ ip: "7.0.0.7", ts: Date.now() - 2000 }],
      Date.now() - 1000,
    );
    assert.equal(
      app.db
        .prepare("SELECT COUNT(*) n FROM ip_blacklist WHERE ip=?")
        .get("7.0.0.7").n,
      1,
    );
    app.db
      .prepare(
        "INSERT INTO risks(panel,uid,active,started,updated,reasons) VALUES(?,?,1,?,?,?)",
      )
      .run(
        id,
        111,
        Date.now(),
        Date.now(),
        JSON.stringify([{ code: "cn60", label: "多个中国大陆 IP 获取订阅" }]),
      );
    const cfAllowed = (
      await review({ user_id: 111, ip: "7.0.0.7", ua: "Shadowrocket" })
    ).result;
    assert.equal(cfAllowed.allow, true);
    assert.deepEqual(cfAllowed.codes, []);
    await reportDenial(cfAllowed.event_id, 200, {
      user_id: 111,
      ip: "7.0.0.7",
      ua: "Shadowrocket",
    });
    assert.equal(requestCounts(app.db, id, 111, Date.now()).total, 1);
    const cfBrowser = (
      await review({ user_id: 111, ip: "7.0.0.7", ua: "Chrome" })
    ).result;
    assert.equal(cfBrowser.allow, false);
    assert.deepEqual(cfBrowser.codes, ["ua"]);
    assert.ok(cfBrowser.redirect);
    await reportDenial(cfBrowser.event_id, 302, {
      user_id: 111,
      ip: "7.0.0.7",
      ua: "Chrome",
    });
    assert.equal(requestCounts(app.db, id, 111, Date.now()).total, 2);
    assert.equal(requestCounts(app.db, id, 111, Date.now()).ipWhitelist, 0);
    assert.deepEqual(
      (await review({ user_id: 111, ip: "7.0.0.7", ua: "Shadowrocket" })).result
        .codes,
      ["daily-limit"],
    );
    assert.deepEqual(
      (await review({ user_id: 111, ip: "7.0.0.7", ua: "Chrome" })).result
        .codes,
      ["daily-limit", "ua"],
    );
    assert.equal(
      app.db
        .prepare("SELECT active FROM risks WHERE panel=? AND uid=111")
        .get(id).active,
      1,
    );
    validated.cloudflareExempt = false;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    const cfNotExempt = (
      await review({ user_id: 110, ip: "7.0.0.7", ua: "Chrome" })
    ).result;
    assert.ok(cfNotExempt.codes.includes("mainland-only"));
    assert.ok(cfNotExempt.codes.includes("ua"));
    assert.ok(cfNotExempt.codes.includes("cloud"));
    assert.ok(cfNotExempt.codes.includes("blacklist"));
    validated.cloudflareExempt = true;
    validated.dailyLimit = 30;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    assert.equal(
      (await review({ user_id: 103, ip: "8.0.0.8", ua: "Chrome" })).result
        .allow,
      true,
    );
    validated.dailyLimit = 1;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    app.db
      .prepare(
        "INSERT INTO risks(panel,uid,active,started,updated,reasons) VALUES(?,?,1,?,?,?)",
      )
      .run(
        id,
        103,
        Date.now(),
        Date.now(),
        JSON.stringify([
          { code: "cloudShort", label: "云服务器 IP 频繁获取订阅" },
        ]),
      );
    assert.deepEqual(
      (await review({ user_id: 103, ip: "8.0.0.8", ua: "Chrome" })).result
        .codes,
      [],
    );
    assert.deepEqual(
      (
        await review({
          user_id: 99,
          email: "white@example.com",
          ip: "8.0.0.2",
          ua: "Chrome",
        })
      ).result.codes,
      [],
    );
    validated.dailyLimit = 30;
    app.db
      .prepare("UPDATE panels SET rules=? WHERE id=?")
      .run(JSON.stringify(validated), id);
    await refreshDomain("exit.example", {
      resolve4: async () => ["9.0.0.9"],
      resolve6: async () => {
        throw Error("no IPv6");
      },
    });
    assert.equal(
      (await review({ user_id: 104, ip: "9.0.0.9", ua: "Chrome" })).result
        .allow,
      true,
    );
    await refreshDomain("exit.example", {
      resolve4: async () => {
        throw Error("DNS unavailable");
      },
      resolve6: async () => {
        throw Error("DNS unavailable");
      },
    });
    assert.deepEqual(
      (await review({ user_id: 105, ip: "9.0.0.9", ua: "Shadowrocket" })).result
        .codes,
      ["mainland-only"],
    );
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
