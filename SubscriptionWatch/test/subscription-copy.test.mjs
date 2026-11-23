import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

// Exercise the shipped plain-script workflow without booting unrelated dashboard widgets.
const app = readFileSync(new URL("../public/app.js", import.meta.url), "utf8");
const workflow = app.slice(
  app.indexOf("function clearSubscriptionOriginLookup()"),
  app.indexOf("function editSubscriptionOrigin("),
);
function harness() {
  const state = {
    calls: [],
    copied: [],
    rendered: [],
    notices: [],
    selected: false,
    removed: 0,
    fallback: false,
    url: "https://sub.example.com/s/current-token",
    email: "customer@example.com",
    synced: true,
  };
  const elements = {
    "#subscriptionOriginLookupBox": { hidden: true },
    "#subscriptionOriginLookup": {
      replaceChildren() {
        state.rendered = [];
      },
    },
    "#subscriptionOriginLookup input": {
      select() {
        state.selected = true;
      },
    },
  };
  const context = vm.createContext({
    panelId: 1,
    tab: "subscriptionOrigins",
    subscriptionOriginLookupEpoch: 0,
    subscriptionOriginLookupRequest: 0,
    $: (selector) => elements[selector],
    navigator: {
      clipboard: { writeText: async (text) => state.copied.push(text) },
    },
    document: {
      activeElement: { focus() {} },
      body: { append() {} },
      execCommand: () => state.fallback,
      createElement: () => ({
        style: {},
        select() {},
        remove() {
          state.removed++;
        },
      }),
    },
    toast: (message) => state.notices.push(message),
    api: async (url, data) => {
      state.calls.push({ url, data });
      if (url.endsWith("/lookup"))
        return {
          user: { id: 7, email: state.email, subscribe_url: state.url },
          setting: null,
        };
      state.url = "http://changed.example.com:8080/s/new-token";
      return { ok: true, sync: { ok: state.synced, message: "saved" } };
    },
  });
  vm.runInContext(workflow, context);
  context.renderSubscriptionOriginResult = (result) => {
    state.rendered.push(result);
  };
  return { state, context, elements };
}

test("复制前实时获取当前完整链接，不复制旧域名或旧Token", async () => {
  const { state, context } = harness();
  await context.getSubscriptionOrigin("7", 1);
  assert.equal(state.copied.length, 0);
  state.url = "http://new.example.com:8080/custom/fresh-token?flag=clash";
  await context.getSubscriptionOrigin("7", 1, {
    email: state.email,
    copy: true,
  });
  assert.equal(state.calls.length, 2);
  assert.equal(state.copied[0], state.url);
  assert.equal(state.notices[0], "已复制客户当前订阅地址");
});

test("修改成功自动重新获取；待同步不展示旧查询结果；删除清除旧链接", async () => {
  const { state, context } = harness();
  await context.mutateSubscriptionOrigin(1, {
    uid: 7,
    email: state.email,
    origin: "http://changed.example.com:8080",
  });
  assert.equal(state.calls.length, 2);
  assert.equal(state.rendered[0].user.subscribe_url, state.url);
  assert.equal(
    state.copied.length,
    0,
    "saving does not overwrite the user's clipboard",
  );
  state.synced = false;
  await context.mutateSubscriptionOrigin(1, { uid: 7, email: state.email });
  assert.equal(state.calls.length, 3);
  assert.equal(state.rendered.length, 0);
  await context.mutateSubscriptionOrigin(
    1,
    { uid: 7, email: state.email },
    "delete",
  );
  assert.ok(state.calls.at(-1).url.endsWith("/delete"));
  assert.equal(state.rendered.length, 0);
});

test("面板切换、后发查询和再次修改阻止过期响应覆盖或复制", async () => {
  const { state, context } = harness();
  const pending = [];
  context.api = () => new Promise((resolve) => pending.push(resolve));
  const reply = {
    user: { id: 7, email: state.email, subscribe_url: state.url },
  };
  const first = context.getSubscriptionOrigin("7", 1, { copy: true });
  context.panelId = 2;
  pending.shift()(reply);
  assert.equal(await first, null);
  assert.equal(state.copied.length, 0);
  context.panelId = 1;
  const old = context.getSubscriptionOrigin("7", 1, { copy: true });
  const latest = context.getSubscriptionOrigin("7", 1);
  pending[1](reply);
  await latest;
  pending[0](reply);
  assert.equal(await old, null);
  assert.equal(state.copied.length, 0);
  pending.length = 0;
  const inFlight = context.getSubscriptionOrigin("7", 1, { copy: true });
  context.clearSubscriptionOriginLookup();
  pending[0](reply);
  assert.equal(await inFlight, null);
  assert.equal(state.rendered.length, 0);
});

test("客户身份变化和复制权限失败不误报成功，支持手动复制", async () => {
  const { state, context } = harness();
  state.email = "changed@example.com";
  await assert.rejects(
    context.getSubscriptionOrigin("7", 1, {
      email: "customer@example.com",
      copy: true,
    }),
    /客户资料已变化/,
  );
  assert.equal(state.copied.length, 0);
  context.navigator.clipboard.writeText = async () => {
    throw Error("permission denied");
  };
  await assert.rejects(
    context.getSubscriptionOrigin("7", 1, { copy: true }),
    /请手动复制/,
  );
  assert.equal(state.selected, true);
  assert.equal(state.removed, 1);
  assert.equal(state.notices.length, 0);
  state.fallback = true;
  await context.getSubscriptionOrigin("7", 1, { copy: true });
  assert.equal(state.notices.length, 1);
});
