import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createUpdates } from "../crates/grok-build-tauri/ui/modules/updates.js";

function fixture(respond) {
  const calls = [];
  const current = { queue: { available: true, activeGlobalRuns: 0, items: [] }, account: {
    selectedTransport: "GrokCliAcp", engine: { schemaVersion: 1, mode: "grokCliStandard", developerCli: null },
  } };
  const created = [];
  const ownerDocument = { createElement(tag) {
    const node = { tag, attributes: {}, setAttribute(key, value) { this.attributes[key] = value; }, addEventListener(_, callback) { this.click = callback; } };
    created.push(node); return node;
  } };
  const button = { ownerDocument, disabled: true, attributes: {}, setAttribute(key, value) { this.attributes[key] = value; }, addEventListener(_, callback) { this.click = callback; } };
  const version = { textContent: "Grok CLI" };
  const status = { textContent: "", after(...nodes) { this.following = nodes; } };
  let busy = false;
  let snapshots = 0;
  const controller = createUpdates({
    invoke: async (method, args) => {
      calls.push({ method, args });
      if (respond) return respond(method, args);
      if (method === "set_engine_settings") return { ...current, account: { ...current.account, engine: args.settings } };
      return method === "bootstrap" ? current : { version: "1.0.30", detail: "Grok CLI is up to date." };
    },
    elements: { updateGrokCli: button, accountCliVersion: version, grokCliCompatibility: status },
    getSnapshot: () => current, getBusy: () => busy,
    setAccountBusy: value => { busy = value; },
    onSnapshot: value => { Object.assign(current, value); snapshots += 1; controller.render(); },
  });
  controller.render();
  return { controller, button, version, status, current, calls, switchButton: created[0], engineDetail: created[1], snapshots: () => snapshots, busy: () => busy, setBusy: value => { busy = value; } };
}

test("Account exposes one update button outside connection disclosures", () => {
  const html = readFileSync(new URL("../crates/grok-build-tauri/ui/index.html", import.meta.url), "utf8");
  const account = html.slice(html.indexOf('<h1 id="account-title">'));
  assert.equal((html.match(/id="update-grok-cli"/g) || []).length, 1);
  assert.ok(account.indexOf('id="update-grok-cli"') < account.indexOf('class="account-advanced"'));
  assert.match(account, /id="grok-cli-compatibility" role="status" aria-live="polite"/);
  assert.match(account, /aria-describedby="grok-cli-compatibility"/);
});

test("opening Account reads the installed version without updating or connecting", async () => {
  const f = fixture();
  await f.controller.refresh();
  assert.equal(f.version.textContent, "Grok CLI 1.0.30");
  assert.deepEqual(f.calls.map(call => call.method), ["inspect_grok_cli"]);
  assert.equal(f.button.disabled, false);
});

test("Update invokes once, announces progress, refreshes connection state and retains the result", async () => {
  let finish;
  const result = new Promise(resolve => { finish = resolve; });
  const f = fixture(method => method === "update_grok_cli" ? result : {});
  const updating = f.button.click();
  assert.equal(f.button.textContent, "Updating…");
  assert.equal(f.button.attributes["aria-busy"], "true");
  assert.equal(f.busy(), true);
  await f.button.click();
  await f.controller.refresh();
  assert.deepEqual(f.calls.map(call => call.method), ["update_grok_cli"]);
  finish({ version: "2.0.0", detail: "Updated from 1.0.30 to 2.0.0." });
  await updating;
  assert.equal(f.version.textContent, "Grok CLI 2.0.0");
  assert.match(f.status.textContent, /Updated from 1\.0\.30 to 2\.0\.0/);
  assert.match(f.status.textContent, /Choose Connect to reconnect/);
  assert.equal(f.snapshots(), 1);
  assert.equal(f.button.disabled, false);
  assert.equal(f.busy(), false);
  assert.equal(f.button.attributes["aria-busy"], "false");
  f.controller.render();
  assert.match(f.status.textContent, /Updated from/);
});

test("active runs anywhere and unavailable queues prevent Update", async () => {
  const f = fixture();
  f.current.queue.activeGlobalRuns = 1;
  await f.button.click();
  assert.match(f.status.textContent, /Finish or stop chats/);
  f.current.queue.activeGlobalRuns = 0;
  f.current.queue.available = false;
  await f.button.click();
  assert.equal(f.calls.length, 0);
  f.current.queue.available = true;
  f.setBusy(true);
  await f.button.click();
  assert.equal(f.calls.length, 0);
});

test("failed updates refresh disconnected state and permit a deliberate retry", async () => {
  const f = fixture(method => {
    if (method === "update_grok_cli") throw new Error("fixture updater failed");
    return {};
  });
  await f.button.click();
  assert.match(f.status.textContent, /Update failed.*fixture updater failed/);
  assert.equal(f.snapshots(), 1);
  assert.equal(f.button.disabled, false);
  assert.equal(f.busy(), false);
  await f.button.click();
  assert.equal(f.calls.filter(call => call.method === "update_grok_cli").length, 2);
});

test("a failed version read does not invent a version or stop retries", async () => {
  const f = fixture(() => { throw new Error("version unavailable"); });
  await f.controller.refresh();
  assert.equal(f.version.textContent, "Grok CLI · version unavailable");
  assert.equal(f.button.disabled, false);
  await f.button.click();
  assert.match(f.status.textContent, /Update failed/);
  assert.match(f.status.textContent, /Reopen Account/);
  assert.equal(f.button.disabled, false);
});

test("version inspection cannot overwrite an overlapping update result", async () => {
  let finish;
  const f = fixture(() => new Promise(resolve => { finish = resolve; }));
  const refreshing = f.controller.refresh();
  await f.button.click();
  assert.deepEqual(f.calls.map(call => call.method), ["inspect_grok_cli"]);
  finish({ version: "1.0.30" });
  await refreshing;
  assert.equal(f.button.disabled, false);
});

test("API transport stays independent and provider strings are rendered only as text", async () => {
  const detail = '<img src=x onerror="unexpected()">';
  const f = fixture(method => method === "bootstrap" ? {} : { version: "1.0.30", detail });
  f.current.account.selectedTransport = "XaiKeychain";
  await f.button.click();
  assert.equal(f.status.textContent, detail);
  assert.equal("innerHTML" in f.status, false);
  assert.equal(f.calls.some(call => call.method.includes("connect")), false);
});

test("updated contained connection offers an explicit standard switch without connecting or replaying work", async () => {
  const f = fixture();
  f.current.account.engine.mode = "gbPlusContained";
  await f.controller.refresh();
  assert.equal(f.switchButton.hidden, false);
  assert.equal(f.switchButton.disabled, false);
  assert.match(f.engineDetail.textContent, /commands run on your Mac/);
  assert.match(f.switchButton.attributes["aria-describedby"], /grok-cli-engine-detail/);
  assert.deepEqual(f.calls.map(call => call.method), ["inspect_grok_cli"]);
  await f.switchButton.click();
  assert.equal(f.current.account.engine.mode, "grokCliStandard");
  assert.equal(f.switchButton.hidden, true);
  assert.match(f.status.textContent, /Choose Connect when ready/);
  assert.deepEqual(f.calls.map(call => call.method), ["inspect_grok_cli", "set_engine_settings"]);
  assert.deepEqual(f.calls[1].args.settings, { schemaVersion: 1, mode: "grokCliStandard", developerCli: null });
});

test("a CLI update in contained mode reports the required switch, not a reconnect that will fail", async () => {
  const f = fixture(method => method === "bootstrap" ? {} : {
    version: "1.0.41", detail: "Updated from 1.0.25 to 1.0.41.",
  });
  f.current.account.engine.mode = "gbPlusContained";
  await f.button.click();
  assert.match(f.status.textContent, /Updated from 1\.0\.25 to 1\.0\.41/);
  assert.match(f.status.textContent, /Switch to standard to use CLI updates/);
  assert.doesNotMatch(f.status.textContent, /Choose Connect to reconnect/);
  assert.equal(f.switchButton.hidden, false);
  assert.equal(f.calls.some(call => call.method === "set_engine_settings"), false);
});

test("queued work, active work, missing queue state and busy operations prevent engine switching", async () => {
  for (const queue of [
    { available: false, activeGlobalRuns: 0 },
    { available: true, activeGlobalRuns: 1 },
    { available: true, activeGlobalRuns: 0, items: [{ state: "queued" }] },
    { available: true, activeGlobalRuns: 0, items: [{ state: "running" }] },
  ]) {
    const f = fixture();
    f.current.account.engine.mode = "gbPlusContained";
    f.current.queue = queue;
    await f.switchButton.click();
    assert.equal(f.calls.length, 0);
    assert.equal(f.switchButton.disabled, true);
  }
  const f = fixture();
  f.current.account.engine.mode = "gbPlusContained";
  f.setBusy(true);
  await f.switchButton.click();
  assert.equal(f.calls.length, 0);
});

test("a refused switch retains the engine and exposes the backend's reason", async () => {
  const f = fixture(() => { throw new Error("Finish or remove queued work before switching engines."); });
  f.current.account.engine.mode = "gbPlusContained";
  await f.switchButton.click();
  assert.match(f.status.textContent, /Finish or remove queued work/);
  assert.equal(f.current.account.engine.mode, "gbPlusContained");
  assert.equal(f.switchButton.disabled, false);
  assert.equal(f.busy(), false);
  assert.deepEqual(f.calls.map(call => call.method), ["set_engine_settings"]);
});
