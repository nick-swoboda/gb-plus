import assert from "node:assert/strict";
import test from "node:test";
import { textAttachments } from "../crates/grok-build-tauri/ui/modules/cli_input.js";
import { appendMarkdownTokens, highlightCode } from "../crates/grok-build-tauri/ui/modules/markdown.js";
import { createCliInteractionCards } from "../crates/grok-build-tauri/ui/modules/cli_interactions.js";
import { createCliChat, mergeCliTool } from "../crates/grok-build-tauri/ui/modules/cli_chat.js";
import { createCliBackground } from "../crates/grok-build-tauri/ui/modules/cli_background.js";
import { createCliModelPicker } from "../crates/grok-build-tauri/ui/modules/cli_models.js";

class Node {
  constructor(tag = "div", text = "") { this.tagName = tag.toUpperCase(); this.children = []; this.textContent = text; this.dataset = {}; this.style = {}; this.listeners = new Map(); this.open = false; }
  append(...nodes) { nodes.forEach(node => { if (node.tagName === "#FRAGMENT") this.append(...node.children); else { node.parentElement = this; this.children.push(node); } }); }
  prepend(...nodes) { nodes.forEach(node => { node.parentElement = this; }); this.children.unshift(...nodes); }
  before(...nodes) { nodes.forEach(node => { node.parentElement = this.parentElement; }); this.parentElement?.children.splice(this.parentElement.children.indexOf(this), 0, ...nodes); }
  after(...nodes) { nodes.forEach(node => { node.parentElement = this.parentElement; }); this.parentElement?.children.splice(this.parentElement.children.indexOf(this) + 1, 0, ...nodes); }
  get childNodes() { return this.children; }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  setAttribute(key, value) { this[key] = value; }
  addEventListener(key, callback) { this.listeners.set(key, callback); }
  querySelectorAll(tag) { const name = tag.split("[")[0].toUpperCase(); return this.children.flatMap(node => [...(node.tagName === name && (!tag.includes("[open]") || node.open) ? [node] : []), ...(node.querySelectorAll?.(tag) || [])]); }
  querySelector(tag) { return this.querySelectorAll(tag)[0] || null; }
  dispatchEvent(event) { this.listeners.get(event.type)?.(event); }
  focus() { document.activeElement = this; }
  showModal() { this.open = true; }
  close() { this.open = false; }
  showPopover() { this.open = true; this.dispatchEvent({type: "toggle"}); }
  hidePopover() { this.open = false; this.dispatchEvent({type: "toggle"}); }
  matches(selector) { return selector === ":popover-open" && this.open; }
  getBoundingClientRect() { return {left: 400, right: 600, top: 50, bottom: 82, width: 280, height: 240}; }
  click() { this.listeners.get("click")?.({ target: this, preventDefault() {} }); }
}
const flush = () => new Promise(resolve => setImmediate(resolve));
function documentFixture() { const old = globalThis.document; globalThis.document = { body: new Node("body"), documentElement: {clientWidth: 1040, clientHeight: 720}, createElement: tag => new Node(tag), createTextNode: text => new Node("#text", text), querySelector: () => null }; return () => { globalThis.document = old; }; }
function snapshot(project = "project-a", state = "running") { return { activeProjectId: project, engine: { mode: "grokCliStandard" }, queue: { runs: [{ id: "run-a", projectId: project, sessionId: `project-${project}`, state }] } }; }
const permission = { id: 7, sessionId: "native-a", kind: "permission", request: { toolCall: { title: "Edit fact.txt", kind: "edit", content: [{ type: "diff", path: "fact.txt", oldText: "before", newText: "after" }] }, options: [{ optionId: "native-yes", name: "Allow once", kind: "allow_once" }, { optionId: "native-no", name: "Reject", kind: "reject_once" }] } };

test("Accept displays the native diff and sends only the exact offered run-bound choice", async () => {
  const restore = documentFixture(); const calls = []; let current = snapshot();
  try {
    const cards = createCliInteractionCards({ invoke: async (method, args) => { calls.push({ method, args }); return method === "pending_cli_interactions" ? [] : undefined; }, getSnapshot: () => current, showToast: value => assert.fail(value) });
    cards.snapshot(current); await flush(); cards.update({ kind: "cli_interaction", payload: permission }, "run-a");
    const dialog = document.body.children[0]; assert.equal(dialog.open, true);
    assert.deepEqual(dialog.querySelectorAll("pre").map(node => node.textContent), ["before", "after"]);
    assert.equal(calls.filter(call => call.method === "answer_cli_interaction").length, 0);
    dialog.querySelectorAll("button").find(node => node.textContent === "Accept").click(); await flush();
    assert.deepEqual(calls.at(-1), { method: "answer_cli_interaction", args: { projectId: "project-a", runId: "run-a", interactionId: 7, answer: { kind: "permission", option_id: "native-yes" } } });
    assert.equal(dialog.open, false);
    current = snapshot("project-a", "done"); cards.snapshot(current); assert.equal(dialog.open, false);
  } finally { restore(); }
});

test("project switches and Stop dismiss stale cards without granting permission", async () => {
  const restore = documentFixture(); const calls = []; let current = snapshot();
  try {
    const cards = createCliInteractionCards({ invoke: async (method, args) => { calls.push({ method, args }); return []; }, getSnapshot: () => current, showToast: value => assert.fail(value) });
    cards.snapshot(current); await flush(); cards.update({ kind: "cli_interaction", payload: permission }, "run-a");
    current = snapshot("project-a", "stop_requested"); cards.snapshot(current); assert.equal(document.body.children[0].open, false);
    current = snapshot("project-b"); cards.snapshot(current); await flush();
    assert.equal(calls.some(call => call.method === "answer_cli_interaction"), false);
  } finally { restore(); }
});

test("Escape answers cancelled and never selects the first offered permission", async () => {
  const restore = documentFixture(); const calls = []; const current = snapshot();
  try {
    const cards = createCliInteractionCards({ invoke: async (method, args) => { calls.push({ method, args }); return []; }, getSnapshot: () => current, showToast: value => assert.fail(value) });
    cards.snapshot(current); await flush(); cards.update({ kind: "cli_interaction", payload: permission }, "run-a");
    document.body.children[0].listeners.get("cancel")({ preventDefault() {} }); await flush();
    assert.deepEqual(calls.at(-1).args.answer, { kind: "cancel" });
  } finally { restore(); }
});

test("native question cards send free text as notes and do not preselect answers", async () => {
  const restore = documentFixture(); const calls = []; const current = snapshot();
  try {
    const cards = createCliInteractionCards({ invoke: async (method, args) => { calls.push({ method, args }); return []; }, getSnapshot: () => current, showToast: value => assert.fail(value) });
    cards.snapshot(current); await flush();
    cards.update({ kind: "cli_interaction", payload: { id: 8, kind: "questions", request: { mode: "default", questions: [{ question: "Which color?", options: [{ label: "Blue", description: "Cool" }] }] } } }, "run-a");
    const dialog = document.body.children[0]; assert.equal(Boolean(dialog.querySelectorAll("input")[0].checked), false);
    dialog.querySelectorAll("textarea")[0].value = "Green";
    dialog.querySelectorAll("form")[0].listeners.get("submit")({ preventDefault() {} }); await flush();
    assert.deepEqual(calls.at(-1).args.answer, { kind: "questions", answers: { "Which color?": ["Other"] }, notes: { "Which color?": "Green" } });
  } finally { restore(); }
});

test("Markdown tokens render text and highlighted code without raw HTML or image loading", () => {
  const restore = documentFixture();
  try {
    const root = new Node();
    appendMarkdownTokens(root, [{ kind: "open", tag: "pre", language: "rust" }, { kind: "text", text: "let value = 42;" }, { kind: "close" }, { kind: "open", tag: "a", href: "javascript:alert(1)" }, { kind: "text", text: "<script>unsafe</script>" }, { kind: "close" }, { kind: "open", tag: "img", href: "https://example.com/x.png" }, { kind: "close" }]);
    assert.equal(root.querySelectorAll("a")[0].href, undefined);
    assert.equal(root.querySelectorAll("img").length, 0);
    assert.equal(root.querySelectorAll("script").length, 0);
    assert.ok(root.querySelectorAll("span").some(node => node.className === "syntax-keyword" && node.textContent === "let"));
  } finally { restore(); }
});

test("large code blocks preserve every character with bounded highlighting nodes", () => {
  const restore = documentFixture();
  try {
    for (const source of ["let a = 1;\n".repeat(4000), "let a = 1;\n".repeat(9000)]) {
      const root = new Node("pre"); highlightCode(root, source);
      assert.equal(root.children.map(node => node.textContent).join(""), source);
      assert.ok(root.querySelectorAll("span").length <= 4096);
      if (source.length > 65536) assert.equal(root.children.length, 1);
    }
  } finally { restore(); }
});

test("tool status updates preserve the original title and reviewed diff", () => {
  const original = { toolCallId: "tool-1", title: "Edit file", content: permission.request.toolCall.content, status: "pending" };
  const completed = mergeCliTool(original, { toolCallId: "tool-1", status: "completed" });
  assert.equal(completed.title, "Edit file"); assert.deepEqual(completed.content, original.content); assert.equal(completed.status, "completed");
});

test("file attachments remain unsent text and reject unavailable images or oversized input", async () => {
  const file = { name: "fact.txt", type: "text/plain", size: 5, text: async () => "amber" };
  assert.equal(await textAttachments([file], 100), "\n\nFile: fact.txt\namber");
  await assert.rejects(textAttachments([{ ...file, type: "image/png" }], 100), /does not advertise image input/);
  await assert.rejects(textAttachments([file], 3), /message limit/);
  await assert.rejects(textAttachments([{ ...file, text: async () => "\u0000" }], 100), /binary files/);
});

test("child model, command and plan events keep the parent chat controls intact", async () => {
  const restore = documentFixture(); const saved = { window: globalThis.window, Option: globalThis.Option, frame: globalThis.requestAnimationFrame };
  const selectors = new Map(["#transcript", "#streaming-body", "#chat-draft", ".chat-run-controls", ".composer-context"].map(name => [name, new Node(name === "#chat-draft" ? "textarea" : "div")]));
  const composer = new Node("div"); composer.append(selectors.get("#chat-draft"));
  document.body.append(...[...selectors].filter(([key]) => key !== "#chat-draft").map(([, value]) => value), composer); document.querySelector = key => selectors.get(key) || null;
  document.createDocumentFragment = () => new Node("#fragment"); document.addEventListener = () => {};
  globalThis.window = { setInterval: () => 1, clearInterval() {}, addEventListener() {} };
  globalThis.Option = class extends Node { constructor(label, value) { super("option", label); this.value = value; } };
  globalThis.requestAnimationFrame = callback => callback();
  const current = snapshot(); const invoke = async method => method === "get_cli_permission" ? { mode: "ask" } : method === "cli_background_activity" ? null : [];
  try {
    const chat = createCliChat({ invoke, getSnapshot: () => current, showToast: value => assert.fail(value) }); chat.snapshot(current); await flush();
    const emit = (session, update) => chat.update({ kind: "cli_update", payload: { session_id: session, update } }, "run-a");
    emit("parent", { sessionUpdate: "session_info_update" });
    emit("parent", { sessionUpdate: "config_option_update", configOptions: [{ id: "model", currentValue: "parent-model" }] });
    emit("parent", { sessionUpdate: "available_commands_update", availableCommands: [{ name: "parent-command", description: "Parent command" }] });
    emit("parent", { sessionUpdate: "plan", entries: [{ status: "in_progress", content: "Parent plan step" }] });
    emit("child", { sessionUpdate: "config_option_update", configOptions: [{ id: "model", currentValue: "child-model" }] });
    emit("child", { sessionUpdate: "available_commands_update", availableCommands: [{ name: "child-command" }] });
    emit("child", { sessionUpdate: "plan", entries: [{ status: "in_progress", content: "Child plan step" }] });
    assert.equal(selectors.get(".chat-run-controls").children[0].textContent, "parent-model");
    const region = document.body.children.find(node => node.className === "cli-chat-activity");
    assert.equal(document.body.children.indexOf(region) + 1, document.body.children.indexOf(selectors.get("#streaming-body")));
    assert.ok(region.querySelectorAll("li").some(node => node.textContent.includes("Parent plan step")));
    assert.ok(region.querySelectorAll("pre").some(node => node.textContent.includes("Child plan step")));
    const draft = selectors.get("#chat-draft"); draft.value = "/"; draft.selectionStart = 1; draft.dispatchEvent({ type: "input" }); await flush();
    const menu = document.body.children.find(node => node.className === "cli-input-menu");
    assert.deepEqual(menu.querySelectorAll("button").map(node => node.textContent), ["/parent-command"]);
    draft.listeners.get("keydown")({ key: "ArrowDown", preventDefault() {} }); assert.equal(document.activeElement, menu.children[0]);
    menu.listeners.get("keydown")({ key: "Escape" }); assert.equal(document.activeElement, draft); assert.equal(menu.hidden, true);
    emit("parent", { sessionUpdate: "background_tasks", tasks: [{ task_id: "bg-1", description: "Background fixture", status: "running" }] });
    emit("parent", { sessionUpdate: "background_stopped" });
    chat.update({ kind: "error", payload: "CLI connection closed" }, "run-a");
    assert.ok(region.querySelectorAll("summary").some(node => node.textContent === "Background fixture · cancelled"));
    assert.ok(region.querySelectorAll("pre").some(node => node.textContent === "CLI connection closed"));
    current.workspaceRef = { worktreeId: "another-worktree" }; chat.snapshot(current); await flush();
    assert.equal(selectors.get(".chat-run-controls").children[0].textContent, "Grok"); assert.equal(region.hidden, true);
  } finally { restore(); globalThis.window = saved.window; globalThis.Option = saved.Option; globalThis.requestAnimationFrame = saved.frame; }
});

test("background questions remain answerable after the durable run ends", async () => {
  const restore = documentFixture(); const calls = []; const current = snapshot("project-a", "done");
  try {
    const cards = createCliInteractionCards({ invoke: async (method, args) => { calls.push({ method, args }); return []; }, getSnapshot: () => current, showToast: value => assert.fail(value) });
    cards.snapshot(current); cards.idle("run-a", [permission]); cards.snapshot(current);
    const dialog = document.body.children[0]; assert.equal(dialog.open, true);
    dialog.querySelectorAll("button").find(node => node.textContent === "Accept").click(); await flush();
    assert.equal(calls.at(-1).args.runId, "run-a"); assert.equal(calls.at(-1).args.interactionId, 7);
    cards.idle(null, []); cards.snapshot(current); assert.equal(dialog.open, false);
  } finally { restore(); }
});

test("switching worktrees dismisses the previous chat's permission card without answering", async () => {
  const restore = documentFixture(); const calls = []; const current = snapshot();
  try {
    const cards = createCliInteractionCards({ invoke: async (method, args) => { calls.push({ method, args }); return []; }, getSnapshot: () => current, showToast: value => assert.fail(value) });
    cards.snapshot(current); await flush(); cards.update({ kind: "cli_interaction", payload: permission }, "run-a");
    assert.equal(document.body.children[0].open, true);
    current.workspaceRef = { worktreeId: "another-worktree" }; cards.snapshot(current);
    assert.equal(document.body.children[0].open, false); assert.equal(calls.some(call => call.method === "answer_cli_interaction"), false);
  } finally { restore(); }
});

test("a late background snapshot cannot replace a new active run and Stop reports confirmed completion", async () => {
  const previous = globalThis.window; globalThis.window = { setInterval: () => 1, clearInterval() {}, addEventListener() {} };
  let current = snapshot("project-a", "done"); let finish; const updates = []; const calls = [];
  let result = new Promise(resolve => { finish = resolve; });
  try {
    const background = createCliBackground({ invoke: async (method, args) => { calls.push({ method, args }); return method === "cli_background_activity" ? result : undefined; }, getSnapshot: () => current, showToast() {}, interactions: { idle() {} }, update: (event, run) => updates.push({ event, run }) });
    const poll = background.poll(); current = snapshot(); current.queue.runs[0].id = "new-run";
    finish({ runId: "old-run", cursor: 1, pending: [], events: [{ kind: "thought_delta", payload: "stale" }] }); await poll;
    assert.equal(updates.length, 0);
    current = snapshot("project-a", "done"); result = { runId: "run-a", cursor: 1, pending: [], events: [] }; await background.poll();
    assert.equal(background.connected(), true); await background.stop();
    assert.deepEqual(calls.at(-1), { method: "stop_cli_background", args: { projectId: "project-a", runId: "run-a" } });
    assert.equal(background.connected(), false); assert.equal(updates.at(-1).event.payload.update.sessionUpdate, "background_stopped");
  } finally { globalThis.window = previous; }
});

test("restored model labels use the chat selection and stale catalog reads cannot replace live metadata", async () => {
  const restore = documentFixture(); const current = snapshot("project-a", "done"); current.account = { connected: true, connection: { model: "account-default" } };
  const button = new Node("button"); let resolve; let calls = 0; let result = { selected: { model: { name: "Saved model" }, reasoningEffort: "high" } };
  try {
    const models = createCliModelPicker({ invoke: async () => { calls += 1; return result; }, getSnapshot: () => current, showToast: value => assert.fail(value), button });
    models.snapshot(current); models.snapshot(current); await flush();
    assert.equal(calls, 1); assert.equal(button.textContent, "Saved model · high");
    models.reset(); current.workspaceRef = { worktreeId: "next" }; result = new Promise(done => { resolve = done; }); models.snapshot(current);
    models.options([{ id: "model", currentValue: "live-model" }]); button.textContent = "Live model";
    resolve({ selected: { model: { name: "Old selection" } } }); await flush(); assert.equal(button.textContent, "Live model");
  } finally { restore(); }
});

test("Chat model picker exposes a discrete effort slider on both connections and applies only on request", async () => {
  const restore = documentFixture(); const oldOption = globalThis.Option;
  globalThis.Option = class extends Node { constructor(label, value) { super("option", label); this.value = value; } };
  try {
    for (const [mode, transport, extraHigh] of [["grokCliStandard", "GrokCliAcp", "2"], ["gbPlusContained", "GrokCliAcp", "2"], ["gbPlusContained", "XaiKeychain", "6"]]) {
      const current = snapshot("project-a", "done"); current.engine.mode = mode; current.account = { connected: true, selectedTransport: transport };
      const button = new Node("button"); const calls = [];
      const model = { id: "grok-a", name: "Grok A", reasoningEfforts: ["xhigh", "high"] };
      const catalog = { transport, models: [model], selected: { model, reasoningEffort: "high" } };
      const picker = createCliModelPicker({ invoke: async (method, args) => { calls.push({ method, args }); return method === "list_session_models" ? catalog : { model, reasoningEffort: args.reasoningEffort }; }, getSnapshot: () => current, showToast: value => assert.fail(value), button });
      picker.snapshot(current); await flush();
      assert.equal(button.hidden, false); assert.equal(button.disabled, false); assert.equal(button.textContent, "Grok A · high");
      button.click(); await flush();
      const dialog = document.body.children.at(-1); const slider = dialog.querySelector("input");
      assert.equal(slider.type, "range"); assert.equal(slider.step, "1"); assert.equal(slider["aria-valuetext"], "High");
      slider.value = extraHigh; slider.dispatchEvent({ type: "input" });
      assert.equal(slider["aria-valuetext"], "Extra high");
      assert.equal(calls.filter(call => call.method === "select_session_model").length, 0);
      dialog.querySelectorAll("button").find(node => node.textContent === "Use model").click(); await flush();
      assert.deepEqual(calls.at(-1), { method: "select_session_model", args: { projectId: "project-a", sessionId: "project-project-a", modelId: "grok-a", reasoningEffort: "xhigh" } });
      assert.equal(button.textContent, "Grok A · xhigh"); assert.equal(dialog.open, false);
    }
  } finally { restore(); globalThis.Option = oldOption; }
});

test("a CLI model without effort metadata keeps its default and an old selection cannot repaint another chat", async () => {
  const restore = documentFixture(); const oldOption = globalThis.Option;
  globalThis.Option = class extends Node { constructor(label, value) { super("option", label); this.value = value; } };
  try {
    const current = snapshot("project-a", "done"); current.account = { connected: true, selectedTransport: "GrokCliAcp" };
    const button = new Node("button"); let finish; const calls = [];
    const model = { id: "grok-default", name: "Grok default", reasoningEfforts: [] };
    const picker = createCliModelPicker({ invoke: async (method, args) => { calls.push({ method, args }); return method === "list_session_models" ? { transport: "GrokCliAcp", models: [model], selected: null } : new Promise(resolve => { finish = resolve; }); }, getSnapshot: () => current, showToast: value => assert.fail(value), button });
    picker.snapshot(current); await flush(); button.click(); await flush();
    const dialog = document.body.children.at(-1); const slider = dialog.querySelector("input");
    assert.equal(slider.disabled, true); assert.equal(slider.max, "0"); assert.equal(slider["aria-valuetext"], "Default");
    dialog.querySelectorAll("button").find(node => node.textContent === "Use model").click(); await flush();
    assert.equal(calls.at(-1).args.reasoningEffort, null);
    current.workspaceRef = { worktreeId: "next" }; picker.snapshot(current); await flush();
    finish({ model: { ...model, name: "Old chat model" }, reasoningEffort: "high" }); await flush();
    assert.equal(button.textContent, "Grok · model default"); assert.equal(dialog.open, false);
  } finally { restore(); globalThis.Option = oldOption; }
});

test("the model selector is an anchored non-modal popover that toggles without applying", async () => {
  const restore = documentFixture(); const oldOption = globalThis.Option;
  globalThis.Option = class extends Node { constructor(label, value) { super("option", label); this.value = value; } };
  try {
    const current = snapshot("project-a", "done"); current.account = { connected: true, selectedTransport: "GrokCliAcp" };
    const button = new Node("button"); const header = new Node(); header.append(button); document.body.append(header);
    const calls = []; const model = { id: "grok", name: "Grok", reasoningEfforts: ["high"] };
    const picker = createCliModelPicker({ invoke: async method => { calls.push(method); return { models: [model] }; }, getSnapshot: () => current, showToast: value => assert.fail(value), button });
    picker.snapshot(current); await flush(); button.click(); await flush();
    const panel = header.children[1];
    assert.equal(panel.tagName, "DIV"); assert.equal(panel.popover, "auto"); assert.equal(panel["aria-modal"], undefined);
    assert.equal(button.popovertarget, panel.id); assert.equal(button["aria-expanded"], "true");
    assert.equal(panel.style.left, "320px"); assert.equal(panel.style.top, "90px");
    button.click(); assert.equal(panel.open, false); assert.equal(button["aria-expanded"], "false");
    button.click(); await flush();
    panel.listeners.get("keydown")({ key: "Escape", preventDefault() {} });
    assert.equal(panel.open, false); assert.equal(document.activeElement, button);
    assert.equal(calls.includes("select_session_model"), false);
  } finally { restore(); globalThis.Option = oldOption; }
});
