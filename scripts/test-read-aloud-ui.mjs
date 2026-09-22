import assert from "node:assert/strict";
import test from "node:test";
import { createChatScroll } from "../crates/grok-build-tauri/ui/modules/chat_scroll.js";
import { createChatScheduling } from "../crates/grok-build-tauri/ui/modules/queue.js";
import { createChatChanges } from "../crates/grok-build-tauri/ui/modules/review.js";

import {
  autoReadDecision,
  completedReplyTransition,
  createReadAloud,
  annotateCompletedRuns,
  parseChatMessages,
  parseAssistantMessages,
} from "../crates/grok-build-tauri/ui/modules/read_aloud.js";

test("workflow attempts cannot insert prompts or shift prior chat run summaries", () => {
  const messages = parseChatMessages("You: first\nAssistant: first reply\nYou: second\nAssistant: second reply");
  const items = ["first", "second", "Workflow: review", "Resume workflow: review"].map((prompt, index) => ({
    id: `item-${index}`, projectId: "project-a", sessionId: "chat-a", ordinal: index + 1, prompt,
    workflow: index > 1 ? { jobId: "workflow-a", attempt: index - 1 } : null,
  }));
  const runs = items.map((item, index) => ({ id: `run-${index}`, queueItemId: item.id,
    projectId: "project-a", state: "done", startedAtUnixMs: 1000, endedAtUnixMs: 2000 + index * 1000 }));
  annotateCompletedRuns(messages, { activeProjectId: "project-a", activeSessionId: "chat-a", queue: { items, runs } });
  assert.deepEqual(messages.map(({role, displayText}) => [role, displayText]), [
    ["user", "first"], ["assistant", "first reply"], ["user", "second"], ["assistant", "second reply"],
  ]);
  assert.equal(messages[0].runSummary, "Worked for 1.0s");
  assert.equal(messages[2].runSummary, "Worked for 2.0s");
});

test("two completed xAI turns become two speaker bubbles with final text only", () => {
  const transcript = [
    "Provider: live xAI (XaiKeychain)",
    "You: first",
    "tool loop not run: live response had no tool requests",
    "Assistant: first reply",
    "Provider: live xAI (XaiKeychain)",
    "You: second",
    "tool propose_write fixture.txt → completed: staged",
    "Assistant: second final reply",
  ].join("\n");
  const messages = parseAssistantMessages(transcript);
  assert.equal(messages.length, 2);
  assert.equal(messages[0].speakText, "first reply");
  assert.equal(messages[1].speakText, "second final reply");
  assert.doesNotMatch(messages[1].speakText, /propose_write/);
});

test("auto-read becomes eligible only on one active-to-terminal run transition", () => {
  const previous = {
    activeProjectId: "project-a",
    chat: "old",
    queue: { runs: [{ id: "run-a", projectId: "project-a", state: "running" }] },
  };
  const midLoop = {
    activeProjectId: "project-a",
    chat: "old",
    queue: { runs: [{ id: "run-a", projectId: "project-a", state: "running" }] },
  };
  const completed = {
    activeProjectId: "project-a",
    chat: "new",
    queue: { runs: [{ id: "run-a", projectId: "project-a", state: "done" }] },
  };
  assert.equal(completedReplyTransition(previous, midLoop), false);
  assert.equal(completedReplyTransition(previous, completed), true);
  assert.equal(completedReplyTransition(null, completed), false);
});

test("auto-read is off by default and rejects recording, long, diff, and terminal content", () => {
  const base = {
    available: true,
    voiceRecording: false,
    completed: true,
    text: "A concise final answer.",
    characterLimit: 1500,
  };
  assert.equal(autoReadDecision({ ...base, enabled: false }).reason, "off");
  assert.equal(autoReadDecision({ ...base, enabled: true }).speak, true);
  assert.equal(
    autoReadDecision({ ...base, enabled: true, voiceRecording: true }).reason,
    "voice_recording",
  );
  assert.equal(
    autoReadDecision({ ...base, enabled: true, text: "x".repeat(1501) }).reason,
    "too_long",
  );
  assert.equal(
    autoReadDecision({ ...base, enabled: true, text: "diff --git a/a b/a\n@@ -1 +1 @@" }).reason,
    "trace_or_dump",
  );
  assert.equal(
    autoReadDecision({ ...base, enabled: true, text: "$ pwd\n$ ls" }).reason,
    "trace_or_dump",
  );
});

test("tool-using turn reads only its committed final assistant prose", () => {
  const transcript = [
    "Provider: live xAI (XaiKeychain)",
    "You: use a tool",
    "tool read_file README.md → completed: bounded output",
    "Assistant: The README confirms the requested behavior.",
  ].join("\n");
  const final = parseAssistantMessages(transcript).at(-1);
  const decision = autoReadDecision({
    enabled: true,
    available: true,
    voiceRecording: false,
    completed: true,
    text: final.speakText,
    characterLimit: 1500,
  });
  assert.equal(final.speakText, "The README confirms the requested behavior.");
  assert.equal(decision.speak, true);
});

test("current and persisted product headings both suppress tool traces", () => {
  for (const heading of ["GB Plus", "Grok Build+"]) {
    const transcript = [
      "Provider: live xAI (XaiKeychain)",
      "You: use a tool",
      `${heading} app-owned tool results:`,
      "private tool trace",
      "Assistant: Safe final reply.",
    ].join("\n");
    const messages = parseAssistantMessages(transcript);
    assert.equal(messages.at(-1).speakText, "Safe final reply.");
    assert.doesNotMatch(messages.at(-1).speakText, /private tool trace/);
  }
});

class FakeElement {
  constructor() {
    this.children = [];
    this.dataset = {};
    this.disabled = false;
    this.checked = false;
    this.listeners = new Map();
    this.textContent = "";
    this.title = "";
    this.scrollTop = 0;
    this.scrollHeight = 1200;
    this.clientHeight = 400;
    this.isConnected = true;
  }

  addEventListener(kind, listener) {
    this.listeners.set(kind, listener);
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
  }

  setAttribute(name, value) {
    this[name] = value;
  }

  removeAttribute(name) {
    delete this[name];
  }

  closest(selector) {
    return selector === "[data-read-aloud-key]" && this.dataset.readAloudKey ? this : null;
  }
}

function fakeElements() {
  return {
    chatCanvas: new FakeElement(),
    readAloudAuto: new FakeElement(),
    readAloudStatus: new FakeElement(),
    transcriptBody: new FakeElement(),
    transcript: new FakeElement(),
    streamingBody: new FakeElement(),
  };
}

let resizeObservers;
let originalResizeObserver;
test.beforeEach(() => {
  resizeObservers = [];
  originalResizeObserver = globalThis.ResizeObserver;
  globalThis.ResizeObserver = class {
    constructor(callback) { this.callback = callback; resizeObservers.push(this); }
    observe(target) { this.target = target; }
  };
});
test.afterEach(() => { globalThis.ResizeObserver = originalResizeObserver; });

test("bottom following handles delayed layout, preserves reading position and resets for another chat", () => {
  const canvas = new FakeElement();
  const content = new FakeElement();
  const scroll = createChatScroll(canvas, content);
  assert.equal(resizeObservers[0].target, content);
  scroll.update();
  assert.equal(canvas.scrollTop, 800);
  canvas.scrollHeight += 300;
  resizeObservers[0].callback();
  assert.equal(canvas.scrollTop, 1100);
  canvas.scrollTop = 240;
  canvas.listeners.get("scroll")();
  canvas.scrollHeight += 400;
  resizeObservers[0].callback();
  scroll.update();
  assert.equal(canvas.scrollTop, 240);
  canvas.scrollTop = 1500;
  canvas.listeners.get("scroll")();
  canvas.scrollHeight += 100;
  resizeObservers[0].callback();
  assert.equal(canvas.scrollTop, 1600);
  canvas.scrollTop = 100;
  canvas.listeners.get("scroll")();
  scroll.reset();
  assert.equal(canvas.scrollTop, 1600);
  canvas.clientHeight = 0;
  canvas.scrollTop = 0;
  scroll.update();
  assert.equal(canvas.scrollTop, 0);
  canvas.clientHeight = 400;
  resizeObservers[0].callback();
  assert.equal(canvas.scrollTop, 1600);
});

const textOf = node => node.textContent + (node.children || []).map(textOf).join("");
test("pending messages keep submission order and Accept stays with the latest completed reply", () => {
  const originalDocument = globalThis.document;
  globalThis.document = { createElement: () => new FakeElement(), addEventListener() {} };
  try {
    const names = ["sendControl", "sendMenuToggle", "sendButton", "sendMenu", "chatNextStrip", "chatPendingTurns", "chatNextList", "chatNextSummary", "chatNextPopover", "chatSteerCancel", "chatSteerSubmit", "chatSteerConfirmation", "chatSteerPreview", "chatChangeCard", "chatChangeView", "chatChangeAccept", "chatChangeReject", "chatChangeList", "transcriptBody"];
    const elements = Object.fromEntries(names.map(name => [name, new FakeElement()]));
    const scheduling = createChatScheduling({ elements, invoke: null });
    const items = [3, 1, 2].map(ordinal => ({ id: `item-${ordinal}`, projectId: "project-a", sessionId: "chat-a", ordinal, prompt: `Message ${ordinal}`, state: "queued", autoStart: true }));
    scheduling.render({ activeProjectId: "project-a", activeSessionId: "chat-a", chat: "", queue: { available: true, items, runs: [], steering: [] } });
    assert.deepEqual(elements.chatPendingTurns.children.map(node => node.children[0].textContent), ["Message 1", "Message 2", "Message 3"]);
    assert.deepEqual(items.map(item => item.ordinal), [3, 1, 2]);
    const anchors = [];
    const replies = ["earlier", "latest"].map(name => ({ insertAdjacentElement: (where, card) => anchors.push({ name, where, card }) }));
    elements.chatPendingTurns.querySelector = () => null;
    elements.transcriptBody.querySelectorAll = () => replies;
    const review = createChatChanges({ elements, onAccept: assert.fail, onReject: assert.fail });
    review.render([{ projectId: "project-a", sessionId: "chat-a", path: "file.txt", proposalFingerprint: "fixture", changeKind: "edit", groupCount: 1, diff: "+new" }]);
    assert.deepEqual(anchors, [{ name: "latest", where: "afterend", card: elements.chatChangeCard }]);
  } finally { globalThis.document = originalDocument; }
});

test("chat renders oldest first and keeps completed messages while the latest reply streams", async () => {
  const originalDocument = globalThis.document;
  globalThis.document = {
    createElement: () => new FakeElement(),
    createTextNode: textContent => ({ textContent }),
  };
  try {
    const elements = fakeElements();
    const controller = createReadAloud({ elements, invoke: null, isVoiceRecording: () => false, onError: assert.fail, onNotice() {} });
    const previous = { activeProjectId: "project-a", activeSessionId: "chat-a",
      chat: "You: first\nAssistant: first reply\nYou: second\nAssistant: second reply" };
    controller.handleSnapshot(previous, null);
    assert.deepEqual(elements.transcriptBody.children.map(node => [node.dataset.role, textOf(node)]), [
      ["user", "first"], ["assistant", "first reply"], ["user", "second"], ["assistant", "second reply"],
    ]);
    const history = [...elements.transcriptBody.children];
    controller.renderStreaming("Assistant: third");
    controller.renderStreaming("Assistant: third reply");
    assert.deepEqual(elements.transcriptBody.children, history);
    assert.equal(elements.streamingBody.children.length, 1);
    assert.equal(textOf(elements.streamingBody.children[0]), "third reply");
    assert.equal(elements.streamingBody.children[0].dataset.streaming, "true");
    controller.setHostBusy(true);
    assert.equal(textOf(elements.streamingBody.children[0]), "third reply");
    elements.chatCanvas.scrollTop = 100;
    elements.chatCanvas.listeners.get("scroll")();
    const completed = { ...previous, chat: `${previous.chat}\nYou: third\nAssistant: third reply` };
    controller.handleSnapshot(completed, previous);
    assert.equal(elements.streamingBody.children.length, 0);
    assert.equal(elements.streamingBody.hidden, true);
    assert.equal(elements.transcriptBody.children.length, 6);
    assert.equal(textOf(elements.transcriptBody.children.at(-1)), "third reply");
    assert.equal(elements.chatCanvas.scrollTop, 100);
    controller.handleSnapshot({ ...completed, activeSessionId: "chat-b" }, completed);
    assert.equal(elements.chatCanvas.scrollTop, 800);
  } finally { globalThis.document = originalDocument; }
});

function buttonAt(elements, index) {
  return elements.transcriptBody.children
    .flatMap((message) => message.children)
    .filter((child) => child.dataset?.readAloudKey)[index];
}

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

test("manual speakers serialize playback and the active speaker stops immediately", async () => {
  const originalDocument = globalThis.document;
  const originalWindow = globalThis.window;
  globalThis.document = {
    createElement: () => new FakeElement(),
    createTextNode: (textContent) => ({ textContent }),
  };
  globalThis.window = { atob: (value) => Buffer.from(value, "base64").toString("binary") };
  const elements = fakeElements();
  const audio = [];
  const revoked = [];
  const controller = createReadAloud({
    invoke: async (command) => {
      if (command === "read_aloud_status") {
        return {
          available: true,
          reason: null,
          autoReadEnabled: false,
          voiceId: "eve",
          manualCharacterLimit: 15000,
          autoCharacterLimit: 1500,
          settingsIssue: null,
        };
      }
      if (command === "read_aloud_synthesize") {
        return { audioBase64: "SUQz", contentType: "audio/mpeg" };
      }
      return undefined;
    },
    elements,
    isVoiceRecording: () => false,
    onError: (reason) => assert.fail(reason),
    onNotice: () => {},
    audioFactory: (url) => {
      const item = {
        url,
        paused: false,
        played: false,
        listeners: new Map(),
        addEventListener(kind, listener) { this.listeners.set(kind, listener); },
        async play() { this.played = true; },
        pause() { this.paused = true; },
        removeAttribute() {},
        load() {},
      };
      audio.push(item);
      return item;
    },
    objectUrls: {
      createObjectURL: () => `blob:fixture-${audio.length}`,
      revokeObjectURL: (url) => revoked.push(url),
    },
  });
  await controller.refresh();
  controller.handleSnapshot({
    activeProjectId: "project-a",
    workspaceRef: { workspaceId: "base-a" },
    account: { selectedTransport: "XaiKeychain", connection: { state: "connected" } },
    chat: [
      "Provider: live xAI (XaiKeychain)\nYou: first\ntool loop not run\nAssistant: first",
      "Provider: live xAI (XaiKeychain)\nYou: second\ntool loop not run\nAssistant: second",
    ].join("\n"),
    queue: { runs: [] },
  }, null);
  await flush();
  await flush();
  elements.transcriptBody.listeners.get("click")({ target: buttonAt(elements, 0) });
  await flush();
  await flush();
  assert.equal(audio.length, 1);
  assert.equal(audio[0].played, true);

  elements.transcriptBody.listeners.get("click")({ target: buttonAt(elements, 1) });
  await flush();
  await flush();
  assert.equal(audio[0].paused, true);
  assert.equal(audio.length, 2);
  assert.equal(audio[1].played, true);

  elements.transcriptBody.listeners.get("click")({ target: buttonAt(elements, 1) });
  await flush();
  assert.equal(audio[1].paused, true);
  assert.equal(revoked.length, 2);
  globalThis.document = originalDocument;
  globalThis.window = originalWindow;
});

test("auto-read invokes synthesis only after final committed run state", async () => {
  const originalDocument = globalThis.document;
  const originalWindow = globalThis.window;
  globalThis.document = {
    createElement: () => new FakeElement(),
    createTextNode: (textContent) => ({ textContent }),
  };
  globalThis.window = { atob: (value) => Buffer.from(value, "base64").toString("binary") };
  const elements = fakeElements();
  let synthesisCount = 0;
  const controller = createReadAloud({
    invoke: async (command) => {
      if (command === "read_aloud_status") {
        return {
          available: true,
          reason: null,
          autoReadEnabled: true,
          voiceId: "eve",
          manualCharacterLimit: 15000,
          autoCharacterLimit: 1500,
          settingsIssue: null,
        };
      }
      if (command === "read_aloud_synthesize") {
        synthesisCount += 1;
        return { audioBase64: "SUQz", contentType: "audio/mpeg" };
      }
      return undefined;
    },
    elements,
    isVoiceRecording: () => false,
    onError: (reason) => assert.fail(reason),
    onNotice: () => {},
    audioFactory: () => ({
      addEventListener() {},
      async play() {},
      pause() {},
      removeAttribute() {},
      load() {},
    }),
    objectUrls: { createObjectURL: () => "blob:auto", revokeObjectURL() {} },
  });
  await controller.refresh();
  const previous = {
    activeProjectId: "project-a",
    workspaceRef: { workspaceId: "base-a" },
    account: { selectedTransport: "XaiKeychain", connection: { state: "connected" } },
    chat: "Provider: live xAI (XaiKeychain)\nYou: old\ntool loop not run\nAssistant: old",
    queue: { runs: [{ id: "run-a", projectId: "project-a", state: "running" }] },
  };
  controller.handleSnapshot(previous, null);
  controller.handleSnapshot({ ...previous }, previous);
  await flush();
  assert.equal(synthesisCount, 0);
  const completed = {
    ...previous,
    chat: `${previous.chat}\nProvider: live xAI (XaiKeychain)\nYou: new\ntool read_file → completed\nAssistant: final only`,
    queue: { runs: [{ id: "run-a", projectId: "project-a", state: "done" }] },
  };
  controller.handleSnapshot(completed, previous);
  await flush();
  await flush();
  assert.equal(synthesisCount, 1);
  await controller.stop();
  globalThis.document = originalDocument;
  globalThis.window = originalWindow;
});
