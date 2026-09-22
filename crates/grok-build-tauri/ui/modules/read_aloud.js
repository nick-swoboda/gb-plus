"use strict";

import { visiblePrompt } from "./cli_input.js";
import { createChatScroll } from "./chat_scroll.js";
import { renderMarkdown } from "./markdown.js";
import { activeSessionId, terminalRunText } from "./run_status.js";
import { compactContextTokens } from "./usage.js";

const ACTIVE_RUN_STATES = new Set(["running", "stop_requested"]);
const READABLE_TERMINAL_STATES = new Set(["done", "needs_review"]);
const XAI_TURN_MARKER = /^Provider: live xAI \((?:XaiKeychain|XAI_API_KEY)\)$/;
const ASSISTANT_LINE = /^Assistant:\s?(.*)$/;
const USER_LINE = /^(?:You|User):\s?(.*)$/;
const TOOL_TRACE_LINE = /^(?:tool(?:\s| loop\b)|plus_tool\s|(?:GB Plus|Grok Build\+) app-owned tool results:)/;
const FILE_REFERENCE_PATTERN = /(^|[\s([{"'`])((?:(?:\.{1,2}|[A-Za-z0-9_-]+)\/)*(?:\.[A-Za-z0-9][A-Za-z0-9._-]*|[A-Za-z0-9_-]+\.[A-Za-z0-9][A-Za-z0-9._-]*))(?=$|[\s)\]}"'`,:;!?])/gm;

export function messageFileSegments(value) {
  const text = String(value || "");
  const segments = [];
  let cursor = 0;
  for (const match of text.matchAll(FILE_REFERENCE_PATTERN)) {
    const start = match.index;
    const prefix = `${text.slice(cursor, start)}${match[1]}`;
    if (prefix) segments.push({ text: prefix, fileName: false });
    segments.push({ text: match[2], fileName: true });
    cursor = start + match[0].length;
  }
  if (cursor < text.length || segments.length === 0) {
    segments.push({ text: text.slice(cursor), fileName: false });
  }
  return segments;
}

function appendMessageTextWithFileNames(target, value) {
  for (const segment of messageFileSegments(value)) {
    if (!segment.fileName) {
      target.append(document.createTextNode(segment.text));
      continue;
    }
    const fileName = document.createElement("span");
    fileName.className = "chat-file-name";
    fileName.textContent = segment.text;
    target.append(fileName);
  }
}

export function parseChatMessages(transcript) {
  const text = typeof transcript === "string" ? transcript.trim() : "";
  if (!text || text === "No chat yet.") return [];
  const messages = [];
  let current = [];
  let currentRole = null;
  let legacy = [];
  let suppressUntilAssistant = false;
  const flush = (parts, role, kind) => {
    const displayText = parts.join("\n").trim();
    parts.length = 0;
    if (displayText) messages.push(messageFromText(displayText, messages.length, role, kind));
  };
  const flushCurrent = () => {
    flush(current, currentRole || "assistant", currentRole || "assistant");
    currentRole = null;
  };
  for (const rawLine of text.split("\n")) {
    const line = rawLine.replace(/\r$/, "");
    if (XAI_TURN_MARKER.test(line)) {
      flushCurrent();
      flush(legacy, "assistant", "legacy");
      suppressUntilAssistant = false;
      continue;
    }
    const user = line.match(USER_LINE);
    if (user) {
      flushCurrent();
      flush(legacy, "assistant", "legacy");
      suppressUntilAssistant = false;
      currentRole = "user";
      current.push(user[1]);
      continue;
    }
    const assistant = line.match(ASSISTANT_LINE);
    if (assistant) {
      flushCurrent();
      flush(legacy, "assistant", "legacy");
      suppressUntilAssistant = false;
      currentRole = "assistant";
      current.push(assistant[1]);
      continue;
    }
    if (TOOL_TRACE_LINE.test(line)) {
      flushCurrent();
      flush(legacy, "assistant", "legacy");
      suppressUntilAssistant = true;
      continue;
    }
    if (suppressUntilAssistant) continue;
    if (current.length) current.push(line);
    else legacy.push(line);
  }
  flushCurrent();
  flush(legacy, "assistant", "legacy");
  return messages;
}

export function parseAssistantMessages(transcript) {
  return parseChatMessages(transcript).filter((message) => message.role === "assistant");
}

function messageFromText(text, index, role, kind) {
  if (role === "user" && kind === "queue") text = visiblePrompt(text);
  const displayText = text.trim();
  const speakText = role === "assistant" ? displayText : "";
  const keyPrefix = `${kind}-${index}-${displayText.length}`;
  return { key: `${keyPrefix}-${displayText.slice(0, 48)}`, role, displayText, speakText };
}
export function annotateCompletedRuns(messages, snapshot) {
  const projectId = snapshot?.activeProjectId;
  if (!projectId) return;
  const sessionId = activeSessionId(snapshot);
  const runs = new Map((snapshot?.queue?.runs || []).map((run) => [run.queueItemId, run]));
  const candidates = (snapshot?.queue?.items || [])
    .filter((item) => item.projectId === projectId && item.sessionId === sessionId && !item.workflow)
    .map((item) => ({ item, run: runs.get(item.id) }))
    .filter(({ run }) => run && ["done", "needs_review"].includes(run.state))
    .sort((left, right) => left.item.ordinal - right.item.ordinal);
  let boundary = messages.length;
  for (const match of candidates.reverse()) {
    let index = messages.findLastIndex((message, position) => position < boundary
      && message.role === "user" && message.displayText === visiblePrompt(match.item.prompt));
    if (index < 0) {
      index = messages.findLastIndex((message, position) => position < boundary
        && message.role === "assistant");
      if (index >= 0) messages.splice(index, 0, messageFromText(match.item.prompt, match.item.ordinal, "user", "queue"));
    }
    if (index < 0) continue;
    boundary = index;
    let summary = terminalRunText(match.run);
    const context = snapshot?.usage?.runId === match.run.id ? snapshot.usage.context : null;
    if (context?.state === "known") {
      const contextUsed = compactContextTokens(context.used);
      const contextSize = compactContextTokens(context.size);
      if (contextUsed && contextSize) summary += ` · ${contextUsed} / ${contextSize}`;
    }
    messages[index].runSummary = summary;
  }
}

export function completedReplyTransition(previous, current) {
  const projectId = current?.activeProjectId;
  if (!projectId || previous?.activeProjectId !== projectId) return false;
  if (previous?.chat === current?.chat) return false;
  const currentRuns = Array.isArray(current?.queue?.runs) ? current.queue.runs : [];
  const previousRuns = Array.isArray(previous?.queue?.runs) ? previous.queue.runs : [];
  return previousRuns.some((run) => {
    if (run.projectId !== projectId || !ACTIVE_RUN_STATES.has(run.state)) return false;
    const next = currentRuns.find((candidate) => candidate.id === run.id);
    return next?.projectId === projectId && READABLE_TERMINAL_STATES.has(next.state);
  });
}

export function autoReadDecision({
  enabled,
  available,
  voiceRecording,
  completed,
  text,
  characterLimit,
}) {
  if (!enabled || !completed) return { speak: false, reason: "off" };
  if (!available) return { speak: false, reason: "unavailable" };
  if (voiceRecording) return { speak: false, reason: "voice_recording" };
  const candidate = typeof text === "string" ? text.trim() : "";
  if (!candidate) return { speak: false, reason: "empty" };
  if (Array.from(candidate).length > characterLimit) {
    return { speak: false, reason: "too_long" };
  }
  if (looksLikeTraceOrDump(candidate)) {
    return { speak: false, reason: "trace_or_dump" };
  }
  return { speak: true, reason: null };
}

function looksLikeTraceOrDump(text) {
  const lines = text.split("\n");
  if (lines.some((line) => /^(tool\s|diff --git |--- a\/|\+\+\+ b\/|@@ |Terminal:|Command output:)/.test(line))) {
    return true;
  }
  if (/```(?:diff|patch|console|terminal|shell|sh|bash|zsh)\b/i.test(text)) return true;
  const promptLines = lines.filter((line) => /^\s*(?:\$|%)\s+\S/.test(line));
  return promptLines.length >= 2;
}

export function createReadAloud({
  invoke,
  elements,
  onError,
  onNotice,
  onConnectRequested,
  onMessagesRendered = () => {},
  isVoiceRecording,
  audioFactory = (url) => new Audio(url),
  objectUrls = URL,
}) {
  let view = {
    available: false,
    reason: "Connect with an API key in Account to use the official Grok voice.",
    autoReadEnabled: false,
    voiceId: "eve",
    credentialSource: null,
    manualCharacterLimit: 15000,
    autoCharacterLimit: 1500,
    settingsIssue: null,
  };
  let standardMode = false;
  let pendingMarkdown = null;
  let markdownTimer = null;
  let messages = [];
  let chatMessages = [];
  let currentKey = null;
  let currentAudio = null;
  let currentObjectUrl = null;
  let requestGeneration = 0;
  let accountSignature = "";
  const scrolling = createChatScroll(elements.chatCanvas, elements.transcript);
  let hostBusy = false;

  elements.readAloudAuto.addEventListener("click", () => {
    if (!view.available) {
      onConnectRequested();
      return;
    }
    void setAutoRead(!view.autoReadEnabled);
  });
  elements.transcriptBody.addEventListener("click", (event) => {
    const button = event.target.closest("[data-read-aloud-key]");
    if (!button || button.disabled) return;
    const message = messages.find((candidate) => candidate.key === button.dataset.readAloudKey);
    if (message) void toggleMessage(message);
  });

  async function refresh(silent = true) {
    if (!invoke) return;
    try {
      view = await invoke("read_aloud_status", {});
      renderStatus();
      renderMessages();
      if (!silent && view.settingsIssue) onError(view.settingsIssue);
    } catch (error) {
      if (!silent) onError(message(error));
    }
  }

  async function setAutoRead(enabled) {
    if (!invoke) return;
    try {
      view = await invoke("set_read_aloud_auto_read", { enabled });
      renderStatus();
      onNotice(enabled ? "Auto-read On · finished replies only" : "Auto-read Off");
    } catch (error) {
      renderStatus();
      onError(message(error));
    }
  }

  async function toggleMessage(assistantMessage) {
    if (currentKey === assistantMessage.key) {
      await stop();
      return;
    }
    await speak(assistantMessage, false);
  }

  async function speak(assistantMessage, automatic) {
    const beforeRender = requestGeneration;
    if (assistantMessage.renderedText) {
      await assistantMessage.renderedText;
      if (requestGeneration !== beforeRender) return;
    }
    if (!view.available) {
      if (!automatic) onError(view.reason || "Grok Read Aloud is unavailable.");
      return;
    }
    if (isVoiceRecording()) {
      if (!automatic) onError("Stop Voice input recording before using Grok Read Aloud.");
      return;
    }
    const charCount = Array.from(assistantMessage.speakText).length;
    if (!assistantMessage.speakText || charCount > view.manualCharacterLimit) {
      if (!automatic) onError(`Read Aloud supports up to ${view.manualCharacterLimit.toLocaleString()} characters.`);
      return;
    }
    await stop();
    const generation = ++requestGeneration;
    currentKey = assistantMessage.key;
    renderMessages();
    renderStatus("Preparing Grok voice…");
    try {
      const payload = await invoke("read_aloud_synthesize", { text: assistantMessage.speakText });
      if (generation !== requestGeneration || currentKey !== assistantMessage.key) return;
      const binary = window.atob(payload.audioBase64);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
      currentObjectUrl = objectUrls.createObjectURL(new Blob([bytes], { type: payload.contentType }));
      currentAudio = audioFactory(currentObjectUrl);
      currentAudio.addEventListener("ended", finishPlayback, { once: true });
      currentAudio.addEventListener("error", playbackFailed, { once: true });
      await currentAudio.play();
      renderStatus("Speaking · click the speaker again to stop");
    } catch (error) {
      if (generation === requestGeneration) {
        cleanupPlayback();
        currentKey = null;
        renderMessages();
        renderStatus();
        if (!String(message(error)).includes("Read Aloud stopped")) onError(message(error));
      }
    }
  }

  async function stop() {
    requestGeneration += 1;
    cleanupPlayback();
    currentKey = null;
    renderMessages();
    renderStatus();
    if (invoke) {
      try {
        await invoke("read_aloud_stop", {});
      } catch {
        // Playback is already stopped locally; backend cancellation is best effort.
      }
    }
  }

  function finishPlayback() {
    cleanupPlayback();
    currentKey = null;
    renderMessages();
    renderStatus();
  }

  function playbackFailed() {
    finishPlayback();
    onError("Grok voice audio could not be played by the macOS web view.");
  }

  function cleanupPlayback() {
    if (currentAudio) {
      currentAudio.pause();
      currentAudio.removeAttribute?.("src");
      currentAudio.load?.();
      currentAudio = null;
    }
    if (currentObjectUrl) {
      objectUrls.revokeObjectURL(currentObjectUrl);
      currentObjectUrl = null;
    }
  }

  function handleSnapshot(snapshot, previous) {
    standardMode = snapshot?.engine?.mode === "grokCliStandard";
    const previousContext = contextIdentity(previous);
    const nextContext = contextIdentity(snapshot);
    if (previous && previousContext !== nextContext) {
      void stop();
      scrolling.reset();
    }
    elements.streamingBody.hidden = true;
    elements.streamingBody.replaceChildren();
    chatMessages = parseChatMessages(snapshot?.chat);
    annotateCompletedRuns(chatMessages, snapshot);
    messages = chatMessages.filter((message) => message.role === "assistant");
    renderMessages();

    const nextAccountSignature = `${snapshot?.account?.selectedTransport || ""}:${snapshot?.account?.connection?.state || ""}`;
    const exactConnected = snapshot?.account?.connection?.state === "connected";
    if (!exactConnected) {
      if (currentKey) void stop();
      view.available = false;
      view.reason = "Connect Account before using the official Grok voice.";
      renderStatus();
      renderMessages();
    }
    if (nextAccountSignature !== accountSignature) {
      accountSignature = nextAccountSignature;
      if (exactConnected) {
        view.available = false;
        view.reason = snapshot?.account?.selectedTransport === "GrokCliAcp"
          ? "Checking direct xAI TTS authorization for this Grok login…"
          : "Checking the saved API-key TTS credential…";
        renderStatus();
        renderMessages();
      }
      void refresh();
    }

    const last = messages.at(-1);
    const decision = autoReadDecision({
      enabled: view.autoReadEnabled,
      available: view.available,
      voiceRecording: isVoiceRecording(),
      completed: completedReplyTransition(previous, snapshot),
      text: last?.speakText,
      characterLimit: view.autoCharacterLimit,
    });
    if (decision.speak && last) {
      void speak(last, true);
    } else if (decision.reason === "too_long") {
      onNotice("Auto-read skipped. Reply is too long; use Read Aloud.");
    } else if (decision.reason === "trace_or_dump") {
      onNotice("Auto-read skipped tool, diff, or terminal-style content.");
    }
  }

  function renderStreaming(text) {
    const visible = parseAssistantMessages(text).at(-1)?.displayText || "Working…";
    elements.streamingBody.hidden = false;
    elements.streamingBody.replaceChildren(messageElement({
      key: "streaming",
      role: "assistant",
      displayText: visible,
      speakText: "",
    }, true));
    onMessagesRendered();
    scrolling.update();
  }

  function renderMessages() {
    if (!elements.transcriptBody) return;
    elements.transcriptBody.replaceChildren(...chatMessages.map((message) => (
      messageElement(message, false)
    )));
    onMessagesRendered();
    scrolling.update();
  }

  function messageElement(chatMessage, streaming) {
    const article = document.createElement("article");
    article.className = "chat-message";
    article.dataset.role = chatMessage.role;
    article.dataset.streaming = String(streaming);
    const pre = document.createElement(standardMode && chatMessage.role === "assistant" ? "div" : "pre");
    if (standardMode && streaming) {
      pre.className = "chat-markdown";
      pre.textContent = chatMessage.displayText;
      pendingMarkdown = { pre, text: chatMessage.displayText };
      if (markdownTimer === null) markdownTimer = window.setTimeout(() => {
        markdownTimer = null;
        const pending = pendingMarkdown; pendingMarkdown = null;
        if (pending?.pre.isConnected) void renderMarkdown(pending.pre, pending.text, invoke);
      }, 120);
    } else if (standardMode && chatMessage.role === "assistant") {
      chatMessage.renderedText = renderMarkdown(pre, chatMessage.displayText, invoke).then(text => {
        if (!streaming) chatMessage.speakText = text;
        return text;
      });
    } else appendMessageTextWithFileNames(pre, chatMessage.displayText);
    article.append(pre);
    if (chatMessage.role === "user" && chatMessage.runSummary) {
      const summary = document.createElement("span");
      summary.className = "chat-run-summary";
      summary.textContent = chatMessage.runSummary;
      article.append(summary);
    }
    if (!streaming && chatMessage.role === "assistant") {
      const button = document.createElement("button");
      button.className = "read-aloud-button";
      button.type = "button";
      button.dataset.readAloudKey = chatMessage.key;
      const active = currentKey === chatMessage.key;
      const tooLong = Array.from(chatMessage.speakText).length > view.manualCharacterLimit;
      const reason = view.reason || "Grok Read Aloud is unavailable.";
      button.disabled = hostBusy || !view.available || !chatMessage.speakText || tooLong;
      button.setAttribute("aria-pressed", String(active));
      button.setAttribute("aria-label", active ? "Stop reading this reply" : "Read this reply aloud");
      button.title = tooLong
        ? `Read Aloud supports up to ${view.manualCharacterLimit.toLocaleString()} characters.`
        : (!view.available ? reason : (active ? "Stop speaking (⌥⌘.)" : "Read aloud"));
      button.innerHTML = active ? stopIcon() : speakerIcon();
      article.append(button);
    }
    return article;
  }

  function renderStatus(override) {
    if (view.available) {
      elements.readAloudAuto.dataset.mode = "toggle";
      elements.readAloudAuto.setAttribute("aria-pressed", String(Boolean(view.autoReadEnabled)));
      elements.readAloudAuto.setAttribute(
        "aria-label",
        view.autoReadEnabled ? "Turn Auto-read off" : "Turn Auto-read on",
      );
      elements.readAloudAuto.title = view.autoReadEnabled
        ? "Auto-read finished assistant replies · On"
        : "Auto-read finished assistant replies · Off";
    } else {
      elements.readAloudAuto.dataset.mode = "connect";
      elements.readAloudAuto.removeAttribute("aria-pressed");
      elements.readAloudAuto.setAttribute("aria-label", "Open Account to connect Grok voice");
      elements.readAloudAuto.title = "Open Account to connect Grok voice";
    }
    elements.readAloudStatus.textContent = override
      || (view.available
        ? `Grok voice ready · ${view.voiceId} · ${view.credentialSource || "verified xAI TTS"}`
        : (view.reason || "Grok Read Aloud unavailable"));
    elements.readAloudStatus.title = elements.readAloudStatus.textContent;
    elements.readAloudStatus.dataset.available = String(Boolean(view.available));
  }

  async function speakLast() {
    const last = messages.at(-1);
    if (!last) {
      onError("No completed assistant reply is available to read aloud.");
      return;
    }
    await speak(last, false);
  }

  function setHostBusy(busy) {
    hostBusy = Boolean(busy);
    renderMessages();
  }

  renderStatus();
  void refresh();
  return { handleSnapshot, renderStreaming, refresh, speakLast, stop, setHostBusy };
}

function contextIdentity(snapshot) {
  return `${snapshot?.activeProjectId || ""}:${snapshot?.workspaceRef?.workspaceId || ""}:${activeSessionId(snapshot) || ""}`;
}

function speakerIcon() {
  return '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 8h3l4-3v10l-4-3H4zM14 7c1 .8 1.5 1.8 1.5 3S15 12.2 14 13M16 5c1.6 1.3 2.5 3 2.5 5S17.6 13.7 16 15"/></svg>';
}

function stopIcon() {
  return '<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="6" y="6" width="8" height="8" rx="1"/></svg>';
}

function message(error) {
  return error instanceof Error ? error.message : String(error);
}
