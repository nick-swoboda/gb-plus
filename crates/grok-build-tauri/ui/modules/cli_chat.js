"use strict";

import { createCliModelPicker } from "./cli_models.js";
import { createCliInput } from "./cli_input.js";
import { createCliPermissionPicker } from "./cli_permissions.js";
import { createCliBackground } from "./cli_background.js";
import { activeSessionId } from "./run_status.js";
import { createCliInteractionCards, appendToolContent, textNode } from "./cli_interactions.js";

export function mergeCliTool(previous, update) {
  return { ...previous, ...update, content: update.content ?? previous?.content ?? [] };
}

export function createCliChat({ invoke, getSnapshot, showToast }) {
  const interactions = createCliInteractionCards({ invoke, getSnapshot, showToast, onBackgroundStopped: run => backgroundConnection.stopped(run) });
  const permissions = createCliPermissionPicker({ invoke, getSnapshot, showToast });
  const input = createCliInput({ invoke, getSnapshot, showToast });
  const backgroundConnection = createCliBackground({ invoke, getSnapshot, showToast, interactions, update });
  const region = document.createElement("section"); region.className = "cli-chat-activity"; region.hidden = true;
  region.setAttribute("aria-label", "Grok activity");
  document.querySelector("#streaming-body")?.before(region);
  const draft = document.querySelector("#chat-draft");
  const menu = document.createElement("div"); menu.className = "cli-input-menu"; menu.hidden = true;
  menu.setAttribute("aria-label", "Commands and files"); menu.setAttribute("role", "listbox"); draft?.parentElement.before(menu);
  draft?.setAttribute("aria-controls", "cli-input-menu"); menu.id = "cli-input-menu";
  const modelButton = textNode("button", "Grok", "cli-model-picker"); modelButton.type = "button";
  modelButton.setAttribute("aria-label", "Choose model and reasoning effort"); modelButton.hidden = true;
  document.querySelector(".chat-run-controls")?.prepend(modelButton);
  const models = createCliModelPicker({ invoke, getSnapshot, showToast, button: modelButton });
  let project = null; let chatSession = null; let currentRun = null; let enabled = false; let mainSession = null;
  let commands = []; let thinking = ""; let plan = []; let rows = new Map(); let renderQueued = false; let menuEpoch = 0;
  const details = (label, content) => {
    const node = document.createElement("details"); node.append(textNode("summary", label), content); return node;
  };
  function paint() {
    renderQueued = false; const open = new Set([...region.querySelectorAll("details[open]")].map(node => node.dataset.key));
    const fragment = document.createDocumentFragment();
    if (thinking) { const node = details("Thinking", textNode("pre", thinking)); node.dataset.key = "thinking"; fragment.append(node); }
    if (plan.length) {
      const list = document.createElement("ol");
      for (const entry of plan) list.append(textNode("li", `${entry.status === "completed" ? "✓ " : entry.status === "in_progress" ? "◦ " : ""}${entry.content}`));
      const node = details("Plan", list); node.dataset.key = "plan"; fragment.append(node);
    }
    const background = document.createElement("div"); let backgroundCount = 0;
    for (const [key, row] of rows) {
      const body = document.createElement("div"); appendToolContent(body, row.content);
      if (row.text) body.append(textNode("pre", row.text));
      const label = `${row.title || "Grok activity"}${row.status ? ` · ${String(row.status).replaceAll("_", " ")}` : ""}`;
      const node = details(label, body); node.dataset.key = key;
      if (row.background || (row.session && mainSession && row.session !== mainSession)) { background.append(node); backgroundCount += 1; }
      else fragment.append(node);
    }
    if (backgroundCount) {
      const stop = textNode("button", "Stop background work", "button button-secondary"); stop.type = "button";
      stop.disabled = !backgroundConnection.connected();
      stop.addEventListener("click", () => { void backgroundConnection.stop(); }); background.append(stop);
      const node = details(`Background tasks · ${backgroundCount}`, background); node.dataset.key = "background"; fragment.append(node);
    }
    region.replaceChildren(fragment);
    region.querySelectorAll("details").forEach(node => { node.open = open.has(node.dataset.key); });
    region.hidden = !enabled || !region.childNodes.length;
  }
  function schedulePaint() { if (!renderQueued) { renderQueued = true; requestAnimationFrame(paint); } }
  function update(event, run) {
    if (!enabled) return;
    if (run && currentRun !== run) { currentRun = run; rows = new Map(); thinking = ""; plan = []; mainSession = null; }
    interactions.update(event, run);
    permissions.update(event);
    if (event.kind === "error") rows.set("connection-error", { title: "CLI connection", status: "failed", text: String(event.payload).slice(0, 8192), background: true });
    if (event.kind === "thought_delta") thinking = (thinking + event.payload).slice(-131072);
    if (event.kind === "cli_update") {
      const update = event.payload?.update || {}; const session = event.payload?.session_id;
      if (!mainSession && ["session_info_update", "available_commands_update"].includes(update.sessionUpdate)) mainSession = session;
      const parent = session === mainSession;
      if (update.sessionUpdate === "background_stopped") {
        for (const row of rows.values()) if ((row.background || (row.session && mainSession && row.session !== mainSession)) && ["running", "pending", "in_progress"].includes(row.status)) row.status = "cancelled";
      }
      else if (update.sessionUpdate === "available_commands_update" && parent) commands = (update.availableCommands || []).slice(0, 256);
      else if (update.sessionUpdate === "config_option_update" && parent) applyOptions(update.configOptions);
      else if (update.sessionUpdate === "plan") {
        if (parent) plan = (update.entries || []).slice(0, 128);
        else rows.set(`${session}:plan`, { title: "Agent plan", text: (update.entries || []).slice(0, 128).map(entry => `${entry.status}: ${entry.content}`).join("\n"), session });
      }
      else if (update.sessionUpdate === "tool_call" || update.sessionUpdate === "tool_call_update") {
        const key = `${session}:${update.toolCallId}`;
        rows.set(key, { ...mergeCliTool(rows.get(key), update), session });
      } else if (["agent_message_chunk", "agent_thought_chunk"].includes(update.sessionUpdate)) {
        const key = `${session}:message`; const row = rows.get(key) || { title: "Agent reply", text: "", session };
        row.text = (row.text + (update.content?.text || "")).slice(-131072); rows.set(key, row);
      } else if (update.sessionUpdate === "background_tasks") {
        if (!update.truncated) for (const [key, row] of rows) if (row.task && row.session === session) rows.delete(key);
        for (const task of (update.tasks || []).slice(0, 128)) rows.set(`${session}:task:${task.task_id}`, { title: task.description || task.display_command || task.command, status: task.status, text: task.exit_code == null ? "" : `Exit ${task.exit_code}`, session, background: true, task: true });
      } else if (["subagent_spawned", "subagent_progress", "subagent_finished"].includes(update.sessionUpdate)) {
        const key = `${session}:child:${update.subagent_id}`; const previous = rows.get(key) || {};
        rows.set(key, { ...previous, title: update.description || previous.title || "Agent", status: update.status || "running", text: update.output || previous.text || "", session: update.child_session_id, background: true });
      } else if (update.sessionUpdate === "background_message") {
        const key = `${session}:background-message`; const previous = rows.get(key);
        rows.set(key, { title: "Background reply", text: ((previous?.text || "") + update.text).slice(-131072), session, background: true });
      } else if (["retry_state", "auto_compact_started", "auto_compact_completed", "auto_compact_failed"].includes(update.sessionUpdate)) {
        rows.set(`${session}:progress`, { title: update.sessionUpdate.startsWith("auto_compact") ? "Context compaction" : "Connection retry", status: update.sessionUpdate.endsWith("failed") ? "failed" : update.sessionUpdate.endsWith("completed") ? "completed" : "running", session });
      } else if (update.sessionUpdate === "display_limit") rows.set(`${session}:limit`, { title: "Display limit", text: update.text, session });
      while (rows.size > 128) rows.delete(rows.keys().next().value);
    }
    schedulePaint();
  }
  function applyOptions(options) {
    models.options(options);
  }
  function snapshot(value) {
    const previousMode = enabled;
    enabled = value?.engine?.mode === "grokCliStandard";
    const nextSession = activeSessionId(value);
    if (previousMode !== enabled || project !== value?.activeProjectId || chatSession !== nextSession) { project = value?.activeProjectId; chatSession = nextSession; currentRun = null; rows.clear(); thinking = ""; plan = []; commands = []; mainSession = null; menu.hidden = true; models.reset(); }
    interactions.snapshot(value); permissions.snapshot(value); input.snapshot(value); models.snapshot(value); schedulePaint(); void backgroundConnection.poll();
  }
  function choose(value, start) {
    draft.setRangeText(value, start, draft.selectionStart, "end"); menu.hidden = true; draft.focus(); draft.dispatchEvent(new Event("input", { bubbles: true }));
  }
  async function inputMenu() {
    const epoch = ++menuEpoch; menu.replaceChildren(); menu.hidden = true;
    if (!enabled || !draft) return;
    const prefix = draft.value.slice(0, draft.selectionStart); let options = []; let start = 0;
    if (/^\/[^\s]*$/.test(prefix)) {
      const query = prefix.slice(1).toLowerCase();
      options = commands.filter(command => command.name.toLowerCase().includes(query)).slice(0, 12).map(command => ({ label: `/${command.name}`, detail: command.description, value: `/${command.name} ` }));
    } else {
      const mention = prefix.match(/(?:^|\s)@([^\s]*)$/); if (!mention) return;
      const query = mention[1]; start = prefix.length - query.length - 1;
      const slash = query.lastIndexOf("/"); const directory = slash < 0 ? "." : query.slice(0, slash); const needle = query.slice(slash + 1).toLowerCase();
      if (directory.startsWith("/") || directory.split("/").includes("..")) return;
      try {
        const listing = await invoke("list_workspace_directory", { path: directory });
        if (epoch !== menuEpoch) return;
        options = (listing.entries || []).filter(entry => entry.name.toLowerCase().includes(needle)).slice(0, 12).map(entry => ({ label: entry.name, detail: entry.kind, value: `@${entry.path}${entry.kind === "directory" ? "/" : " "}` }));
      } catch { return; }
    }
    for (const option of options) {
      const button = textNode("button", option.label); button.type = "button"; button.setAttribute("role", "option"); button.title = option.detail || "";
      button.addEventListener("click", () => choose(option.value, start)); menu.append(button);
    }
    menu.hidden = !options.length; draft.setAttribute("aria-expanded", String(!menu.hidden));
  }
  draft?.addEventListener("input", () => { void inputMenu(); });
  draft?.addEventListener("keydown", event => {
    if (event.key === "ArrowDown" && !menu.hidden) { event.preventDefault(); menu.querySelector("button")?.focus(); }
    if (event.key === "Escape") { menu.hidden = true; draft.setAttribute("aria-expanded", "false"); }
  });
  menu.addEventListener("keydown", event => {
    const options = [...menu.querySelectorAll("button")]; const current = options.indexOf(document.activeElement);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); options[(current + (event.key === "ArrowDown" ? 1 : options.length - 1)) % options.length]?.focus(); }
    if (event.key === "Escape") { menu.hidden = true; draft.focus(); }
  });
  return { update, snapshot, prepareInput: input.prepare, inputSent: input.sent };
}
