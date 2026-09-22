"use strict";
import { activeSessionId } from "./run_status.js";

function text(tag, copy) { const node = document.createElement(tag); node.textContent = copy; return node; }
function button(copy, action) { const node = text("button", copy); node.type = "button"; node.className = "button"; node.addEventListener("click", action); return node; }

export function createAgentSettings({ invoke, currentScope, getSnapshot, onStatus, onChange }) {
  let projectId = null;
  let settings = null;
  let issue = null;
  let busy = false;
  let generation = 0;
  async function load(scope) {
    const request = ++generation; projectId = scope.projectId; settings = null; issue = null;
    if (!projectId || !invoke) return;
    try { const value = await invoke("agent_settings", { projectId }); if (request === generation && currentScope().projectId === projectId) settings = value; }
    catch (error) { if (request === generation) issue = String(error); }
    if (request === generation) onChange();
  }
  function render(container, needle) {
    if (needle && !"grok collaboration children agents explore plan worker parallel".includes(needle)) return;
    const row = document.createElement("article"); row.className = "extension-model-row";
    row.append(text("h3", "Grok children"));
    if (!settings) { row.append(text("p", issue || "Open a project to configure Grok collaboration.")); container.append(row); return; }
    const toggle = document.createElement("input"); toggle.type = "checkbox"; toggle.checked = settings.enabled;
    toggle.setAttribute("aria-label", "Enable Grok children for this project");
    toggle.disabled = busy || (getSnapshot()?.queue?.activeGlobalRuns || 0) > 0;
    const label = document.createElement("label"); label.append(toggle, document.createTextNode(settings.enabled ? " Enabled for this project" : " Off"));
    row.append(label, text("p", "Allow Grok to delegate to Explore, Plan, or Worker children. Up to two model executions run at once. Worker changes stay separate for your review."));
    row.append(text("small", "Parallel children use separate managed worktrees. Projects without safe Git isolation run children one at a time. Change this setting after active runs finish."));
    toggle.addEventListener("change", async () => {
      if (currentScope().projectId !== projectId) { onStatus("Project changed. Reopen Extensions."); return; }
      const request = generation; busy = true; toggle.disabled = true;
      try { const value = await invoke("set_agents_enabled", { projectId, enabled: toggle.checked }); if (request === generation && currentScope().projectId === projectId) { settings = value; onStatus(value.enabled ? "Grok children enabled for future runs." : "Grok children are off."); } }
      catch (error) { if (request === generation) onStatus(String(error)); }
      finally { busy = false; onChange(); }
    });
    container.append(row);
  }
  return { load, render };
}

export function createChildActivity({ invoke, getSnapshot, onSnapshot, showToast }) {
  const chat = document.createElement("section"); chat.className = "child-activity"; chat.hidden = true; chat.setAttribute("aria-label", "Grok children");
  document.querySelector("#transcript")?.append(chat);
  const activity = document.createElement("section"); activity.className = "child-activity panel"; activity.hidden = true; activity.setAttribute("aria-label", "Grok child activity");
  document.querySelector("#timeline-list")?.closest("article")?.insertAdjacentElement("beforebegin", activity);
  const cache = new Map();
  const versions = new Map();
  const opened = new Set();
  const busy = new Set();
  let scope = null;
  function currentScope(snapshot = getSnapshot()) { return `${snapshot?.activeProjectId || ""}:${snapshot?.folderPath || ""}`; }
  function args(child) { return { projectId: child.project, parentRunId: child.parent, childRunId: child.id }; }
  async function act(child, command, extra = {}) {
    const expected = scope; busy.add(child.id); render(getSnapshot());
    try {
      await invoke(command, { ...args(child), ...extra });
      cache.delete(child.id);
      const snapshot = await invoke("bootstrap", {});
      if (expected === currentScope()) onSnapshot(snapshot);
    } catch (error) { if (expected === currentScope()) showToast(String(error), true); }
    finally { busy.delete(child.id); render(getSnapshot()); }
  }
  async function load(child) {
    const expected = scope;
    try { const value = await invoke("child_agent_result", args(child)); if (expected === currentScope()) cache.set(child.id, value); }
    catch (error) { if (expected === currentScope()) cache.set(child.id, { error: String(error) }); }
    if (expected === currentScope()) render(getSnapshot());
  }
  function row(child, index, surface, snapshot) {
    const details = document.createElement("details"); const key = `${surface}:${child.id}`; details.open = opened.has(key);
    const status = child.state === "needs_review" && !child.reviewPending ? "reviewed" : child.state.replaceAll("_", " ");
    details.append(text("summary", `${child.role} child ${index + 1} · ${status}${child.reviewPending ? " · Review required" : ""}`));
    details.addEventListener("toggle", () => { if (!details.isConnected) return; if (details.open) { opened.add(key); if (!cache.has(child.id)) void load(child); } else opened.delete(key); });
    details.append(text("small", `${child.agentId} · ${child.isolated ? "Separate managed worktree" : "Serial captured workspace"}`));
    const value = cache.get(child.id);
    if (value?.error) details.append(text("p", value.error));
    else if (value?.payload?.status === "unavailable") details.append(text("p", "This child used transient context that is no longer available. Reattach the source in a new context or discard this retained review."));
    else if (value?.payload) {
      details.append(text("p", value.payload.assistant || "No completed child reply is recorded yet."));
      for (const proposal of value.payload.pending?.items || []) {
        const change = document.createElement("details"); change.append(text("summary", proposal.relative_path));
        const decoder = new TextDecoder();
        change.append(text("h4", "Before"), text("pre", decoder.decode(new Uint8Array(proposal.before))), text("h4", "After"), text("pre", decoder.decode(new Uint8Array(proposal.after))));
        details.append(change);
      }
      if (value.decision && value.decision !== "pending") details.append(text("p", `Review: ${value.decision}`));
    } else if (details.open) details.append(text("p", "Loading child details…"));
    for (const message of value?.messages || []) details.append(text("small", `Guidance ${message.id}: ${message.delivery.replaceAll("_", " ")}`));
    const active = ["waiting", "running", "stop_requested"].includes(child.state);
    if (active) { const stop = button("Stop child", () => { void act(child, "stop_child_agent"); }); stop.disabled = busy.has(child.id) || child.state === "stop_requested"; details.append(stop); }
    if (child.reviewPending && !active) {
      const discard = button("Discard child review", () => { void act(child, "decide_child_changes", { accept: false }); });
      const accept = button("Accept child changes", () => { void act(child, "decide_child_changes", { accept: true }); });
      const idle = (snapshot?.queue?.activeGlobalRuns || 0) === 0;
      discard.disabled = busy.has(child.id) || !idle;
      accept.disabled = busy.has(child.id) || !idle || value?.decision !== "pending" || !value?.payload?.pending?.items?.length;
      details.append(discard, accept);
    }
    return details;
  }
  function render(snapshot) {
    const next = currentScope(snapshot);
    if (scope !== next) { scope = next; cache.clear(); versions.clear(); opened.clear(); }
    const runs = new Map((snapshot?.queue?.runs || []).map(run => [run.id, run]));
    const children = (snapshot?.queue?.children || []).filter(child => child.project === snapshot?.activeProjectId).slice(-128);
    const sessionId = activeSessionId(snapshot);
    for (const child of children) {
      const version = `${child.state}:${child.reviewPending}:${child.endedAtUnixMs}`;
      if (versions.get(child.id) !== version) { cache.delete(child.id); versions.set(child.id, version); }
    }
    const chatChildren = sessionId ? children.filter(child => runs.get(child.parent)?.sessionId === sessionId) : children;
    for (const [surface, container, visible] of [["chat", chat, chatChildren], ["activity", activity, children]]) {
      container.hidden = !visible.length;
      container.replaceChildren(text("h3", "Grok children"), ...visible.map((child, index) => row(child, index, surface, snapshot)));
    }
    for (const key of cache.keys()) if (!children.some(child => child.id === key)) cache.delete(key);
  }
  return { render };
}
