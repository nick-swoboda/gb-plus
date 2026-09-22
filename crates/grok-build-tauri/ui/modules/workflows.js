"use strict";
import { activeSessionId } from "./run_status.js";

function text(tag, copy) { const node = document.createElement(tag); node.textContent = copy; return node; }
function button(copy, action) { const node = text("button", copy); node.type = "button"; node.className = "button"; node.addEventListener("click", action); return node; }

export function createWorkflowControls({ invoke, currentScope, getSnapshot, onStatus, onChange }) {
  let scope = null;
  let data = null;
  let generation = 0;
  let busy = false;
  const drafts = new Map();
  const results = new Map();
  const opened = new Set();
  const same = () => JSON.stringify(scope) === JSON.stringify(currentScope());
  async function load(next = currentScope()) {
    const changed = JSON.stringify(scope) !== JSON.stringify(next);
    scope = { ...next }; const request = ++generation;
    if (changed) { data = null; drafts.clear(); results.clear(); opened.clear(); }
    if (!scope.projectId) return;
    try {
      const value = await invoke("list_project_workflows", { projectId: scope.projectId });
      if (request === generation && same()) { data = value; results.clear(); onChange(); }
    } catch (error) { if (request === generation && same()) onStatus(String(error)); }
  }
  async function act(command, args) {
    if (!same()) { onStatus("Project or chat changed. Reopen Extensions."); return; }
    busy = true; onChange();
    try { await invoke(command, args); if (same()) { onStatus("Workflow request recorded."); await load(); } }
    catch (error) { if (same()) onStatus(String(error)); }
    finally { busy = false; onChange(); }
  }
  function form(workflow) {
    const key = `${workflow.extension}:${workflow.component}`;
    if (!drafts.has(key)) drafts.set(key, { args: "{}", maximum: 8, transient: false });
    const draft = drafts.get(key);
    const row = document.createElement("article"); row.className = "extension-model-row";
    row.append(text("h3", workflow.name));
    const source = document.createElement("details"); source.append(text("summary", "Inspect workflow script"), text("pre", workflow.script)); row.append(source);
    const inputLabel = text("label", "Input JSON "); const input = document.createElement("textarea"); input.value = draft.args; input.rows = 3; input.maxLength = 65536; input.setAttribute("aria-label", `Input JSON for ${workflow.name}`); input.addEventListener("input", () => { draft.args = input.value; }); inputLabel.append(input);
    const budgetLabel = text("label", "Maximum Grok calls "); const budget = document.createElement("input"); budget.type = "number"; budget.min = "1"; budget.max = "32"; budget.step = "1"; budget.value = String(draft.maximum); budget.addEventListener("input", () => { draft.maximum = Number(budget.value); }); budgetLabel.append(budget);
    const transientLabel = document.createElement("label"); const transient = document.createElement("input"); transient.type = "checkbox"; transient.checked = draft.transient; transient.addEventListener("change", () => { draft.transient = transient.checked; }); transientLabel.append(transient, document.createTextNode(" Keep input and results temporary"));
    row.append(inputLabel, budgetLabel, transientLabel, text("small", "Temporary input and results cannot resume after restarting the app. Up to two Grok children execute at once; proposed changes stay separate for review."));
    const run = button("Run workflow", () => {
      let args;
      try { args = JSON.parse(draft.args); } catch { onStatus("Enter valid JSON for the workflow input."); return; }
      if (!Number.isInteger(draft.maximum) || draft.maximum < 1 || draft.maximum > 32) { onStatus("Choose a whole-number budget from 1 to 32."); return; }
      void act("start_project_workflow", { request: { projectId: scope.projectId, extension: workflow.extension, component: workflow.component, args, maximum: draft.maximum, transient: draft.transient } });
    });
    run.disabled = busy; row.append(run); return row;
  }
  function history(job) {
    const row = document.createElement("details"); row.open = opened.has(job.id);
    row.append(text("summary", `${job.name} · ${job.state} · ${job.used}/${job.maximum} Grok calls`));
    if (job.phase) row.append(text("p", job.phase));
    if (!job.available) row.append(text("p", "Temporary context is unavailable. Start a new workflow with reattached input."));
    const result = results.get(job.id);
    if (result) row.append(text("pre", JSON.stringify(result, null, 2)));
    row.addEventListener("toggle", () => {
      if (!row.isConnected) return;
      if (!row.open) { opened.delete(job.id); return; }
      opened.add(job.id);
      if (!results.has(job.id)) {
        const request = generation;
        void invoke("workflow_result", { projectId: scope.projectId, jobId: job.id }).then(value => { if (request === generation && same()) { results.set(job.id, value); onChange(); } }).catch(error => { if (request === generation && same()) onStatus(String(error)); });
      }
    });
    if (["paused", "interrupted", "failed", "stopped"].includes(job.state)) {
      const resume = button("Resume workflow", () => { void act("resume_project_workflow", { projectId: scope.projectId, jobId: job.id }); });
      resume.disabled = busy || !job.available || (getSnapshot()?.queue?.activeGlobalRuns || 0) > 0; row.append(resume);
    }
    if (job.state === "running") {
      const stop = button("Stop workflow", () => { void act("stop_project_workflow", { projectId: scope.projectId, jobId: job.id }); }); stop.disabled = busy; row.append(stop);
    }
    return row;
  }
  function render(container, needle) {
    const section = document.createElement("section"); section.className = "workflow-controls";
    section.append(text("h3", "Workflows"), text("p", "Enable a reviewed workflow below, then choose Run. Enabling a workflow does not schedule it."));
    const refresh = button("Refresh workflows", () => { void load(); }); refresh.disabled = busy; section.append(refresh);
    const workflows = (data?.workflows || []).filter(item => !needle || item.name.toLocaleLowerCase().includes(needle));
    for (const workflow of workflows) section.append(form(workflow));
    for (const job of (data?.jobs || []).filter(item => !needle || item.name.toLocaleLowerCase().includes(needle))) section.append(history(job));
    if (!workflows.length) section.append(text("p", "No matching enabled workflows."));
    container.append(section);
  }
  return { load, render };
}

export function createWorkflowActivity({ invoke, getSnapshot }) {
  const chat = document.createElement("section"); chat.className = "child-activity"; chat.hidden = true; chat.setAttribute("aria-label", "Workflows"); document.querySelector("#transcript")?.append(chat);
  const activity = document.createElement("section"); activity.className = "child-activity panel"; activity.hidden = true; activity.setAttribute("aria-label", "Workflow activity"); document.querySelector("#timeline-list")?.closest("article")?.insertAdjacentElement("beforebegin", activity);
  const opened = new Set(); const cache = new Map(); const versions = new Map(); const pending = new Set(); let project = null; let generation = 0;
  function refresh(item) {
    if (cache.has(item.id) || pending.has(item.id)) return;
    pending.add(item.id);
    const expected = project; const request = generation; const version = item.state;
    const current = () => request === generation && expected === getSnapshot()?.activeProjectId && versions.get(item.id) === version;
    void invoke("workflow_result", { projectId: project, jobId: item.workflow.jobId }).then(value => {
      if (current()) cache.set(item.id, value);
    }).catch(error => {
      if (current()) cache.set(item.id, { error: String(error) });
    }).finally(() => {
      if (current()) { pending.delete(item.id); render(getSnapshot()); }
    });
  }
  function row(item, surface) {
    const key = `${surface}:${item.id}`; const details = document.createElement("details"); details.open = opened.has(key);
    const result = cache.get(item.id);
    const status = result?.state || (item.state === "done" ? "attempt finished" : item.state.replaceAll("_", " "));
    details.append(text("summary", `${item.prompt} · ${status}`));
    if (result) details.append(text("pre", JSON.stringify(result, null, 2)));
    details.addEventListener("toggle", () => {
      if (!details.isConnected) return;
      if (!details.open) { opened.delete(key); return; }
      opened.add(key); refresh(item);
    });
    return details;
  }
  function render(snapshot) {
    if (project !== snapshot?.activeProjectId) { project = snapshot?.activeProjectId; generation += 1; cache.clear(); versions.clear(); pending.clear(); opened.clear(); }
    const items = (snapshot?.queue?.items || []).filter(item => item.projectId === project && item.workflow).slice(-64);
    for (const item of items) {
      if (versions.get(item.id) !== item.state) { cache.delete(item.id); pending.delete(item.id); versions.set(item.id, item.state); }
      refresh(item);
    }
    const session = activeSessionId(snapshot);
    for (const [surface, target, visible] of [["chat", chat, items.filter(item => item.sessionId === session)], ["activity", activity, items]]) {
      target.hidden = !visible.length; target.replaceChildren(text("h3", "Workflows"), ...visible.map(item => row(item, surface)));
    }
  }
  return { render };
}
