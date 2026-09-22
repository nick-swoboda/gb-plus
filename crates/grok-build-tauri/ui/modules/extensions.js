"use strict";

import { activeSessionId } from "./run_status.js";
import { createExtensionInventory } from "./extension_inventory.js";
import { createProjectMemory } from "./project_memory.js";
import { createAgentSettings } from "./agents.js";
import { createWorkflowControls } from "./workflows.js";
import { createNativeProtocolControls } from "./native_protocol.js";

export function createExtensions({ invoke, getSnapshot, showToast }) {
  const dialog = document.createElement("dialog");
  dialog.className = "extensions-overlay";
  dialog.setAttribute("aria-labelledby", "extensions-heading");
  dialog.innerHTML = `<header><h2 id="extensions-heading">Extensions</h2><button type="button" class="button" data-close aria-label="Close Extensions">Close</button></header>
    <label>Search <input type="search" placeholder="Find models and extensions" data-search></label>
    <nav aria-label="Extension filters">${["Tools", "Skills", "Automations", "Agents", "Models"].map(name => `<button type="button" class="button" data-filter="${name}" aria-pressed="${name === "Models"}">${name}</button>`).join("")}</nav>
    <p role="status" data-status></p><div data-results></div>`;
  document.body.append(dialog);
  const status = dialog.querySelector("[data-status]");
  const results = dialog.querySelector("[data-results]");
  const search = dialog.querySelector("[data-search]");
  let filter = "Models";
  let catalog = null;
  let scope = null;
  let generation = 0;
  let busy = false;
  const inventory = createExtensionInventory({ dialog, invoke, currentScope, onStatus: value => { status.textContent = value; }, onChange: render });
  const memory = createProjectMemory({ invoke, currentScope, onStatus: value => { status.textContent = value; }, onChange: render });
  const agents = createAgentSettings({ invoke, currentScope, getSnapshot, onStatus: value => { status.textContent = value; }, onChange: render });

  const workflows = createWorkflowControls({ invoke, currentScope, getSnapshot, onStatus: value => { status.textContent = value; }, onChange: render });

  const connection = createNativeProtocolControls({ invoke, currentScope, onStatus: value => { status.textContent = value; }, onChange: render, isBusy: () => busy, onBusy: value => { busy = value; } });

  function currentScope() {
    const snapshot = getSnapshot();
    return { projectId: snapshot?.activeProjectId, sessionId: activeSessionId(snapshot), transport: snapshot?.account?.selectedTransport };
  }
  function scopeMatches() { return JSON.stringify(scope) === JSON.stringify(currentScope()); }
  function text(tag, copy) { const node = document.createElement(tag); node.textContent = copy; return node; }
  function render() {
    results.replaceChildren();
    if (filter !== "Models") {
      if (filter === "Agents") { agents.render(results, search.value.trim().toLocaleLowerCase()); memory.render(results, search.value.trim().toLocaleLowerCase()); }
      if (filter === "Automations") workflows.render(results, search.value.trim().toLocaleLowerCase());
      inventory.render(results, filter, search.value.trim().toLocaleLowerCase());
      return;
    }
    inventory.hideSources();
    const needle = search.value.trim().toLocaleLowerCase();
    connection.render(results, needle);
    if (!catalog) return;
    const models = catalog.models.filter(model => `${model.id} ${model.name}`.toLocaleLowerCase().includes(needle));
    for (const model of models) {
      const row = document.createElement("article");
      row.className = "extension-model-row";
      row.append(text("h3", model.name), text("code", model.id));
      const context = model.contextWindow == null ? "Unknown" : model.contextWindow.toLocaleString();
      const image = model.acceptsImages == null ? "Unknown" : model.acceptsImages ? "Supported" : "Unavailable";
      row.append(text("p", `Context: ${context} · Images: ${image}`));
      const label = text("label", "Reasoning effort ");
      const effort = document.createElement("select");
      const offered = catalog.transport === "XaiKeychain" ? ["none", "minimal", "low", "medium", "high", "xhigh"] : model.reasoningEfforts;
      if (catalog.transport === "XaiKeychain" || !offered.length) effort.append(new Option("Model default", ""));
      for (const value of offered) effort.append(new Option(value, value));
      if (catalog.selected?.model?.id === model.id && catalog.selected.reasoningEffort != null) effort.value = catalog.selected.reasoningEffort;
      label.append(effort);
      row.append(label);
      const select = text("button", catalog.selected?.model?.id === model.id ? "Verify selection" : "Verify and select");
      select.type = "button";
      select.className = "button button-secondary";
      select.disabled = busy;
      select.addEventListener("click", async () => {
        if (!scopeMatches()) { status.textContent = "Project or transport changed. Reopen Extensions."; return; }
        busy = true;
        status.textContent = "Verifying this model and its app tool support…";
        dialog.querySelectorAll(".extension-model-row button").forEach(button => { button.disabled = true; });
        try {
          const selected = await invoke("select_session_model", { projectId: scope.projectId, sessionId: scope.sessionId, modelId: model.id, reasoningEffort: effort.value || null });
          if (scopeMatches()) { catalog.selected = selected; status.textContent = `Selected ${model.name}${selected.reasoningEffort ? ` · ${selected.reasoningEffort}` : ""} for this chat.`; }
        } catch (error) { status.textContent = String(error); }
        finally { busy = false; render(); }
      });
      row.append(select);
      results.append(row);
    }
    if (!models.length) results.append(text("p", "No matching models in this authenticated catalog."));
  }
  async function open() {
    if (busy) { dialog.showModal(); return; }
    scope = currentScope();
    const request = ++generation;
    catalog = null;
    dialog.showModal();
    search.focus();
    render();
    void workflows.load(scope);
    void inventory.load(scope).catch(error => { if (request === generation && filter !== "Models") status.textContent = String(error); });
    void memory.load(scope);
    void agents.load(scope);
    void connection.load(scope);
    if (!scope.projectId || !scope.sessionId || !invoke) { status.textContent = "Open a project and connect Account to inspect its models."; return; }
    status.textContent = filter === "Models" ? "Loading models from the selected account…" : "Review versions and enable components for this project.";
    try {
      const loaded = await invoke("list_session_models", { projectId: scope.projectId, sessionId: scope.sessionId });
      if (request !== generation || !scopeMatches()) return;
      catalog = loaded;
      if (filter === "Models") status.textContent = `Models available through ${loaded.transport}. Selection includes a live capability check.`;
      render();
    } catch (error) { if (request === generation && filter === "Models") status.textContent = String(error); }
  }
  dialog.querySelector("[data-close]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => inventory.close());
  dialog.querySelectorAll("[data-filter]").forEach(button => button.addEventListener("click", () => {
    filter = button.dataset.filter;
    status.textContent = filter === "Models" ? (catalog ? `Models available through ${catalog.transport}. Selection includes a live capability check.` : "Connect Account to inspect available models.") : "Review versions and enable components for this project.";
    dialog.querySelectorAll("[data-filter]").forEach(item => item.setAttribute("aria-pressed", String(item === button)));
    render();
  }));
  search.addEventListener("input", render);
  document.querySelector("#open-extensions")?.addEventListener("click", () => { void open().catch(error => showToast(String(error), true)); });
}
