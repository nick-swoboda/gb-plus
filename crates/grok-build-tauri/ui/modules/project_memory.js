"use strict";

export function createProjectMemory({ invoke, currentScope, onStatus, onChange }) {
  let projectId = null;
  let data = null;
  let generation = 0;
  let busy = false;
  let issue = null;
  let draft = "";
  let expanded = false;
  function text(tag, value) { const node = document.createElement(tag); node.textContent = value; return node; }
  function button(value) { const node = text("button", value); node.type = "button"; node.className = "button"; node.disabled = busy; return node; }
  async function load(scope) {
    const request = ++generation;
    if (projectId !== scope.projectId) { draft = ""; expanded = false; }
    projectId = scope.projectId;
    data = null;
    issue = null;
    if (!projectId) return;
    try {
      const result = await invoke("project_memory_view", { projectId });
      if (request === generation && projectId === currentScope().projectId) data = result;
    } catch (error) { if (request === generation) issue = String(error); }
    onChange();
  }
  async function act(command, args) {
    if (busy || !projectId || projectId !== currentScope().projectId) return;
    const request = generation;
    const project = projectId;
    busy = true;
    onChange();
    try {
      const result = await invoke(command, { projectId: project, ...args });
      if (request === generation && projectId === currentScope().projectId) {
        data = result;
        if (command === "remember_project_fact") draft = "";
        onStatus("Project memory updated for future runs.");
      }
    } catch (error) { if (request === generation) onStatus(String(error)); }
    finally { busy = false; onChange(); }
  }
  function render(results, needle) {
    if (needle && !`project memory facts ${data?.facts?.map(f => f.text).join(" ") || ""}`.toLocaleLowerCase().includes(needle)) return;
    const row = document.createElement("article");
    row.className = "extension-model-row";
    row.append(text("h3", "Project memory"));
    if (!data) { row.append(text("p", issue || "Open a project to view its memory.")); results.append(row); return; }
    const label = text("label", "");
    const enabled = document.createElement("input");
    enabled.type = "checkbox";
    enabled.setAttribute("aria-label", "Enable memory for this project");
    enabled.checked = data.enabled;
    enabled.disabled = busy;
    enabled.addEventListener("change", () => { void act("set_project_memory", { enabled: enabled.checked }); });
    label.append(enabled, document.createTextNode(data.enabled ? " Enabled for this project" : " Off"));
    row.append(label, text("p", "Save non-secret facts for future runs. Previously sent facts can remain in chat history."));
    const facts = document.createElement("details");
    facts.open = expanded;
    facts.addEventListener("toggle", () => { expanded = facts.open; });
    facts.append(text("summary", `View ${data.facts.length} saved ${data.facts.length === 1 ? "fact" : "facts"}`));
    for (const fact of data.facts) {
      const item = document.createElement("div");
      item.append(text("p", fact.text), text("small", "You saved this fact in this project."));
      const forget = button("Forget");
      forget.addEventListener("click", () => { void act("forget_project_fact", { factId: fact.id }); });
      item.append(forget);
      facts.append(item);
    }
    if (data.facts.length) {
      const clear = button("Forget all facts");
      clear.addEventListener("click", () => { void act("forget_project_fact", { factId: null }); });
      facts.append(clear);
    }
    row.append(facts);
    const form = document.createElement("form");
    const inputLabel = text("label", "New fact ");
    const input = document.createElement("textarea");
    input.rows = 2;
    input.value = draft;
    input.addEventListener("input", () => { draft = input.value; });
    input.maxLength = 1024;
    input.required = true;
    input.disabled = busy || !data.enabled;
    inputLabel.append(input);
    const save = button("Save fact");
    save.type = "submit";
    save.disabled = busy || !data.enabled;
    form.append(inputLabel, save);
    form.addEventListener("submit", event => { event.preventDefault(); void act("remember_project_fact", { text: input.value }); });
    row.append(form);
    results.append(row);
  }
  return { load, render };
}
