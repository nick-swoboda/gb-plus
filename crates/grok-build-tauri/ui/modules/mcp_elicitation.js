"use strict";

export function createMcpElicitation({ invoke, getSnapshot, showToast }) {
  const parent = document.querySelector("#chat-canvas");
  if (!parent || !invoke) return;
  const section = document.createElement("section");
  section.className = "mcp-call-approvals mcp-elicitations";
  section.setAttribute("aria-label", "MCP server requests for information");
  section.hidden = true;
  parent.append(section);
  let project = null;
  let checking = false;
  const rows = new Map();
  const text = (tag, value) => { const node = document.createElement(tag); node.textContent = value; return node; };
  function button(label, handler) {
    const node = text("button", label);
    node.type = "button";
    node.className = "button button-secondary";
    node.dataset.busyAllowed = "";
    node.addEventListener("click", handler);
    return node;
  }
  async function answer(entry, action, content = null) {
    const view = entry.view;
    if (entry.busy || getSnapshot()?.activeProjectId !== view.projectId) return;
    entry.busy = true;
    entry.row.querySelectorAll("button").forEach(node => { node.disabled = true; });
    try {
      await invoke("answer_mcp_elicitation", { projectId: view.projectId,
        answer: { id: view.id, commitment: view.commitment, action, content } });
      entry.row.remove(); rows.delete(view.id);
      section.hidden = rows.size === 0;
      showToast("Response queued for this server.");
    } catch (error) { showToast(String(error)); }
    finally { entry.busy = false; entry.row.querySelectorAll("button").forEach(node => { node.disabled = false; }); update(entry); }
  }
  function fieldInput(field) {
    const label = document.createElement("label");
    label.append(text("span", `${field.title}${field.required ? " (required)" : ""}`));
    let input;
    if (field.options.length) {
      input = document.createElement("select");
      input.append(new Option("Choose…", ""));
      field.options.forEach((option, index) => input.append(new Option(option, String(index))));
      const selected = field.options.indexOf(field.default);
      if (selected >= 0) input.value = String(selected);
    } else {
      input = document.createElement("input");
      input.type = field.kind === "boolean" ? "checkbox" : field.kind === "string" ? "text" : "number";
      if (input.type === "checkbox") input.checked = field.default === true;
      else if (field.default != null) input.value = String(field.default);
      if (input.type === "text") {
        input.maxLength = field.constraints.maxLength ?? 4096;
        if (field.constraints.minLength != null) input.minLength = field.constraints.minLength;
      }
      if (input.type === "number") {
        input.step = field.kind === "integer" ? "1" : "any";
        input.min = String(field.constraints.minimum ?? -Number.MAX_SAFE_INTEGER);
        input.max = String(field.constraints.maximum ?? Number.MAX_SAFE_INTEGER);
      }
    }
    input.autocomplete = "off";
    input.spellcheck = false;
    if (input.type !== "checkbox") input.required = field.required;
    label.append(input);
    if (field.description) label.append(text("small", field.description));
    const constraints = Object.entries(field.constraints).filter(([, value]) => value != null).map(([key, value]) => `${key}: ${value}`);
    if (constraints.length) label.append(text("small", constraints.join(" · ")));
    return { label, input, value() {
      if (field.options.length) return input.value === "" ? undefined : field.options[Number(input.value)];
      if (field.kind === "boolean") return input.checked;
      if (input.value === "" && !field.required) return undefined;
      return field.kind === "string" ? input.value : Number(input.value);
    } };
  }
  function create(view) {
    const row = document.createElement("article");
    const entry = { view, row, busy: false, continueButton: null };
    row.append(text("h3", `${view.server} requests input`), text("p", view.endpoint), text("p", view.message));
    if (view.request.kind === "form") {
      row.append(text("p", "These values go to this server. Do not enter passwords, API keys, payment credentials or other secrets."));
      const form = document.createElement("form");
      const inputs = view.request.fields.map(field => ({ field, ...fieldInput(field) }));
      inputs.forEach(item => form.append(item.label));
      const send = () => {
        if (!form.reportValidity()) return;
        const content = Object.create(null);
        for (const item of inputs) { const value = item.value(); if (value !== undefined) content[item.field.name] = value; }
        void answer(entry, "accept", content);
      };
      form.addEventListener("submit", event => { event.preventDefault(); send(); });
      form.append(button("Send response", send));
      row.append(form);
    } else if (view.request.kind === "url") {
      row.append(text("p", `The server requests a link to ${view.request.host}.`), text("code", view.request.url));
      const open = button(`Open ${view.request.host}`, async () => {
        if (entry.busy || getSnapshot()?.activeProjectId !== view.projectId) return;
        entry.busy = true; open.disabled = true;
        try {
          await invoke("open_mcp_elicitation_link", { projectId: view.projectId, id: view.id, commitment: view.commitment });
          entry.view.opened = true;
          showToast("Browser launch acknowledged. Continue to acknowledge navigation to the server.");
        } catch (error) { showToast(String(error)); }
        finally { entry.busy = false; open.disabled = false; update(entry); }
      });
      entry.continueButton = button("Continue after opening", () => { void answer(entry, "accept"); });
      row.append(open, entry.continueButton);
    }
    row.append(button("Decline", () => { void answer(entry, "decline"); }), button("Cancel request", () => { void answer(entry, "cancel"); }));
    update(entry);
    return entry;
  }
  function update(entry) { if (entry.continueButton) entry.continueButton.disabled = entry.busy || !entry.view.opened; }
  async function refresh() {
    const selected = getSnapshot()?.activeProjectId;
    if (project !== selected) { project = selected; rows.clear(); section.replaceChildren(); section.hidden = true; }
    if (!selected || checking || document.hidden) return;
    checking = true;
    try {
      const views = await invoke("list_mcp_elicitations", { projectId: selected });
      if (getSnapshot()?.activeProjectId !== selected) return;
      const active = new Set(views.map(view => view.id));
      for (const [id, entry] of rows) if (!active.has(id)) { entry.row.remove(); rows.delete(id); }
      for (const view of views) {
        const entry = rows.get(view.id);
        if (entry && entry.view.commitment === view.commitment) { entry.view.opened = view.opened; update(entry); }
        else { if (entry) entry.row.remove(); const next = create(view); rows.set(view.id, next); section.append(next.row); }
      }
      section.hidden = rows.size === 0;
    } catch { /* No pending app ticket means no interaction authority. */ }
    finally { checking = false; }
  }
  const timer = window.setInterval(() => { void refresh(); }, 1000);
  window.addEventListener("pagehide", () => { window.clearInterval(timer); rows.clear(); section.remove(); }, { once: true });
}
