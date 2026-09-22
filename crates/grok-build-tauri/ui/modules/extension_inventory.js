"use strict";

import { createMcpReviews } from "./extension_mcp.js";

export function createExtensionInventory({ dialog, invoke, currentScope, onStatus, onChange }) {
  let loadedScope = null;
  let data = null;
  let busy = false;
  let generation = 0;
  const mcp = createMcpReviews({ invoke, currentScope, onStatus, onChange });
  const panel = document.createElement("form");
  panel.className = "extension-source";
  const label = text("label", "Local extension folder ");
  const sourceType = document.createElement("select");
  sourceType.setAttribute("aria-label", "Extension source type");
  sourceType.append(new Option("Local folder", "local"), new Option("Pinned HTTPS archive", "https"));
  const path = document.createElement("input");
  path.type = "text";
  path.placeholder = "/absolute/path/to/plugin";
  path.autocomplete = "off";
  path.required = true;
  label.append(path);
  const preview = button("Preview folder");
  preview.type = "submit";
  const hashLabel = text("label", "Archive SHA-256 ");
  const hash = document.createElement("input");
  hash.pattern = "[a-f0-9]{64}";
  hash.autocomplete = "off";
  hashLabel.append(hash);
  const sizeLabel = text("label", "Exact archive bytes ");
  const size = document.createElement("input");
  size.type = "number";
  size.min = "1";
  size.max = "67108864";
  size.step = "1";
  sizeLabel.append(size);
  hashLabel.hidden = sizeLabel.hidden = true;
  sourceType.addEventListener("change", () => {
    const remote = sourceType.value === "https";
    label.firstChild.textContent = remote ? "Direct HTTPS archive URL " : "Local extension folder ";
    path.placeholder = remote ? "https://example.com/plugin-1.0.0.zip" : "/absolute/path/to/plugin";
    hashLabel.hidden = sizeLabel.hidden = !remote;
    hash.required = size.required = remote;
    preview.textContent = remote ? "Download and preview" : "Preview folder";
  });
  panel.append(sourceType, label, hashLabel, sizeLabel, preview);
  dialog.querySelector("nav").after(panel);

  function text(tag, content) { const node = document.createElement(tag); node.textContent = content; return node; }
  function button(content) { const node = text("button", content); node.type = "button"; node.className = "button button-secondary"; return node; }
  function validScope() { return loadedScope?.projectId && loadedScope.projectId === currentScope().projectId; }
  async function load(scope) {
    mcp.reset();
    const request = ++generation;
    loadedScope = { ...scope };
    data = null;
    if (!scope.projectId) return;
    const result = await invoke("list_project_extensions", { projectId: scope.projectId });
    if (request === generation && validScope()) { data = result; onChange(); }
  }
  async function action(description, operation, success = "Extension settings saved. Changes apply to future runs.") {
    if (busy) return;
    if (!validScope()) { onStatus("Project changed. Reopen Extensions."); return; }
    const operationScope = { ...loadedScope };
    const request = generation;
    busy = true;
    preview.disabled = true;
    onStatus(description);
    onChange();
    try {
      const result = await operation(operationScope.projectId);
      if (request === generation && validScope() && loadedScope.projectId === operationScope.projectId) {
        if (result?.extensions) data = result;
        else {
          const refreshed = await invoke("list_project_extensions", { projectId: operationScope.projectId });
          if (request === generation && validScope()) data = refreshed;
        }
        onStatus(success);
      }
    } catch (error) { if (request === generation) onStatus(String(error)); }
    finally { busy = false; preview.disabled = false; onChange(); }
  }
  panel.addEventListener("submit", event => {
    event.preventDefault();
    const request = sourceType.value === "https"
      ? { command: "preview_https_extension", args: { url: path.value.trim(), byteLen: size.valueAsNumber, sha256: hash.value.trim() } }
      : { command: "preview_local_extension", args: { path: path.value.trim() } };
    void action("Reading the extension and freezing its preview…", projectId => invoke(request.command, { projectId, ...request.args }), "Preview ready. Review the files before installing.");
  });
  function render(results, filter, needle) {
    panel.hidden = filter === "Models";
    if (!data) { results.append(text("p", "Open a project to inspect its extensions.")); return; }
    let matches = 0;
    for (const entry of data.extensions) {
      const p = entry.preview;
      const components = p.components.filter(c => c.kind === filter.toLowerCase());
      if (!components.length && filter !== "Tools") continue;
      if (!`${p.name} ${p.description} ${p.version} ${components.map(c => c.name).join(" ")}`.toLocaleLowerCase().includes(needle)
        && !components.some(c => mcp.matches(loadedScope.projectId, p.digest, c.id, needle))) continue;
      matches += 1;
      const row = document.createElement("article");
      row.className = "extension-model-row";
      row.append(text("h3", `${p.name} · ${p.version}`), text("p", p.description));
      row.append(text("p", `${entry.installed ? "Installed" : "Preview"} · ${p.license} · ${p.inventory.length.toLocaleString()} files · ${p.byteCount.toLocaleString()} bytes`));
      const review = document.createElement("details");
      review.append(text("summary", "Review source, hashes and files"), text("p", p.source), text("code", p.digest));
      const content = text("pre", "Select a file to read its frozen text. Executable content is never run here.");
      const fileSelect = document.createElement("select");
      fileSelect.setAttribute("aria-label", `Inspect ${p.name} file`);
      fileSelect.append(new Option("Choose a file…", ""));
      for (const file of p.inventory) fileSelect.append(new Option(`${file.path} (${file.bytes} bytes${file.executable ? ", executable flag" : ""})`, file.path));
      fileSelect.addEventListener("change", async () => {
        if (!validScope() || !fileSelect.value) return;
        const selected = fileSelect.value;
        const file = p.inventory.find(file => file.path === selected);
        content.textContent = `SHA-256: ${file?.sha256}\nLoading…`;
        try {
          const value = await invoke("inspect_extension_file", { projectId: loadedScope.projectId, contentDigest: p.digest, path: selected });
          if (validScope() && fileSelect.value === selected) content.textContent = `SHA-256: ${file?.sha256}\n\n${value}`;
        } catch (error) { content.textContent = String(error); }
      });
      review.append(fileSelect, content);
      row.append(review);
      if (!entry.installed) {
        const install = button(entry.complete ? "Install, keep off" : "Preview interrupted");
        install.disabled = busy || !entry.complete;
        install.addEventListener("click", () => { void action("Installing the reviewed content…", projectId => invoke("install_extension", { projectId, contentDigest: p.digest }), "Installed. Components remain off until you enable them for this project."); });
        row.append(install);
      }
      for (const component of components) {
        const setting = text("label", "");
        const toggle = document.createElement("input");
        toggle.type = "checkbox";
        toggle.checked = entry.enabledComponents.includes(component.id);
        toggle.disabled = busy || !entry.installed || (Boolean(component.quarantine) && !toggle.checked);
        toggle.addEventListener("change", () => { void action("Saving project enablement…", projectId => invoke("set_extension_component", { projectId, contentDigest: p.digest, componentId: component.id, enabled: toggle.checked })); });
        setting.append(toggle, document.createTextNode(` ${component.name}`));
        row.append(setting);
        if (component.quarantine) row.append(text("p", `Quarantined: ${component.quarantine}`));
        if (component.kind === "tools" && component.name === "mcpServers" && entry.installed) {
          mcp.render(row, loadedScope.projectId, p.digest, component.id, busy || Boolean(component.quarantine));
        }
      }
      results.append(row);
    }
    if (!matches) results.append(text("p", `No matching ${filter.toLowerCase().replace(/s$/, "")} extensions. Preview a local plugin to inspect its contents.`));
  }
  return { load, render, close: () => mcp.reset(), hideSources: () => { panel.hidden = true; } };
}
