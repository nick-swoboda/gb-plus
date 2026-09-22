"use strict";
import { createMcpAccounts } from "./mcp_accounts.js";

export function createMcpReviews({ invoke, currentScope, onStatus, onChange }) {
  const components = new Map();
  const accounts = createMcpAccounts({ invoke, currentScope, onStatus, onChange });
  let generation = 0;
  let busy = false;
  function text(tag, value) { const node = document.createElement(tag); node.textContent = value; return node; }
  function button(label) { const node = text("button", label); node.type = "button"; node.className = "button button-secondary"; return node; }
  function current(projectId, epoch) { return generation === epoch && currentScope().projectId === projectId; }
  async function close(review) {
    if (!review?.reviewId) return;
    await invoke("close_extension_mcp_review", { projectId: review.projectId, reviewId: review.reviewId });
  }
  function reset() {
    accounts.reset();
    generation += 1;
    busy = false;
    for (const entry of components.values()) {
      for (const review of entry.reviews.values()) void close(review).catch(() => {});
    }
    components.clear();
  }
  async function action(projectId, label, operation) {
    if (currentScope().projectId !== projectId) { onStatus("Project changed. Reopen Extensions."); return; }
    if (busy) return;
    const epoch = generation;
    busy = true;
    onStatus(label);
    onChange();
    try { await operation(epoch); }
    catch (error) { if (current(projectId, epoch)) onStatus(String(error)); }
    finally { if (current(projectId, epoch)) { busy = false; onChange(); } }
  }
  function render(parent, projectId, contentDigest, componentId, disabled) {
    const key = `${projectId}:${contentDigest}:${componentId}`;
    const entry = components.get(key);
    const inspect = button(entry ? "Refresh server inventory" : "Inspect MCP servers");
    inspect.disabled = disabled || busy;
    inspect.addEventListener("click", () => { void action(projectId, "Reading the installed MCP configuration…", async epoch => {
      const servers = await invoke("list_extension_mcp_servers", { projectId, contentDigest, componentId });
      if (!current(projectId, epoch)) return;
      if (entry) for (const review of entry.reviews.values()) await close(review);
      components.set(key, { servers, reviews: new Map(), openTools: new Set(), openSchemas: new Set(), focusTool: null });
      onStatus("Choose a server to read its tool catalog. Inspection does not enable tool execution.");
    }); });
    parent.append(inspect);
    if (!entry) return;
    for (const server of entry.servers) {
      const section = document.createElement("section");
      section.className = "extension-mcp-server";
      section.append(text("h4", server.name));
      if (server.unavailable) { section.append(text("p", server.unavailable)); parent.append(section); continue; }
      section.append(text("p", server.endpoint));
      if (!server.contained) accounts.render(section, { projectId, contentDigest, componentId, serverName: server.name }, disabled || busy);
      if (server.contained) {
        const admission = document.createElement("details");
        admission.append(text("summary", "Review local server execution"));
        admission.append(text("p", "Starts this bundled executable in the managed Linux guest. It can read the captured working files and write private scratch space. Network access is blocked. App state, conventional credential paths and generated trees are excluded. Tool calls require separate approval."));
        admission.append(text("pre", JSON.stringify({ command: server.contained.command, arguments: server.contained.arguments, architecture: server.contained.architecture, bytes: server.contained.executableBytes, sha256: server.contained.executableDigest, content: server.contained.content }, null, 2)));
        section.append(admission);
      }
      const catalog = button(server.contained ? "Start contained server and inspect" : "Read tool catalog");
      catalog.disabled = disabled || busy;
      catalog.addEventListener("click", () => { void action(projectId, "Reading the server’s tool catalog…", async epoch => {
        const previous = entry.reviews.get(server.name);
        if (previous) { await close(previous); entry.reviews.delete(server.name); }
        const review = await invoke("inspect_extension_mcp_catalog", { projectId, contentDigest, componentId, serverName: server.name });
        if (!current(projectId, epoch)) { await close(review); return; }
        entry.reviews.set(server.name, review);
        onStatus(`Read ${review.tools.length} tools from ${review.serverName}. ${review.toolExecutionEnabled ? "Enabled calls require their own app approval." : "Enable this component explicitly to make its tools available to Chat."}`);
      }); });
      section.append(catalog);
      const review = entry.reviews.get(server.name);
      if (review) for (const item of review.tools) {
        const tool = item.tool;
        const row = document.createElement("details");
        row.open = entry.openTools.has(tool.appName);
        row.addEventListener("toggle", () => { if (row.isConnected) { if (row.open) entry.openTools.add(tool.appName); else entry.openTools.delete(tool.appName); } });
        row.append(text("summary", tool.wireName), text("p", tool.description));
        row.append(text("p", "The app has not classified this tool’s effects. Its server annotations do not grant permission."));
        const policy = document.createElement("select");
        policy.setAttribute("aria-label", `${tool.wireName} policy in this project`);
        policy.append(new Option("Ask for each call", "ask"), new Option("Block this tool", "deny"));
        policy.value = item.policy;
        policy.disabled = disabled || busy;
        policy.addEventListener("change", () => {
          entry.focusTool = tool.appName;
          void action(projectId, "Saving the tool policy for this project…", async epoch => {
          const result = await invoke("set_extension_mcp_policy", { projectId, choice: {
            reviewId: review.reviewId, revision: review.revision, appName: tool.appName,
            fingerprint: tool.fingerprint, policy: policy.value,
          } });
          if (!current(projectId, epoch)) return;
          entry.reviews.set(server.name, result);
          onStatus("Tool policy saved for this project and the reviewed server/schema version.");
        }); });
        row.append(policy);
        if (!busy && entry.focusTool === tool.appName) queueMicrotask(() => {
          if (policy.isConnected && policy.closest("dialog")?.open && document.activeElement === document.body) policy.focus({ preventScroll: true });
          entry.focusTool = null;
        });
        const schema = document.createElement("details");
        schema.open = entry.openSchemas.has(tool.appName);
        schema.addEventListener("toggle", () => { if (schema.isConnected) { if (schema.open) entry.openSchemas.add(tool.appName); else entry.openSchemas.delete(tool.appName); } });
        schema.append(text("summary", "Review schema and fingerprint"), text("code", tool.fingerprint), text("pre", JSON.stringify(tool.inputSchema, null, 2)));
        row.append(schema);
        section.append(row);
      }
      parent.append(section);
    }
  }
  function matches(projectId, contentDigest, componentId, needle) {
    const entry = components.get(`${projectId}:${contentDigest}:${componentId}`);
    if (!entry) return false;
    return [...entry.reviews.values()].some(review => review.tools.some(({ tool }) =>
      `${tool.wireName} ${tool.description}`.toLocaleLowerCase().includes(needle)));
  }
  return { render, reset, matches };
}
