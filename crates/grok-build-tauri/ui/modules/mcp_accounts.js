"use strict";

export function createMcpAccounts({ invoke, currentScope, onStatus, onChange }) {
  const entries = new Map();
  let generation = 0;
  let busy = false;
  const text = (tag, value) => { const n = document.createElement(tag); n.textContent = value; return n; };
  const button = label => { const n = text("button", label); n.type = "button"; n.className = "button button-secondary"; return n; };
  const current = (selection, epoch) => generation === epoch && currentScope().projectId === selection.projectId;
  async function close(entry) {
    if (entry.review) await invoke("close_mcp_account_review", { projectId: entry.selection.projectId, reviewId: entry.review.reviewId });
  }
  function reset() {
    generation += 1;
    busy = false;
    for (const entry of entries.values()) { clearTimeout(entry.timer); void close(entry).catch(() => {}); }
    entries.clear();
  }
  async function refresh(entry, epoch) {
    const status = await invoke("mcp_account_status", { selection: entry.selection });
    if (!current(entry.selection, epoch)) return;
    entry.status = status;
    clearTimeout(entry.timer);
    if (status.signInActive) entry.timer = setTimeout(() => {
      if (!current(entry.selection, epoch)) return;
      void refresh(entry, epoch).then(onChange).catch(error => { if (current(entry.selection, epoch)) onStatus(String(error)); });
    }, 1500);
  }
  async function action(entry, operation) {
    if (busy || currentScope().projectId !== entry.selection.projectId) return;
    const epoch = generation;
    busy = true;
    onChange();
    try { await operation(epoch); }
    catch (error) { if (current(entry.selection, epoch)) onStatus(String(error)); }
    finally { if (current(entry.selection, epoch)) { busy = false; onChange(); } }
  }
  function render(parent, selection, disabled) {
    const key = JSON.stringify(selection);
    let entry = entries.get(key);
    if (!entry) { entry = { selection, status: null, review: null, issuer: 0, scopes: new Set(), client: "", register: false }; entries.set(key, entry); }
    const panel = document.createElement("details");
    panel.className = "extension-mcp-account";
    panel.open = Boolean(entry.open);
    panel.addEventListener("toggle", () => { if (panel.isConnected) entry.open = panel.open; });
    panel.append(text("summary", "MCP account"));
    const statusButton = button("Check account status");
    statusButton.disabled = disabled || busy;
    statusButton.addEventListener("click", () => { void action(entry, epoch => refresh(entry, epoch)); });
    panel.append(statusButton);
    if (entry.status) {
      const s = entry.status;
      panel.append(text("p", s.connected ? `Saved account: ${s.issuer}. Each connection validates its credential and tool catalog.` : s.requiresAccount ? "Signed out. This server requires sign-in before Chat can use it." : "No account is connected in this project."));
      if (s.error) panel.append(text("p", s.error));
      if (s.scopes.length) panel.append(text("p", `Account scopes: ${s.scopes.join(", ")}`));
      if (s.phase && s.phase !== "cleared") panel.append(text("p", `Sign-in: ${s.phase}${s.signInActive ? " (running)" : ""}`));
      if (s.signInActive) {
        const cancel = button("Cancel sign-in");
        cancel.disabled = busy;
        cancel.addEventListener("click", () => { void action(entry, async epoch => {
          await invoke("cancel_mcp_account_signin", { projectId: selection.projectId });
          onStatus("Cancellation requested. The account worker retains ownership until it stops.");
          await refresh(entry, epoch);
        }); });
        panel.append(cancel);
      } else {
        if (s.connected) {
          const disconnect = button("Sign out of this MCP server");
          disconnect.disabled = disabled || busy;
          disconnect.addEventListener("click", () => { void action(entry, async epoch => {
            try { await invoke("disconnect_mcp_account", { selection }); onStatus("Signed out. Account access was revoked for this server."); }
            finally { await refresh(entry, epoch); }
          }); });
          panel.append(disconnect);
        }
        if (s.phase === "interrupted" || s.cleanupPending) {
          panel.append(text("p", "Interrupted requests are not retried. Cleanup removes pending or retired credentials and keeps the active account."));
          const cleanup = button("Clear interrupted sign-in and retired credentials");
          cleanup.disabled = disabled || busy;
          cleanup.addEventListener("click", () => { void action(entry, async epoch => {
            try { await invoke("cleanup_mcp_accounts", { projectId: selection.projectId }); onStatus("Interrupted sign-in and retired credential cleanup completed."); }
            finally { await refresh(entry, epoch); }
          }); });
          panel.append(cleanup);
        }
      }
    }
    const reviewButton = button("Review sign-in options");
    reviewButton.disabled = disabled || busy || Boolean(entry.status?.signInActive);
    reviewButton.addEventListener("click", () => { void action(entry, async epoch => {
      await close(entry);
      entry.review = null;
      const review = await invoke("review_mcp_account", { selection });
      if (!current(selection, epoch)) { await invoke("close_mcp_account_review", { projectId: selection.projectId, reviewId: review.reviewId }); return; }
      entry.review = review; entry.issuer = 0; entry.scopes = new Set(); entry.register = false; entry.client = "";
      onStatus("Review the authorization service and select the scopes you want to grant.");
    }); });
    panel.append(reviewButton);
    if (entry.review) {
      const r = entry.review;
      const issuer = document.createElement("select");
      issuer.setAttribute("aria-label", "MCP authorization service");
      r.issuers.forEach((m, i) => issuer.append(new Option(m.issuer, String(i))));
      issuer.value = String(entry.issuer); issuer.disabled = disabled || busy;
      issuer.addEventListener("change", () => { entry.issuer = Number(issuer.value); entry.register = false; onChange(); });
      panel.append(issuer);
      const m = r.issuers[entry.issuer];
      panel.append(text("p", `Resource: ${r.resource}`), text("p", `Browser authorization: ${m.authorization}`), text("p", `Credential exchange: ${m.token}`));
      for (const scope of r.scopes) {
        const label = document.createElement("label");
        const check = document.createElement("input"); check.type = "checkbox"; check.checked = entry.scopes.has(scope); check.disabled = disabled || busy;
        check.addEventListener("change", () => { if (check.checked) entry.scopes.add(scope); else entry.scopes.delete(scope); });
        label.append(check, document.createTextNode(` ${scope} `)); panel.append(label);
      }
      const clientLabel = text("label", "Existing public client ID");
      const client = document.createElement("input"); client.type = "text"; client.maxLength = 1024; client.value = entry.client; client.autocomplete = "off"; client.disabled = disabled || busy || entry.register;
      client.addEventListener("input", () => { entry.client = client.value; });
      clientLabel.append(client); panel.append(clientLabel);
      if (m.registration) {
        const label = document.createElement("label"); const check = document.createElement("input"); check.type = "checkbox"; check.checked = entry.register; check.disabled = disabled || busy;
        check.addEventListener("change", () => { entry.register = check.checked; onChange(); });
        label.append(check, document.createTextNode(` Register GB Plus as a public client at ${m.registration}. This creates a registration on that service.`)); panel.append(label);
      }
      const start = button("Start reviewed sign-in in browser"); start.disabled = disabled || busy;
      start.addEventListener("click", () => { void action(entry, async epoch => {
        await invoke("begin_mcp_account_signin", { selection, choice: {
          reviewId: r.reviewId, issuer: entry.issuer, scopes: [...entry.scopes],
          clientId: entry.register ? null : entry.client, registerClient: entry.register,
        } });
        entry.review = null;
        onStatus("Sign-in started. Complete authorization in your browser, then return here for verified status.");
        await refresh(entry, epoch);
      }); });
      panel.append(start);
    }
    parent.append(panel);
  }
  return { render, reset };
}
