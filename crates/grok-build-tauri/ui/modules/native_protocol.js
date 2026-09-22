"use strict";

export function createNativeProtocolControls({ invoke, currentScope, onStatus, onChange, isBusy, onBusy }) {
  let scope = null;
  let generation = 0;
  let confirmed = null;
  let selected = "http";
  const same = () => JSON.stringify(scope) === JSON.stringify(currentScope());
  const text = (tag, value) => { const node = document.createElement(tag); node.textContent = value; return node; };
  async function load(next = currentScope()) {
    scope = { ...next }; const request = ++generation;
    confirmed = null; selected = "http";
    if (!scope.projectId || !scope.sessionId || scope.transport !== "XaiKeychain") { onChange(); return; }
    try {
      const value = await invoke("get_session_native_protocol", { projectId: scope.projectId, sessionId: scope.sessionId });
      if (request !== generation || !same()) return;
      if (!["http", "websocket"].includes(value)) throw new Error("The saved connection choice is unavailable.");
      confirmed = value; selected = value; onChange();
    } catch (error) { if (request === generation && same()) { onStatus(String(error)); onChange(); } }
  }
  async function apply() {
    if (isBusy() || confirmed == null || !same()) return;
    const request = generation;
    const target = selected;
    onBusy(true); onStatus("Verifying the selected connection and this chat's model tool support…"); onChange();
    try {
      const value = await invoke("set_session_native_protocol", { projectId: scope.projectId, sessionId: scope.sessionId, protocol: target });
      if (request !== generation || !same()) return;
      if (value !== target) throw new Error("The connection choice was not confirmed. Refresh before continuing.");
      confirmed = value; selected = value;
      onStatus(`This chat uses ${value === "websocket" ? "WebSocket" : "HTTP"}.`);
    } catch (error) { if (request === generation && same()) onStatus(String(error)); }
    finally { onBusy(false); onChange(); }
  }
  function render(container, needle = "") {
    if (scope?.transport !== "XaiKeychain" || !same() || (needle && !"connection mode http websocket".includes(needle))) return;
    const row = document.createElement("article"); row.className = "extension-model-row";
    row.append(text("h3", "Connection mode"), text("p", "HTTP is the default. Optional WebSocket uses xAI streaming. A lost connection stops the turn for review."));
    const label = text("label", "Use for this chat ");
    const choice = document.createElement("select"); choice.setAttribute("aria-label", "Native xAI connection mode");
    choice.append(new Option("HTTP", "http"), new Option("WebSocket (optional)", "websocket")); choice.value = selected; choice.disabled = isBusy() || confirmed == null;
    choice.addEventListener("change", () => { selected = choice.value; }); label.append(choice); row.append(label);
    const verify = text("button", "Verify and use connection"); verify.type = "button"; verify.className = "button button-secondary";
    verify.disabled = isBusy() || confirmed == null; verify.addEventListener("click", () => { void apply(); }); row.append(verify);
    if (confirmed != null) row.append(text("small", `Current choice: ${confirmed === "websocket" ? "WebSocket" : "HTTP"}.`));
    container.append(row);
  }
  return { load, render };
}
