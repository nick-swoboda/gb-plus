export function createUpdates({ invoke, elements, getSnapshot, getBusy, setAccountBusy, onSnapshot }) {
  const { updateGrokCli: button, accountCliVersion: version, grokCliCompatibility: status } = elements;
  let pending = false;
  let updating = false;
  let message = "Updates Grok and its built-in features.";

  function render() {
    const queue = getSnapshot()?.queue;
    const active = queue?.activeGlobalRuns > 0;
    button.disabled = !invoke || pending || getBusy() || !queue?.available || active;
    button.textContent = updating ? "Updating…" : "Update Grok CLI";
    button.setAttribute("aria-busy", String(updating));
    status.textContent = active && !updating ? "Finish or stop chats before updating." : message;
  }

  async function refresh() {
    if (!invoke || pending) return;
    pending = true;
    render();
    try {
      const result = await invoke("inspect_grok_cli");
      version.textContent = `Grok CLI ${result.version}`;
    } catch {
      version.textContent = "Grok CLI · version unavailable";
    } finally {
      pending = false;
      render();
    }
  }

  async function update() {
    render();
    if (button.disabled) return;
    pending = true;
    updating = true;
    message = "Updating Grok CLI…";
    setAccountBusy(true);
    render();
    try {
      const result = await invoke("update_grok_cli");
      version.textContent = `Grok CLI ${result.version}`;
      message = result.detail;
      if (getSnapshot()?.account?.selectedTransport === "GrokCliAcp") {
        message += " Choose Connect to reconnect.";
      }
    } catch (error) {
      message = `Update failed. ${String(error)}`;
    } finally {
      try { onSnapshot(await invoke("bootstrap", {})); }
      catch { message += " Reopen Account to check connection status."; }
      pending = false;
      updating = false;
      setAccountBusy(false);
      render();
    }
  }

  button.addEventListener("click", update);
  return { refresh, render };
}
