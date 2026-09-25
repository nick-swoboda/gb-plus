export function createUpdates({ invoke, elements, getSnapshot, getBusy, setAccountBusy, onSnapshot }) {
  const { updateGrokCli: button, accountCliVersion: version, grokCliCompatibility: status } = elements;
  let pending = false;
  let updating = false;
  let message = "Updates Grok and its built-in features.";
  const switchButton = button.ownerDocument.createElement("button");
  switchButton.type = "button";
  switchButton.className = button.className;
  switchButton.textContent = "Use Grok CLI standard";
  switchButton.setAttribute("aria-describedby", "grok-cli-engine-detail grok-cli-compatibility");
  const engineDetail = button.ownerDocument.createElement("p");
  engineDetail.id = "grok-cli-engine-detail";
  engineDetail.textContent = "Standard follows xAI updates and shares your Terminal settings. CLI commands run on your Mac, with Ask permissions by default.";
  status.after(engineDetail, switchButton);

  const contained = () => getSnapshot()?.account?.engine?.mode === "gbPlusContained";
  function render() {
    const queue = getSnapshot()?.queue;
    const active = queue?.activeGlobalRuns > 0;
    button.disabled = !invoke || pending || getBusy() || !queue?.available || active;
    button.textContent = updating ? "Updating…" : "Update Grok CLI";
    button.setAttribute("aria-busy", String(updating));
    status.textContent = active && !updating ? "Finish or stop chats before updating." : message;
    switchButton.hidden = engineDetail.hidden = !contained();
    const queued = queue?.items?.some(item => ["queued", "running"].includes(item.state));
    switchButton.disabled = button.disabled || queued;
    if (contained() && !pending) {
      status.textContent += " Switch to standard to use CLI updates.";
      if (queued && !active) status.textContent += " Finish or remove queued work before switching.";
    }
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
      if (!contained() && getSnapshot()?.account?.selectedTransport === "GrokCliAcp") {
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

  async function useStandard() {
    render();
    if (switchButton.disabled || !contained()) return;
    pending = true;
    setAccountBusy(true);
    render();
    try {
      onSnapshot(await invoke("set_engine_settings", { settings: {
        ...getSnapshot().account.engine, mode: "grokCliStandard",
      } }));
      message = "Grok CLI standard selected. Choose Connect when ready.";
      elements.loginGrokCli?.focus();
    } catch (error) {
      message = `Could not switch engines. ${String(error)}`;
    } finally {
      pending = false;
      setAccountBusy(false);
      render();
    }
  }

  button.addEventListener("click", update);
  switchButton.addEventListener("click", useStandard);
  return { refresh, render };
}
