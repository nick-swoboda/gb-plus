"use strict";

export function createDesktopControl({ invoke, elements, getActiveProjectId, onError, onNotice, onCapabilityState }) {
  let view = null;
  let localBusy = false;
  let stopBusy = false;
  let hostBusy = true;
  let lastProjectId = null;
  let monitor = null;
  let countdown = null;

  elements.desktopSelect.addEventListener("click", () => void selectTarget());
  elements.desktopArm.addEventListener("click", () => void arm());
  elements.desktopStop.addEventListener("click", () => void stop());

  async function refresh(silent = true) {
    if (!invoke) return;
    try {
      view = await invoke("desktop_status", {});
      render();
    } catch (error) {
      if (!silent) onError(message(error));
    }
  }

  async function selectTarget() {
    if (!invoke || localBusy || hostBusy || !getActiveProjectId()) return;
    localBusy = true;
    beginCountdown("Switch to the app window you want to target", "Selecting");
    render();
    try {
      view = await invoke("desktop_select_target", {});
      onNotice("Desktop target selected · review the exact PID, window, display, and geometry");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      endCountdown();
      localBusy = false;
      render();
    }
  }

  async function arm() {
    const target = view?.pendingTarget;
    if (!invoke || localBusy || hostBusy || !target?.windowId) return;
    localBusy = true;
    beginCountdown(`Switch back to ${target.application} · window ${target.windowId}`, "Arming");
    render();
    try {
      view = await invoke("desktop_arm", { windowId: target.windowId });
      if (view?.phase === "armed") {
        onNotice("Desktop Control armed · exact target · run lifetime or 10 minutes");
      } else if (view?.phase === "target_selected" && view?.pendingTarget) {
        onNotice(view.detail || "Accessibility permission is pending · Desktop Control remains Off");
      } else {
        throw new Error("Desktop Control returned neither Armed nor an honest permission-pending state.");
      }
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      endCountdown();
      localBusy = false;
      render();
    }
  }

  async function stop() {
    if (!invoke || stopBusy) return;
    stopBusy = true;
    render();
    try {
      view = await invoke("desktop_stop", {});
      onNotice("Desktop Control stopped · target and grant cleared");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      stopBusy = false;
      render();
    }
  }

  function beginCountdown(instruction, verb) {
    endCountdown();
    let seconds = 3;
    countdown = { instruction, verb, seconds };
    const tick = window.setInterval(() => {
      seconds -= 1;
      if (countdown) countdown.seconds = Math.max(0, seconds);
      render();
      if (seconds <= 0) window.clearInterval(tick);
    }, 1000);
    countdown.timer = tick;
  }

  function endCountdown() {
    if (countdown?.timer) window.clearInterval(countdown.timer);
    countdown = null;
  }

  function reset(snapshot) {
    hostBusy = !snapshot?.activeProjectId;
    const projectId = snapshot?.activeProjectId || null;
    if (projectId !== lastProjectId) {
      lastProjectId = projectId;
      void refresh();
    } else if (!view || view.stopVisible) {
      void refresh();
    }
    render();
  }

  function setHostBusy(busy) {
    hostBusy = Boolean(busy);
    render();
  }

  function onViewShown() {
    void refresh(false);
  }

  function render() {
    const phase = view?.phase || "off";
    const armed = phase === "armed" || phase === "acting";
    const selected = phase === "target_selected" && Boolean(view?.pendingTarget);
    const error = phase === "failed" || Boolean(view?.lastRefusal);
    const kind = armed ? "on" : (error ? "error" : "off");
    const label = armed ? "Desktop Control On" : (error ? "Desktop Control error" : "Desktop Control Off");

    elements.desktopChip.dataset.kind = kind;
    elements.desktopChip.textContent = label;
    elements.desktopToolbarChip.dataset.kind = kind;
    elements.desktopToolbarChip.textContent = armed ? "Desktop On" : (error ? "Desktop error" : "Desktop Off");
    elements.desktopToolbarChip.setAttribute("aria-label", `Show Desktop Control: ${label}`);
    elements.desktopSelect.disabled = localBusy || hostBusy || armed;
    elements.desktopArm.disabled = localBusy || hostBusy || !selected;
    elements.desktopStop.hidden = !view?.stopVisible && !error;
    elements.desktopStop.disabled = stopBusy;
    elements.desktopStop.textContent = view?.stopVisible ? "Stop" : "Reset";
    renderTarget(elements.desktopTarget, view?.target || view?.pendingTarget);
    elements.desktopGrantDetail.textContent = grantDetail(view, countdown);
    elements.desktopStatus.textContent = countdown
      ? `${countdown.instruction}. ${countdown.verb} in ${countdown.seconds}…`
      : (view?.lastRefusal || view?.detail || "Desktop Control is Off.");
    elements.desktopStatus.dataset.kind = error ? "error" : (armed ? "on" : "off");
    onCapabilityState("desktop", Boolean(view?.stopVisible), stopBusy);
    updateMonitor(Boolean(view?.stopVisible));
  }

  function updateMonitor(active) {
    if (active && !monitor) {
      monitor = window.setInterval(() => void refresh(), 1000);
    } else if (!active && monitor) {
      window.clearInterval(monitor);
      monitor = null;
    }
  }

  return { refresh, reset, setHostBusy, onViewShown, stop };
}

function renderTarget(container, target) {
  const nodes = [];
  if (!target) {
    const empty = document.createElement("span");
    empty.textContent = "No app selected.";
    container.replaceChildren(empty);
    return;
  }
  const bounds = target.bounds || {};
  const geometry = `${number(bounds.x)}, ${number(bounds.y)} · ${number(bounds.width)}×${number(bounds.height)}`;
  const application = document.createElement("strong");
  application.textContent = target.application || "Application";
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = target.windowTitle || "Window details";
  const identity = document.createElement("span");
  identity.textContent = `PID ${number(target.pid)} · window ${number(target.windowId)} · display ${number(target.displayId)} · ${geometry}`;
  details.append(summary, identity);
  nodes.push(application, details);
  container.replaceChildren(...nodes);
}

function grantDetail(view, countdown) {
  if (countdown) return `${countdown.verb} in ${countdown.seconds}…`;
  if (view?.phase === "target_selected") return "App selected";
  return view?.stopVisible ? "On" : "Off";
}

function number(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? String(parsed) : "?";
}

function message(error) {
  return error instanceof Error ? error.message : String(error);
}
