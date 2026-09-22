"use strict";

export function createCaptureControl({ invoke, elements, getActiveProjectId, onError, onNotice, onCapabilityState }) {
  let view = null;
  let localBusy = false;
  let stopBusy = false;
  let hostBusy = true;
  let lastProjectId = null;
  let monitor = null;

  elements.captureArm.addEventListener("click", () => void arm());
  elements.captureTake.addEventListener("click", () => void take());
  elements.captureStop.addEventListener("click", () => void stop());

  async function refresh(silent = true) {
    if (!invoke) return;
    try {
      view = await invoke("capture_status", {});
      render();
    } catch (error) {
      if (!silent) onError(message(error));
    }
  }

  async function arm() {
    if (!invoke || localBusy || hostBusy || !getActiveProjectId()) return;
    localBusy = true;
    view = { ...(view || {}), phase: "arming", detail: "Waiting for macOS Screen Recording permission…", lastRefusal: null };
    render();
    try {
      view = await invoke("capture_arm", {});
      onNotice("Capture armed · main display · 15-minute maximum");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  async function take() {
    if (!invoke || localBusy || view?.phase !== "armed") return;
    localBusy = true;
    view = { ...view, phase: "capturing", detail: "Capturing one bounded still…", lastRefusal: null };
    render();
    try {
      view = await invoke("capture_take", {});
      onNotice("Still ready · it will attach once to the next Chat run");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  async function stop() {
    if (!invoke || stopBusy) return;
    stopBusy = true;
    render();
    try {
      view = await invoke("capture_stop", {});
      onNotice("Capture stopped · transient frame cleared");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      stopBusy = false;
      render();
    }
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
    const armed = phase === "armed" || phase === "ready" || phase === "capturing";
    const error = phase === "failed" || Boolean(view?.lastRefusal);
    const kind = armed ? "on" : (error ? "error" : "off");
    const label = armed ? (phase === "ready" ? "Capture ready" : "Capture On") : (error ? "Capture error" : "Capture Off");
    elements.captureChip.dataset.kind = kind;
    elements.captureChip.textContent = label;
    elements.captureToolbarChip.dataset.kind = kind;
    elements.captureToolbarChip.textContent = armed ? "Capture On" : (error ? "Capture error" : "Capture Off");
    elements.captureToolbarChip.setAttribute("aria-label", `Show Capture: ${label}`);
    elements.captureArm.disabled = localBusy || hostBusy || armed;
    elements.captureTake.disabled = localBusy || phase !== "armed";
    elements.captureStop.hidden = !view?.stopVisible && phase !== "failed";
    elements.captureStop.disabled = stopBusy;
    elements.captureStop.textContent = view?.stopVisible ? "Stop" : "Reset";
    elements.captureGrantDetail.textContent = grantDetail(view);
    const screenshot = typeof view?.frameDataUrl === "string" && view.frameDataUrl.startsWith("data:image/png;base64,")
      ? view.frameDataUrl
      : null;
    elements.capturePreview.hidden = !screenshot;
    if (screenshot) elements.capturePreview.src = screenshot;
    else elements.capturePreview.removeAttribute("src");
    elements.captureEmpty.hidden = Boolean(screenshot);
    elements.captureStatus.textContent = view?.lastRefusal || view?.detail || "Capture is Off.";
    elements.captureStatus.dataset.kind = error ? "error" : (armed ? "on" : "off");
    onCapabilityState("capture", Boolean(view?.stopVisible), stopBusy);
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

function grantDetail(view) {
  if (view?.phase === "arming") return "Requesting permission…";
  return view?.stopVisible ? "On" : "Off";
}

function message(error) {
  return typeof error === "string" ? error : (error?.message || String(error));
}
